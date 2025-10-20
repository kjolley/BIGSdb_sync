#!/usr/bin/env python3
# Client software for synchronising sequence definition and isolate databases
# with a remote BIGSdb installation via the API
# Written by Keith Jolley
# Copyright (c) 2025, University of Oxford
# E-mail: keith.jolley@biology.ox.ac.uk
#
# BIGSdb_sync is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# BIGSdb_sync is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# Version 20251020
import argparse
import sys
import os
import stat
import re
import configparser
import json
import threading
import time
import random
import logging
import psycopg2

from pathlib import Path
from urllib.parse import parse_qs
from bigsdb.script import Script
from rauth import OAuth1Service, OAuth1Session
from requests.exceptions import Timeout, ConnectionError, RequestException

USER_AGENT = "BIGSdb_sync"
BASE_WEB = {
    "PubMLST": "https://pubmlst.org/bigsdb",
    "Pasteur": "https://bigsdb.pasteur.fr/cgi-bin/bigsdb/bigsdb.pl",
}
MAX_REFRESH_ATTEMPTS = 1
MAX_ROUTE_ATTEMPTS = 10
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 60
CONNECTION_FAIL_RETRY = 60
MAX_CONNECTION_ATTEMPTS = 10
TOO_MANY_REQUESTS_DELAY = 60

session_provider = None
access_provider = None
args = None


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--add_new_loci",
        action="store_true",
        help="Set up new loci if they do not exist in local database.",
    )
    parser.add_argument(
        "--add_new_seqs", action="store_true", help="Add new allele/variant sequences."
    )
    parser.add_argument(
        "--api_db_url",
        required=True,
        help="URL for the top-level database API call, e.g. "
        "https://rest.pubmlst.org/db/pubmlst_neisseria_seqdef.",
    )
    parser.add_argument(
        "--base_web_url",
        required=False,
        help="URL to BIGSdb script on target web site. "
        "This is only needed to set up the access token.\n"
        "It should not be necessary to set this for PubMLST or BIGSdb Pasteur.",
    )
    parser.add_argument(
        "--check_seqs",
        action="store_true",
        help="Warn of changes to attributes of existing sequences. "
        "Combine with --update_seqs to modify existing records if changed.",
    )
    parser.add_argument(
        "--cron",
        action="store_true",
        help="Script is being run as a CRON job or non-interactively. "
        "Output will be sent to a log file (defined by --log_file).",
    )
    parser.add_argument("--db", required=True, help="Local database config name.")
    parser.add_argument(
        "--key_name",
        required=True,
        help="Name of API key - use a different name for each site.",
    )
    parser.add_argument("--loci", required=False, help="Comma-separated list of loci.")
    parser.add_argument(
        "--log_file",
        required=False,
        default="/var/log/bigsdb_sync.log",
        help="Path to log file if run with --cron option. Default is /var/log/bigsdb_sync.log.",
    )
    parser.add_argument(
        "--log_level",
        required=False,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level. Default to ERROR when run with --cron, or INFO when run interactively.",
    )
    parser.add_argument(
        "--reldate",
        required=False,
        type=int,
        help="Only add/update records modified in the last X days.",
    )
    parser.add_argument(
        "--schemes", required=False, help="Comma-separated list of scheme ids."
    )
    parser.add_argument(
        "--token_dir",
        required=False,
        default="./.bigsdb_tokens",
        help="Directory into which keys and tokens will be saved.",
    )
    parser.add_argument(
        "--update_seqs",
        action="store_true",
        help="Update sequence attributes if they have changed.",
    )
    return parser.parse_args()


class TokenProvider:
    """
    In-memory provider backed by the on-disk token files used by script.
    Single-process safe: uses threading locks to avoid concurrent refreshes in threads.
    If you run multiple processes you should replace the refresh lock with a file lock
    or use a central store (Redis/DB) + distributed lock.
    """

    def __init__(self, token_dir, key_name, token_type="session"):
        self.token_dir = Path(token_dir)
        self.key_name = key_name
        self.token_type = token_type  # "session" by default
        self._lock = threading.RLock()  # protects _token/_secret reads/writes
        self._refresh_lock = threading.Lock()  # single-flight refresh
        self._token = None
        self._secret = None
        # lazy load
        self._load_from_disk()

    def _token_file(self):
        return self.token_dir / f"{self.token_type}_tokens"

    def _load_from_disk(self):
        file_path = self._token_file()
        if not file_path.is_file():
            self._token = None
            self._secret = None
            return
        config = configparser.ConfigParser(interpolation=None)
        config.read(file_path)
        if config.has_section(self.key_name):
            self._token = config[self.key_name].get("token")
            self._secret = config[self.key_name].get("secret")
        else:
            self._token = None
            self._secret = None

    def _write_to_disk(self, token, secret):
        file_path = self._token_file()
        config = configparser.ConfigParser(interpolation=None)
        if file_path.is_file():
            config.read(file_path)
        config[self.key_name] = {"token": token, "secret": secret}
        with open(file_path, "w") as fh:
            config.write(fh)
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

    def get(self):
        with self._lock:
            # ensure we have the latest from disk (in case another process updated it)
            self._load_from_disk()
            return self._token, self._secret

    def set(self, token, secret):
        with self._lock:
            self._token = token
            self._secret = secret
            # persist immediately
            self._write_to_disk(token, secret)

    def refresh(self, refresh_func):
        """
        Single-flight refresh. refresh_func is a callable that returns (token, secret).
        If another thread is already refreshing we will wait and re-read the token.
        """
        # try to acquire refresh lock: if we get it, we'll do the refresh; otherwise wait.
        if self._refresh_lock.acquire(blocking=False):
            try:
                # call refresh_func which must not call get_route() (to avoid recursion)
                token, secret = refresh_func()
                if not token or not secret:
                    raise RuntimeError("Refresh function returned invalid credentials")
                # store & persist
                self.set(token, secret)
                return token, secret
            finally:
                self._refresh_lock.release()
        else:
            # someone else is refreshing — wait a short while for it to finish
            waited = 0.0
            while self._refresh_lock.locked() and waited < 10.0:
                time.sleep(0.05)
                waited += 0.05
            # then return latest
            return self.get()


def main():
    global session_provider, access_provider, script, args
    args = parse_args()
    check_required_args()
    check_token_dir(args.token_dir)
    logger = init_logger()

    try:
        script = Script(database=args.db, logger=logger)
    except Exception as e:
        sys.exit(f"Error setting up script object for config {args.db}. {e}")

    session_provider = TokenProvider(
        args.token_dir, args.key_name, token_type="session"
    )
    access_provider = TokenProvider(args.token_dir, args.key_name, token_type="access")
    token, secret = session_provider.get()
    if not token or not secret:
        token, secret = get_new_session_token()
        session_provider.set(token, secret)
    db_type = check_db_types_match()
    if db_type == "seqdef":
        update_seqdef(token, secret)


def init_logger():
    logger = logging.getLogger(__name__)
    if args.log_level is None:
        if args.cron:
            args.log_level = "ERROR"
        else:
            args.log_level = "INFO"
    level = logging.getLevelName(args.log_level)
    logger.setLevel(level)
    logger.propagate = False
    formats = {
        "cron_debug": "%(asctime)s - %(levelname)s: - %(module)s:%(lineno)d - %(message)s",
        "cron": "%(asctime)s - %(levelname)s: - %(message)s",
        "interactive_debug": "%(levelname)s: - %(module)s:%(lineno)d - %(message)s",
        "interactive": "%(levelname)s: %(message)s",
    }

    if args.cron:
        log_path = Path(args.log_file)
        if log_path.exists():
            # Check if it's writable
            if not os.access(log_path, os.W_OK):
                sys.stderr.write(
                    f"CRITICAL: Log file {args.log_file} exists but is not writable.\n"
                )
                exit(1)
        else:
            # Create a new empty log file
            try:
                log_path.touch(mode=0o644, exist_ok=False)
            except Exception as e:
                sys.stderr.write(f"CRITICAL: Failed to create log file: {e}.\n")
                exit(1)
        f_handler = logging.FileHandler(args.log_file)
        f_handler.setLevel(level)
        format = (
            formats.get("cron_debug")
            if args.log_level == "DEBUG"
            else formats.get("cron")
        )
        f_format = logging.Formatter(format)
        f_handler.setFormatter(f_format)
        logger.addHandler(f_handler)
    else:
        c_handler = logging.StreamHandler()
        c_handler.setLevel(level)
        format = (
            formats.get("interactive_debug")
            if args.log_level == "DEBUG"
            else formats.get("interactive")
        )
        c_format = logging.Formatter(format)
        c_handler.setFormatter(c_format)
        logger.addHandler(c_handler)
    return logger


def check_required_args():
    if not re.search(r"^https?://.*/db/[A-Za-z0-9_-]+$", args.api_db_url):
        script.logger.error(
            "--api_db_url should be a valid URL (starting with http(s):// and\n"
            "ending with /db/xxx where xxx is a database configuration)."
        )
        sys.exit(1)


def get_base_web():
    if args.base_web_url:
        return args.base_web_url
    if re.search(r"pubmlst.org", args.api_db_url):
        return BASE_WEB["PubMLST"]
    if re.search(r"bigsdb.pasteur.fr", args.api_db_url):
        return BASE_WEB["Pasteur"]
    script.logger.error("Base web URL not determined. Please set with --base_web_url.")
    sys.exit(1)


def get_db_type():
    try:
        db_type = script.datastore.run_query(
            "SELECT value FROM db_attributes WHERE field=?", "type"
        )
    except ValueError as e:
        script.logger.error("Could not determine local database type.")
        sys.exit(1)
    if db_type not in ("seqdef", "isolates"):
        script.logger.error("Invalid db_type for local database.")
        sys.exit(1)
    return db_type


def get_db_value():
    match = re.search(r"/db/([^/]+)", args.api_db_url)
    if match:
        db = match.group(1)
    else:
        raise ValueError("No db value found in the URL.")
    return db


def check_token_dir(directory):
    if os.path.isdir(directory):
        if os.access(directory, os.W_OK):
            return
        else:
            script.logger.critical(
                f"The token directory '{directory}' exists but is not writable."
            )
            sys.exit(1)
    else:
        try:
            os.makedirs(directory)
            os.chmod(directory, stat.S_IRWXU)  # Set permissions to 0700
        except OSError as e:
            script.logger.critical(
                f"Failed to create token directory '{directory}': {e}"
            )
            sys.exit(1)


def get_service():
    db = get_db_value()
    (client_key, client_secret) = get_client_credentials()
    request_token_url = f"{args.api_db_url}/oauth/get_request_token"
    access_token_url = f"{args.api_db_url}/oauth/get_access_token"
    return OAuth1Service(
        name=USER_AGENT,
        consumer_key=client_key,
        consumer_secret=client_secret,
        request_token_url=request_token_url,
        access_token_url=access_token_url,
        base_url=args.api_db_url,
    )


def get_new_session_token():
    global access_provider, session_provider
    (access_token, access_secret) = access_provider.get()
    if not access_token or not access_secret:
        (access_token, access_secret) = get_new_access_token()
    service = get_service()
    (client_key, client_secret) = get_client_credentials()
    db = get_db_value()
    url = f"{args.api_db_url}/oauth/get_session_token"
    session_request = OAuth1Session(
        client_key,
        client_secret,
        access_token=access_token,
        access_token_secret=access_secret,
    )
    r = session_request.get(url, headers={"User-Agent": USER_AGENT})
    if r.status_code == 200:
        response_json = get_response_content(r)
        token = response_json.get("oauth_token", "")
        secret = response_json.get("oauth_token_secret", "")
        session_provider.set(token, secret)
        return (token, secret)
    else:
        try:
            payload = r.json()
        except ValueError:
            payload = {}
        msg = payload.get("message", "") if isinstance(payload, dict) else ""
        script.logger.error(f"Failed to get new session token. {msg}")
        if args.cron:
            script.logger.error("Run interactively to fix.")
        if re.search("verification", msg) or re.search("Invalid access token", msg):
            script.logger.error("New access token required - removing old one.")
            access_provider.set(None, None)

        sys.exit(1)


def get_response_content(r):
    content_type = r.headers.get("content-type", "")
    if "json" in content_type.lower():
        try:
            return r.json()
        except ValueError:
            script.logger.error("Response declared JSON but could not parse JSON.")
            sys.exit(1)
    # fallback: try JSON anyway then fallback to text
    try:
        return r.json()
    except Exception:
        return r.text


def get_new_request_token():
    (client_key, client_secret) = get_client_credentials()
    db = get_db_value()
    service = get_service()

    r = service.get_raw_request_token(
        params={"oauth_callback": "oob"}, headers={"User-Agent": USER_AGENT}
    )
    if r.status_code == 404:
        script.logger.error(f"404 Page not found. {args.api_db_url}.")
        sys.exit(1)
    if r.status_code == 200:
        response_json = get_response_content(r)
        token = response_json.get("oauth_token", "")
        secret = response_json.get("oauth_token_secret", "")
        return (token, secret)
    else:
        try:
            payload = r.json()
        except ValueError:
            payload = {}
        msg = payload.get("message", "") if isinstance(payload, dict) else ""
        script.logger.error(f"Failed to get new request token. {msg}")
        exit(1)


def get_new_access_token():
    global access_provider
    web_base_url = get_base_web()
    if args.cron:
        script.logger.error(
            f"No access token saved for {args.key_name}. "
            "Run interactively to set (without --cron)."
        )
        sys.exit(1)
    file_path = Path(f"{args.token_dir}/access_tokens")
    (request_token, request_secret) = get_new_request_token()
    db = get_db_value()
    print(
        "Please log in using your user account at "
        f"{web_base_url}?db={db}&page=authorizeClient&oauth_token={request_token} "
        "using a web browser to obtain a verification code."
    )
    verifier = input("Please enter verification code: ")
    service = get_service()
    r = service.get_raw_access_token(
        request_token,
        request_secret,
        params={"oauth_verifier": verifier},
        headers={"User-Agent": USER_AGENT},
    )
    if r.status_code == 200:
        response_json = get_response_content(r)
        token = response_json.get("oauth_token", "")
        secret = response_json.get("oauth_token_secret", "")
        access_provider.set(token, secret)
        print("Access Token:        " + token)
        print("Access Token Secret: " + secret + "\n")
        print(
            "This access token will not expire but may be revoked by the \n"
            f"user or the service provider. It will be saved to \n{file_path}."
        )
        return (token, secret)
    else:
        try:
            payload = r.json()
        except ValueError:
            payload = {}
        msg = payload.get("message", "") if isinstance(payload, dict) else ""
        script.logger.error(f"Failed to get new access token. {msg}")
        sys.exit(1)


def get_client_credentials():
    config = configparser.ConfigParser(interpolation=None)
    file_path = Path(f"{args.token_dir}/client_credentials")
    client_id = None
    if file_path.is_file():
        config.read(file_path)
        if config.has_section(args.key_name):
            client_id = config[args.key_name]["client_id"]
            client_secret = config[args.key_name]["client_secret"]
    if not client_id:
        if args.cron:
            script.logger.error(
                f"No client credentials saved for {args.key_name}. Run interactively to set."
            )
            sys.exit(1)
        client_id = input("Enter client id: ").strip()
        while len(client_id) != 24:
            print("Client ids are exactly 24 characters long.")
            client_id = input("Enter client id: ").strip()
        client_secret = input("Enter client secret: ").strip()
        while len(client_secret) != 42:
            print("Client secrets are exactly 42 characters long.")
            client_secret = input("Enter client secret: ").strip()

        config[args.key_name] = {"client_id": client_id, "client_secret": client_secret}
        with open(file_path, "w") as configfile:
            config.write(configfile)
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    return client_id, client_secret


def get_route(
    url,
    token_provider,
    method="GET",
    json_body=None,
):
    if json_body is None:
        json_body = {}
    (client_key, client_secret) = get_client_credentials()
    refresh_attempts = 0
    connection_attempts = 0
    route_attempts = 0
    route_fail_delay = 5
    while True:
        token, secret = token_provider.get()
        session = OAuth1Session(
            client_key, client_secret, access_token=token, access_token_secret=secret
        )
        trimmed_url, request_params = trim_url_args(url)
        try:
            if method == "GET":
                r = session.get(
                    trimmed_url,
                    params=request_params,
                    headers={"User-Agent": USER_AGENT},
                    timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                )
            else:
                if not is_valid_json(json_body):
                    script.logger.error("Body does not contain valid JSON")
                    sys.exit(1)
                r = session.post(
                    trimmed_url,
                    params=request_params,
                    data=json_body,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": USER_AGENT,
                    },
                    header_auth=True,
                    timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                )
        except Timeout as exc:
            script.logger.debug(exc)
            script.logger.warning(f"Request to {url} timed out.")
            route_attempts += 1
            if route_attempts >= MAX_ROUTE_ATTEMPTS:
                script.logger.error(
                    f"Timeouts exceeded for {url} after {route_attempts} attempts. Terminating."
                )
                sys.exit(1)
            time.sleep(route_fail_delay)
            route_fail_delay += 5
            continue
        except ConnectionError as exc:
            connection_attempts += 1
            if connection_attempts > MAX_CONNECTION_ATTEMPTS:
                script.logger.error(
                    f"Network connection failed {connection_attempts} times. Terminating."
                )
                sys.exit(1)
            script.logger.debug(f"Network error connecting to {url}: {exc}")
            script.logger.error(
                f"Network connection error. Retrying in {CONNECTION_FAIL_RETRY} seconds."
            )
            time.sleep(CONNECTION_FAIL_RETRY)
            continue
        if r.status_code in (200, 201):
            return get_response_content(r)
        elif r.status_code in (502, 503, 504):
            route_attempts += 1
            if route_attempts > MAX_ROUTE_ATTEMPTS:
                script.logger.error(
                    f"Attempt to connect to {url} failed {route_attempts} times. Terminating."
                )
                sys.exit(1)
            script.logger.warning(
                f"Network error when called {url}: {r.status_code} "
                f"(attempt {route_attempts}/{MAX_ROUTE_ATTEMPTS})"
            )
            time.sleep(route_fail_delay)
            route_fail_delay += 5
            continue
        elif r.status_code == 400:
            try:
                payload = r.json()
            except ValueError:
                payload = {}
            msg = payload.get("message", "") if isinstance(payload, dict) else ""
            script.logger.error(f"Bad request - {msg}")
            sys.exit(1)
        elif r.status_code == 401:
            try:
                msg = r.json().get("message", "")
            except Exception:
                msg = r.text or ""
            if "unauthorized" in msg.lower():
                script.logger.error("Access denied - client is unauthorized.")
                sys.exit(1)
            else:
                refresh_attempts += 1
                if refresh_attempts > MAX_REFRESH_ATTEMPTS:
                    script.logger.error(
                        "Invalid session token and refresh attempts exhausted."
                    )
                    sys.exit(1)

                script.logger.info(f"{msg}\n")
                script.logger.info("Invalid session token, requesting new one...")
                token_provider.refresh(get_new_session_token)
                continue
        elif r.status_code == 429:
            jitter = random.uniform(-5, 5)  # Jitter ranger +- 5 seconds
            delay = TOO_MANY_REQUESTS_DELAY + jitter
            script.logger.warning(
                "429 Error from server - too many requests. "
                f"Pausing for about {TOO_MANY_REQUESTS_DELAY} seconds before retrying."
            )
            time.sleep(delay)
            continue
        else:
            script.logger.error(f"Error from API: {r.text}")
            exit(1)


def is_valid_json(json_string):
    try:
        json.loads(json_string)
        return True
    except ValueError:
        return False


def trim_url_args(url):
    if "?" not in url:
        return url, {}
    trimmed_url, param_string = url.split("?")
    params = parse_qs(param_string)

    processed_params = {}
    for k, v in params.items():
        try:
            processed_params[k] = int(v[0])
        except ValueError:
            processed_params[k] = v[0]  # Keep the original value if it's not an integer

    return trimmed_url, processed_params


def check_db_types_match():
    response = get_route(args.api_db_url, session_provider)
    if "isolates" in response:
        remote = "isolates"
    elif "sequences" in response:
        remote = "seqdef"
    else:
        script.logger.error("Cannot determine remote database type.")
        sys.exit(1)
    local = get_db_type()
    if remote != local:
        script.logger.error(
            f"Remote db type: {remote}; Local db type: {local}. DATABASE MISMATCH!"
        )
        sys.exit(1)
    return local


def get_remote_locus_list(schemes: list[int], loci: list[str]):
    locus_urls = []
    if schemes:
        for scheme_id in schemes:
            scheme_loci = get_route(
                f"{args.api_db_url}/schemes/{scheme_id}/loci", session_provider
            )
            if scheme_loci["loci"]:
                locus_urls.extend(scheme_loci["loci"])
    if loci:
        for locus in loci:
            if re.search(r"[^\w_\-']", locus):
                script.logger.error(f"Invalid locus name in list: {locus}.")
            else:
                locus_urls.append(f"{args.api_db_url}/loci/{locus}")
    if schemes == None and loci == None:
        loci = get_route(f"{args.api_db_url}/loci?return_all=1", session_provider)
        if loci["loci"]:
            locus_urls.extend(loci["loci"])
    locus_urls = list(dict.fromkeys(locus_urls))
    return locus_urls


def get_local_locus_list(
    schemes: list[int] | None = None, loci: list[str] | None = None
):
    locus_list = []
    if schemes:
        for scheme_id in schemes:
            scheme_loci = script.datastore.get_scheme_loci(scheme_id)
            if scheme_loci:
                locus_list.extend(scheme_loci)
    if loci:
        all_loci = script.datastore.get_loci()
        if all(locus in all_loci for locus in loci):
            locus_list.extend(loci)
        else:
            missing = [locus for locus in loci if locus not in all_loci]
            script.logger.error(
                f"Following loci in your list are not defined locally: {missing}"
            )
            sys.exit(1)
    locus_list = list(dict.fromkeys(locus_list))
    if schemes == None and loci == None:
        locus_list = script.datastore.get_loci()
    return locus_list


def update_seqdef(token, secret):
    selected_schemes = get_selected_scheme_list()
    selected_loci = get_selected_locus_list()
    remote_locus_urls = get_remote_locus_list(
        schemes=selected_schemes, loci=selected_loci
    )
    remote_loci = extract_locus_names_from_urls(remote_locus_urls)

    local_loci = get_local_locus_list()
    remote_count = len(remote_loci)
    local_count = len(local_loci)
    if remote_count != local_count:
        filtered = " (filtered)" if selected_loci or selected_schemes else ""
        script.logger.debug(
            f"Remote loci{filtered}: {remote_count}; Local loci: {local_count}"
        )
        not_in_local = [x for x in remote_loci if x not in local_loci]
        if len(not_in_local):
            script.logger.info(f"Not defined in local: {not_in_local}")
            if args.add_new_loci:
                add_new_loci(not_in_local)
            else:
                script.logger.info("Run with --add_new_loci to define these locally.")

    if args.add_new_seqs:
        local_loci = get_local_locus_list(schemes=selected_schemes, loci=selected_loci)
        if args.reldate != None:
            updated_remote_locus_urls = get_route(
                f"{args.api_db_url}/loci?return_all=1&alleles_updated_reldate={args.reldate}",
                session_provider,
            )

            remote_loci = extract_locus_names_from_urls(
                updated_remote_locus_urls.get("loci", [])
            )
            local_set = set(local_loci)
            local_loci = [locus for locus in remote_loci if locus in local_set]

        add_new_seqs(local_loci)
    # TODO --check_seqs
    # TODO --update_seqs


def extract_locus_names_from_urls(urls):
    return [url.rstrip("/").split("/")[-1] for url in urls]


def extract_last_value_from_url(url):
    return url.rstrip("/").split("/")[-1]


def get_selected_scheme_list():
    if args.schemes:
        try:
            scheme_list = sorted(
                {int(scheme_id.strip()) for scheme_id in args.schemes.split(",")}
            )
        except ValueError as e:
            script.logger.error(
                "Invalid non-integer value found in --schemes argument."
            )
            exit(1)
        return scheme_list


def get_selected_locus_list():
    if args.loci:
        locus_list = sorted({locus.strip() for locus in args.loci.split(",")})
        return locus_list


def add_new_loci(loci):
    for locus in loci:
        url = f"{args.api_db_url}/loci/{locus}"
        locus_info = get_route(url, session_provider)
        possible_fields = [
            "id",
            "data_type",
            "allele_id_format",
            "coding_sequence",
            "formatted_name",
            "common_name",
            "formatted_common_name",
            "locus_type",
            "allele_id_regex",
            "length",
            "length_varies",
            "min_length",
            "max_length",
            "complete_cds",
            "start_codons",
            "orf",
            "genome_position",
            "match_longest",
            "id_check_type_alleles",
            "id_check_threshold",
        ]
        fields = []
        placeholders = []
        values = []
        for field in possible_fields:
            if locus_info.get(field) == None:
                continue
            fields.append(field)
            values.append(locus_info.get(field))
            placeholders.append("%s")
        fields.extend(["curator", "date_entered", "datestamp"])
        placeholders.extend(["%s", "%s", "%s"])
        values.extend([0, "now", "now"])
        inserts = []
        qry = (
            "INSERT INTO loci ("
            + ",".join(fields)
            + ") VALUES ("
            + ",".join(placeholders)
            + ")"
        )
        inserts.append({"qry": qry, "values": values})

        db = script.db
        cursor = db.cursor()
        if locus_info.get("aliases"):
            aliases = locus_info.get("aliases")
            for alias in aliases:
                inserts.append(
                    {
                        "qry": "INSERT INTO locus_aliases (locus,alias,curator,datestamp) VALUES (%s,%s,%s,%s)",
                        "values": [locus, alias, 0, "now"],
                    }
                )
        db_type = get_db_type()
        if db_type == "seqdef":
            if set(["full_name", "product", "description"]) & locus_info.keys():
                inserts.append(
                    {
                        "qry": "INSERT INTO locus_descriptions(locus,full_name,product,description,"
                        "datestamp,curator) VALUES (%s,%s,%s,%s,%s,%s)",
                        "values": [
                            locus,
                            locus_info.get("full_name"),
                            locus_info.get("product"),
                            locus_info.get("description"),
                            "now",
                            0,
                        ],
                    }
                )
            if locus_info.get("extended_attributes"):
                attributes = locus_info.get("extended_attributes")
                for attribute in attributes:
                    option_list = None
                    if attribute.get("allowed_values"):
                        option_list = "|".join(attribute.get("allowed_values"))
                    inserts.append(
                        {
                            "qry": "INSERT INTO locus_extended_attributes "
                            "(locus,field,value_format,length,value_regex,description,option_list,"
                            "required,field_order,main_display,datestamp,curator) VALUES "
                            "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                            "values": [
                                locus,
                                attribute.get("field"),
                                attribute.get("value_format"),
                                attribute.get("length"),
                                attribute.get("value_regex"),
                                attribute.get("description"),
                                option_list,
                                attribute.get("required"),
                                attribute.get("field_order"),
                                True,
                                "now",
                                0,
                            ],
                        }
                    )
        try:
            for insert in inserts:
                cursor.execute(insert.get("qry"), insert.get("values", []))
            db.commit()
            script.logger.info(f"Locus {locus} added.")
        except Exception as e:
            db.rollback()
            if "already exists" in str(e):
                script.logger.warning(f"Locus {locus} already exists. Skipped.")
                continue
            script.logger.error(f"INSERT failed - {e}")
            exit(1)


def get_local_users():
    return script.datastore.run_query(
        "SELECT * FROM users ORDER BY id",
        None,
        {"fetch": "all_arrayref", "slice": {}},
    )


def add_user(url):
    user = get_route(url, session_provider)
    db = script.db
    cursor = db.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (id,user_name,surname,first_name,affiliation,status,"
            "date_entered,datestamp,curator) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            [
                user.get("id"),
                f"user-{user.get('id')}",
                user.get("surname"),
                user.get("first_name"),
                user.get("affiliation"),
                "user",
                "now",
                "now",
                0,
            ],
        )
        db.commit()
        script.logger.info(
            f"User {user.get('id')}: {user.get('first_name')} {user.get('surname')} added."
        )
    except Exception as e:
        db.rollback()
        script.logger.error(f"INSERT failed - {e}")
        exit(1)


def add_new_seqs(loci: list[str]):
    users = get_local_users()
    user_ids = {user["id"] for user in users}
    db = script.db
    cursor = db.cursor()
    for locus in loci:
        if args.check_seqs or args.update_seqs:
            local_seqs = script.datastore.run_query(
                "SELECT * FROM sequences WHERE locus=%s ORDER BY allele_id",
                locus,
                {"fetch": "all_arrayref", "slice": {}},
            )
        else:
            local_seqs = script.datastore.run_query(
                "SELECT allele_id FROM sequences WHERE locus=%s ORDER BY allele_id",
                locus,
                {"fetch": "all_arrayref", "slice": {}},
            )
        local_allele_ids = {seq["allele_id"] for seq in local_seqs}

        url = f"{args.api_db_url}/loci/{locus}/alleles?include_records=1"
        if args.reldate != None:
            url += f"&updated_reldate={args.reldate}"
        extended_att = script.datastore.run_query(
            "SELECT * FROM locus_extended_attributes WHERE locus=?",
            locus,
            {"fetch": "all_arrayref", "slice": {}},
        )

        while True:
            remote_seqs = get_route(url, session_provider)
            if args.reldate == None and len(local_allele_ids) >= remote_seqs.get(
                "records", 0
            ):
                break
            if remote_seqs.get("alleles"):
                for seq in remote_seqs.get("alleles"):
                    sender = int(extract_last_value_from_url(seq.get("sender")))
                    if sender not in user_ids:
                        add_user(seq.get("sender"))
                        user_ids.add(sender)
                    curator = int(extract_last_value_from_url(seq.get("curator")))
                    if curator not in user_ids:
                        add_user(seq.get("curator"))
                        user_ids.add(curator)
                    if seq.get("allele_id") in local_allele_ids:
                        pass
                    else:
                        inserts = []
                        inserts.append(
                            {
                                "qry": "INSERT INTO sequences (locus,allele_id,sequence,status,comments,"
                                "type_allele,sender,curator,date_entered,datestamp) VALUES "
                                "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                                "values": [
                                    locus,
                                    seq.get("allele_id"),
                                    seq.get("sequence"),
                                    seq.get("status"),
                                    seq.get("comments"),
                                    seq.get("type_allele"),
                                    sender,
                                    curator,
                                    seq.get("date_entered"),
                                    seq.get("datestamp"),
                                ],
                            }
                        )
                        for att in extended_att:
                            if seq.get(att.get("field")) != None:
                                field = att.get("field")
                                inserts.append(
                                    {
                                        "qry": "INSERT INTO sequence_extended_attributes "
                                        "(locus,field,allele_id,value,datestamp,curator) VALUES "
                                        "(%s,%s,%s,%s,%s,%s)",
                                        "values": [
                                            locus,
                                            field,
                                            seq.get("allele_id"),
                                            seq.get(field),
                                            seq.get("datestamp"),
                                            curator,
                                        ],
                                    }
                                )

                        try:
                            for insert in inserts:
                                cursor.execute(insert.get("qry"), insert.get("values"))
                            db.commit()
                            script.logger.info(
                                f"Locus {locus}-{seq.get('allele_id')} added."
                            )
                        except Exception as e:
                            db.rollback()
                            script.logger.error(f"INSERT failed - {e}")
                            exit(1)

            else:
                script.logger.error(f"No alleles attribute for {locus}")
                break
            if remote_seqs.get("paging"):
                if remote_seqs.get("paging").get("next"):
                    url = remote_seqs.get("paging").get("next")
                    continue
                else:
                    break
            else:
                break


if __name__ == "__main__":
    main()
