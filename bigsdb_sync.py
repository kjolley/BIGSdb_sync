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
# Version 20251003
import argparse
import sys
import os
import stat
import re
import configparser
import json
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs
from bigsdb.script import Script
from rauth import OAuth1Service, OAuth1Session

session_provider = None
access_provider = None


class TokenProvider:
    """
    In-memory provider backed by the on-disk token files used by your script.
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


USER_AGENT = "BIGSdb_sync"
BASE_WEB = {
    "PubMLST": "https://pubmlst.org/bigsdb",
    "Pasteur": "https://bigsdb.pasteur.fr/cgi-bin/bigsdb/bigsdb.pl",
}
MAX_REFRESH_ATTEMPTS = 1

parser = argparse.ArgumentParser()
parser.add_argument(
    "--add_new_loci",
    action="store_true",
    help="Set up new loci if they do not exist in local database.",
)
parser.add_argument(
    "--api_db_url",
    required=True,
    help="URL for the top-level database API call, e.g. https://rest.pubmlst.org/db/pubmlst_neisseria_seqdef",
)
parser.add_argument(
    "--base_web_url",
    required=False,
    help="URL to BIGSdb script on target web site. This is only needed to set up the access token.\n"
    "It should not be necessary to set this for PubMLST or BIGSdb Pasteur.",
)
parser.add_argument(
    "--cron",
    action="store_true",
    help="Script is being run as a CRON job or non-interactively.",
)
parser.add_argument("--db", required=True, help="Local database config name.")
parser.add_argument(
    "--key_name",
    required=True,
    help="Name of API key - use a different name for each site.",
)
parser.add_argument("--loci", required=False, help="Comma-separated list of loci.")
parser.add_argument(
    "--quiet", required=False, help="Suppress output except for errors."
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


args = parser.parse_args()


def main():
    global session_provider, access_provider, script
    check_required_args()
    check_token_dir(args.token_dir)

    try:
        script = Script(database=args.db)
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


def check_required_args():
    if not re.search(r"^https?://.*/db/[A-Za-z0-9_-]+$", args.api_db_url):
        sys.exit(
            "--api_db_url should be a valid URL (starting with http(s):// and\n"
            "ending with /db/xxx where xxx is a database configuration)."
        )


def get_base_web():
    if args.base_web_url:
        return args.base_web_url
    if re.search(r"pubmlst.org", args.api_db_url):
        return BASE_WEB["PubMLST"]
    if re.search(r"bigsdb.pasteur.fr", args.api_db_url):
        return BASE_WEB["Pasteur"]
    sys.exit("Base web URL not determined. Please set with --base_web_url.")


def get_db_type():
    try:
        db_type = script.datastore.run_query(
            "SELECT value FROM db_attributes WHERE field=?", "type"
        )
    except ValueError as e:
        sys.exit("Could not determine local database type.")
    if db_type not in ("seqdef", "isolates"):
        sys.exit("Invalid db_type for local database.")
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
            sys.exit(f"The token directory '{directory}' exists but is not writable.")
    else:
        try:
            os.makedirs(directory)
            os.chmod(directory, stat.S_IRWXU)  # Set permissions to 0700
        except OSError as e:
            sys.exit(f"Failed to create token directory '{directory}': {e}")


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
        sys.stderr.write(f"Failed to get new session token. {msg}\n")
        if args.cron:
            sys.stderr.write("Run interactively to fix.\n")
        if re.search("verification", msg) or re.search("Invalid access token", msg):
            sys.stderr.write("New access token required - removing old one.\n")
            access_provider.set(None, None)

        sys.exit(1)


def get_response_content(r):
    content_type = r.headers.get("content-type", "")
    if "json" in content_type.lower():
        try:
            return r.json()
        except ValueError:
            sys.stderr.write("Response declared JSON but could not parse JSON.\n")
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
        sys.exit(f"404 Page not found. {args.api_db_url}.")
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
        sys.exit(f"Failed to get new request token. {msg}")


def get_new_access_token():
    global access_provider
    web_base_url = get_base_web()
    if args.cron:
        sys.stderr.write(f"No access token saved for {args.key_name}.\n")
        sys.stderr.write("Run interactively to set (without --cron).\n")
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
        sys.stderr.write(f"Failed to get new access token. {msg}")
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
            sys.stderr.write(f"No client credentials saved for {args.key_name}.\n")
            sys.stderr.write("Run interactively to set.\n")
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
    attempts = 0
    while True:
        token, secret = token_provider.get()
        session = OAuth1Session(
            client_key, client_secret, access_token=token, access_token_secret=secret
        )
        trimmed_url, request_params = trim_url_args(url)
        if method == "GET":
            r = session.get(
                trimmed_url,
                params=request_params,
                headers={"User-Agent": USER_AGENT},
            )
        else:
            if not is_valid_json(json_body):
                parser.error("Body does not contain valid JSON")
            r = session.post(
                trimmed_url,
                params=request_params,
                data=json_body,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": USER_AGENT,
                },
                header_auth=True,
            )

        if r.status_code in (200, 201):
            return get_response_content(r)
        elif r.status_code == 400:
            try:
                payload = r.json()
            except ValueError:
                payload = {}
            msg = payload.get("message", "") if isinstance(payload, dict) else ""
            sys.stderr.write(f"Bad request - {msg}")
            sys.exit(1)
        elif r.status_code == 401:
            try:
                msg = r.json().get("message", "")
            except Exception:
                msg = r.text or ""
            if "unauthorized" in msg.lower():
                sys.stderr.write("Access denied - client is unauthorized\n")
                sys.exit(1)
            else:
                attempts += 1
                if attempts > MAX_REFRESH_ATTEMPTS:
                    sys.stderr.write(
                        "Invalid session token and refresh attempts exhausted.\n"
                    )
                    sys.exit(1)
                sys.stderr.write(f"{msg}\n")
                sys.stderr.write("Invalid session token, requesting new one...\n")
                token_provider.refresh(get_new_session_token)
                continue
        else:
            sys.stderr.write(f"Error from API: {r.text}\n")
            sys.exit(1)


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
        sys.exit("Cannot determine remote database type.")
    local = get_db_type()
    if remote != local:
        sys.exit(
            f"Remote db type: {remote}; Local db type: {local}. DATABASE MISMATCH!"
        )
    return local


def get_remote_locus_list(schemes: [int] = None):
    locus_urls = []
    if schemes:
        for scheme_id in schemes:
            scheme_loci = get_route(
                f"{args.api_db_url}/schemes/{scheme_id}/loci", session_provider
            )
            if scheme_loci["loci"]:
                locus_urls.extend(scheme_loci["loci"])
        locus_urls = list(dict.fromkeys(locus_urls))
    else:
        loci = get_route(f"{args.api_db_url}/loci?return_all=1", session_provider)
        if loci["loci"]:
            locus_urls.extend(loci["loci"])
    return locus_urls


def get_local_locus_list(schemes: [int] = None):
    loci = []
    if schemes:
        for scheme_id in schemes:
            scheme_loci = script.datastore.get_scheme_loci(scheme_id)
            if scheme_loci:
                loci.extend(scheme_loci)
        loci = list(dict.fromkeys(loci))
    else:
        loci = script.datastore.get_loci()
    return loci


def update_seqdef(token, secret):
    selected_schemes = get_selected_scheme_list()
    remote_locus_urls = get_remote_locus_list(selected_schemes)
    remote_loci = extract_locus_names_from_urls(remote_locus_urls)
    local_loci = get_local_locus_list(selected_schemes)
    remote_count = len(remote_loci)
    local_count = len(local_loci)
    if remote_count != local_count:
        print(f"Remote loci: {remote_count}; Local loci: {local_count}")


def extract_locus_names_from_urls(urls):
    return [url.rstrip("/").split("/")[-1] for url in urls]


def get_selected_scheme_list():
    if args.schemes:
        try:
            scheme_list = sorted(
                {int(scheme_id.strip()) for scheme_id in args.schemes.split(",")}
            )
        except ValueError as e:
            sys.exit("Error: invalid non-integer value found in --schemes argument.")
        return scheme_list


if __name__ == "__main__":
    main()
