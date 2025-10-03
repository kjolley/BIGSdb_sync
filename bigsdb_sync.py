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
from pathlib import Path
from urllib.parse import parse_qs
from bigsdb.script import Script
from rauth import OAuth1Service, OAuth1Session

USER_AGENT = "BIGSdb_sync"
BASE_WEB = {
    "PubMLST": "https://pubmlst.org/bigsdb",
    "Pasteur": "https://bigsdb.pasteur.fr/cgi-bin/bigsdb/bigsdb.pl",
}

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
try:
    self = Script(database=args.db)
except Exception as e:
    sys.exit(f"Error setting up script object for config {args.db}.")


def main():
    check_required_args()
    check_token_dir(args.token_dir)

    (token, secret) = retrieve_token("session")
    if not token or not secret:
        (token, secret) = get_new_session_token()
    db_type = check_db_types_match(token, secret)
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
        db_type = self.datastore.run_query(
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
        raiseValueError("No db value found in the URL.")
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


def retrieve_token(token_type):
    file_path = Path(f"{args.token_dir}/{token_type}_tokens")
    if file_path.is_file():
        config = configparser.ConfigParser(interpolation=None)
        config.read(file_path)
        if config.has_section(args.key_name):
            token = config[args.key_name]["token"]
            secret = config[args.key_name]["secret"]
            return (token, secret)
    return (None, None)


def get_new_session_token():
    file_path = Path(f"{args.token_dir}/session_tokens")
    (access_token, access_secret) = retrieve_token("access")
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
        token = r.json()["oauth_token"]
        secret = r.json()["oauth_token_secret"]
        config = configparser.ConfigParser(interpolation=None)
        if file_path.is_file():
            config.read(file_path)
        config[args.key_name] = {"token": token, "secret": secret}
        with open(file_path, "w") as configfile:
            config.write(configfile)

        return (token, secret)
    else:
        sys.stderr.write(
            "Failed to get new session token. " + r.json()["message"] + "\n"
        )
        if args.cron:
            sys.stderr.write("Run interactively to fix.\n")
        if re.search("verification", r.json()["message"]) or re.search(
            "Invalid access token", r.json()["message"]
        ):
            sys.stderr.write("New access token required - removing old one.\n")
            config = configparser.ConfigParser(interpolation=None)
            file_path = Path(f"{args.token_dir}/access_tokens")
            if file_path.is_file():
                config.read(file_path)
                config.remove_section(args.key_name)
                with open(file_path, "w") as configfile:
                    config.write(configfile)
        sys.exit(1)


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
        token = r.json()["oauth_token"]
        secret = r.json()["oauth_token_secret"]
        return (token, secret)
    else:
        sys.exit("Failed to get new request token." + r.json()["message"])


def get_new_access_token():
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
        token = r.json()["oauth_token"]
        secret = r.json()["oauth_token_secret"]
        file_path = Path(f"{args.token_dir}/access_tokens")
        print("Access Token:        " + token)
        print("Access Token Secret: " + secret + "\n")
        print(
            "This access token will not expire but may be revoked by the \n"
            f"user or the service provider. It will be saved to \n{file_path}."
        )
        config = configparser.ConfigParser(interpolation=None)
        if file_path.is_file():
            config.read(file_path)
        config[args.key_name] = {"token": token, "secret": secret}
        with open(file_path, "w") as configfile:
            config.write(configfile)
        return (token, secret)
    else:
        sys.stderr.write("Failed to get new access token." + r.json()["message"])
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
    return client_id, client_secret


def get_route(
    url,
    token,
    secret,
    method="GET",
    json_body={},
):
    (client_key, client_secret) = get_client_credentials()
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

    if r.status_code == 200 or r.status_code == 201:

        if re.search("json", r.headers["content-type"], flags=0):
            return r.json()
        else:
            return r.text
    elif r.status_code == 400:
        sys.stderr.write("Bad request - " + r.json()["message"])
        sys.exit(1)
    elif r.status_code == 401:
        if re.search("unauthorized", r.json()["message"]):
            sys.stderr.write("Access denied - client is unauthorized\n")
            sys.exit(1)
        else:
            sys.stderr.write(r.json()["message"] + "\n")
            sys.stderr.write("Invalid session token, requesting new one...\n")
            (token, secret) = get_new_session_token()
            get_route(url, token, secret)
    else:
        sys.stderr.write(f"Error from API: {r.text}\n")
        sys.exit(1)


def trim_url_args(url):
    if not "?" in url:
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


def check_db_types_match(token, secret):
    response = get_route(args.api_db_url, token, secret)
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


def get_remote_locus_list(token, secret, schemes: [int] = None):
    locus_urls = []
    if schemes:
        for scheme_id in schemes:
            scheme_loci = get_route(
                f"{args.api_db_url}/schemes/{scheme_id}/loci", token, secret
            )
            if scheme_loci["loci"]:
                locus_urls.extend(scheme_loci["loci"])
            locus_urls = list(dict.fromkeys(locus_urls))
    else:
        loci = get_route(f"{args.api_db_url}/loci?return_all=1", token, secret)
        if loci["loci"]:
            locus_urls.extend(loci["loci"])
    return locus_urls


def update_seqdef(token, secret):
    selected_schemes = get_selected_scheme_list()
    remote_locus_urls = get_remote_locus_list(token, secret, selected_schemes)
    remote_loci = extract_locus_names_from_urls(remote_locus_urls)
    print(remote_loci)


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
