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

import re
from pathlib import Path
from rauth import OAuth1Service, OAuth1Session
import config
from oauth_utils import get_client_credentials
from api_client import get_response_content
from errors import AuthError, ConfigError


def get_db_value():
    match = re.search(r"/db/([^/]+)", config.args.api_db_url)
    if match:
        db = match.group(1)
    else:
        raise ValueError("No db value found in the URL.")
    return db


def get_service():
    (client_key, client_secret) = get_client_credentials()
    request_token_url = f"{config.args.api_db_url}/oauth/get_request_token"
    access_token_url = f"{config.args.api_db_url}/oauth/get_access_token"
    return OAuth1Service(
        name=config.USER_AGENT,
        consumer_key=client_key,
        consumer_secret=client_secret,
        request_token_url=request_token_url,
        access_token_url=access_token_url,
        base_url=config.args.api_db_url,
    )


def get_new_request_token():
    (client_key, client_secret) = get_client_credentials()
    service = get_service()
    r = service.get_raw_request_token(
        params={"oauth_callback": "oob"}, headers={"User-Agent": config.USER_AGENT}
    )
    if r.status_code == 404:
        raise AuthError(f"404 Page not found. {config.args.api_db_url}.")
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
        raise AuthError(f"Failed to get request token: {msg}")


def get_new_access_token():
    web_base_url = get_base_web()
    if config.args.cron:
        raise AuthError(f"No access token saved for {config.args.key_name}.")
    file_path = Path(f"{config.args.token_dir}/access_tokens")
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
        headers={"User-Agent": config.USER_AGENT},
    )
    if r.status_code == 200:
        response_json = get_response_content(r)
        token = response_json.get("oauth_token", "")
        secret = response_json.get("oauth_token_secret", "")
        config.access_provider.set(token, secret)
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
        raise AuthError(f"Failed to get new access token: {msg}")


def get_new_session_token():
    (access_token, access_secret) = config.access_provider.get()
    if not access_token or not access_secret:
        (access_token, access_secret) = get_new_access_token()
    (client_key, client_secret) = get_client_credentials()
    session_request = OAuth1Session(
        client_key,
        client_secret,
        access_token=access_token,
        access_token_secret=access_secret,
    )
    url = f"{config.args.api_db_url}/oauth/get_session_token"
    r = session_request.get(url, headers={"User-Agent": config.USER_AGENT})
    if r.status_code == 200:
        response_json = get_response_content(r)
        token = response_json.get("oauth_token", "")
        secret = response_json.get("oauth_token_secret", "")
        config.session_provider.set(token, secret)
        return (token, secret)
    else:
        try:
            payload = r.json()
        except ValueError:
            payload = {}
        msg = payload.get("message", "") if isinstance(payload, dict) else ""
        config.script.logger.error(f"Failed to get new session token. {msg}")
        if config.args.cron:
            config.script.logger.error("Run interactively to fix.")
        if re.search("verification", msg) or re.search("Invalid access token", msg):
            config.script.logger.error("New access token required - removing old one.")
            config.access_provider.set(None, None)
        raise AuthError(f"Failed to get new session token: {msg}")


def get_base_web():
    if config.args.base_web_url:
        return config.args.base_web_url
    if re.search(r"pubmlst.org", config.args.api_db_url):
        return config.BASE_WEB["PubMLST"]
    if re.search(r"bigsdb.pasteur.fr", config.args.api_db_url):
        return config.BASE_WEB["Pasteur"]
    raise ConfigError("Base web URL not determined. Please set with --base_web_url.")
