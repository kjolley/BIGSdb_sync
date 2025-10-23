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

import os
import stat
import configparser
import re
from pathlib import Path
from rauth import OAuth1Session
from typing import Tuple

import config
from errors import ConfigError, AuthError
from response_utils import get_response_content


def get_client_credentials() -> Tuple[str, str]:
    """
    Read client credentials from the token dir/client_credentials file for the
    configured key_name (config.args.key_name). If not present and running
    interactively, prompt the user. Raises ConfigError on problems when running
    non-interactively.
    """
    cfg = configparser.ConfigParser(interpolation=None)
    file_path = Path(f"{config.args.token_dir}/client_credentials")
    client_id = None
    client_secret = None
    if file_path.is_file():
        cfg.read(file_path)
        if cfg.has_section(config.args.key_name):
            client_id = cfg[config.args.key_name].get("client_id")
            client_secret = cfg[config.args.key_name].get("client_secret")
    if not client_id:
        if config.args.cron:
            raise ConfigError(
                f"No client credentials saved for {config.args.key_name}. Run interactively to set."
            )
        # interactive prompt
        client_id = input("Enter client id: ").strip()
        while len(client_id) != 24:
            print("Client ids are exactly 24 characters long.")
            client_id = input("Enter client id: ").strip()
        client_secret = input("Enter client secret: ").strip()
        while len(client_secret) != 42:
            print("Client secrets are exactly 42 characters long.")
            client_secret = input("Enter client secret: ").strip()

        cfg[config.args.key_name] = {
            "client_id": client_id,
            "client_secret": client_secret,
        }
        with open(file_path, "w") as configfile:
            cfg.write(configfile)
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    return client_id, client_secret


def get_new_session_token() -> Tuple[str, str]:
    """
    Obtain a session token using the saved access token. If access token is not
    present we raise AuthError (auth flow should be kicked off by caller).
    This mirrors the previous behaviour but raises exceptions instead of exiting.
    """
    if config.access_provider is None:
        raise AuthError("Missing access_provider configuration.")
    (access_token, access_secret) = config.access_provider.get()
    if not access_token or not access_secret:
        raise AuthError("No access token available (interactive action required).")

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
        if not token or not secret:
            raise AuthError("Session token response missing token/secret.")
        # persist to session_provider
        if config.session_provider is None:
            raise AuthError("Missing session_provider configuration.")
        config.session_provider.set(token, secret)
        return token, secret
    else:
        try:
            payload = r.json()
        except Exception:
            payload = {}
        msg = payload.get("message", "") if isinstance(payload, dict) else ""
        config.script.logger.error(f"Failed to get new session token. {msg}")
        # On certain messages we clear access token so the interactive flow can be retried
        if re.search("verification", msg) or re.search("Invalid access token", msg):
            config.script.logger.error("New access token required - removing old one.")
            config.access_provider.set(None, None)
        raise AuthError(f"Failed to get new session token: {msg or r.text}")
