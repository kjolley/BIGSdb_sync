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

import time
import random
import json
from urllib.parse import parse_qs

import config
from requests.exceptions import Timeout, ConnectionError
from errors import APIError, AuthError
from oauth_utils import get_client_credentials, get_new_session_token
from rauth import OAuth1Session
from response_utils import get_response_content


def is_valid_json(json_string):
    try:
        json.loads(json_string)
        return True
    except Exception:
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
            processed_params[k] = v[0]
    return trimmed_url, processed_params


def get_route(url, token_provider, method="GET", json_body=None):
    if json_body is None:
        json_body = {}
    (client_key, client_secret) = get_client_credentials()
    refresh_attempts = 0
    connection_attempts = 0
    route_attempts = 0
    route_fail_delay = 5
    while True:
        token, secret = token_provider.get()
        if not token or not secret:
            # try to obtain a session token via oauth_utils
            try:
                get_new_session_token()
            except AuthError as e:
                raise AuthError(
                    f"Unable to obtain session token for route {url}: {e}"
                ) from e
            token, secret = token_provider.get()
            if not token or not secret:
                raise AuthError("Session token still missing after attempted refresh.")

        session = OAuth1Session(
            client_key, client_secret, access_token=token, access_token_secret=secret
        )

        trimmed_url, request_params = trim_url_args(url)
        try:
            if method == "GET":
                r = session.get(
                    trimmed_url,
                    params=request_params,
                    headers={"User-Agent": config.USER_AGENT},
                    timeout=(config.CONNECT_TIMEOUT, config.READ_TIMEOUT),
                )
            else:
                if not is_valid_json(json_body):
                    raise APIError("Body does not contain valid JSON")
                r = session.post(
                    trimmed_url,
                    params=request_params,
                    data=json_body,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": config.USER_AGENT,
                    },
                    header_auth=True,
                    timeout=(config.CONNECT_TIMEOUT, config.READ_TIMEOUT),
                )
        except Timeout as exc:
            config.script.logger.debug(exc)
            config.script.logger.warning(f"Request to {url} timed out.")
            route_attempts += 1
            if route_attempts >= config.MAX_ROUTE_ATTEMPTS:
                raise APIError(
                    f"Timeouts exceeded for {url} after {route_attempts} attempts."
                )
            time.sleep(route_fail_delay)
            route_fail_delay += 5
            continue
        except ConnectionError as exc:
            connection_attempts += 1
            if connection_attempts > config.MAX_CONNECTION_ATTEMPTS:
                raise APIError(
                    f"Network connection failed {connection_attempts} times: {exc}"
                )
            config.script.logger.debug(f"Network error connecting to {url}: {exc}")
            config.script.logger.error(
                f"Network connection error. Retrying in {config.CONNECTION_FAIL_RETRY} seconds."
            )
            time.sleep(config.CONNECTION_FAIL_RETRY)
            continue

        # handle responses
        if r.status_code in (200, 201):
            return get_response_content(r)
        elif r.status_code in (502, 503, 504):
            route_attempts += 1
            if route_attempts > config.MAX_ROUTE_ATTEMPTS:
                raise APIError(
                    f"Attempt to connect to {url} failed {route_attempts} times."
                )
            config.script.logger.warning(
                f"Network error when called {url}: {r.status_code} (attempt {route_attempts}/{config.MAX_ROUTE_ATTEMPTS})"
            )
            time.sleep(route_fail_delay)
            route_fail_delay += 5
            continue
        elif r.status_code == 400:
            try:
                payload = r.json()
            except Exception:
                payload = {}
            msg = payload.get("message", "") if isinstance(payload, dict) else ""
            raise APIError(f"Bad request - {msg}")
        elif r.status_code == 401:
            try:
                msg = r.json().get("message", "")
            except Exception:
                msg = r.text or ""
            if "unauthorized" in msg.lower():
                raise AuthError("Access denied - client is unauthorized.")
            else:
                refresh_attempts += 1
                if refresh_attempts > config.MAX_REFRESH_ATTEMPTS:
                    raise AuthError(
                        "Invalid session token and refresh attempts exhausted."
                    )
                config.script.logger.info(f"{msg}\n")
                config.script.logger.info(
                    "Invalid session token, requesting new one..."
                )
                # use token_provider.refresh which will call back to get_new_session_token
                token_provider.refresh(get_new_session_token)
                continue
        elif r.status_code == 429:
            jitter = random.uniform(-5, 5)
            delay = config.TOO_MANY_REQUESTS_DELAY + jitter
            config.script.logger.warning(
                "429 Error from server - too many requests. "
                f"Pausing for about {config.TOO_MANY_REQUESTS_DELAY} seconds before retrying."
            )
            time.sleep(delay)
            continue
        else:
            # unexpected
            full_text = getattr(r, "text", "")
            raise APIError(f"Error from API (status {r.status_code}): {full_text}")
