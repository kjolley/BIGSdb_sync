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

import sys
from bigsdb.script import Script

import config
from utils import (
    parse_args,
    init_logger,
    check_required_args,
    check_token_dir,
    check_api_dns,
)
from token_provider import TokenProvider
from auth import get_new_session_token, get_new_access_token
import sync
import traceback
from errors import BIGSdbSyncError, ConfigError, AuthError, APIError, DBError


def main():
    try:
        config.args = parse_args()
        logger = init_logger()
        try:
            config.script = Script(database=config.args.db, logger=logger)
        except Exception as e:
            raise ConfigError(
                f"Error setting up script object for config {config.args.db}. {e}"
            )
        if not check_api_dns(config.args.api_db_url, retries=2, backoff=2):
            # fail fast with a clear message
            sys.exit(2)
        check_required_args()
        check_token_dir(config.args.token_dir)

        config.session_provider = TokenProvider(
            config.args.token_dir, config.args.key_name, token_type="session"
        )
        config.access_provider = TokenProvider(
            config.args.token_dir, config.args.key_name, token_type="access"
        )
        access_token, access_secret = config.access_provider.get()
        if not config.args.cron and (access_token == None or access_secret == None):
            get_new_access_token()

        token, secret = config.session_provider.get()
        if not token or not secret:
            token, secret = get_new_session_token()
            config.session_provider.set(token, secret)

        remote_db_type = sync.get_remote_db_type()

        local_db_type = sync.get_local_db_type()
        if remote_db_type != local_db_type:
            raise ConfigError(
                f"Remote db type: {remote_db_type}; Local db type: {local_db_type}. "
                "DATABASE MISMATCH!"
            )
        sync.set_delay(config.args.delay)
        if local_db_type == "seqdef":
            sync.update_seqdef()
        else:
            raise ConfigError("Only seqdef sync currently implemented.")
    except (ConfigError, AuthError, APIError, DBError) as e:
        # Log and exit with non-zero code. Keep error messages clear for callers.
        # If we have script/logger set up, use it; otherwise print to stderr.
        if hasattr(config, "script") and config.script:
            config.script.logger.error(str(e))
            if config.args.log_level == "DEBUG":
                traceback.print_exc()
        else:
            sys.stderr.write(f"ERROR: {e}\n")
        sys.exit(1)
    except Exception as e:
        # Unexpected / programming error — print traceback to help debugging.

        traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()
