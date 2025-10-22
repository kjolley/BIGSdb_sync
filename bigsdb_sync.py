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
from utils import parse_args, init_logger, check_required_args, check_token_dir
from token_provider import TokenProvider
from auth import get_new_session_token
import sync
from errors import BIGSdbSyncError, ConfigError, AuthError, APIError


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

        check_required_args()
        check_token_dir(config.args.token_dir)

        config.session_provider = TokenProvider(
            config.args.token_dir, config.args.key_name, token_type="session"
        )
        config.access_provider = TokenProvider(
            config.args.token_dir, config.args.key_name, token_type="access"
        )

        token, secret = config.session_provider.get()
        if not token or not secret:
            token, secret = get_new_session_token()
            config.session_provider.set(token, secret)

        db_type = sync.get_db_type()
        if db_type == "seqdef":
            sync.update_seqdef()
        else:
            logger.error("Only seqdef sync implemented in this refactor.")
    except (ConfigError, AuthError, APIError) as e:
        # Log and exit with non-zero code. Keep error messages clear for callers.
        # If we have script/logger set up, use it; otherwise print to stderr.
        if hasattr(config, "script") and config.script:
            config.script.logger.error(str(e))
        else:
            sys.stderr.write(f"ERROR: {e}\n")
        sys.exit(1)
    except Exception as e:
        # Unexpected / programming error — print traceback to help debugging.
        import traceback

        traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()
