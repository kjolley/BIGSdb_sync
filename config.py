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

from pathlib import Path

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

# runtime shared state (globals)
args = None  # will be set by cli.py
script = None  # will be set by cli.py (bigsdb.script.Script)
session_provider = None  # TokenProvider instance
access_provider = None  # TokenProvider instance

# default token dir (will be overridden by args.token_dir when available)
DEFAULT_TOKEN_DIR = Path("./.bigsdb_tokens")
