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
# BIGSdb_downloader is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# Version 20251002
import argparse
import sys
from bigsdb.script import Script

BASE_WEB = {
    "PubMLST": "https://pubmlst.org/bigsdb",
    "Pasteur": "https://bigsdb.pasteur.fr/cgi-bin/bigsdb/bigsdb.pl",
}
BASE_API = {
    "PubMLST": "https://rest.pubmlst.org",
    "Pasteur": "https://bigsdb.pasteur.fr/api",
}

parser = argparse.ArgumentParser()
parser.add_argument("--db", required=True, help="Local database config name.")
parser.add_argument("--loci", required=False, help="Comma-separated list of loci.")
parser.add_argument(
    "--schemes", required=False, help="Comma-separated list of scheme ids."
)
parser.add_argument(
    "--setup", action="store_true", help="Initial setup to obtain access token."
)
parser.add_argument("--site", required=False, choices=["PubMLST", "Pasteur"])
parser.add_argument(
    "--token_dir",
    required=False,
    default="./.bigsdb_tokens",
    help="Directory into which keys and tokens will be saved.",
)


args = parser.parse_args()
try:
    self = Script(database=args.db)
except ValueError as e:
    sys.exit(f"ValueError: {e}")


def main():
    check_required_args()


def check_required_args():
    db_type = get_db_type()


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


if __name__ == "__main__":
    main()
