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

import argparse
import re
import os
import stat
from pathlib import Path
import logging
import sys
import socket
from urllib.parse import urlparse
import time
import sys

import config
from errors import ConfigError


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
        help="URL for the top-level database API call, e.g. https://rest.pubmlst.org/db/pubmlst_neisseria_seqdef.",
    )
    parser.add_argument(
        "--base_web_url",
        required=False,
        help="URL to BIGSdb script on target web site.",
    )
    parser.add_argument(
        "--check_seqs",
        action="store_true",
        help="Warn of changes to attributes of existing sequences.",
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
        "--log_file",
        required=False,
        default="/var/log/bigsdb_sync.log",
        help="Path to log file if run with --cron option.",
    )
    parser.add_argument(
        "--log_level",
        required=False,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level.",
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
        default=str(config.DEFAULT_TOKEN_DIR),
        help="Directory into which keys and tokens will be saved.",
    )
    parser.add_argument(
        "--update_seqs",
        action="store_true",
        help="Update sequence attributes if they have changed.",
    )
    return parser.parse_args()


def init_logger():
    logger = logging.getLogger(__name__)
    if config.args.log_level is None:
        if config.args.cron:
            config.args.log_level = "ERROR"
        else:
            config.args.log_level = "INFO"
    level = logging.getLevelName(config.args.log_level)
    logger.setLevel(level)
    logger.propagate = False
    formats = {
        "cron_debug": "%(asctime)s - %(levelname)s: - %(module)s:%(lineno)d - %(message)s",
        "cron": "%(asctime)s - %(levelname)s: - %(message)s",
        "interactive_debug": "%(levelname)s: - %(module)s:%(lineno)d - %(message)s",
        "interactive": "%(levelname)s: %(message)s",
    }

    if config.args.cron:
        log_path = Path(config.args.log_file)
        if log_path.exists():
            if not os.access(log_path, os.W_OK):
                sys.stderr.write(
                    f"CRITICAL: Log file {config.args.log_file} exists but is not writable.\n"
                )
                sys.exit(1)
        else:
            try:
                log_path.touch(mode=0o644, exist_ok=False)
            except Exception as e:
                sys.stderr.write(f"CRITICAL: Failed to create log file: {e}.\n")
                sys.exit(1)
        f_handler = logging.FileHandler(config.args.log_file)
        f_handler.setLevel(level)
        fmt = (
            formats.get("cron_debug")
            if config.args.log_level == "DEBUG"
            else formats.get("cron")
        )
        f_format = logging.Formatter(fmt)
        f_handler.setFormatter(f_format)
        logger.addHandler(f_handler)
    else:
        c_handler = logging.StreamHandler()
        c_handler.setLevel(level)
        fmt = (
            formats.get("interactive_debug")
            if config.args.log_level == "DEBUG"
            else formats.get("interactive")
        )
        c_format = logging.Formatter(fmt)
        c_handler.setFormatter(c_format)
        logger.addHandler(c_handler)
    return logger


def check_required_args():
    if not re.search(r"^https?://.*/db/[A-Za-z0-9_-]+$", config.args.api_db_url):
        raise ConfigError(
            "--api_db_url should be a valid URL (starting with http(s):// and\n"
            "ending with /db/xxx where xxx is a database configuration)."
        )


def check_token_dir(directory):
    if os.path.isdir(directory):
        if os.access(directory, os.W_OK):
            return
        else:
            raise ConfigError(
                f"The token directory '{directory}' exists but is not writable."
            )
    else:
        try:
            os.makedirs(directory)
            os.chmod(directory, stat.S_IRWXU)  # Set permissions to 0700
        except OSError as e:
            raise ConfigError(f"Failed to create token directory '{directory}': {e}")


def extract_locus_names_from_urls(urls):
    return [url.rstrip("/").split("/")[-1] for url in urls]


def extract_last_value_from_url(url):
    return url.rstrip("/").split("/")[-1]


def get_selected_scheme_list():
    if config.args.schemes:
        try:
            scheme_list = sorted(
                {int(scheme_id.strip()) for scheme_id in config.args.schemes.split(",")}
            )
        except ValueError as e:
            raise ConfigError(
                f"Invalid non-integer value found in --schemes argument. {e}"
            )
        return scheme_list


def get_selected_locus_list():
    if config.args.loci:
        locus_list = sorted({locus.strip() for locus in config.args.loci.split(",")})
        return locus_list


def check_api_dns(api_url, retries=0, backoff=2):
    """
    Check DNS resolution for the host in api_url.

    Returns True if resolved, False if not.
    retries: number of additional resolution attempts (0 = no retry)
    backoff: base seconds between retries (backoff multiplier applied)
    """

    if not api_url:
        config.script.logger.error("test")
        return False

    parsed = urlparse(api_url)
    host = parsed.hostname
    if not host:
        config.script.logger.error(
            f"ERROR: Unable to extract hostname from URL: {api_url}"
        )
        return False

    attempt = 0
    while True:
        try:
            # getaddrinfo is recommended: supports IPv4/IPv6 and is portable
            socket.getaddrinfo(
                host,
                parsed.port or None,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
            return True
        except socket.gaierror as e:
            attempt += 1
            if attempt > retries:
                config.script.logger.error(
                    f"ERROR: DNS lookup failed for host '{host}' (from URL: {api_url}).\n"
                    f"socket.gaierror: {e}\n"
                    "Check DNS, host name, or network connectivity."
                )
                return False
            else:
                wait = backoff * (2 ** (attempt - 1))
                config.script.logger.warning(
                    f"WARNING: DNS lookup failed for '{host}', retry {attempt}/{retries} after {wait}s..."
                )
                time.sleep(wait)
        except Exception as e:
            # catch unexpected errors (permission, etc.)
            config.script.logger.error(
                f"ERROR: Unexpected error resolving host '{host}': {e}", file=sys.stderr
            )
            return False
