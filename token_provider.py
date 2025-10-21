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
import threading
import time
import configparser
from pathlib import Path


class TokenProvider:
    """
    In-memory provider backed by the on-disk token files used by script.
    Single-process safe: uses threading locks to avoid concurrent refreshes in threads.
    """

    def __init__(self, token_dir, key_name, token_type="session"):
        self.token_dir = Path(token_dir)
        self.key_name = key_name
        self.token_type = token_type  # "session" by default
        self._lock = threading.RLock()
        self._refresh_lock = threading.Lock()
        self._token = None
        self._secret = None
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
            self._load_from_disk()
            return self._token, self._secret

    def set(self, token, secret):
        with self._lock:
            self._token = token
            self._secret = secret
            self._write_to_disk(token, secret)

    def refresh(self, refresh_func):
        """
        Single-flight refresh. refresh_func is a callable that returns (token, secret).
        """
        if self._refresh_lock.acquire(blocking=False):
            try:
                token, secret = refresh_func()
                if not token or not secret:
                    raise RuntimeError("Refresh function returned invalid credentials")
                self.set(token, secret)
                return token, secret
            finally:
                self._refresh_lock.release()
        else:
            waited = 0.0
            while self._refresh_lock.locked() and waited < 10.0:
                time.sleep(0.05)
                waited += 0.05
            return self.get()
