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

class BIGSdbSyncError(Exception):
    """Base exception for BIGSdb_sync library errors."""

class ConfigError(BIGSdbSyncError):
    """Errors due to bad CLI args or configuration."""

class AuthError(BIGSdbSyncError):
    """Authentication / token errors."""

class APIError(BIGSdbSyncError):
    """HTTP/API related errors."""

class DBError(BIGSdbSyncError):
    """Database related errors."""
