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
# response_utils.py
"""
Small helpers for parsing HTTP responses. Kept separate to avoid circular imports.
"""

from typing import Any
import json
import config
from errors import APIError


def get_response_content(r) -> Any:
    """
    Return parsed JSON when possible, otherwise return r.text.
    Raises APIError on declared-JSON but unparseable content.
    """
    content_type = getattr(r.headers, "get", lambda k, d=None: "")("content-type", "")
    if "json" in (content_type or "").lower():
        try:
            return r.json()
        except Exception as exc:
            text = getattr(r, "text", "") or ""
            config.script.logger.error(
                "Response declared JSON but could not parse JSON."
            )
            raise APIError(
                f"Invalid JSON response (status {getattr(r, 'status_code', 'unknown')}): {text[:1000]}"
            ) from exc

    # fallback: try JSON, otherwise return text
    try:
        return r.json()
    except Exception:
        return getattr(r, "text", "")
