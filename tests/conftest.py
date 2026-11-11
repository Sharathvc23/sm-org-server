"""Test-session defaults.

``sm_server.app`` builds the uvicorn entrypoint (``app = create_app()``) at
import, and ``create_app`` opens the default file database. Tests must never
leave ``./sm-server.sqlite`` behind in the checkout, so the default is pointed
at memory before any test module imports the app. Tests that build their own
app pass ``SqliteStore(":memory:")`` explicitly.
"""

from __future__ import annotations

import os

os.environ.setdefault("SERVER_DB_PATH", ":memory:")
