"""Backward-compat re-export. Use stackraider.web.server."""

from stackraider.web.server import create_app, start

__all__ = ["create_app", "start"]
