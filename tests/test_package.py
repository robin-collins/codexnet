"""Smoke tests for the application package."""

import field_discovery


def test_package_version() -> None:
    """The package can be imported without external setup."""
    assert field_discovery.__version__ == "0.1.0"
