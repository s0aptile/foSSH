"""foSSH Console — local administration for a foSSH install."""

__all__ = ["main"]

def main(argv=None):
    from .app import main as _main

    return _main(argv)
