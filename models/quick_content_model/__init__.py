"""Quick content threat model package."""

__all__ = ["QuickContentThreatModel"]


def __getattr__(name: str):
    if name == "QuickContentThreatModel":
        from .model import QuickContentThreatModel

        return QuickContentThreatModel
    raise AttributeError(name)
