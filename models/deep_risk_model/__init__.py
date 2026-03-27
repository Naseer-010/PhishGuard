"""Deep risk model package."""

__all__ = ["DeepRiskModel"]


def __getattr__(name: str):
    if name == "DeepRiskModel":
        from .model import DeepRiskModel

        return DeepRiskModel
    raise AttributeError(name)
