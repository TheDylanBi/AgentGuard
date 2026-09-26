"""Dataset adapters: raw dataset -> normalized auth samples."""
from .base import DatasetAdapter
from .mind2web import Mind2WebAdapter
from .wasp import WaspAdapter

ADAPTERS = {
    "wasp": WaspAdapter,
    "mind2web": Mind2WebAdapter,
}

__all__ = ["DatasetAdapter", "WaspAdapter", "Mind2WebAdapter", "ADAPTERS"]
