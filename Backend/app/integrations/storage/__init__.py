from app.integrations.storage.base import ObjectStorage, StoredObject, UploadTicket
from app.integrations.storage.provider import get_object_storage, set_object_storage

__all__ = [
    "ObjectStorage",
    "StoredObject",
    "UploadTicket",
    "get_object_storage",
    "set_object_storage",
]
