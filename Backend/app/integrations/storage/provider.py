"""Object storage providers.

Only the ``disabled`` provider ships. Avatars and attachments are optional for
the first release, and a half-built storage path is worse than a clearly
unavailable one: every method raises a documented 503 so callers cannot mistake
it for a working feature.
"""

from __future__ import annotations

from app.core.config import settings
from app.core.errors import IntegrationNotConfigured
from app.integrations.storage.base import (
    ALLOWED_CONTENT_TYPES,
    MAX_UPLOAD_BYTES,
    ObjectStorage,
    StoredObject,
    UploadTicket,
)


class DisabledObjectStorage(ObjectStorage):
    name = "disabled"

    @property
    def configured(self) -> bool:
        return False

    async def create_upload_ticket(
        self, *, object_key: str, content_type: str, max_bytes: int
    ) -> UploadTicket:
        raise IntegrationNotConfigured(
            "File uploads are not available: object storage is not configured."
        )

    async def create_download_url(self, *, object_key: str) -> StoredObject:
        raise IntegrationNotConfigured(
            "File downloads are not available: object storage is not configured."
        )

    async def delete(self, *, object_key: str) -> bool:
        raise IntegrationNotConfigured(
            "Object deletion is not available: object storage is not configured."
        )


def validate_upload(content_type: str, size_bytes: int) -> None:
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise ValueError(f"Content type '{content_type}' is not accepted.")
    if size_bytes <= 0 or size_bytes > MAX_UPLOAD_BYTES:
        raise ValueError(f"File size must be between 1 and {MAX_UPLOAD_BYTES} bytes.")


_storage: ObjectStorage | None = None


def get_object_storage() -> ObjectStorage:
    global _storage
    if _storage is None:
        if settings.object_storage_provider == "s3_compatible":
            # Intentionally not implemented: see module docstring.
            raise IntegrationNotConfigured(
                "OBJECT_STORAGE_PROVIDER=s3_compatible is declared but no S3 client is "
                "bundled in this release. Set OBJECT_STORAGE_PROVIDER=disabled."
            )
        _storage = DisabledObjectStorage()
    return _storage


def set_object_storage(storage: ObjectStorage | None) -> None:
    global _storage
    _storage = storage
