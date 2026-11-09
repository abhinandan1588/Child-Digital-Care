"""Private object storage interface (avatars, support attachments, exports).

Rules encoded here:

* Buckets are private. Access is always a short-lived signed URL issued *after*
  an authorization check, never a public object URL.
* Content type and size are validated against an allow-list before a ticket is
  issued, so the bucket cannot be used to host arbitrary files.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

#: Attachment types the product accepts. Deliberately narrow.
ALLOWED_CONTENT_TYPES: frozenset[str] = frozenset(
    {"image/png", "image/jpeg", "image/webp", "application/pdf", "text/plain"}
)
MAX_UPLOAD_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class UploadTicket:
    upload_url: str
    object_key: str
    expires_at: datetime
    required_headers: dict[str, str]
    max_bytes: int


@dataclass(frozen=True, slots=True)
class StoredObject:
    object_key: str
    download_url: str
    expires_at: datetime


class ObjectStorage(ABC):
    name: str = "base"

    @property
    @abstractmethod
    def configured(self) -> bool: ...

    @abstractmethod
    async def create_upload_ticket(
        self, *, object_key: str, content_type: str, max_bytes: int
    ) -> UploadTicket: ...

    @abstractmethod
    async def create_download_url(self, *, object_key: str) -> StoredObject: ...

    @abstractmethod
    async def delete(self, *, object_key: str) -> bool: ...
