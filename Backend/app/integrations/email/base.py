"""Email provider interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(slots=True)
class EmailMessage:
    to: str
    subject: str
    text_body: str
    html_body: str | None = None
    #: Safe tags for provider-side analytics. Never include a token here.
    tags: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SendResult:
    sent: bool
    provider: str
    provider_message_id: str | None = None
    error_code: str | None = None


class EmailProvider(ABC):
    name: str = "base"

    @property
    @abstractmethod
    def configured(self) -> bool: ...

    @abstractmethod
    async def send(self, message: EmailMessage) -> SendResult: ...
