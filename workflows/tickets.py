"""Ticket creation (HTTP stub + in-process record for tests)."""

from __future__ import annotations

from dataclasses import dataclass
import uuid

import httpx


@dataclass
class Ticket:
    ticket_id: str
    subject: str
    body: str


class TicketClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.created: list[Ticket] = []

    def create(self, subject: str, body: str) -> Ticket:
        ticket = Ticket(ticket_id=str(uuid.uuid4()), subject=subject, body=body)
        self.created.append(ticket)
        # Best-effort webhook to internal ITSM; failures are non-fatal in demo.
        try:
            httpx.post(
                f"{self.base_url}/tickets",
                json={"subject": subject, "body": body, "ticket_id": ticket.ticket_id},
                timeout=2.0,
            )
        except (httpx.HTTPError, OSError):
            pass
        return ticket
