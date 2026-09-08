"""
Authorization gate and engagement metadata.

Every module in this framework performs *active* Layer 2 / routing attacks that
disrupt or redirect production traffic. They must only be run against assets
explicitly listed in a signed Rules of Engagement (RoE) / Statement of Work.

This module does not (and cannot) enforce authorization technically. It records
the operator-supplied engagement metadata into the audit log so that every
action is traceable back to a specific authorized engagement.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


BANNER = r"""
  ____                     _   _      _
 | __ )  ___  __ _ _ __   | \ | | ___| |_
 |  _ \ / _ \/ _` | '__|  |  \| |/ _ \ __|
 | |_) |  __/ (_| | |     | |\  |  __/ |_
 |____/ \___|\__,_|_|     |_| \_|\___|\__|  RapidStrike
 ─────────────────────────────────────────────────────────
 Bear Net RapidStrike — Layer 2 / Routing Assessment Framework
 Authorized engagement use only. Every run is logged.
"""


@dataclass
class Engagement:
    """Engagement metadata carried into the audit log for every action."""
    engagement_id: str = "UNSPECIFIED"
    operator: str = "UNSPECIFIED"
    client: str = "UNSPECIFIED"
    scope_note: str = ""
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def as_log_prefix(self) -> str:
        return (
            f"[eng={self.engagement_id} op={self.operator} "
            f"client={self.client}]"
        )


def add_engagement_args(parser):
    """Attach the shared engagement/authorization flags to any (sub)parser."""
    grp = parser.add_argument_group("engagement (audit trail)")
    grp.add_argument("--engagement-id", default="UNSPECIFIED",
                     help="Engagement / RoE reference ID")
    grp.add_argument("--operator", default="UNSPECIFIED",
                     help="Operator name or handle")
    grp.add_argument("--client", default="UNSPECIFIED",
                     help="Client / target organization")
    grp.add_argument("--scope-note", default="",
                     help="Free-text scope note recorded in the log")


def engagement_from_args(args) -> Engagement:
    return Engagement(
        engagement_id=getattr(args, "engagement_id", "UNSPECIFIED"),
        operator=getattr(args, "operator", "UNSPECIFIED"),
        client=getattr(args, "client", "UNSPECIFIED"),
        scope_note=getattr(args, "scope_note", ""),
    )
