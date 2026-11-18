"""Pulp REST API models."""

from dataclasses import dataclass, field
from pathlib import Path

from slan_cuan.pulp.constants import AUTH_TYPE_TBR, TASK_POLL_TIMEOUT_SECONDS


@dataclass(frozen=True)
class PulpConfig:
    """Connection configuration for a Pulp instance."""

    base_url: str
    verify_ssl: bool
    ca_cert: Path | None = None
    domain: str | None = None
    auth_type: str = AUTH_TYPE_TBR
    username: str | None = None
    password: str | None = None
    client_cert: Path | None = None
    client_key: Path | None = None
    task_timeout: float = TASK_POLL_TIMEOUT_SECONDS
    max_total_task_timeout: float | None = None
    custom_headers: dict[str, str] = field(default_factory=dict)
    verbose: bool = False


@dataclass(frozen=True)
class ContentUnit:
    """A content unit returned by the synchronous upload endpoint."""

    pulp_href: str
    relative_path: str
    group_id: str
    artifact_id: str
    version: str
    filename: str


@dataclass(frozen=True)
class MavenDistribution:
    """A Maven distribution returned by the Pulp distribution API."""

    pulp_href: str
    name: str
    base_path: str
    repository: str | None = None


@dataclass(frozen=True)
class FileContentUnit:
    """A content unit returned by the Pulp File upload endpoint."""

    pulp_href: str
    relative_path: str
    sha256: str


@dataclass(frozen=True)
class NpmContentUnit:
    """A content unit returned by the Pulp npm package upload endpoint."""

    pulp_href: str
    name: str
    version: str


@dataclass(frozen=True)
class ModifyResult:
    """Result of a repository modify operation."""

    task_href: str
    state: str
    repository_version: str | None
    content_units_added: int
