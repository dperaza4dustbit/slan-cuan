"""Data models for the slan-cuan release pipeline."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

EXTRACT_RESULT_FILENAME = "extract-result.json"
PUBLISH_RESULT_FILENAME = "publish-result.json"
REGISTER_RESULT_FILENAME = "register-result.json"

# Directory names, relative to extract's output_dir, that extract.py writes
# and that the slan-cuan-extract Task's prepare-source-data step copies by
# hardcoded path. Kept here as the single source of truth so
# output_contract_test.py can assert the Task stays in sync.
EXTRACT_METADATA_DIRNAME = "metadata"
EXTRACT_ATTACHMENTS_DIRNAME = "attachments"

# Conventional directory name, relative to the artifact directory, that
# generate-security-metadata writes OSV/VEX records into and that the publish
# task unpacks securityMetadataArtifact into. Used as a fallback when the
# extract-result.json does not record security_metadata_dir (see LWLP-2339).
_SECURITY_METADATA_DIRNAME = "security_metadata"

PROVENANCE_SIGSTORE_FILE_SUFFIX = ".provenance.sigstore.json"
SPDX_FILE_SUFFIX = ".spdx.json"
VSA_FILE_SUFFIX = ".vsa.json"
CYCLONEDX_FILE_SUFFIX = ".cyclonedx.json"
OSV_FILE_SUFFIX = ".osv.json"
VEX_FILE_SUFFIX = ".vex.json"


@dataclass(frozen=True)
class GlobalContext:
    """Immutable context passed from the Click group to all subcommands."""

    verbose: bool
    dry_run: bool
    ca_cert: Path | None
    tekton_results_dir: Path | None


@dataclass(frozen=True)
class ImageReference:
    """Parsed OCI image reference."""

    registry: str
    repository: str
    tag: str | None
    digest: str | None

    @classmethod
    def parse(cls, ref: str) -> ImageReference:
        """Parse an OCI image reference string.

        Supports:
        - registry/repo@sha256:digest (digest form)
        - registry/repo:tag (tag form)
        - registry/repo:tag@sha256:digest (both, tag ignored for pull)

        Args:
            ref: Image reference string to parse

        Returns:
            Parsed ImageReference object

        Raises:
            ValueError: If reference is invalid or has neither tag nor digest

        """
        if "@" in ref:
            # Has digest
            base_ref, digest = ref.rsplit("@", 1)
            if not digest.startswith("sha256:"):
                raise ValueError(f"Invalid digest format: {digest}")

            # Check for tag before digest
            if ":" in base_ref:
                registry_repo, tag = base_ref.rsplit(":", 1)
            else:
                registry_repo = base_ref
                tag = None
        elif ":" in ref:
            # Has tag, no digest
            # Need to distinguish registry:port from repo:tag
            parts = ref.split("/")
            if len(parts) < 2:
                raise ValueError(f"Invalid image reference: {ref}")

            # Last part contains :tag
            last_part = parts[-1]
            if ":" not in last_part:
                raise ValueError(f"Invalid image reference: {ref}")

            registry_repo, tag = ref.rsplit(":", 1)
            digest = None
        else:
            raise ValueError(f"Image reference must have tag or digest: {ref}")

        # Split registry from repository
        if "/" not in registry_repo:
            raise ValueError(f"Invalid image reference: {ref}")

        registry, repository = registry_repo.split("/", 1)

        # Validate we have tag or digest
        if tag is None and digest is None:
            raise ValueError(f"Image reference must have tag or digest: {ref}")

        return cls(
            registry=registry,
            repository=repository,
            tag=tag,
            digest=digest,
        )

    def __str__(self) -> str:
        """Return canonical reference string."""
        ref = f"{self.registry}/{self.repository}"
        if self.tag:
            ref = f"{ref}:{self.tag}"
        if self.digest:
            ref = f"{ref}@{self.digest}"
        return ref


@dataclass(frozen=True)
class LayerInfo:
    """Metadata for a single OCI artifact layer."""

    digest: str
    media_type: str
    size: int
    annotations: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class OCIManifest:
    """Parsed OCI image manifest from oras manifest fetch."""

    deliverable_name: str
    layers: tuple[LayerInfo, ...]
    annotations: dict[str, str]
    artifact_type: str
    raw: dict[str, object]

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> OCIManifest:
        """Parse raw oras manifest-fetch JSON.

        Raises:
            ValueError: If deliverable name cannot be determined.

        """
        # Parse layers
        layers_data = data.get("layers", [])
        if not isinstance(layers_data, list):
            layers_data = []

        layers = tuple(
            LayerInfo(
                digest=str(layer["digest"]),
                media_type=str(layer["mediaType"]),
                size=int(layer["size"]),
                annotations=dict(layer.get("annotations", {})),
            )
            for layer in layers_data
            if isinstance(layer, dict)
        )

        # Parse annotations
        annotations_data = data.get("annotations", {})
        if not isinstance(annotations_data, dict):
            annotations_data = {}
        annotations = {str(k): str(v) for k, v in annotations_data.items()}

        # Resolve deliverable name (title annotation preferred, fallback
        # to deliverable.name)
        deliverable_name_raw = annotations.get(
            "org.opencontainers.image.title"
        ) or annotations.get("deliverable.name")

        if not deliverable_name_raw:
            raise ValueError(
                "Could not determine deliverable name from manifest annotations"
            )

        return cls(
            deliverable_name=str(deliverable_name_raw),
            layers=layers,
            annotations=annotations,
            artifact_type=str(data.get("artifactType", "")),
            raw=data,
        )

    def to_dict(self) -> dict[str, object]:
        """Return the original manifest dict for serialization."""
        return self.raw


def _parse_extension(filename: str) -> str:
    """Extract the file extension for Maven artifact classification."""
    if filename.endswith(".tar.gz"):
        return "tar.gz"
    elif filename.endswith(PROVENANCE_SIGSTORE_FILE_SUFFIX):
        return "provenance"
    elif filename.endswith(SPDX_FILE_SUFFIX):
        return "spdx"
    elif filename.endswith(VSA_FILE_SUFFIX):
        return "vsa"
    elif filename.endswith(CYCLONEDX_FILE_SUFFIX):
        return "cyclonedx"
    elif filename.endswith(OSV_FILE_SUFFIX):
        return "osv"
    elif filename.endswith(VEX_FILE_SUFFIX):
        return "vex"
    return filename.rsplit(".", 1)[-1] if "." in filename else ""


def _parse_classifier(
    filename: str, artifact_id: str, version: str
) -> str | None:
    """Extract Maven classifier from filename.

    Classifier appears between version and extension:
    artifact_id-version[-classifier].extension

    """
    prefix = f"{artifact_id}-{version}"
    if not filename.startswith(prefix):
        return None
    remainder = filename[len(prefix) :]
    if not remainder or remainder[0] == ".":
        return None
    # remainder starts with "-classifier.ext"
    if remainder[0] != "-":
        return None
    # Strip leading dash and extension
    classifier_with_ext = remainder[1:]

    # Handle .tar.gz extension specially
    if classifier_with_ext.endswith(".tar.gz"):
        classifier = classifier_with_ext[:-7]  # Remove ".tar.gz"
    elif "." in classifier_with_ext:
        classifier = classifier_with_ext.rsplit(".", 1)[0]
    else:
        classifier = classifier_with_ext

    return classifier if classifier else None


def _read_sidecar(file_path: Path, suffix: str) -> str | None:
    """Read checksum value from sidecar file if it exists."""
    sidecar_path = file_path.parent / f"{file_path.name}{suffix}"
    if sidecar_path.exists():
        content = sidecar_path.read_text().strip()
        # Checksum files often have format: "checksum filename"
        if content:
            parts = content.split()
            return parts[0] if parts else None
    return None


@dataclass(frozen=True)
class MavenCoordinate:
    """Maven GAV coordinate."""

    group_id: str
    artifact_id: str
    version: str


@dataclass(frozen=True)
class MavenArtifact:
    """A single uploadable Maven artifact.

    Fields map to Pulp Maven upload API parameters.

    """

    relative_path: str
    file_path: Path
    group_id: str
    artifact_id: str
    version: str
    classifier: str | None
    extension: str
    md5: str | None
    sha1: str | None
    sha256: str | None

    @property
    def coordinate(self) -> MavenCoordinate:
        """Return the GAV coordinate for this artifact."""
        return MavenCoordinate(
            group_id=self.group_id,
            artifact_id=self.artifact_id,
            version=self.version,
        )

    @property
    def is_metadata(self) -> bool:
        """True for Maven metadata XML files."""
        name = self.file_path.name
        return name == "maven-metadata.xml" or name.startswith(
            "maven-metadata.xml."
        )

    @property
    def is_signable(self) -> bool:
        """True for JARs and POMs (sign stage filter)."""
        return self.extension in ("jar", "pom")

    @property
    def is_provenance(self) -> bool:
        """True for provenance files."""
        return self.extension == "provenance"

    @property
    def is_spdx(self) -> bool:
        """True for SPDX files."""
        return self.extension == "spdx"

    @property
    def is_vsa(self) -> bool:
        """True for VSA files."""
        return self.extension == "vsa"

    @property
    def is_cyclonedx(self) -> bool:
        """True for CycloneDX files."""
        return self.extension == "cyclonedx"

    @property
    def is_sbom(self) -> bool:
        """True for SBOM files."""
        return (
            self.is_cyclonedx or self.is_spdx or self.is_vsa or self.is_provenance
        )


@dataclass(frozen=True)
class BuildOutput:
    """Parsed PNC build-output deliverable."""

    deliverable_dir: Path
    artifacts: tuple[MavenArtifact, ...]
    source_archive_path: Path | None
    security_metadata_dir: Path | None

    @property
    def coordinates(self) -> frozenset[MavenCoordinate]:
        """Unique GAV coordinates across all artifacts."""
        return frozenset(a.coordinate for a in self.artifacts)

    @property
    def signable(self) -> tuple[MavenArtifact, ...]:
        """Artifacts eligible for signing (JARs + POMs)."""
        return tuple(a for a in self.artifacts if a.is_signable)

    @classmethod
    def from_extract_result(
        cls,
        result: ExtractResult,
        output_dir: Path,
        require_supply_chain_metadata: bool = False,
    ) -> BuildOutput:
        """Parse deliverable directory using ExtractResult metadata.

        Walks repository/ tree, parses GAV from paths, reads
        checksum sidecars, determines classifiers from filenames.

        """
        deliverable_path = output_dir / result.deliverable_dir
        repo_dir = deliverable_path / "repository"

        security_metadata_path: Path | None = None
        if result.security_metadata_dir:
            candidate = output_dir / result.security_metadata_dir
            if candidate.is_dir():
                security_metadata_path = candidate
        if security_metadata_path is None:
            # LWLP-2339: since the Trusted Artifact split (slan-cuan#111), the
            # extract-result.json reaching publish no longer carries the
            # security_metadata_dir written by generate-security-metadata (that
            # updated file stays in the generate task's workdir and is not
            # packaged into securityMetadataArtifact). Fall back to the
            # conventional directory the publish task unpacks the metadata into.
            fallback = output_dir / _SECURITY_METADATA_DIRNAME
            if fallback.is_dir():
                security_metadata_path = fallback

        artifacts: list[MavenArtifact] = []

        # Process repository directory
        if repo_dir.is_dir():
            for file_path in sorted(repo_dir.rglob("*")):
                if not file_path.is_file():
                    continue

                rel_to_repo = file_path.relative_to(repo_dir)
                parts_list = list(rel_to_repo.parts)

                filename = parts_list[-1]

                if filename == "maven-metadata.xml" or filename.startswith(
                    "maven-metadata.xml."
                ):
                    # Maven metadata can appear at two levels:
                    #   Artifact: group/.../artifact_id/maven-metadata.xml
                    #   Version:  group/.../artifact_id/version/maven-metadata.xml
                    # PNC produces releases (not SNAPSHOTs), so artifact-level
                    # is expected. Use Pulp's heuristic: if second-to-last
                    # segment looks like a version, treat as version-level.
                    _VERSION_RE = re.compile(
                        r"\d+(\.\d+)?(\.\d+)?([.-][a-zA-Z0-9]+)*$"
                    )
                    candidate = parts_list[-2] if len(parts_list) >= 4 else ""
                    if candidate and _VERSION_RE.match(candidate):
                        # Version-level metadata (SNAPSHOT case)
                        version = candidate
                        artifact_id = parts_list[-3]
                        group_id = ".".join(parts_list[:-3])
                    elif len(parts_list) >= 3:
                        # Artifact-level metadata (expected case)
                        version = ""
                        artifact_id = parts_list[-2]
                        group_id = ".".join(parts_list[:-2])
                    else:
                        continue
                else:
                    # Versioned artifacts: group/.../artifact_id/version/filename
                    if len(parts_list) < 4:
                        continue
                    version = parts_list[-2]
                    artifact_id = parts_list[-3]
                    group_id = ".".join(parts_list[:-3])

                if not group_id:
                    continue

                # Determine extension and classifier
                extension = _parse_extension(filename)
                classifier = _parse_classifier(filename, artifact_id, version)

                # Read checksum sidecars
                md5 = _read_sidecar(file_path, ".md5")
                sha1_val = _read_sidecar(file_path, ".sha1")
                sha256_val = _read_sidecar(file_path, ".sha256")

                artifacts.append(
                    MavenArtifact(
                        relative_path=str(rel_to_repo),
                        file_path=file_path,
                        group_id=group_id,
                        artifact_id=artifact_id,
                        version=version,
                        classifier=classifier,
                        extension=extension,
                        md5=md5,
                        sha1=sha1_val,
                        sha256=sha256_val,
                    )
                )

        if require_supply_chain_metadata:
            signable_coords: set[tuple[str, str, str]] = set()
            sbom_coords: set[tuple[str, str, str]] = set()
            for a in artifacts:
                coord = (a.group_id, a.artifact_id, a.version)
                if a.extension in ("jar", "pom"):
                    signable_coords.add(coord)
                elif a.extension in ("cyclonedx", "spdx", "vsa", "provenance"):
                    sbom_coords.add(coord)
            missing = signable_coords - sbom_coords
            if missing:
                missing_str = ", ".join(
                    f"{g}:{a}:{v}" for g, a, v in sorted(missing)
                )
                raise ValueError(f"Missing SBOM artifacts for: {missing_str}")

            if not security_metadata_path or not any(
                security_metadata_path.iterdir()
            ):
                raise ValueError(
                    "No security metadata found: "
                    "generate-security-metadata must run before publish"
                )

        # Locate well-known files
        sources_path = deliverable_path / "sources" / "sources.tar.gz"

        return cls(
            deliverable_dir=deliverable_path,
            artifacts=tuple(artifacts),
            source_archive_path=(sources_path if sources_path.exists() else None),
            security_metadata_dir=security_metadata_path,
        )


@dataclass(frozen=True)
class ExtractResult:
    """Result manifest for the extract stage."""

    image: ImageReference
    manifest_digest: str
    layers: list[LayerInfo]
    annotations: dict[str, str]
    deliverable_dir: str
    files: list[str]
    extracted_at: str
    security_metadata_dir: str | None = None
    attachment_files: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        """Serialize to JSON string.

        Returns:
            JSON string with 2-space indentation

        """
        data = asdict(self)
        # Convert ImageReference to dict manually for clean serialization
        data["image"] = {
            "registry": self.image.registry,
            "repository": self.image.repository,
            "tag": self.image.tag,
            "digest": self.image.digest,
        }
        return json.dumps(data, indent=2)

    @classmethod
    def from_file(cls, path: Path) -> ExtractResult:
        """Deserialize from a JSON file.

        Args:
            path: Path to the extract-result.json file

        Returns:
            Deserialized ExtractResult object

        Raises:
            FileNotFoundError: If file does not exist
            json.JSONDecodeError: If file contains invalid JSON
            KeyError: If required fields are missing

        """
        with path.open("r") as f:
            data = json.load(f)

        # Reconstruct ImageReference
        image_data = data["image"]
        image = ImageReference(
            registry=image_data["registry"],
            repository=image_data["repository"],
            tag=image_data.get("tag"),
            digest=image_data.get("digest"),
        )

        # Reconstruct LayerInfo list
        layers = [
            LayerInfo(
                digest=layer["digest"],
                media_type=layer["media_type"],
                size=layer["size"],
                annotations=layer.get("annotations", {}),
            )
            for layer in data["layers"]
        ]

        return cls(
            image=image,
            manifest_digest=data["manifest_digest"],
            layers=layers,
            annotations=data["annotations"],
            deliverable_dir=data["deliverable_dir"],
            files=data["files"],
            security_metadata_dir=data.get("security_metadata_dir"),
            extracted_at=data["extracted_at"],
            attachment_files=data.get("attachment_files", []),
        )

    def save(self, path: Path) -> None:
        """Write JSON to file.

        Args:
            path: Path to write the JSON file

        """
        with path.open("w") as f:
            f.write(self.to_json())


@dataclass(frozen=True)
class PublishResult:
    """Result manifest for the publish stage."""

    pulp_url: str
    distribution: str
    artifacts_uploaded: int
    artifacts_skipped: int
    coordinates: tuple[MavenCoordinate, ...]
    published_at: str
    repository_version: str | None = None
    content_unit_hrefs: tuple[str, ...] = ()
    pulp_labels: dict[str, str] | None = None
    file_repository: str | None = None
    security_metadata_uploaded: int = 0
    security_metadata_skipped: int = 0

    def to_json(self) -> str:
        """Serialize to JSON string."""
        data = asdict(self)
        data["coordinates"] = [asdict(c) for c in self.coordinates]
        data["content_unit_hrefs"] = list(self.content_unit_hrefs)
        return json.dumps(data, indent=2)

    def save(self, path: Path) -> None:
        """Write JSON to file."""
        with path.open("w") as f:
            f.write(self.to_json())

    @classmethod
    def from_file(cls, path: Path) -> PublishResult:
        """Deserialize from a JSON file."""
        with path.open("r") as f:
            data = json.load(f)

        coordinates = tuple(
            MavenCoordinate(
                group_id=c["group_id"],
                artifact_id=c["artifact_id"],
                version=c["version"],
            )
            for c in data["coordinates"]
        )

        # Handle optional new fields for backward compatibility
        repository_version = data.get("repository_version")
        content_unit_hrefs_raw = data.get("content_unit_hrefs", [])
        content_unit_hrefs = (
            tuple(content_unit_hrefs_raw) if content_unit_hrefs_raw else ()
        )
        pulp_labels = data.get("pulp_labels")
        file_repository = data.get("file_repository")
        security_metadata_uploaded = data.get("security_metadata_uploaded", 0)
        security_metadata_skipped = data.get("security_metadata_skipped", 0)

        return cls(
            pulp_url=data["pulp_url"],
            distribution=data["distribution"],
            artifacts_uploaded=data["artifacts_uploaded"],
            artifacts_skipped=data["artifacts_skipped"],
            coordinates=coordinates,
            published_at=data["published_at"],
            repository_version=repository_version,
            content_unit_hrefs=content_unit_hrefs,
            pulp_labels=pulp_labels,
            file_repository=file_repository,
            security_metadata_uploaded=security_metadata_uploaded,
            security_metadata_skipped=security_metadata_skipped,
        )


@dataclass(frozen=True)
class RegisterResult:
    """Result manifest for the register stage."""

    trustify_api_url: str
    sbom_urn: str
    sbom_file: str
    sbom_size: int
    registered_at: str

    def to_json(self) -> str:
        """Serialize to JSON string."""
        data = asdict(self)
        return json.dumps(data, indent=2)

    def save(self, path: Path) -> None:
        """Write JSON to file."""
        with path.open("w") as f:
            f.write(self.to_json())

    @classmethod
    def from_file(cls, path: Path) -> RegisterResult:
        """Deserialize from a JSON file."""
        with path.open("r") as f:
            data = json.load(f)
        return cls(
            trustify_api_url=data["trustify_api_url"],
            sbom_urn=data["sbom_urn"],
            sbom_file=data["sbom_file"],
            sbom_size=data["sbom_size"],
            registered_at=data["registered_at"],
        )
