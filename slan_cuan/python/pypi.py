"""PyPI filename and PURL conventions for the Python ecosystem.

This is the ecosystem-specific kernel behind the (ecosystem-generic)
build-index filter engine in ``slan_cuan.tasks.build_index``: it maps
PURL coordinates to the distribution filenames they can produce and
recognizes distribution-shaped filenames. When a second ecosystem needs
filtering, the equivalent kernel for that ecosystem lives beside this
module and the engine dispatches on the build-index ``ecosystem`` field.
"""

from __future__ import annotations

import fnmatch
import re

from packageurl import PackageURL

_SIDECAR_SUFFIXES = (".sha256", ".sha512", ".sha1", ".md5", ".asc", ".sig")

_DIST_FILENAME_SUFFIXES = (
    ".whl",
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".zip",
)


def canonicalize_name(name: str) -> str:
    """Canonicalize a package name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_pypi_purl(purl: str) -> tuple[str, str] | None:
    """Parse a PyPI PURL string into (canonical_name, version).

    Accepts 'pkg:pypi/name@version' (with optional namespace or qualifiers).
    Returns None if the PURL is not a valid PyPI PURL or missing name/version.
    """
    try:
        p = PackageURL.from_string(purl)
        if p.type == "pypi" and p.name and p.version:
            return canonicalize_name(p.name), p.version
    except ValueError:
        pass
    return None


def get_base_artifact_filename(filename: str) -> str:
    """Strip known sidecar checksum/signature extensions."""
    for suffix in _SIDECAR_SUFFIXES:
        if filename.endswith(suffix):
            return filename[: -len(suffix)]
    return filename


def is_distribution_filename(filename: str) -> bool:
    """Whether a file looks like a Python distribution artifact or sidecar.

    This is the filter's removal predicate: only distribution-shaped files
    are ever removed. Anything else in the payload -- most importantly the
    ``chains-provenance/`` directory that extract-py-artifacts writes and
    rh-sign-python-wheels consumes to build PEP 740 attestations -- passes
    through untouched. Non-distribution files are never upload targets for
    twine, so passing them through cannot leak out-of-scope content.
    """
    base = get_base_artifact_filename(filename).lower()
    return base.endswith(_DIST_FILENAME_SUFFIXES)


def get_purl_candidate_patterns(purl_str: str) -> set[str]:
    """Generate expected filename patterns for a PyPI PURL.

    Derives candidate artifact filenames from PURL coordinates:
    - Wheel: name with '-' -> '_' (PEP 503-ish), version with runs of
      non-alphanumeric chars (esp. '+' and '.' in local versions, or '-')
      escaped to '_' per PEP 427:
      '{name}-{version}-py3-none-any.whl' plus '{name}-{version}-*.whl' glob.
    - Sdist: '{name}-{version}.tar.gz' (both hyphen and underscore name variants).
    """
    coord = parse_pypi_purl(purl_str)
    if not coord:
        return set()

    canonical_name, version = coord
    wheel_name = canonical_name.replace("-", "_")
    wheel_version = re.sub(r"[^\w.]+", "_", version)

    sdist_name_hyphen = canonical_name
    sdist_name_underscore = wheel_name

    patterns = {
        f"{wheel_name}-{wheel_version}-py3-none-any.whl",
        f"{wheel_name}-{wheel_version}-*.whl",
        f"{sdist_name_hyphen}-{version}.tar.gz",
        f"{sdist_name_underscore}-{version}.tar.gz",
    }
    return patterns


def matches_any_candidate(filename: str, candidates: set[str]) -> bool:
    """Check if filename matches any candidate pattern case-insensitively."""
    base_name = get_base_artifact_filename(filename).lower()
    for pattern in candidates:
        pat_lower = pattern.lower()
        if "*" in pat_lower:
            if fnmatch.fnmatchcase(base_name, pat_lower):
                return True
        else:
            if base_name == pat_lower:
                return True
    return False
