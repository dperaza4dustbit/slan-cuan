"""Tests for the PyPI filename/PURL kernel (slan_cuan.python.pypi)."""

from __future__ import annotations

from slan_cuan.python.pypi import (
    canonicalize_name,
    get_base_artifact_filename,
    get_purl_candidate_patterns,
    is_distribution_filename,
    matches_any_candidate,
    parse_pypi_purl,
)


class TestHelpers:
    """Tests for coordinate and purl parsing helper functions."""

    def test_canonicalize_name(self) -> None:
        """Canonicalize package names per PEP 503."""
        assert canonicalize_name("Foo_Bar.Baz") == "foo-bar-baz"
        assert canonicalize_name("my--package..name") == "my-package-name"
        assert canonicalize_name("simple") == "simple"

    def test_parse_pypi_purl(self) -> None:
        """Parse PyPI PURLs into canonical name and version."""
        assert parse_pypi_purl("pkg:pypi/Flask@2.0.1") == ("flask", "2.0.1")
        assert parse_pypi_purl("pkg:pypi/my_pkg@1.0.0?extension=whl") == (
            "my-pkg",
            "1.0.0",
        )
        assert parse_pypi_purl("pkg:maven/org.example/artifact@1.0.0") is None
        assert parse_pypi_purl("invalid-purl") is None

    def test_get_base_artifact_filename(self) -> None:
        """Strip checksum and signature sidecar extensions."""
        assert (
            get_base_artifact_filename("foo-1.0-py3-none-any.whl.sha256")
            == "foo-1.0-py3-none-any.whl"
        )
        assert (
            get_base_artifact_filename("foo-1.0.tar.gz.asc") == "foo-1.0.tar.gz"
        )
        assert (
            get_base_artifact_filename("foo-1.0-py3-none-any.whl")
            == "foo-1.0-py3-none-any.whl"
        )

    def test_get_purl_candidate_patterns_and_matching(self) -> None:
        """Test candidate generation and matching across PEP 427/440 variants."""
        # Standard purl
        pats = get_purl_candidate_patterns("pkg:pypi/foo-bar@1.2.3")
        assert "foo_bar-1.2.3-py3-none-any.whl" in pats
        assert "foo_bar-1.2.3-*.whl" in pats
        assert "foo-bar-1.2.3.tar.gz" in pats
        assert "foo_bar-1.2.3.tar.gz" in pats
        assert matches_any_candidate("foo_bar-1.2.3-py3-none-any.whl", pats)
        assert matches_any_candidate(
            "foo_bar-1.2.3-py3-none-any.whl.sha512", pats
        )
        assert matches_any_candidate("foo-bar-1.2.3.tar.gz", pats)
        assert matches_any_candidate("foo_bar-1.2.3.tar.gz.sig", pats)

        # Hyphenated version sdist
        pats_hyphen = get_purl_candidate_patterns("pkg:pypi/my-pkg@1.0.0-beta")
        assert "my_pkg-1.0.0_beta-*.whl" in pats_hyphen
        assert "my-pkg-1.0.0-beta.tar.gz" in pats_hyphen
        assert "my_pkg-1.0.0-beta.tar.gz" in pats_hyphen
        assert matches_any_candidate("my-pkg-1.0.0-beta.tar.gz", pats_hyphen)
        assert matches_any_candidate("my_pkg-1.0.0-beta.tar.gz", pats_hyphen)

        # Local version wheel: '+' and '.' in local versions escaped to '_'
        pats_local = get_purl_candidate_patterns("pkg:pypi/my-pkg@1.0.0+rhlw.1")
        assert "my_pkg-1.0.0_rhlw.1-py3-none-any.whl" in pats_local
        assert "my_pkg-1.0.0_rhlw.1-*.whl" in pats_local
        assert matches_any_candidate(
            "my_pkg-1.0.0_rhlw.1-py3-none-any.whl", pats_local
        )
        assert matches_any_candidate(
            "my_pkg-1.0.0_rhlw.1-cp39-cp39-linux_x86_64.whl",
            pats_local,
        )

        # Case variants
        assert matches_any_candidate("Foo_Bar-1.2.3-py3-none-any.whl", pats)
        assert matches_any_candidate("FOO-BAR-1.2.3.TAR.GZ", pats)

        # Multi-glob wheel tags
        assert matches_any_candidate(
            "foo_bar-1.2.3-cp311-cp311-manylinux_2_17_x86_64.whl",
            pats,
        )

        # Unmatched / unknown files
        assert not matches_any_candidate("random-file.txt", pats)
        assert not matches_any_candidate("invalid.whl", pats)
        assert not matches_any_candidate("other-1.2.3.tar.gz", pats)


class TestIsDistributionFilename:
    """Tests for the distribution-shape removal predicate."""

    def test_distribution_shapes(self) -> None:
        """Wheels, sdists, and zips are distribution files."""
        assert is_distribution_filename("foo-1.0-py3-none-any.whl")
        assert is_distribution_filename("foo-1.0.tar.gz")
        assert is_distribution_filename("foo-1.0.tar.bz2")
        assert is_distribution_filename("foo-1.0.tar.xz")
        assert is_distribution_filename("foo-1.0.zip")
        assert is_distribution_filename("FOO-1.0.TAR.GZ")

    def test_sidecars_are_distribution_files(self) -> None:
        """Checksum/signature sidecars follow their base artifact."""
        assert is_distribution_filename("foo-1.0-py3-none-any.whl.sha256")
        assert is_distribution_filename("foo-1.0.tar.gz.asc")
        assert is_distribution_filename("foo-1.0-py3-none-any.whl.sig")

    def test_metadata_is_not_distribution(self) -> None:
        """Metadata files (provenance, JSON) must never match."""
        assert not is_distribution_filename("sha256:abc123.json")
        assert not is_distribution_filename("data.json")
        assert not is_distribution_filename("README.md")
        assert not is_distribution_filename("foo-1.0-py3-none-any.whl.json")
