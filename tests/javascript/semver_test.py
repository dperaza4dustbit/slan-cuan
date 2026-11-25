"""Test npm semver range matching."""

from slan_cuan.javascript.semver import Version, max_satisfying, satisfies


class TestVersionParsing:
    """Test Version class parsing and comparison."""

    def test_version_parses_major_minor_patch(self):
        """Version parses MAJOR.MINOR.PATCH."""
        v = Version("1.2.3")
        assert v.major == 1
        assert v.minor == 2
        assert v.patch == 3
        assert v.prerelease is None

    def test_version_parses_with_v_prefix(self):
        """Version strips leading 'v' or 'V'."""
        v1 = Version("v1.2.3")
        v2 = Version("V1.2.3")
        assert v1.major == 1
        assert v2.major == 1

    def test_version_parses_prerelease_and_build(self):
        """Version parses prerelease and strips build metadata."""
        v = Version("1.2.3-alpha.1+build.123")
        assert v.major == 1
        assert v.minor == 2
        assert v.patch == 3
        assert v.prerelease == ("alpha", "1")

    def test_version_prerelease_only_no_build(self):
        """Version parses prerelease without build."""
        v = Version("1.2.3-beta")
        assert v.prerelease == ("beta",)

    def test_version_build_metadata_stripped(self):
        """Version strips build metadata."""
        v1 = Version("1.2.3+build.123")
        v2 = Version("1.2.3")
        assert v1 == v2

    def test_version_ordering_with_prerelease(self):
        """1.0.0-alpha < 1.0.0 (prerelease < release)."""
        alpha = Version("1.0.0-alpha")
        release = Version("1.0.0")
        assert alpha < release
        assert release > alpha
        assert not (alpha > release)
        assert not (release < alpha)

    def test_version_prerelease_numeric_vs_string(self):
        """Numeric prerelease identifiers compare numerically."""
        v1 = Version("1.0.0-1")
        v2 = Version("1.0.0-9")
        assert v1 < v2
        v3 = Version("1.0.0-alpha")
        v4 = Version("1.0.0-9")
        # Numeric < non-numeric per npm spec
        assert v4 < v3

    def test_version_equality(self):
        """Versions are equal if MAJOR.MINOR.PATCH and prerelease match."""
        assert Version("1.2.3") == Version("1.2.3")
        assert Version("1.2.3-alpha") == Version("1.2.3-alpha")
        assert Version("1.2.3") != Version("1.2.4")
        assert Version("1.2.3-alpha") != Version("1.2.3")

    def test_version_comparison_operators(self):
        """Version supports __le__, __ge__."""
        v1 = Version("1.0.0")
        v2 = Version("1.0.0")
        v3 = Version("1.0.1")
        assert v1 <= v2
        assert v1 >= v2
        assert v1 <= v3
        assert v3 >= v1


class TestSatisfies:
    """Test satisfies() function for version range matching."""

    def test_satisfies_exact_version(self):
        """satisfies("1.2.3", "1.2.3") is True."""
        assert satisfies("1.2.3", "1.2.3") is True
        assert satisfies("1.2.4", "1.2.3") is False

    def test_satisfies_wildcard_spec(self):
        """satisfies("1.2.3", "*") is True, but excludes prerelease."""
        assert satisfies("1.2.3", "*") is True
        assert satisfies("1.2.3-alpha", "*") is False
        assert satisfies("1.2.3", "") is True

    def test_satisfies_caret_range(self):
        """Satisfies uses caret ^ range: compatible with minor/patch."""
        # ^1.2.0 allows 1.2.3 (patch bump), not 2.0.0 (major bump)
        assert satisfies("1.2.3", "^1.2.0") is True
        assert satisfies("1.5.0", "^1.2.0") is True
        assert satisfies("2.0.0", "^1.2.0") is False
        # ^0.2.0 allows 0.2.3 (patch bump), not 0.3.0 (minor bump when major=0)
        assert satisfies("0.2.3", "^0.2.0") is True
        assert satisfies("0.3.0", "^0.2.0") is False
        # ^0.0.3 allows only 0.0.3 (when major=0, minor=0, only exact patch)
        assert satisfies("0.0.3", "^0.0.3") is True
        assert satisfies("0.0.4", "^0.0.3") is False

    def test_satisfies_tilde_range(self):
        """Satisfies uses tilde ~: allows patch bump when minor specified."""
        # ~1.2.0 allows 1.2.9 (patch bump), not 1.3.0 (minor bump)
        assert satisfies("1.2.9", "~1.2.0") is True
        assert satisfies("1.3.0", "~1.2.0") is False
        # ~1 allows any 1.x.x
        assert satisfies("1.5.0", "~1") is True
        assert satisfies("2.0.0", "~1") is False

    def test_satisfies_comparator_range(self):
        """Satisfies uses comparators: >=, <=, >, <."""
        # >=1.0.0 <2.0.0 (range)
        assert satisfies("1.5.0", ">=1.0.0 <2.0.0") is True
        assert satisfies("0.9.0", ">=1.0.0 <2.0.0") is False
        assert satisfies("2.0.0", ">=1.0.0 <2.0.0") is False
        # Hyphen range (syntactic sugar for >= and <=)
        assert satisfies("1.5.0", "1.0.0 - 1.9.0") is True
        assert satisfies("2.0.0", "1.0.0 - 1.9.0") is False

    def test_satisfies_or_clause(self):
        """Satisfies supports || (or) between clauses."""
        # ^0.4 || ^0.5
        assert satisfies("0.4.5", "^0.4.0 || ^0.5.0") is True
        assert satisfies("0.5.1", "^0.4.0 || ^0.5.0") is True
        assert satisfies("0.6.0", "^0.4.0 || ^0.5.0") is False

    def test_satisfies_prerelease_excluded_by_default(self):
        """Prerelease versions excluded unless spec also uses prerelease."""
        # 1.2.3-alpha doesn't match 1.2.3 (no prerelease in spec)
        assert satisfies("1.2.3-alpha", "1.2.3") is False
        # But does match if spec has prerelease
        assert satisfies("1.2.3-alpha", "1.2.3-alpha") is True
        # And matches ranges that have a prerelease in the spec
        assert satisfies("1.2.3-beta", ">=1.2.3-alpha") is True

    def test_satisfies_prerelease_allowed_when_matching_bound_has_one(self):
        """A prerelease is allowed when the MATCHING bound has one.

        >=1.2.3-0 <1.2.4: the lower bound shares (1, 2, 3) with the
        tested version and carries a prerelease tag, so 1.2.3-alpha.1
        is allowed through.
        """
        assert satisfies("1.2.3-alpha.1", ">=1.2.3-0 <1.2.4") is True

    def test_satisfies_prerelease_or_clause_matching_branch_allows(self):
        """A prerelease satisfies an OR-range via whichever branch allows it.

        ``^2.0.0`` doesn't share (1, 2, 3) with the tested version, so it
        can't allow the prerelease through; but the second branch's lower
        bound does share that tuple and carries a prerelease tag.
        """
        assert satisfies("1.2.3-alpha.1", "^2.0.0 || >=1.2.3-0 <1.2.4") is True

    def test_satisfies_prerelease_or_clause_no_branch_allows(self):
        """A prerelease is excluded when NO OR-branch's bound allows it.

        Here the second branch's lower bound shares (1, 2, 3) with the
        tested version but has no prerelease tag of its own, so neither
        branch allows the prerelease through.
        """
        assert satisfies("1.2.3-alpha.1", "^2.0.0 || >=1.2.3 <1.2.4") is False

    def test_satisfies_prerelease_hyphen_range_boundary_allows(self):
        """A prerelease at a hyphen-range boundary that itself allows it.

        ``1.2.3-0 - 2.0.0`` expands to ``>=1.2.3-0 <=2.0.0``; the lower
        bound shares (1, 2, 3) with the tested version and carries a
        prerelease tag, so 1.2.3-alpha.1 is allowed through.
        """
        assert satisfies("1.2.3-alpha.1", "1.2.3-0 - 2.0.0") is True

    def test_satisfies_prerelease_hyphen_range_boundary_excludes(self):
        """A hyphen-range boundary without a prerelease tag excludes it.

        ``1.2.3 - 2.0.0`` shares (1, 2, 3) with the tested version but the
        bound itself has no prerelease tag, so 1.2.3-alpha.1 is excluded.
        """
        assert satisfies("1.2.3-alpha.1", "1.2.3 - 2.0.0") is False

    def test_satisfies_invalid_version_returns_false(self):
        """Satisfies returns False for invalid version strings."""
        assert satisfies("not-a-version", "1.2.3") is False
        assert satisfies("1.2.x", "1.2.3") is False

    def test_satisfies_invalid_spec_returns_false(self):
        """Satisfies returns False for invalid spec strings."""
        assert satisfies("1.2.3", "not-a-spec!!") is False


class TestMaxSatisfying:
    """Test max_satisfying() function."""

    def test_max_satisfying_returns_highest_matching(self):
        """max_satisfying returns the highest version that satisfies spec."""
        versions = ["0.1.0", "1.0.0", "1.2.0", "1.2.3", "2.0.0"]
        # ^1.2.0 matches 1.2.0 and 1.2.3, highest is 1.2.3
        result = max_satisfying(versions, "^1.2.0")
        assert result == "1.2.3"

    def test_max_satisfying_returns_none_when_no_match(self):
        """max_satisfying returns None when no version satisfies spec."""
        versions = ["0.1.0", "0.2.0"]
        result = max_satisfying(versions, "^1.0.0")
        assert result is None

    def test_max_satisfying_excludes_prerelease_by_default(self):
        """max_satisfying excludes prerelease versions by default."""
        versions = ["1.0.0-alpha", "1.0.0-beta", "1.0.1"]
        result = max_satisfying(versions, ">=1.0.0")
        assert result == "1.0.1"

    def test_max_satisfying_includes_prerelease_if_spec_has_one(self):
        """max_satisfying includes prerelease if spec specifies one."""
        versions = ["1.0.0-alpha", "1.0.0-beta", "1.0.1"]
        result = max_satisfying(versions, ">=1.0.0-alpha")
        assert result == "1.0.1"

    def test_max_satisfying_with_multiple_specs(self):
        """max_satisfying works with || (or) in spec."""
        versions = ["0.5.0", "0.6.0", "1.0.0", "1.1.0", "2.0.0"]
        # ^0.5.0 allows [0.5.0, 0.6.0), ^1.0.0 allows [1.0.0, 2.0.0)
        result = max_satisfying(versions, "^0.5.0 || ^1.0.0")
        assert result == "1.1.0"

    def test_max_satisfying_ignores_invalid_versions(self):
        """max_satisfying ignores versions it can't parse."""
        versions = ["1.0.0", "not-a-version", "1.2.3", "also-bad"]
        result = max_satisfying(versions, "^1.0.0")
        assert result == "1.2.3"

    def test_max_satisfying_empty_list(self):
        """max_satisfying returns None for empty input."""
        result = max_satisfying([], "^1.0.0")
        assert result is None
