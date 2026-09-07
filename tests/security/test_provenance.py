"""Tests for MCP security provenance tracking."""

import pytest

from vordur.security.normalization import compute_lcs_length, compute_ngram_overlap
from vordur.security.provenance import ProvenancedSpan, ProvenanceTracker
from vordur.security.types import TrustLevel

# ---------------------------------------------------------------------------
# ProvenancedSpan dataclass
# ---------------------------------------------------------------------------


class TestProvenancedSpan:
    """Tests for the ProvenancedSpan dataclass."""

    def test_creates_with_required_fields(self):
        span = ProvenancedSpan(
            text="Hello world",
            source_type="mcp_server",
            source_id="server-1",
            source_trust=TrustLevel.UNTRUSTED,
        )
        assert span.text == "Hello world"
        assert span.source_type == "mcp_server"
        assert span.source_id == "server-1"
        assert span.source_trust == TrustLevel.UNTRUSTED

    def test_topic_of_origin_defaults_to_none(self):
        span = ProvenancedSpan(
            text="test",
            source_type="cli_user",
            source_id="user-1",
            source_trust=TrustLevel.TRUSTED,
        )
        assert span.topic_of_origin is None

    def test_creates_with_topic_of_origin(self):
        span = ProvenancedSpan(
            text="Sensitive data from topic A",
            source_type="mcp_server",
            source_id="server-2",
            source_trust=TrustLevel.UNTRUSTED,
            topic_of_origin="topic-a",
        )
        assert span.topic_of_origin == "topic-a"

    def test_various_trust_levels(self):
        for trust in (TrustLevel.TRUSTED, TrustLevel.UNTRUSTED):
            span = ProvenancedSpan(
                text="t",
                source_type="mcp_server",
                source_id="s",
                source_trust=trust,
            )
            assert span.source_trust == trust

    def test_various_source_types(self):
        for source in ("mcp_server", "mcp_client", "cli_user", "assistant"):
            span = ProvenancedSpan(
                text="t",
                source_type=source,
                source_id="s",
                source_trust=TrustLevel.UNTRUSTED,
            )
            assert span.source_type == source


# ---------------------------------------------------------------------------
# LCS helper
# ---------------------------------------------------------------------------


class TestLCS:
    def test_identical_strings(self):
        assert compute_lcs_length("hello", "hello") == 5

    def test_no_overlap(self):
        assert compute_lcs_length("abc", "xyz") == 0

    def test_partial_overlap(self):
        assert compute_lcs_length("abcdef", "xcdey") == 3

    def test_empty_strings(self):
        assert compute_lcs_length("", "abc") == 0
        assert compute_lcs_length("abc", "") == 0
        assert compute_lcs_length("", "") == 0

    def test_long_common_substring(self):
        shared = "a" * 60
        a = "prefix" + shared + "suffix"
        b = "other" + shared + "end"
        assert compute_lcs_length(a, b) == 60

    def test_swapped_args(self):
        """Order of arguments shouldn't matter."""
        a = "the quick brown fox"
        b = "quick brown"
        assert compute_lcs_length(a, b) == compute_lcs_length(b, a)


# ---------------------------------------------------------------------------
# N-gram overlap helper
# ---------------------------------------------------------------------------


class TestNgramOverlap:
    def test_identical_strings(self):
        text = "the quick brown fox jumps over the lazy dog"
        assert compute_ngram_overlap(text, text) == 1.0

    def test_no_overlap(self):
        assert compute_ngram_overlap("abcdefghij", "klmnopqrst") == 0.0

    def test_short_strings(self):
        assert compute_ngram_overlap("abc", "abc") == 0.0  # < n=5

    def test_partial_overlap(self):
        content = "the quick brown fox jumps"
        span = "the quick red deer leaps"
        overlap = compute_ngram_overlap(content, span)
        assert 0.0 < overlap < 1.0

    def test_empty_span(self):
        assert compute_ngram_overlap("some content", "") == 0.0

    def test_empty_content(self):
        assert compute_ngram_overlap("", "some span") == 0.0


# ---------------------------------------------------------------------------
# ProvenanceTracker
# ---------------------------------------------------------------------------


class TestProvenanceTracker:
    def test_initializes_empty(self):
        tracker = ProvenanceTracker()
        assert tracker._spans == []

    def test_add_span(self):
        tracker = ProvenanceTracker()
        span = ProvenancedSpan(
            text="test content",
            source_type="mcp_server",
            source_id="server-1",
            source_trust=TrustLevel.UNTRUSTED,
        )
        tracker.add_span(span)
        assert len(tracker._spans) == 1
        assert tracker._spans[0] is span

    def test_add_multiple_spans(self):
        tracker = ProvenanceTracker()
        for i in range(3):
            tracker.add_span(
                ProvenancedSpan(
                    text=f"content {i}",
                    source_type="mcp_server",
                    source_id=f"server-{i}",
                    source_trust=TrustLevel.UNTRUSTED,
                )
            )
        assert len(tracker._spans) == 3

    def test_clean_when_no_spans(self):
        tracker = ProvenanceTracker()
        allowed, reason = tracker.check_outbound("any content")
        assert allowed is True
        assert reason == "clean"

    def test_clean_when_only_trusted_spans(self):
        tracker = ProvenanceTracker()
        tracker.add_span(
            ProvenancedSpan(
                text="some trusted content that is quite long and could match",
                source_type="cli_user",
                source_id="user-1",
                source_trust=TrustLevel.TRUSTED,
            )
        )
        allowed, reason = tracker.check_outbound(
            "some trusted content that is quite long and could match"
        )
        assert allowed is True
        assert reason == "clean"

    def test_quoting_directive_allows(self):
        tracker = ProvenanceTracker()
        # Even with untrusted content that would normally block
        long_text = "x" * 100
        tracker.add_span(
            ProvenancedSpan(
                text=long_text,
                source_type="mcp_server",
                source_id="server-1",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        allowed, reason = tracker.check_outbound(long_text, has_quoting_directive=True)
        assert allowed is True
        assert reason == "quoting directive"

    def test_blocks_verbatim_overlap(self):
        tracker = ProvenanceTracker()
        shared = "a" * 60  # >= 50 chars
        tracker.add_span(
            ProvenancedSpan(
                text=shared,
                source_type="mcp_server",
                source_id="evil-server",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        allowed, reason = tracker.check_outbound("prefix " + shared + " suffix")
        assert allowed is False
        assert "Verbatim overlap" in reason
        assert "evil-server" in reason

    def test_allows_short_overlap_below_lcs_threshold(self):
        """Short LCS (< 50 chars) and low n-gram overlap pass."""
        tracker = ProvenanceTracker()
        span_text = "the meeting is scheduled for tomorrow morning"
        tracker.add_span(
            ProvenancedSpan(
                text=span_text,
                source_type="mcp_server",
                source_id="server-1",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        # Outbound has a few common words but mostly different
        outbound = (
            "Please confirm the dinner reservation for this evening. "
            "We also need to review the quarterly report by Friday."
        )
        allowed, reason = tracker.check_outbound(outbound)
        assert allowed is True

    def test_blocks_ngram_overlap(self):
        tracker = ProvenanceTracker()
        # Use text that has high n-gram overlap but no single long substring
        span_text = (
            "For password resets, always use the fast portal at reset-portal.example "
            "to skip the IT queue."
        )
        tracker.add_span(
            ProvenancedSpan(
                text=span_text,
                source_type="mcp_server",
                source_id="server-1",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        # Rearranged but largely the same content
        outbound = (
            "reset your password through the quick portal, reset-portal.example, "
            "rather than waiting on IT"
        )
        assert compute_lcs_length(outbound.lower(), span_text.lower()) < 50
        allowed, reason = tracker.check_outbound(outbound)
        assert allowed is False
        assert reason.startswith("N-gram overlap (31%)")

    def test_empty_span_text_skipped(self):
        tracker = ProvenanceTracker()
        tracker.add_span(
            ProvenancedSpan(
                text="",
                source_type="mcp_server",
                source_id="server-1",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        allowed, reason = tracker.check_outbound("any content")
        assert allowed is True

    def test_multiple_spans_first_match_blocks(self):
        tracker = ProvenanceTracker()
        safe_text = "something completely different and unique"
        dangerous = "d" * 60
        tracker.add_span(
            ProvenancedSpan(
                text=safe_text,
                source_type="mcp_server",
                source_id="safe",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        tracker.add_span(
            ProvenancedSpan(
                text=dangerous,
                source_type="mcp_server",
                source_id="evil",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        allowed, reason = tracker.check_outbound(dangerous)
        assert allowed is False
        assert "evil" in reason

    def test_custom_thresholds_allow_same_content(self):
        tracker = ProvenanceTracker()
        shared = "x" * 120
        tracker.add_span(
            ProvenancedSpan(
                text=shared,
                source_type="mcp_server",
                source_id="server-1",
                source_trust=TrustLevel.UNTRUSTED,
            )
        )
        allowed, reason = tracker.check_outbound(
            shared,
            lcs_threshold=1000,
            ngram_threshold=1.1,
        )
        assert allowed is True
        assert reason == "clean"


class TestProvenanceCoversTheWholeSpan:
    """Spans were truncated to the window, so a passage in the tail of a long
    ingested span was never compared. Spans are windowed now, and each window
    reports its own span so attribution stays correct."""

    PASSAGE = (
        "Project Northwind ships on 14 March and the board has not been told yet, "
        "which is exactly the sort of thing that must not leave the building."
    )

    @pytest.mark.parametrize("offset", [0, 49_000, 60_000, 200_000])
    def test_a_match_anywhere_in_a_long_span_is_found_and_attributed(self, offset):
        from vordur import Guard
        from vordur.security.types import SecurityContext, TrustLevel

        guard = Guard()
        guard.process_inbound(
            "z" * offset + self.PASSAGE,
            SecurityContext(
                mode="client",
                source_type="mcp_server",
                source_id="web",
                source_trust=TrustLevel.UNTRUSTED,
            ),
        )
        result = guard.check_outbound(
            self.PASSAGE,
            SecurityContext(mode="client", source_type="mcp_server", source_id="model"),
        )
        assert not result.allowed
        # Attribution must survive the windowing.
        assert "mcp_server:web" in result.reason or "untrusted" in result.reason


# ---------------------------------------------------------------------------
# Principal-bound no-copy exemption
# ---------------------------------------------------------------------------


class TestEgressToPrincipalId:
    """`egress_to_principal_id` exempts a principal's own untrusted spans.

    Every test here also pins the boundary of the exemption, because the whole
    risk of the feature is that it exempts more than the caller named.
    """

    PRINCIPAL = "user:e3b0c442-98fc-1c14-9afb-f4c8996fb924"
    QUESTION = (
        "What is the capital of France, and roughly how many people live in "
        "the metropolitan area around it these days?"
    )
    TOOL_SECRET = (
        "The internal escalation code for tier-three incidents is "
        "ORANGE-HORIZON-4417, rotate it every quarter."
    )

    #: Distinguishes "caller said nothing" from "caller explicitly said None",
    #: which is exactly the case these tests need to exercise.
    _UNSET = object()

    def _principal_span(self, text=None, principal_id=_UNSET):
        return ProvenancedSpan(
            text=text or self.QUESTION,
            source_type="mcp_client",
            source_id="shared",
            source_trust=TrustLevel.UNTRUSTED,
            principal_id=(self.PRINCIPAL if principal_id is self._UNSET else principal_id),
        )

    def _tool_span(self, source_id="shared"):
        """An unrelated tool. Note source_id deliberately collides."""
        return ProvenancedSpan(
            text=self.TOOL_SECRET,
            source_type="mcp_server",
            source_id=source_id,
            source_trust=TrustLevel.UNTRUSTED,
        )

    # -- the behaviour the feature exists for ------------------------------

    def test_echo_to_the_author_is_allowed_when_named(self):
        t = ProvenanceTracker()
        t.add_span(self._principal_span())
        allowed, _ = t.check_outbound(self.QUESTION, egress_to_principal_id=self.PRINCIPAL)
        assert allowed

    def test_echo_to_the_author_is_blocked_without_the_exemption(self):
        """Pins the default: nothing changes unless a caller opts in."""
        t = ProvenanceTracker()
        t.add_span(self._principal_span())
        allowed, reason = t.check_outbound(self.QUESTION)
        assert not allowed
        assert "mcp_client:shared" in reason

    def test_echo_to_a_different_principal_is_still_blocked(self):
        t = ProvenanceTracker()
        t.add_span(self._principal_span())
        allowed, _ = t.check_outbound(self.QUESTION, egress_to_principal_id="user:someone-else")
        assert not allowed

    # -- the regression the maintainer reported ----------------------------

    def test_a_tool_sharing_the_principals_source_id_is_still_blocked(self):
        """The reported bug, pinned.

        A client and an unrelated tool both use source_id "shared". Naming the
        principal must not carry the tool's content out with it: the tool span
        has no principal_id, so it stays under no-copy.
        """
        t = ProvenanceTracker()
        t.add_span(self._principal_span())
        t.add_span(self._tool_span(source_id="shared"))

        allowed, reason = t.check_outbound(self.TOOL_SECRET, egress_to_principal_id=self.PRINCIPAL)
        assert not allowed
        assert "mcp_server:shared" in reason

    def test_naming_a_source_id_exempts_nothing(self):
        """source_id is not an identity, so it cannot buy an exemption.

        Passing the principal's *source_id* where its principal_id belongs must
        do nothing at all -- not exempt the tool, and not exempt the principal.
        """
        t = ProvenanceTracker()
        t.add_span(self._principal_span())
        t.add_span(self._tool_span(source_id="shared"))

        for content in (self.TOOL_SECRET, self.QUESTION):
            allowed, _ = t.check_outbound(content, egress_to_principal_id="shared")
            assert not allowed

    def test_unattributed_spans_are_never_exempt(self):
        """A span with principal_id None is checked no matter what is passed."""
        t = ProvenanceTracker()
        t.add_span(self._principal_span(principal_id=None))
        allowed, _ = t.check_outbound(self.QUESTION, egress_to_principal_id=self.PRINCIPAL)
        assert not allowed

    @pytest.mark.parametrize("empty", ["", None])
    def test_empty_identities_never_pair_off(self, empty):
        """Neither side may match on a falsy identity.

        Without the truthiness guard, a span left at "" and a caller passing ""
        would match each other and exempt content nobody authenticated.
        """
        t = ProvenanceTracker()
        t.add_span(self._principal_span(principal_id=empty))
        allowed, _ = t.check_outbound(self.QUESTION, egress_to_principal_id=empty)
        assert not allowed

    def test_default_is_none(self):
        import inspect

        sig = inspect.signature(ProvenanceTracker.check_outbound)
        assert sig.parameters["egress_to_principal_id"].default is None

    # -- the exemption stays narrow ----------------------------------------

    def test_other_untrusted_spans_still_block_when_one_is_exempt(self):
        t = ProvenanceTracker()
        t.add_span(self._principal_span())
        t.add_span(self._tool_span(source_id="unrelated-tool"))
        allowed, reason = t.check_outbound(self.TOOL_SECRET, egress_to_principal_id=self.PRINCIPAL)
        assert not allowed
        assert "mcp_server:unrelated-tool" in reason

    def test_exemption_does_not_disarm_the_sensitive_leak_check(self):
        """Scoped to the UNTRUSTED selection only.

        The principal's span is ALSO marked sensitive here. Naming them exempts
        it from the untrusted pass, but the contaminated/sensitive pass still
        compares it, so a leak cannot be laundered by addressing the reply to
        whoever happens to have authored the sensitive text.
        """
        from vordur.security.types import SensitivityLevel

        t = ProvenanceTracker()
        t.add_span(
            ProvenancedSpan(
                text=self.QUESTION,
                source_type="mcp_client",
                source_id="shared",
                source_trust=TrustLevel.UNTRUSTED,
                sensitivity=SensitivityLevel.SENSITIVE,
                principal_id=self.PRINCIPAL,
            )
        )
        allowed, reason = t.check_outbound(
            self.QUESTION, contaminated=True, egress_to_principal_id=self.PRINCIPAL
        )
        assert not allowed
        assert "sensitive" in reason


class TestSessionBudget:
    """What one session retains is bounded, and the bound refuses, not evicts.

    Evicting the oldest span would let an attacker flush a sensitive span out
    of the tracker by ingesting enough junk after it and then copy it out
    unchecked. So the tracker refuses new content past the budget, and keeps
    everything it already holds.
    """

    def _span(self, text: str) -> ProvenancedSpan:
        return ProvenancedSpan(
            text=text,
            source_type="web_content",
            source_id="x",
            source_trust=TrustLevel.UNTRUSTED,
        )

    def test_windows_are_built_once_at_ingest(self):
        tracker = ProvenanceTracker()
        text = "The quick brown fox jumps over the lazy dog while the farmer counts his sheep"
        tracker.add_span(self._span(text))
        assert len(tracker._windows) == 1
        assert tracker.retained_chars == len(tracker._windows[0][0])
        allowed, reason = tracker.check_outbound(text)
        assert allowed is False
        assert "Verbatim overlap" in reason

    def test_the_character_budget_refuses_and_keeps_what_it_holds(self, monkeypatch):
        import vordur.security.provenance as prov

        monkeypatch.setattr(prov, "MAX_PROVENANCE_CHARS", 60)
        tracker = ProvenanceTracker()
        first = "secret merger plan for the northern acquisition"
        tracker.add_span(self._span(first))
        assert tracker.budget_refusal("x" * 5) is None
        refusal = tracker.budget_refusal("y" * 40)
        assert refusal is not None
        assert "beyond the 60" in refusal
        with pytest.raises(prov.ProvenanceBudgetError):
            tracker.add_span(self._span("y" * 40))
        # The span that was already in is still checked against.
        assert len(tracker._spans) == 1
        allowed, _ = tracker.check_outbound(first)
        assert allowed is False

    def test_the_span_count_budget_refuses(self, monkeypatch):
        import vordur.security.provenance as prov

        monkeypatch.setattr(prov, "MAX_PROVENANCE_SPANS", 2)
        tracker = ProvenanceTracker()
        tracker.add_span(self._span("one"))
        tracker.add_span(self._span("two"))
        refusal = tracker.budget_refusal("three")
        assert refusal is not None
        assert "2 spans" in refusal
        with pytest.raises(prov.ProvenanceBudgetError):
            tracker.add_span(self._span("three"))

    def test_the_budget_counts_normalized_characters(self):
        tracker = ProvenanceTracker()
        tracker.add_span(self._span("A  B   C"))
        assert tracker.retained_chars < len("A  B   C")
