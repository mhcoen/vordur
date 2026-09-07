"""Part 8: Provenance tracking and no-copy enforcement.

Tracks the origin of content through the pipeline using ProvenancedSpan
objects. Prevents untrusted content from being copied into outbound
messages without explicit user authorization.
"""

from __future__ import annotations

from dataclasses import dataclass

from vordur.security.normalization import (
    MAX_OVERLAP_SCAN_CHARS,
    deobfuscate_reversed,
    deobfuscate_spelled,
    normalize_for_overlap,
    overlap_scan,
    overlap_windows,
)
from vordur.security.types import SensitivityLevel, TrustLevel

#: What one session retains for the no-copy check, as a span count and as
#: normalized characters. Every span is kept for the life of the session: an
#: eviction policy would let an attacker flush a sensitive span out of the
#: tracker by ingesting enough junk after it and then copy it out unchecked,
#: which is the bypass the tracker exists to prevent. Past these limits the
#: tracker refuses new content, and the pipeline reports the refusal as a
#: blocked ingest, so a session that hits them fails visibly rather than
#: quietly weakening. Every egress check scans everything retained, so the
#: character budget is what bounds check_outbound: measured at 0.36s per
#: check with 1,000,000 characters retained and 0.73s with 2,000,000, on
#: ordinary prose. The DLP buffers hold up to 2,500,000, so this is the same
#: order as what the session can already compare against.
MAX_PROVENANCE_SPANS = 10_000
MAX_PROVENANCE_CHARS = 2_000_000


class ProvenanceBudgetError(ValueError):
    """The session already retains as much provenance as it will hold."""


@dataclass
class ProvenancedSpan:
    """A span of text with provenance tracking.

    Carries the origin of content through the pipeline so that
    outbound DLP and no-copy enforcement can determine whether
    content came from an untrusted source.
    """

    text: str
    source_type: str  # "mcp_server", "mcp_client", "cli_user", "assistant"
    source_id: str  # Specific source identifier
    source_trust: TrustLevel = TrustLevel.UNTRUSTED
    sensitivity: SensitivityLevel = SensitivityLevel.PUBLIC
    topic_of_origin: str | None = None  # For cross-topic leak detection
    #: Authenticated identity of the principal who authored this span, or None.
    #:
    #: This is NOT source_id. source_id is a descriptive label -- source_gate
    #: documents it as possibly an email sender -- and nothing makes it unique
    #: across source types: an mcp_client and an unrelated mcp_server may both
    #: use "shared". Keying an exemption on it therefore exempts more than the
    #: caller named.
    #:
    #: principal_id is a separate field with one job, and the integrator must
    #: set it ONLY from an identity their transport actually authenticated (a
    #: verified session, API key, or token subject). Never populate it from
    #: content, from a client-supplied header, or by copying source_id.
    #:
    #: Defaults to None, and None is never exempt, so a span has to be
    #: deliberately attributed to an authenticated principal before
    #: check_outbound will skip it.
    principal_id: str | None = None


class ProvenanceTracker:
    """Tracks provenance spans and enforces no-copy policy.

    See spec Part 8 for full requirements:
    - Tag all content with source provenance
    - Block outbound content containing untrusted spans
    - Last-mile guard: mechanical overlap check
    - Exception for explicit quoting/forwarding directives
    """

    def __init__(self) -> None:
        self._spans: list[ProvenancedSpan] = []
        # Each span's normalized, windowed form, computed once at ingest.
        # check_outbound used to renormalize and rewindow every span on every
        # call, so each egress check cost the whole session's ingest history
        # over again: measured at 3.3 seconds per check after 1,600 documents.
        self._windows: list[tuple[str, ...]] = []
        self._chars = 0

    @property
    def retained_chars(self) -> int:
        """Normalized characters currently held against the session budget."""
        return self._chars

    def budget_refusal(self, text: str) -> str | None:
        """Why ``text`` cannot be retained, or ``None`` while it still fits."""
        return self._refusal(len(normalize_for_overlap(text)))

    def _refusal(self, size: int) -> str | None:
        if len(self._spans) >= MAX_PROVENANCE_SPANS:
            return (
                f"provenance tracker holds {len(self._spans)} spans, the most one session retains"
            )
        if self._chars + size > MAX_PROVENANCE_CHARS:
            return (
                f"provenance tracker would hold {self._chars + size} normalized characters, "
                f"beyond the {MAX_PROVENANCE_CHARS} one session retains"
            )
        return None

    def add_span(self, span: ProvenancedSpan) -> None:
        """Register a provenance span.

        Raises :class:`ProvenanceBudgetError` past the session budget. The
        pipeline asks :meth:`budget_refusal` first and withholds the content,
        so this is the backstop for a caller that did not.
        """
        normalized = normalize_for_overlap(span.text)
        refusal = self._refusal(len(normalized))
        if refusal is not None:
            raise ProvenanceBudgetError(refusal)
        self._spans.append(span)
        self._windows.append(tuple(w for w in overlap_windows(normalized) if w))
        self._chars += len(normalized)

    def check_outbound(
        self,
        content: str,
        has_quoting_directive: bool = False,
        *,
        lcs_threshold: int = 50,
        ngram_threshold: float = 0.30,
        contaminated: bool = False,
        egress_to_principal_id: str | None = None,
    ) -> tuple[bool, str]:
        """Check if outbound content violates no-copy policy.

        ``egress_to_principal_id`` is the authenticated identity of the
        principal this egress is addressed TO. Untrusted spans that principal
        authored are skipped, because no-copy protects untrusted content from
        reaching a THIRD party and returning a principal's own words to that
        principal is not exfiltration -- the recipient is the author.

        Without it, a gateway that marks the principal UNTRUSTED (so
        contamination arms the sensitive-leak check) blocks ordinary answers,
        because ordinary answers restate the question.

        The exemption is bound to :attr:`ProvenancedSpan.principal_id`, never
        to ``source_id``. source_id is a descriptive label that is not unique
        across source types, so keying on it would let an unrelated tool whose
        source_id collided with the principal's ride out of the session
        unchecked. A span is skipped only when it carries an authenticated
        principal_id equal to this one; spans with ``principal_id is None`` --
        which is every span the integrator did not deliberately attribute --
        are always checked. Empty strings never match on either side.

        Deliberately narrow: only the UNTRUSTED selection is filtered.
        Sensitive spans are always compared, so naming a recipient can never
        disarm leak detection.

        Returns (allowed, reason).
        """
        if has_quoting_directive:
            return (True, "quoting directive")

        def _is_own_span(span: ProvenancedSpan) -> bool:
            """True when `span` was authored by the principal being replied to.

            Requires a truthy identity on BOTH sides, so neither None nor ""
            can pair off into an accidental exemption.
            """
            return bool(
                egress_to_principal_id
                and span.principal_id
                and span.principal_id == egress_to_principal_id
            )

        # Select spans to check: always untrusted, plus sensitive when contaminated
        rows = list(zip(self._spans, self._windows, strict=True))
        check_spans: list[tuple[ProvenancedSpan, str, tuple[str, ...]]] = [
            (s, "untrusted", w)
            for s, w in rows
            if s.source_trust == TrustLevel.UNTRUSTED and not _is_own_span(s)
        ]
        if contaminated:
            check_spans.extend(
                (s, "sensitive", w) for s, w in rows if s.sensitivity == SensitivityLevel.SENSITIVE
            )

        if not check_spans:
            return (True, "clean")

        # Scans ALL of the content, in windows. This used to truncate to
        # MAX_OVERLAP_CHARS and compare only that prefix, which was a silent
        # bypass: a copied passage padded past the cap came back clean. Beyond
        # what we will scan, refuse rather than truncate.
        normalized_content = normalize_for_overlap(content)
        if len(normalized_content) > MAX_OVERLAP_SCAN_CHARS:
            return (
                False,
                f"content is {len(normalized_content)} normalized characters, beyond the "
                f"{MAX_OVERLAP_SCAN_CHARS} the provenance overlap check inspects",
            )

        # Build deobfuscated variants for overlap checks
        content_variants = [normalized_content]
        reversed_norm = normalize_for_overlap(deobfuscate_reversed(content))
        if reversed_norm != normalized_content:
            content_variants.append(reversed_norm)
        spelled_norm = normalize_for_overlap(deobfuscate_spelled(content))
        if spelled_norm != normalized_content:
            content_variants.append(spelled_norm)

        # Spans are windowed too, not truncated. A span longer than the window
        # was cut to it, so a passage copied out of the TAIL of a 60,000
        # character ingested document came back clean: the same bypass as the
        # outbound cap, in the other direction. Each window is compared
        # separately and reports its own span, so a match anywhere in a long
        # span is found and attributed correctly. The windows were built at
        # ingest, so this is a flatten, not a normalization pass.
        normalized_spans = [
            (span, label, window) for span, label, windows in check_spans for window in windows
        ]
        for variant in content_variants:
            deob = " (deobfuscated)" if variant is not normalized_content else ""
            # One windowed pass over the whole variant for every span. The
            # substring check is gated on a shared gram the length of the
            # threshold, which is exact: a common substring that long contains
            # such a gram, so no shared gram proves no blocking overlap.
            scanned = overlap_scan(
                variant, [row[2] for row in normalized_spans], lcs_gate=lcs_threshold
            )
            for (span, label, _text), (overlap, lcs_len) in zip(
                normalized_spans, scanned, strict=True
            ):
                if lcs_len >= lcs_threshold:
                    return (
                        False,
                        f"Verbatim overlap ({lcs_len} chars){deob} with {label} "
                        f"content from {span.source_type}:{span.source_id}",
                    )

                # N-gram overlap check: configurable (default >= 30%) is a block
                if overlap >= ngram_threshold:
                    return (
                        False,
                        f"N-gram overlap ({overlap:.0%}){deob} with {label} "
                        f"content from {span.source_type}:{span.source_id}",
                    )

        return (True, "clean")
