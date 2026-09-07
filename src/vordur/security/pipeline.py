"""§12.1: Unified security pipeline.

Orchestrates all security layers for both client and server mode.
Parameterized by SecurityContext rather than branching on direction.
"""

from __future__ import annotations

from dataclasses import replace

from vordur.security.canary import detect_canary, generate_canary
from vordur.security.isolation import wrap_untrusted
from vordur.security.normalization import normalize_confusables
from vordur.security.outbound_dlp import OutboundDLP
from vordur.security.policy_engine import PolicyEngine
from vordur.security.privacy_vault import PrivacyVault
from vordur.security.prompt_injection_detector import detect_prompt_injection
from vordur.security.provenance import ProvenancedSpan, ProvenanceTracker
from vordur.security.rate_limiter import RateLimiter
from vordur.security.request_binding import verify_binding
from vordur.security.sanitizer import sanitize
from vordur.security.source_gate import (
    SourceGateResult,
    check_extraction_allowed,
)
from vordur.security.types import (
    AuthorizationEvent,
    Binding,
    GateResult,
    OutboundResult,
    PrivacyConfig,
    ProcessedContent,
    RateLimitResult,
    SecurityContext,
    SensitivityLevel,
    TrustLevel,
)
from vordur.security.vault_store import VaultStore

# Tool-gating policy strictness ranking. When multiple session-risk signals
# fire (contamination, egress escalation), the strictest policy wins.
_POLICY_RANK = {"allow": 0, "require_auth": 1, "deny": 2}

#: The most content one process_inbound call inspects. Beyond it the call
#: refuses rather than truncating, for the same reason the provenance overlap
#: check does: a limit that trims silently is a bypass, since whatever was
#: trimmed was never examined but is still handed to the model. Matches
#: MAX_OVERLAP_SCAN_CHARS, so content that gets in can also be checked on the
#: way out. Every scan on this path is linear in the input, so the bound is a
#: budget, not a workaround for anything superlinear.
MAX_INBOUND_CHARS = 1_000_000


class SecurityPipeline:
    """Unified security pipeline for client and server mode.

    Entry points:
    - process_inbound: Content arriving from any source
    - check_outbound: Content leaving the system
    - check_tool_execution: Policy check before tool execution
    """

    def __init__(
        self,
        audit_logger: object | None = None,
        canary_session_id: str | None = None,
        principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
        privacy: PrivacyConfig | None = None,
        vault_store: VaultStore | None = None,
    ) -> None:
        self._sanitizer = sanitize
        self._provenance = ProvenanceTracker()
        self._dlp = OutboundDLP()
        self._policy = PolicyEngine()
        self._rate_limiter = RateLimiter()
        self._audit_logger = audit_logger
        self._principal_trust = principal_trust
        self._context_contaminated: bool = False
        self._session_escalated: bool = False
        self._privacy = privacy
        self._vault = PrivacyVault(privacy, store=vault_store) if privacy is not None else None
        self._canary_session_id: str | None = canary_session_id
        self._canary: str | None = None
        if canary_session_id:
            self._canary = generate_canary(canary_session_id)

    @property
    def principal_trust(self) -> TrustLevel:
        """Session-level principal trust, immutable after construction."""
        return self._principal_trust

    @property
    def context_contaminated(self) -> bool:
        """True once untrusted content has entered this session."""
        return self._context_contaminated

    @property
    def session_escalated(self) -> bool:
        """True after a high-confidence exfiltration block in this session."""
        return self._session_escalated

    def carry_session_risk(self, *, contaminated: bool = False, escalated: bool = False) -> None:
        """Re-raise session-risk flags on a rebuilt pipeline. Never lowers them.

        For a host that must reconstruct a session whose object it no longer
        holds, which for the gateway means one the LRU or the TTL evicted.
        Contamination and escalation only ever tighten policy, so losing them
        is not the harmless "rebuild is stricter" that eviction was assumed to
        be: it is the one direction that loosens.

        Deliberately monotonic. A setter that could also clear these would be a
        way to launder a contaminated session back to clean, which is the bug
        this exists to close rather than a feature to offer.

        Only the flags travel. The DLP buffers and provenance spans are not
        reconstructible from two booleans, so overlap detection against content
        ingested before the eviction does not come back; the tool gate, which
        is what the flags drive, does.
        """
        if contaminated:
            self._context_contaminated = True
        if escalated:
            self._session_escalated = True

    @property
    def canary_token(self) -> str | None:
        """Return the canary trusted host code must place in private context."""
        return self._canary

    @property
    def vault(self) -> PrivacyVault | None:
        """L13 vault, or None when privacy is not configured."""
        return self._vault

    def _vault_applies(self, ctx: SecurityContext) -> bool:
        if self._vault is None:
            return False
        if ctx.source_trust == TrustLevel.UNTRUSTED:
            return True
        return (
            ctx.sensitivity == SensitivityLevel.SENSITIVE
            and self._vault.config.deidentify_sensitive_ingest
        )

    def reset(self, *, canary_session_id: str | None = None) -> None:
        """Reset transient pipeline state, optionally rotating the canary.

        With no ``canary_session_id``, the current logical session and canary
        are retained. Passing a new ID rotates an already-enabled canary while
        clearing session risk. Canary protection cannot be enabled through
        reset on a pipeline constructed without it.
        """
        if canary_session_id is not None:
            if not canary_session_id:
                raise ValueError("canary_session_id must be non-empty")
            if self._canary_session_id is None:
                raise ValueError(
                    "Cannot enable canary protection through reset; construct a new pipeline"
                )
            self._canary_session_id = canary_session_id
            self._canary = generate_canary(canary_session_id)
        self._context_contaminated = False
        self._session_escalated = False
        self._provenance = ProvenanceTracker()
        self._dlp = OutboundDLP()
        self._rate_limiter = RateLimiter()
        if self._vault is not None:
            # Clearing invalidates every token still live in the host's
            # transcript. A replayed earlier turn will resolve to nothing.
            self._vault.clear()

    def process_inbound(
        self,
        content: str,
        ctx: SecurityContext,
    ) -> ProcessedContent:
        """Process content arriving from any source.

        Runs: confusable normalization -> injection signal -> L0 sanitize ->
        L1 isolate -> DLP ingest -> provenance -> remembered-canary check.

        Client mode: MCP server response content.
        Server mode: MCP client argument content.
        """
        if ctx.principal_trust != self._principal_trust:
            raise ValueError(
                f"principal_trust mismatch: context has {ctx.principal_trust}, "
                f"pipeline was constructed with {self._principal_trust}"
            )
        warnings: list[str] = []

        # Bounds, checked before anything is recorded. A refusal here changes
        # no session state: nothing was ingested, so nothing is remembered,
        # and the host sees ``blocked=True`` with the content withheld, the
        # same shape a failed de-identification takes below.
        refusal: str | None = None
        if len(content) > MAX_INBOUND_CHARS:
            refusal = (
                f"content is {len(content)} characters, beyond the "
                f"{MAX_INBOUND_CHARS} the inbound pipeline inspects"
            )
        else:
            refusal = self._provenance.budget_refusal(content)
        if refusal is not None:
            return ProcessedContent(
                content="[inbound refused: content withheld]",
                source_type=ctx.source_type,
                source_id=ctx.source_id,
                warnings=[f"Inbound refused: {refusal}"],
                blocked=True,
            )

        # TR39 confusable normalization at inbound trust boundary.
        # Maps homoglyph characters to ASCII before any security check.
        content = normalize_confusables(content)

        # Early prompt-injection signal pass on raw input.
        detection = detect_prompt_injection(content, ctx.content_type)
        warnings.extend(detection.warnings)

        # L0: Sanitize
        san_result = self._sanitizer(content, ctx.content_type)
        cleaned = san_result.cleaned_text
        warnings.extend(san_result.warnings)

        # L13a: ingress token scrub. Token SHAPE is audited only: an attacker
        # can type "[[GL:...]]" without knowing an issued value, and so can a
        # benign page, since this project's own docs carry example tokens.
        # Escalating on shape would let A1 degrade every later tool call for
        # free. An exact match to a live issued token cannot be guessed, so it
        # means a token from this session's prompt came back from an untrusted
        # source, and that is evidence.
        if self._vault is not None and ctx.source_trust == TrustLevel.UNTRUSTED:
            cleaned, shaped, issued = self._vault.scrub_tokens(cleaned)
            if shaped:
                warnings.append(f"Stripped {shaped} token-shaped span(s) from untrusted content")
            if issued:
                warnings.append("Live issued privacy token present in untrusted content")
                self._session_escalated = True

        # L13b: substitute identifiers. Applied to `cleaned` only. `content`
        # stays plaintext because DLP and provenance need the values
        # themselves: their function is recognizing a specific string
        # reappearing at egress, and a tokenized copy holds nothing worth
        # remembering.
        pii_findings: list = []
        blocked = False
        detection_incomplete = False
        inference_used = False
        if self._vault_applies(ctx):
            deid = self._vault.deidentify(cleaned, deny_action="marker")
            if deid.allowed:
                cleaned = deid.content
                pii_findings = deid.findings
                warnings.extend(deid.warnings)
                san_result = replace(san_result, cleaned_text=cleaned)
            else:
                # Fail CLOSED. Continuing with the original text would hand the
                # host prompt-ready plaintext with only a warning to notice,
                # and a normal host forwards ProcessedContent.content. A
                # capacity limit or an ambiguous overlap must not become a
                # disclosure.
                blocked = True
                cleaned = "[de-identification failed: content withheld]"
                san_result = replace(san_result, cleaned_text=cleaned)
                warnings.append(f"De-identification failed: {deid.reason}")
            detection_incomplete = deid.detection_incomplete
            inference_used = deid.inference_used

        # L1: Isolate untrusted content
        isolated = False
        # The wrapper is model-visible, so it receives an opaque handle rather
        # than the caller's source_id, which source_gate documents as possibly
        # an email sender. The real identifier stays in provenance, the DLP
        # buffers, and audit below.
        wrapper_source_id = ctx.source_id
        if self._vault is not None:
            wrapper_source_id = self._vault.source_handle(ctx.source_type, ctx.source_id)

        if ctx.source_trust == TrustLevel.UNTRUSTED:
            cleaned = wrap_untrusted(
                cleaned,
                source_type=ctx.source_type,
                source_id=wrapper_source_id,
                trust=ctx.source_trust.value,
            )
            isolated = True
        elif detection.is_attack:
            # If trusted content carries strong injection signals, keep the same
            # structural boundary used for untrusted input.
            cleaned = wrap_untrusted(
                cleaned,
                source_type=ctx.source_type,
                source_id=wrapper_source_id,
                trust=ctx.source_trust.value,
            )
            isolated = True

        # Ingest into DLP buffer for later outbound checks
        if ctx.source_trust == TrustLevel.UNTRUSTED:
            self._dlp.ingest_untrusted(content)
            self._context_contaminated = True

        # Ingest sensitive content into DLP for contaminated-context checks
        if ctx.sensitivity == SensitivityLevel.SENSITIVE:
            self._dlp.ingest_sensitive(content)

        # Add provenance span
        self._provenance.add_span(
            ProvenancedSpan(
                text=content,
                source_type=ctx.source_type,
                source_id=ctx.source_id,
                source_trust=ctx.source_trust,
                sensitivity=ctx.sensitivity,
                principal_id=ctx.principal_id,
            )
        )

        # Canary detection on inbound (exfiltration attempt)
        if self._canary and detect_canary(content, self._canary):
            warnings.append("Canary token detected in inbound content")

        # Scrub LAST, over the complete warning list. SanitizationResult has
        # four string-bearing public fields, not one: mixed_script_words holds
        # offending words verbatim, sanitization_summary joins up to five of
        # them, the same words reach warnings, and those are copied onto
        # ProcessedContent. One homoglyph in an address puts a value in all of
        # them, and that path fires precisely on adversarial input.
        if self._vault is not None:
            san_result, warnings = self._vault.scrub_diagnostics(san_result, warnings)

        return ProcessedContent(
            content=cleaned,
            sanitization=san_result,
            isolated=isolated,
            source_type=ctx.source_type,
            source_id=ctx.source_id,
            warnings=warnings,
            pii_findings=pii_findings,
            blocked=blocked,
            detection_incomplete=detection_incomplete,
            inference_used=inference_used,
        )

    def ingest_sensitive(self, content: str) -> None:
        """Record plaintext in the L3 sensitive buffer.

        Used by direct de-identification, which does not pass through
        ``process_inbound`` and would otherwise leave the contaminated-context
        egress check with nothing to compare against.
        """
        self._dlp.ingest_sensitive(normalize_confusables(content))

    def check_outbound_content(
        self,
        content: str,
        ctx: SecurityContext,
        has_quoting_directive: bool = False,
        *,
        egress_to_principal_id: str | None = None,
    ) -> OutboundResult:
        """L5, L3, and L4 with no L6 quota or action accounting.

        The exclusion is L6 *only*. Egress escalation is preserved: a canary
        block and a DLP hard block both still set ``_session_escalated``.
        Dropping those would silently remove backward-propagating escalation
        from ``check_outbound`` as well, since that method is built on this
        one, so a high-confidence leak would stop tightening later tool calls.

        Separated from ``check_outbound`` so a tool call can be content-checked
        during preparation, before L9/L11/L12 have admitted it. Recording an
        outbound action there would let repeatedly denied proposals consume
        quota and mark recipients as known for calls that never happened.
        """
        return self._content_checks(
            content, ctx, has_quoting_directive, egress_to_principal_id=egress_to_principal_id
        )

    def check_outbound(
        self,
        content: str,
        ctx: SecurityContext,
        has_quoting_directive: bool = False,
        recipient: str | None = None,
        *,
        egress_to_principal_id: str | None = None,
    ) -> OutboundResult:
        """Check content leaving the system.

        Runs: L5 (remembered canary) -> L3 (DLP) -> L4 (provenance)
        -> L6 (rate limit).

        Ordering rationale (spec §7, §8):
        - The remembered canary runs first because it is a more specific,
          session-scoped signal than generic secret or entropy detection.
        - DLP then runs as a coarse pre-filter (default LCS >= 14 for
          untrusted echo, >= 12 for sensitive leak, n-gram >= 40%,
          configurable via PolicyConfig) to catch exfiltration cheaply
          before provenance.
        - Provenance runs second as the primary no-copy enforcement
          (default LCS >= 50, n-gram >= 30%, configurable via PolicyConfig).
        - Both layers share overlap utilities from normalization.py.
        - Secrets are always checked (even with quoting) in the DLP step.

        Client mode: tool arguments (e.g. email body).
        Server mode: tool responses.
        """
        result = self._content_checks(
            content, ctx, has_quoting_directive, egress_to_principal_id=egress_to_principal_id
        )
        if not result.allowed:
            return result

        # L6: Rate limit check
        rate_result = self._rate_limiter.check(
            action="outbound",
            ctx=ctx,
            recipient=recipient,
        )
        if not rate_result.allowed:
            return OutboundResult(
                allowed=False,
                reason=rate_result.reason,
                anomalies=rate_result.anomalies,
            )
        self._rate_limiter.record(action="outbound", ctx=ctx, recipient=recipient)
        result.anomalies = rate_result.anomalies
        return result

    def _content_checks(
        self,
        content: str,
        ctx: SecurityContext,
        has_quoting_directive: bool = False,
        egress_to_principal_id: str | None = None,
    ) -> OutboundResult:
        if ctx.principal_trust != self._principal_trust:
            raise ValueError(
                f"principal_trust mismatch: context has {ctx.principal_trust}, "
                f"pipeline was constructed with {self._principal_trust}"
            )
        # TR39 confusable normalization at outbound trust boundary.
        content = normalize_confusables(content)

        # L13: an issued token at egress proves restoration was skipped. This
        # is an exact membership test against the registry, not a pattern
        # match, so it cannot fire on real content. It blocks rather than warns
        # because A-AS9 has hosts enforce on `allowed`, so a warning would let
        # a compliant host dispatch a payload carrying a literal token. It does
        # not escalate: a missing prepare_tool_call is a host bug, not an
        # attack, and escalation is reserved for evidence of one.
        if self._vault is not None and self._vault.contains_issued_token(content):
            return OutboundResult(
                allowed=False,
                reason="Unrestored privacy token in outbound content (restoration was skipped)",
            )

        # L5: a remembered canary is authoritative session metadata. Attribute
        # it before generic DLP can claim the same random-looking token as an
        # entropy finding. Quoting never authorizes private-context disclosure.
        if self._canary and detect_canary(content, self._canary):
            self._session_escalated = True
            return OutboundResult(
                allowed=False,
                reason="Canary token detected in outbound content",
                canary_detected=True,
            )

        # L3: DLP scan (coarse pre-filter, higher thresholds)
        dlp_result = self._dlp.check(
            content,
            ctx,
            has_quoting_directive,
            contaminated=self._context_contaminated,
        )
        if not dlp_result.allowed:
            # Egress-feedback escalation: a DLP hard block is a high-confidence
            # signal that something bad happened this session. Record it so
            # subsequent tool calls can be tightened (backward-propagating,
            # the reverse complement of _context_contaminated). Echo signals
            # return allowed=True; provenance and rate blocks do not escalate.
            self._session_escalated = True
            return dlp_result

        # L4: Provenance check
        prov_allowed, prov_reason = self._provenance.check_outbound(
            content,
            has_quoting_directive,
            lcs_threshold=int(getattr(ctx.policy, "provenance_verbatim_lcs_min", 50)),
            ngram_threshold=float(getattr(ctx.policy, "provenance_ngram_overlap_min", 0.30)),
            contaminated=self._context_contaminated,
            egress_to_principal_id=egress_to_principal_id,
        )
        if not prov_allowed:
            contamination_triggered = "sensitive" in prov_reason and self._context_contaminated
            reason = prov_reason
            if contamination_triggered and ctx.policy.contaminated_action == "confirm":
                reason = f"Confirmation required: {prov_reason}"
            return OutboundResult(
                allowed=False,
                reason=reason,
                provenance_blocked=True,
                contamination_triggered=contamination_triggered,
                echo_detected=dlp_result.echo_detected,
                echo_lcs=dlp_result.echo_lcs,
            )

        return OutboundResult(
            allowed=True,
            reason="clean" if not dlp_result.echo_detected else "clean (echo signal only)",
            echo_detected=dlp_result.echo_detected,
            echo_lcs=dlp_result.echo_lcs,
        )

    def check_tool_execution(
        self,
        tool: str,
        args: dict,
        ctx: SecurityContext,
        auth_event: AuthorizationEvent | None = None,
        binding: Binding | None = None,
        message_hash: str | None = None,
        recipient: str | None = None,
        record_rate_limit: bool = True,
    ) -> GateResult:
        """Policy check before tool execution.

        Runs: contamination gate -> L9 (policy) -> L6 (rate limit) -> L11 (request binding).

        Client mode: calling external MCP tool.
        Server mode: executing internal tool for MCP client.

        record_rate_limit: when True (the default, and the correct choice for a
        standalone check that is itself the terminal decision) a permitted call
        is recorded against the L6 rate limiter. Pass False when a later gate in
        the same flow can still abort the call -- e.g. the guard flow's user
        confirmation -- so that an aborted call does not consume quota. In that
        case the caller must invoke ``record_tool_execution`` once the call is
        fully cleared. The rate-limit *check* still runs regardless.
        """
        if ctx.principal_trust != self._principal_trust:
            raise ValueError(
                f"principal_trust mismatch: context has {ctx.principal_trust}, "
                f"pipeline was constructed with {self._principal_trust}"
            )
        # Session-risk tool gating (cross-stage invariant). Contamination
        # (forward, from untrusted ingest) and egress escalation (backward,
        # from a high-confidence exfiltration block) are independent signals
        # that each tighten tool policy. Compute one effective policy -- the strictest of the active
        # signals -- and enumerate the contributing triggers in the reason so
        # provenance is preserved.
        active_signals: list[tuple[str, str]] = []
        if self._context_contaminated:
            active_signals.append(("session contaminated", ctx.policy.contaminated_tool_policy))
        if self._session_escalated:
            active_signals.append(("egress escalated", ctx.policy.escalated_tool_policy))

        effective_policy = "allow"
        for _label, policy in active_signals:
            if _POLICY_RANK[policy] > _POLICY_RANK[effective_policy]:
                effective_policy = policy

        if effective_policy != "allow":
            # Auditability: name each contributing trigger with its policy, e.g.
            # "session contaminated=deny; egress escalated=require_auth", so the
            # deciding signal is unambiguous in mixed-policy denials.
            triggers = "; ".join(
                f"{label}={policy}" for label, policy in active_signals if policy != "allow"
            )
            if effective_policy == "deny":
                return GateResult(
                    allowed=False,
                    reason=f"Tool call denied: {triggers}",
                    confidence="none",
                )
            if effective_policy == "require_auth" and auth_event is None:
                return GateResult(
                    allowed=False,
                    reason=f"Authorization required: {triggers}",
                    confidence="none",
                )

        # L9: Policy engine check. Pass the genuine current message hash (not
        # the auth_event fallback) so message binding can detect replay.
        policy_result = self._policy.check_tool_execution(
            tool, args, auth_event, ctx, current_message_hash=message_hash
        )
        if not policy_result.allowed:
            return policy_result

        # L6: Rate limit
        rate_result = self._rate_limiter.check(action=tool, ctx=ctx, recipient=recipient)
        if not rate_result.allowed:
            return GateResult(
                allowed=False,
                reason=rate_result.reason,
                confidence="none",
                anomalies=rate_result.anomalies,
            )

        # L11: Request binding verification
        if binding is not None:
            msg_hash = message_hash or (auth_event.message_hash if auth_event else "")
            bind_ok, bind_reason = verify_binding(binding, tool, args, msg_hash)
            if not bind_ok:
                return GateResult(
                    allowed=False,
                    reason=bind_reason,
                    confidence="none",
                )

        # L6: record the now-permitted tool action so the rate limiter
        # accumulates state across calls (otherwise check() never trips).
        # Deferred when record_rate_limit is False so a call that a later gate
        # (e.g. user confirmation) may still deny does not consume quota; the
        # caller records via record_tool_execution once the call is cleared.
        if record_rate_limit:
            self._rate_limiter.record(action=tool, ctx=ctx, recipient=recipient)

        # Surface non-blocking anomaly signals (burst, novel recipient) rather
        # than discarding them.
        policy_result.anomalies = rate_result.anomalies
        # Session risk was present and did not stop the call: either the policy
        # is "allow", or it is "require_auth" and an authorization was supplied.
        # Name the signal and its setting either way. Without this the caller
        # sees only the policy engine's own reason, typically "Non-destructive
        # tool, implicit allow", which attributes the outcome to the tool's
        # classification when classification had nothing to do with it: the
        # same call is refused under "deny" whether the tool is declared or not.
        # Two reviewers read that string as evidence that declaring the tool
        # would have changed the answer. It would not.
        if active_signals:
            noted = "; ".join(f"{label}={policy}" for label, policy in active_signals)
            policy_result.reason = f"{policy_result.reason} [session risk present: {noted}]"
        return policy_result

    def record_tool_execution(
        self,
        tool: str,
        ctx: SecurityContext,
        recipient: str | None = None,
    ) -> RateLimitResult:
        """Atomically re-check and record a tool action against the L6 limiter.

        Companion to ``check_tool_execution(..., record_rate_limit=False)``:
        the guard flow calls this only after a permitted call has also cleared
        user confirmation and G6 commitment verification, so a denied
        confirmation leaves no rate-limit trace.

        The re-check here is NOT redundant with the earlier check in
        ``check_tool_execution``. That check ran before the confirmation
        ``await``, so two concurrent confirmations could both pass a near-full
        limit before either recorded. ``check_and_record`` re-checks and records
        under the rate limiter's lock, so the compound is atomic for both
        asyncio concurrency (no ``await`` between the two) and multithreaded
        hosts. At most ``limit`` confirmed calls are ever admitted. The caller
        must deny the call when the returned result's ``allowed`` is False.
        """
        return self._rate_limiter.check_and_record(action=tool, ctx=ctx, recipient=recipient)

    def check_kg_extraction(
        self,
        ctx: SecurityContext,
    ) -> SourceGateResult:
        """Check if KG extraction is allowed for this source (Layer 2)."""
        return check_extraction_allowed(
            ctx.source_type,
            ctx.source_id,
            source_trust=ctx.source_trust,
            source_gate_overrides=ctx.policy.source_gate_overrides,
            require_source_id_for=ctx.policy.require_source_id_for,
        )
