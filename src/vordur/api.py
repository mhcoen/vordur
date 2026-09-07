"""Stable high-level API for integrating vordur into applications."""

from __future__ import annotations

import hashlib
import time

from vordur.security import profiles
from vordur.security.action_gate import ActionGate, ActionProposal
from vordur.security.audit import AuditLogger
from vordur.security.error_sanitizer import sanitize_error
from vordur.security.pipeline import SecurityPipeline
from vordur.security.policy_engine import is_destructive_tool
from vordur.security.request_binding import create_binding
from vordur.security.types import (
    AuditEvent,
    AuthorizationEvent,
    Binding,
    ContentType,
    DeidentifyResult,
    Destination,
    GateResult,
    OutboundResult,
    PIIClass,
    PolicyConfig,
    PreparedCall,
    PrivacyConfig,
    ProcessedContent,
    ReidentifyResult,
    SecurityContext,
    TrustLevel,
)
from vordur.security.validation import ValidationResult, validate_arguments
from vordur.security.vault_store import VaultStore


def _string_leaves(node: object) -> list[str]:
    """Every string leaf of an argument tree, including nested and array values.

    Mirrors the traversal ``validation._walk_value`` already performs, so the
    content check covers exactly what validation covers.
    """
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        out: list[str] = []
        for k, v in node.items():
            if isinstance(k, str):
                out.append(k)
            out.extend(_string_leaves(v))
        return out
    if isinstance(node, list | tuple | set):
        out = []
        for v in node:
            out.extend(_string_leaves(v))
        return out
    return []


def _string_values(node: object) -> list[str]:
    """Every string VALUE of an argument tree, in traversal order, keys excluded.

    The sibling of ``_string_leaves``, which includes dict keys because a
    per-field scan should look at a field name too. This one must not: it feeds
    the joined scan below, and interleaving keys between values breaks exactly
    the contiguity that scan exists to restore.
    """
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        out: list[str] = []
        for value in node.values():
            out.extend(_string_values(value))
        return out
    if isinstance(node, list | tuple | set):
        out = []
        for value in node:
            out.extend(_string_values(value))
        return out
    return []


def joined_call_payload(args: object) -> str:
    """The call's string values concatenated, as one outbound payload.

    A per-field scan sees each argument alone, so a secret cut across two
    fields passes both halves: ``{"left": "AKIA", "right": "IOSFODNN7EXAMPLE"}``
    was allowed while the same twenty characters in one field were blocked.
    The same split works on a canary or on a copied passage. What actually
    leaves the boundary is the whole call, so the whole call is also checked as
    one string.

    Joined with no separator, because any separator would reinsert the break
    the attacker created and defeat the point.

    Two limits, stated because this narrows the gap rather than closing it.
    Values are joined in traversal order, so a caller that controls field
    order can place the halves so no ordering this produces makes them
    adjacent. And nothing here sees across calls or turns: a secret sent one
    half per request is not reassembled by any per-call check. Detecting that
    needs cross-request accumulation, which is a different mechanism.
    """
    return "".join(_string_values(args))


class Guard:
    """High-level facade for vordur security workflows."""

    def __init__(
        self,
        *,
        canary_session_id: str | None = None,
        audit_logger: object | None = None,
        principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
        privacy: PrivacyConfig | None = None,
        vault_store: VaultStore | None = None,
    ) -> None:
        # A store with no vault to fill is the failure persist_vault refuses by
        # name: persistence configured but never happening, which looks healthy
        # until a restart comes up empty. Caught here rather than at the first
        # persist_vault call, which a host may not make until shutdown.
        if vault_store is not None and privacy is None:
            raise ValueError(
                "vault_store needs privacy=PrivacyConfig(...): there is no vault to persist"
            )
        self._pipeline = SecurityPipeline(
            audit_logger=audit_logger,
            canary_session_id=canary_session_id,
            principal_trust=principal_trust,
            privacy=privacy,
            vault_store=vault_store,
        )
        self._action_gate = ActionGate()
        self._audit_logger = audit_logger

    @property
    def canary_token(self) -> str | None:
        """Return the canary trusted host code must place in private context."""
        return self._pipeline.canary_token

    @staticmethod
    def hash_message(message: str) -> str:
        """Create a stable SHA-256 hash for a user message."""
        return hashlib.sha256(message.encode()).hexdigest()

    @staticmethod
    def authorize(
        action: str,
        scope: dict,
        *,
        source: str = "api",
        user_message: str | None = None,
        message_hash: str | None = None,
        session_id: str | None = None,
        timestamp: float | None = None,
    ) -> AuthorizationEvent:
        """Build an authorization event for a tool call."""
        msg_hash = message_hash
        if msg_hash is None and user_message is not None:
            msg_hash = Guard.hash_message(user_message)
        if not msg_hash:
            raise ValueError("Provide either user_message or message_hash")
        return AuthorizationEvent(
            action=action,
            scope=scope,
            message_hash=msg_hash,
            timestamp=time.time() if timestamp is None else timestamp,
            source=source,
            session_id=session_id,
        )

    @staticmethod
    def bind_request(
        tool: str,
        args: dict,
        *,
        authorization: AuthorizationEvent | None = None,
        user_message: str | None = None,
        message_hash: str | None = None,
        ttl: float = 120.0,
    ) -> Binding:
        """Create a request binding to protect against replay."""
        msg_hash = message_hash
        if msg_hash is None and user_message is not None:
            msg_hash = Guard.hash_message(user_message)
        return create_binding(
            tool=tool,
            args=args,
            auth_event=authorization,
            message_hash=msg_hash,
            ttl=ttl,
        )

    @staticmethod
    def context_mcp_server(
        server_id: str,
        *,
        source_trust: TrustLevel = TrustLevel.UNTRUSTED,
        content_type: ContentType = ContentType.PLAINTEXT,
        policy: PolicyConfig | None = None,
        principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
    ) -> SecurityContext:
        return profiles.mcp_server_response(
            server_id=server_id,
            source_trust=source_trust,
            content_type=content_type,
            policy=policy,
            principal_trust=principal_trust,
        )

    @staticmethod
    def context_mcp_client(
        client_id: str,
        *,
        source_trust: TrustLevel = TrustLevel.UNTRUSTED,
        content_type: ContentType = ContentType.PLAINTEXT,
        policy: PolicyConfig | None = None,
        principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
        principal_id: str | None = None,
    ) -> SecurityContext:
        return profiles.mcp_client_request(
            client_id=client_id,
            source_trust=source_trust,
            content_type=content_type,
            policy=policy,
            principal_trust=principal_trust,
            principal_id=principal_id,
        )

    @staticmethod
    def context_document(
        document_id: str,
        *,
        content_type: ContentType = ContentType.PLAINTEXT,
        policy: PolicyConfig | None = None,
        principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
    ) -> SecurityContext:
        return profiles.untrusted_document(
            document_id=document_id,
            content_type=content_type,
            policy=policy,
            principal_trust=principal_trust,
        )

    @staticmethod
    def context_web(
        *,
        source_id: str = "web",
        content_type: ContentType = ContentType.HTML,
        policy: PolicyConfig | None = None,
        principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
    ) -> SecurityContext:
        return profiles.web_query_result(
            source_id=source_id,
            content_type=content_type,
            policy=policy,
            principal_trust=principal_trust,
        )

    @staticmethod
    def context_internal_sensitive(
        *,
        source_id: str = "internal",
        content_type: ContentType = ContentType.PLAINTEXT,
        policy: PolicyConfig | None = None,
        principal_trust: TrustLevel = TrustLevel.UNTRUSTED,
    ) -> SecurityContext:
        return profiles.internal_sensitive(
            source_id=source_id,
            content_type=content_type,
            policy=policy,
            principal_trust=principal_trust,
        )

    def reset(self, *, canary_session_id: str | None = None) -> None:
        """Reset transient state, optionally rotating an enabled canary."""
        self._pipeline.reset(canary_session_id=canary_session_id)
        self._action_gate = ActionGate()

    def process_inbound(self, content: str, context: SecurityContext) -> ProcessedContent:
        """Sanitize and isolate inbound content."""
        result = self._pipeline.process_inbound(content, context)
        self._audit(
            AuditEvent(
                event_type="inbound_processed",
                action_summary="Processed inbound content",
                warnings=result.warnings,
                session_id=context.source_id,
            )
        )
        return result

    def process_inbound_compound(
        self,
        spans: list[tuple[str, SecurityContext]],
        compound_id: str | None = None,
    ) -> list[ProcessedContent]:
        """Process multiple spans of a compound message with different provenance.

        Each span is processed independently through the existing inbound
        pipeline.  Session state (contamination, DLP buffers, provenance)
        accumulates across all spans.  If any span has
        source_trust == UNTRUSTED, the session contamination flag is set,
        widening downstream egress checks for the entire session.

        Args:
            spans: (content, SecurityContext) pairs, one per provenance span.
            compound_id: Links spans for provenance and audit.  Generated
                from a hash of all span contents when None.

        Returns:
            List of ProcessedContent, one per input span, in order.
        """
        if compound_id is None:
            h = hashlib.sha256()
            for content, _ in spans:
                h.update(content.encode())
            compound_id = h.hexdigest()[:16]

        results: list[ProcessedContent] = []
        for content, ctx in spans:
            result = self.process_inbound(content, ctx)
            results.append(result)

        self._audit(
            AuditEvent(
                event_type="compound_inbound_processed",
                action_summary=f"Processed {len(spans)} spans",
                request_id=compound_id,
                warnings=[w for r in results for w in r.warnings] or None,
            )
        )
        return results

    def check_tool_call(
        self,
        tool: str,
        args: dict,
        context: SecurityContext,
        *,
        authorization: AuthorizationEvent | None = None,
        binding: Binding | None = None,
        user_message: str | None = None,
        message_hash: str | None = None,
        recipient: str | None = None,
        validate: bool = True,
        record_rate_limit: bool = True,
    ) -> GateResult:
        """Run validation, then policy/rate-limit/binding checks for a tool call.

        validate defaults to True so this method is safe to call directly:
        arguments that fail validation (e.g. path traversal) are denied before
        any authorization decision. Pass validate=False only when validation is
        already handled by the caller (as guard_tool_call does).

        record_rate_limit defaults to True: a permitted call is the terminal
        decision and is recorded against the rate limiter. guard_tool_call
        passes False when a user confirmation still follows, so a denied
        confirmation does not consume quota.
        """
        if validate:
            validation = self.validate_tool_args(tool, args, policy=context.policy)
            if not validation.valid:
                return GateResult(
                    allowed=False,
                    reason=f"Validation failed: {validation.errors[0]}",
                    confidence="none",
                )
        msg_hash = message_hash
        if msg_hash is None and user_message is not None:
            msg_hash = self.hash_message(user_message)
        result = self._pipeline.check_tool_execution(
            tool=tool,
            args=args,
            ctx=context,
            auth_event=authorization,
            binding=binding,
            message_hash=msg_hash,
            recipient=recipient,
            record_rate_limit=record_rate_limit,
        )
        self._audit(
            AuditEvent(
                event_type="tool_call_checked",
                tool_name=tool,
                action_summary=result.reason,
                firewall_result={"allowed": result.allowed, "confidence": result.confidence},
                rate_limit_result={"anomalies": result.anomalies} if result.anomalies else None,
                session_id=context.source_id,
            )
        )
        return result

    # ---------------------------------------------------------------
    # L13: privacy vault
    # ---------------------------------------------------------------

    def seed_private_values(self, values: dict[str, PIIClass]) -> None:
        """Register values the host already knows are private.

        The mechanism for person names and street addresses. An application
        with PII to protect got it from a database row and knows what it is,
        so it declares it rather than having the library guess. Guessing would
        mean inferring a label from content, which this library does not do.
        """
        vault = self._pipeline.vault
        if vault is None:
            raise ValueError("Guard was constructed without privacy=PrivacyConfig(...)")
        vault.seed(values)

    def carry_session_risk(self, *, contaminated: bool = False, escalated: bool = False) -> None:
        """Re-raise session-risk flags on a rebuilt guard. Never lowers them.

        For a host reconstructing a session whose guard it no longer holds. See
        ``SecurityPipeline.carry_session_risk``: monotonic on purpose, because
        a setter that could also clear these would launder a contaminated
        session back to clean.
        """
        self._pipeline.carry_session_risk(contaminated=contaminated, escalated=escalated)

    def persist_vault(self) -> None:
        """Write the privacy vault to the store this guard was constructed with.

        Explicit, and the host chooses when: at the end of a turn, on a
        checkpoint, or on shutdown. Nothing writes on its own, and a guard
        built without ``vault_store`` raises rather than silently doing
        nothing, because "persistence configured but never happening" is the
        failure that looks fine until a restart.
        """
        vault = self._pipeline.vault
        if vault is None:
            raise ValueError("Guard was constructed without privacy=PrivacyConfig(...)")
        vault.persist()

    def deidentify(self, content: str) -> DeidentifyResult:
        """Replace identifiers in host-assembled content before it reaches a model.

        The primary entry point. Host-owned sensitive content (a chart, a CRM
        record, a ticket) never passes through ``process_inbound``, because it
        is trusted and the host assembles it directly, so it needs its own
        call. A DENY-class hit fails here rather than being marked: a
        credential in a prompt the host built is a bug in the host.
        """
        vault = self._pipeline.vault
        if vault is None:
            raise ValueError("Guard was constructed without privacy=PrivacyConfig(...)")
        # Ingest the PLAINTEXT into the sensitive DLP buffer before
        # substituting. A host calling this has already told us the content is
        # sensitive, and without the ingest the contaminated-context control
        # has nothing to compare against: the value would leave uninspected on
        # any path the vault does not cover.
        self._pipeline.ingest_sensitive(content)
        result = vault.deidentify(content, deny_action="fail")
        self._audit(
            AuditEvent(
                event_type="deidentified",
                action_summary=result.reason,
                warnings=result.warnings or None,
            )
        )
        return result

    def reidentify(
        self,
        content: str,
        *,
        destination: Destination,
        allowed_classes: frozenset[PIIClass] | None = None,
    ) -> ReidentifyResult:
        """Resolve tokens in free text for one destination.

        Every destination restores nothing by default, including ``USER``: the
        channel does not establish the viewer's entitlement.
        """
        vault = self._pipeline.vault
        if vault is None:
            raise ValueError("Guard was constructed without privacy=PrivacyConfig(...)")
        result = vault.reidentify(content, destination=destination, allowed_classes=allowed_classes)
        self._audit(
            AuditEvent(
                event_type="reidentified",
                action_summary=result.reason,
                warnings=result.warnings or None,
            )
        )
        return result

    def prepare_tool_call(
        self,
        tool: str,
        args: dict,
        context: SecurityContext,
        *,
        has_quoting_directive: bool = False,
    ) -> PreparedCall:
        """Stage 1 of the guarded flow: restore tokens, then content-check.

        Must run before the host builds its ``AuthorizationEvent`` and
        ``Binding``, because both bind exactly: a scope authorized over a token
        fails against the restored value, and the binding hash mismatches. The
        host dispatches ``PreparedCall.args``, and builds its authorization
        over those same arguments.

        The content check here is an early rejection, not the final decision.
        Session state can change between preparation and dispatch, so stage 3
        re-checks after the last await.
        """
        vault = self._pipeline.vault
        if vault is None:
            return PreparedCall(allowed=True, tool=tool, args=args, reason="privacy disabled")
        prepared = vault.prepare_args(tool, args)
        if not prepared.allowed:
            self._audit(
                AuditEvent(
                    event_type="tool_call_prepare_denied",
                    tool_name=tool,
                    action_summary=prepared.reason,
                )
            )
            return prepared
        # L5/L3/L4 over every string leaf of the restored tree. Checking only
        # the body would miss a canary in a subject line, a credential in a
        # filename, or a protected value in nested metadata.
        for leaf in _string_leaves(prepared.args):
            outcome = self._pipeline.check_outbound_content(leaf, context, has_quoting_directive)
            if not outcome.allowed:
                return PreparedCall(
                    allowed=False,
                    tool=tool,
                    reason=outcome.reason,
                    warnings=prepared.warnings,
                )
        # And the whole call as one payload, so a secret cut across two fields
        # is seen. See joined_call_payload for what this does not reach.
        joined = joined_call_payload(prepared.args)
        if joined:
            outcome = self._pipeline.check_outbound_content(joined, context, has_quoting_directive)
            if not outcome.allowed:
                return PreparedCall(
                    allowed=False,
                    tool=tool,
                    reason=f"{outcome.reason} (across argument fields)",
                    warnings=prepared.warnings,
                )
        return prepared

    def check_outbound_content(
        self,
        content: str,
        context: SecurityContext,
        *,
        has_quoting_directive: bool = False,
        egress_to_principal_id: str | None = None,
    ) -> OutboundResult:
        """Content checks only: L5, L3 and L4, with no L6 quota accounting.

        For a caller that has to inspect several pieces of one outbound action,
        which is the shape a tool call has: many argument leaves, one send.
        ``check_outbound`` records an outbound action against the rate limiter
        every time it is called, so looping it over the leaves of a single call
        charges that call once per string and exhausts the hourly quota inside
        one request. ``prepare_tool_call`` has always used this variant for the
        same reason.

        Escalation is preserved: a canary block or a high-confidence DLP block
        still sets session escalation, so a leak found in an argument still
        tightens later tool calls.
        """
        result = self._pipeline.check_outbound_content(
            content,
            context,
            has_quoting_directive,
            egress_to_principal_id=egress_to_principal_id,
        )
        self._audit(
            AuditEvent(
                event_type="outbound_content_checked",
                action_summary=result.reason,
                dlp_result={
                    "allowed": result.allowed,
                    "overlap_pct": result.overlap_pct,
                    "secrets_found": result.secrets_found,
                    "canary_detected": result.canary_detected,
                    "session_escalated": self._pipeline.session_escalated,
                },
                provenance_result={"blocked": result.provenance_blocked},
                session_id=context.source_id,
            )
        )
        return result

    def check_outbound(
        self,
        content: str,
        context: SecurityContext,
        *,
        has_quoting_directive: bool = False,
        recipient: str | None = None,
        egress_to_principal_id: str | None = None,
    ) -> OutboundResult:
        """Run outbound DLP/provenance/rate checks.

        Records an outbound action against L6. For several checks belonging to
        one action, use ``check_outbound_content``.

        ``egress_to_principal_id`` is the authenticated identity of the
        principal this egress is addressed to. That principal's own untrusted
        spans are skipped by the no-copy check -- returning someone their own
        words is not exfiltration. It matches
        :attr:`ProvenancedSpan.principal_id`, which the integrator must set
        only from an identity they actually authenticated; it is deliberately
        NOT ``source_id``, which is a descriptive label and not unique across
        source types. Sensitive spans are always still compared, so this
        cannot disarm leak detection.
        """
        result = self._pipeline.check_outbound(
            content=content,
            ctx=context,
            has_quoting_directive=has_quoting_directive,
            recipient=recipient,
            egress_to_principal_id=egress_to_principal_id,
        )
        self._audit(
            AuditEvent(
                event_type="outbound_checked",
                action_summary=result.reason,
                dlp_result={
                    "allowed": result.allowed,
                    "overlap_pct": result.overlap_pct,
                    "secrets_found": result.secrets_found,
                    "canary_detected": result.canary_detected,
                    "session_escalated": self._pipeline.session_escalated,
                },
                provenance_result={"blocked": result.provenance_blocked},
                rate_limit_result={"anomalies": result.anomalies} if result.anomalies else None,
                session_id=context.source_id,
            )
        )
        return result

    def validate_tool_args(
        self, tool: str, args: dict, *, policy: PolicyConfig | None = None
    ) -> ValidationResult:
        """Validate tool arguments before security checks/dispatch.

        ``policy`` supplies ``argument_limits``. Optional, so a host with no
        context in hand still gets the universal safety checks; the two gates
        below pass the active context's policy, which is the path that
        matters.
        """
        result = validate_arguments(tool, args, policy.argument_limits if policy else None)
        self._audit(
            AuditEvent(
                event_type="tool_args_validated",
                tool_name=tool,
                action_summary="validation_passed" if result.valid else "validation_failed",
                warnings=result.errors if not result.valid else None,
            )
        )
        return result

    def sanitize_exception(self, exception: Exception, retry_after: int | None = None) -> dict:
        """Return a sanitized outward-safe error payload."""
        result = sanitize_error(exception, retry_after=retry_after)
        self._audit(
            AuditEvent(
                event_type="error_sanitized",
                action_summary=result.get("error", {}).get("code"),
            )
        )
        return result

    async def confirm_action(
        self,
        tool: str,
        args: dict,
        context: SecurityContext,
        *,
        summary: str,
        proposal_context: dict | None = None,
        heightened_scrutiny: bool = False,
        context_has_web_derived: bool = False,
    ) -> bool:
        """Run L12 action-gate confirmation for a proposed operation."""
        proposal = ActionProposal(
            tool_name=tool,
            args=args,
            summary=summary,
            context=proposal_context or {},
            heightened_scrutiny=heightened_scrutiny,
        )
        # A missing handler is a configuration failure, not an authorization
        # decision. Both deny, but recording them the same way tells an operator
        # a user declined when no user was ever asked, and leaves the audit trail
        # asserting a decision nobody made.
        if context.confirmation_handler is None:
            self._audit(
                AuditEvent(
                    event_type="action_gate_unavailable",
                    tool_name=tool,
                    user_confirmed=None,
                    action_summary=summary,
                    session_id=context.source_id,
                )
            )
            return False
        allowed = await self._action_gate.confirm(
            proposal,
            context,
            context_has_web_derived=context_has_web_derived,
        )
        self._audit(
            AuditEvent(
                event_type="action_gate_confirmed",
                tool_name=tool,
                user_confirmed=allowed,
                action_summary=summary,
                session_id=context.source_id,
            )
        )
        return allowed

    async def guard_tool_call(
        self,
        tool: str,
        args: dict,
        context: SecurityContext,
        *,
        summary: str | None = None,
        proposal_context: dict | None = None,
        authorization: AuthorizationEvent | None = None,
        binding: Binding | None = None,
        user_message: str | None = None,
        message_hash: str | None = None,
        context_has_web_derived: bool = False,
        require_confirmation: bool = False,
        heightened_scrutiny: bool = False,
        validate: bool = True,
        recipient: str | None = None,
    ) -> GateResult:
        """Full tool-call guard flow: validation -> policy -> optional confirmation."""
        # L12: auto-require confirmation for destructive tools when policy says so
        if context.policy.auto_confirm_destructive and is_destructive_tool(tool, context.policy):
            require_confirmation = True

        # INV-MUSE-7 / confirm_all_below: escalate to enhanced confirmation when
        # the policy demands it for web-derived context or a low-trust principal.
        # Without this the escalation gate never fires through the guard flow.
        if not require_confirmation:
            escalation_proposal = ActionProposal(
                tool_name=tool,
                args=args,
                summary=summary or f"Execute tool {tool}",
                context=proposal_context or {},
                heightened_scrutiny=heightened_scrutiny,
            )
            if self._action_gate.requires_confirmation(
                escalation_proposal,
                context,
                context_has_web_derived=context_has_web_derived,
            ):
                require_confirmation = True

        if validate:
            validation = self.validate_tool_args(tool, args, policy=context.policy)
            if not validation.valid:
                return GateResult(
                    allowed=False,
                    reason=f"Validation failed: {validation.errors[0]}",
                    confidence="none",
                )

        gate = self.check_tool_call(
            tool=tool,
            args=args,
            context=context,
            authorization=authorization,
            binding=binding,
            user_message=user_message,
            message_hash=message_hash,
            recipient=recipient,
            validate=False,  # already validated above per the `validate` flag
            # Defer L6 rate-limit accounting when a confirmation still follows,
            # so a denied confirmation does not consume the session's quota. We
            # record explicitly below once the call is fully cleared.
            record_rate_limit=not require_confirmation,
        )
        if not gate.allowed:
            return gate

        if require_confirmation:
            approved = await self.confirm_action(
                tool=tool,
                args=args,
                context=context,
                summary=summary or f"Execute tool {tool}",
                proposal_context=proposal_context,
                heightened_scrutiny=heightened_scrutiny,
                context_has_web_derived=context_has_web_derived,
            )
            if not approved:
                if context.confirmation_handler is None:
                    return GateResult(
                        allowed=False,
                        reason=("Confirmation unavailable: no confirmation handler configured"),
                        confidence="none",
                    )
                return GateResult(
                    allowed=False,
                    reason="User denied confirmation",
                    confidence="none",
                )
            # G6: verify args match the confirmed commitment
            ok, reason = self._action_gate.verify_commitment(tool, args)
            if not ok:
                return GateResult(
                    allowed=False,
                    reason=f"Commitment verification failed: {reason}",
                    confidence="none",
                )
            # L6: the call is now fully cleared (permitted + confirmed +
            # commitment verified). Atomically re-check and record it against
            # the rate limiter, since check_tool_call deferred it. The re-check
            # closes a race where two concurrent confirmations both pass the
            # pre-confirmation check before either records; the check and record
            # run with no intervening await, so at most `limit` confirmed calls
            # are admitted. A denied confirmation or a failed commitment returns
            # above, leaving no rate-limit trace.
            rate_final = self._pipeline.record_tool_execution(tool, context, recipient=recipient)
            if not rate_final.allowed:
                return GateResult(
                    allowed=False,
                    reason=rate_final.reason,
                    confidence="none",
                    anomalies=rate_final.anomalies,
                )

        return gate

    def _audit(self, event: AuditEvent) -> None:
        if self._audit_logger is None:
            return
        if isinstance(self._audit_logger, AuditLogger):
            self._audit_logger.log(event)
            return
        if hasattr(self._audit_logger, "log"):
            self._audit_logger.log(event)
