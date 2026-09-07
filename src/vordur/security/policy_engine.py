"""Parts 6 + 12: Unified policy engine.

Combines client-mode tool firewall (allowlist + authorization event
verification) with server-mode capability token authorization.
"""

from __future__ import annotations

import time

from vordur.security.types import (
    AuthorizationEvent,
    GateResult,
    PolicyConfig,
    SecurityContext,
    TrustLevel,
    expiry_reason,
)

# Tools that can modify external state (spec §6)
DESTRUCTIVE_TOOLS: frozenset[str] = frozenset(
    {
        "gmail_send_email",
        "gmail_delete_email",
        "gmail_modify_labels",
        "calendar_create_event",
        "calendar_delete_event",
        "slack_send_message",
        "slack_delete_message",
        "file_write",
        "file_delete",
        "shell_execute",
        # mcp-gsuite tools (v1.1)
        "delete_calendar_event",
        "delete_gmail_draft",
        "create_calendar_event",
        "reply_gmail_email",
        "create_gmail_draft",
    }
)


def is_destructive_tool(
    tool: str,
    policy: PolicyConfig,
    default_tools: frozenset[str] = DESTRUCTIVE_TOOLS,
) -> bool:
    """One classification for authorization and automatic confirmation.

    A deployment's declaration replaces the default set, including when it is
    empty. PolicyEngine can supply its own constructor default; the Guard API
    uses the built-in one, matching the engine it constructs.
    """
    declared = policy.destructive_tools
    return tool in (default_tools if declared is None else declared)


class PolicyEngine:
    """Unified policy engine for client and server mode.

    Client mode: requires AuthorizationEvent for write-capable tools.
    Server mode: checks capability token (auth_event not required).
    """

    def __init__(
        self,
        auth_ttl: float = 300.0,
        destructive_tools: frozenset[str] | None = None,
    ) -> None:
        self._auth_ttl = auth_ttl
        self._destructive_tools = (
            destructive_tools if destructive_tools is not None else DESTRUCTIVE_TOOLS
        )

    def check_tool_execution(
        self,
        tool: str,
        args: dict,
        auth_event: AuthorizationEvent | None,
        ctx: SecurityContext,
        current_message_hash: str | None = None,
    ) -> GateResult:
        """Policy check before tool execution.

        Trust-gated layer runs first (principal_trust checks), then
        server/client mode-specific logic.

        current_message_hash: SHA-256 of the user message driving this
            execution, used for anti-replay message binding (client mode).
        """
        # Principal-trust deny list: block before any scope/auth check
        if ctx.principal_trust == TrustLevel.UNTRUSTED and tool in ctx.policy.untrusted_deny_tools:
            return GateResult(
                allowed=False,
                reason=f"Tool '{tool}' denied for untrusted principal",
                confidence="none",
            )

        # Principal-trust require auth: block if no auth_event
        if (
            ctx.principal_trust == TrustLevel.UNTRUSTED
            and ctx.policy.untrusted_require_auth
            and auth_event is None
        ):
            return GateResult(
                allowed=False,
                reason="Authorization required for untrusted principal",
                confidence="none",
            )

        if ctx.mode == "server":
            return self._check_server(tool, args, auth_event, ctx)
        return self._check_client(tool, args, auth_event, ctx, current_message_hash)

    def _check_server(
        self,
        tool: str,
        args: dict,
        auth_event: AuthorizationEvent | None,
        ctx: SecurityContext,
    ) -> GateResult:
        """Server mode: check capability scopes."""
        scopes = ctx.policy.capability_scopes
        if scopes is None:
            # No capability scopes configured. Fail closed when the operator
            # has opted into default-deny; otherwise legacy allow-by-default.
            if ctx.policy.server_default_deny:
                return GateResult(
                    allowed=False,
                    reason="No capability scopes configured (default-deny)",
                    confidence="none",
                )
        else:
            # Empty dict = deny all tools; non-empty = tool must be in set
            if not scopes or tool not in scopes:
                return GateResult(
                    allowed=False,
                    reason=f"Tool '{tool}' not in capability scopes",
                    confidence="none",
                )

        # Destructive tools require explicit enablement. Same per-context
        # override as the client path, so a deployment's declaration holds in
        # server mode too rather than only where it happened to be read.
        if is_destructive_tool(tool, ctx.policy, self._destructive_tools):
            if not ctx.policy.enable_destructive:
                return GateResult(
                    allowed=False,
                    reason=f"Destructive tool '{tool}' not enabled in policy",
                    confidence="none",
                )

        return GateResult(
            allowed=True,
            reason="Server policy allows execution",
            confidence="implicit",
        )

    def _check_client(
        self,
        tool: str,
        args: dict,
        auth_event: AuthorizationEvent | None,
        ctx: SecurityContext,
        current_message_hash: str | None = None,
    ) -> GateResult:
        """Client mode: verify authorization event."""
        # A per-context override wins over the set this engine was built with,
        # so a host can name its own destructive tools through PolicyConfig
        # instead of reaching for a PolicyEngine it does not construct.
        is_destructive = is_destructive_tool(tool, ctx.policy, self._destructive_tools)

        # Destructive tools must be enabled in policy
        if is_destructive and not ctx.policy.enable_destructive:
            return GateResult(
                allowed=False,
                reason=f"Destructive tool '{tool}' not enabled",
                confidence="none",
            )

        # Destructive tools require an authorization event
        if is_destructive and auth_event is None:
            return GateResult(
                allowed=False,
                reason=f"Destructive tool '{tool}' requires authorization",
                confidence="none",
            )

        # L9: tool_allowlist enforcement
        # None = no allowlist (disabled); dict (including empty {}) = deny unless listed
        if ctx.policy.tool_allowlist is not None:
            allowed_tools = {k[0] if isinstance(k, tuple) else k for k in ctx.policy.tool_allowlist}
            if tool not in allowed_tools:
                return GateResult(
                    allowed=False,
                    reason=f"Tool '{tool}' not in session allowlist",
                    confidence="none",
                )

        # Capability scopes apply in client mode too (restrict allowed tools)
        if ctx.policy.capability_scopes is not None:
            if not ctx.policy.capability_scopes or tool not in ctx.policy.capability_scopes:
                return GateResult(
                    allowed=False,
                    reason=f"Tool '{tool}' not in capability scopes",
                    confidence="none",
                )

        # Non-destructive tools without auth_event are implicitly allowed
        if auth_event is None:
            return GateResult(
                allowed=True,
                reason="Non-destructive tool, implicit allow",
                confidence="implicit",
            )

        # L11 anti-replay: bind this authorization to the current user message.
        # A supplied current hash that differs from the authorized message is
        # positive evidence of replay and is always denied. When
        # require_message_binding demands it, a missing current hash fails
        # closed rather than allowing an unbound (replayable) authorization.
        binding_required = ctx.policy.require_message_binding == "all" or (
            ctx.policy.require_message_binding == "destructive" and is_destructive
        )
        if current_message_hash is not None:
            if auth_event.message_hash != current_message_hash:
                return GateResult(
                    allowed=False,
                    reason="Authorization does not match the current message (possible replay)",
                    confidence="none",
                )
        elif binding_required:
            return GateResult(
                allowed=False,
                reason="Message binding required but no current message hash was provided",
                confidence="none",
            )

        # Verify auth_event.action matches the tool
        if auth_event.action != tool:
            return GateResult(
                allowed=False,
                reason=(f"Action mismatch: authorized='{auth_event.action}', executing='{tool}'"),
                confidence="none",
            )

        # Verify scope constraints: auth scope must cover all args keys
        for key, value in auth_event.scope.items():
            if key not in args:
                return GateResult(
                    allowed=False,
                    reason=f"Scope key '{key}' missing from args",
                    confidence="none",
                )
            if args[key] != value:
                return GateResult(
                    allowed=False,
                    reason=(f"Scope violation: '{key}' expected '{value}', got '{args[key]}'"),
                    confidence="none",
                )

        # Reverse check: args must not contain keys outside the explicitly
        # authorized scope keys (prevents parameter expansion: e.g. authorizing
        # gmail_send_email(to=alice) and the LLM tacking on bcc=attacker).
        #
        # For destructive tools, an empty scope is treated as "no constraint
        # specified" and the reverse check denies any args -- destructive
        # actions must be authorized with explicit per-arg constraints.
        #
        # For non-destructive tools, an empty scope means "no per-arg
        # restriction" (the auth_event itself is sufficient evidence of
        # operator intent); the action match, TTL, and source checks still
        # apply. This is what lets contaminated-context require_auth flows
        # authorize a read/search tool without enumerating every arg key.
        if auth_event.scope or is_destructive:
            uncovered = set(args.keys()) - set(auth_event.scope.keys())
            if uncovered:
                return GateResult(
                    allowed=False,
                    reason=(f"Args key(s) {sorted(uncovered)} not covered by authorization scope"),
                    confidence="none",
                )

        # Verify timestamp within TTL. Fails closed on a non-finite or future
        # timestamp: the plain `elapsed > ttl` form this replaced accepted NaN,
        # infinity, and any sufficiently future value, each of which made an
        # authorization that never expires. See types.expiry_reason.
        # `now` passed explicitly rather than left to expiry_reason's default:
        # it keeps the clock read in this module, which is the seam the demo
        # builder and several tests patch, and makes the time source visible at
        # the decision rather than one call away.
        stale = expiry_reason(auth_event.timestamp, self._auth_ttl, now=time.time())
        if stale is not None:
            return GateResult(
                allowed=False,
                reason=f"Authorization {stale}",
                confidence="none",
            )

        return GateResult(
            allowed=True,
            reason="Authorization verified",
            matched_directive=auth_event.source,
            confidence="explicit",
        )
