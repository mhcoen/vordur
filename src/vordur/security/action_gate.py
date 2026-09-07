"""Part 3: Action gate, user confirmation for write operations.

Presents proposed actions to the user and requires explicit
confirmation before execution. The gate is the last line of defense
after all deterministic checks pass.

INV-MUSE-7 (Amendment B, Erratum 2): When conversation context
includes web-derived content, ALL tool calls (read, write, destructive)
require enhanced confirmation with a hardcoded warning.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from vordur.security.types import SecurityContext


def canonicalize_args(args: dict[str, Any]) -> str:
    """Exact canonical JSON representation of args for G6 commitment.

    Keys are sorted for order-independence, but values are preserved EXACTLY --
    the commitment binds the precise bytes that were confirmed. No whitespace or
    numeric normalization: for whitespace-sensitive fields (shell commands,
    prompts, regexes, file bodies), "a\\nb" and "a b" are different payloads and
    must not pass commitment verification.
    """
    return json.dumps(args, sort_keys=True, separators=(",", ":"))


@dataclass
class ActionProposal:
    """A proposed action awaiting user confirmation."""

    tool_name: str
    args: dict[str, Any]
    summary: str  # Human-readable action summary
    context: dict[str, Any]  # Additional context for display
    heightened_scrutiny: bool = False  # True if class_hiding_possible


# Hardcoded warning text, NOT LLM-generated (INV-MUSE-7)
_WEB_DERIVED_WARNING = "\u26a0\ufe0f  Your conversation context includes content from web search."


class ActionGate:
    """User confirmation gate for write operations.

    See spec Part 3 for full requirements:
    - All write-capable tools require confirmation
    - Read-only tools skip the gate
    - Heightened scrutiny when class_hiding_possible
    - Cancelled actions are never executed
    - G6: Args-changed-after-confirmation check (commitment verification)
    - INV-MUSE-7: Enhanced confirmation for ALL tool calls when
      context_has_web_derived is True (gated on muse_escalation_gate config)
    """

    #: Confirmed-but-unverified commitments kept per tool. A confirmation the
    #: host never follows with a verify would otherwise accumulate for the
    #: life of the session.
    MAX_PENDING_PER_TOOL = 32

    def __init__(self) -> None:
        # G6: commitment storage. Key = tool_name, value = the canonical args
        # strings confirmed for it, oldest first. Keyed by both because one
        # slot per tool was a race: two confirmations of the same tool in
        # flight overwrote each other, and the first to verify was refused as
        # "args changed" against the second's arguments. Fail-closed, but a
        # spurious denial of a call the user did confirm.
        self._commitments: dict[str, OrderedDict[str, None]] = {}

    def verify_commitment(self, tool: str, args: dict[str, Any]) -> tuple[bool, str]:
        """Verify that tool+args match a confirmed commitment (G6), consuming it.

        Returns (ok, reason). With no commitment for this tool the answer is
        (False, "no commitment found"); with commitments for the tool but none
        for these exact bytes, (False, "args changed after confirmation"). A
        commitment verifies once: the confirmation covered one dispatch.
        """
        pending = self._commitments.get(tool)
        if not pending:
            return False, "no commitment found"
        actual = canonicalize_args(args)
        if actual not in pending:
            return False, "args changed after confirmation"
        del pending[actual]
        return True, "commitment verified"

    def requires_confirmation(
        self,
        proposal: ActionProposal,
        ctx: SecurityContext,
        context_has_web_derived: bool = False,
    ) -> bool:
        """Return True if this proposal requires user confirmation.

        Confirmation is required when:
        - confirm_all_below is set and principal_trust <= that threshold
        - context_has_web_derived is True and escalation_gate_enabled
        """
        # confirm_all_below: require confirmation for ALL tools (including
        # non-destructive) when principal_trust is at or below the threshold
        if (
            ctx.policy.confirm_all_below is not None
            and ctx.principal_trust <= ctx.policy.confirm_all_below
        ):
            return True

        # INV-MUSE-7: web-derived content triggers enhanced confirmation
        if context_has_web_derived and ctx.policy.escalation_gate_enabled:
            return True

        return False

    async def confirm(
        self,
        proposal: ActionProposal,
        ctx: SecurityContext,
        context_has_web_derived: bool = False,
    ) -> bool:
        """Present action to user and await confirmation.

        Returns True if user confirms, False if cancelled.
        Delegates to ctx.confirmation_handler if available;
        otherwise denies by default (safe fallback).

        Args:
            proposal: The action proposal to confirm
            ctx: Security context
            context_has_web_derived: If True, ALL tool calls require enhanced
                confirmation with hardcoded web-content warning (INV-MUSE-7)
        """
        if ctx.confirmation_handler is not None:
            context_dict: dict[str, Any] = {
                **proposal.context,
                "summary": proposal.summary,
                "heightened_scrutiny": proposal.heightened_scrutiny,
            }

            # confirm_all_below: force confirmation for all tools when
            # principal_trust is at or below the configured threshold
            if (
                ctx.policy.confirm_all_below is not None
                and ctx.principal_trust <= ctx.policy.confirm_all_below
            ):
                context_dict["trust_gated_confirmation"] = True

            # INV-MUSE-7: Enhanced confirmation when web-derived content present
            if context_has_web_derived and ctx.policy.escalation_gate_enabled:
                context_dict["web_derived_warning"] = _WEB_DERIVED_WARNING
                context_dict["enhanced_confirmation"] = True

            # G6: capture canonical args before handler (handler may mutate args)
            canonical_before = canonicalize_args(proposal.args)
            confirmed = await ctx.confirmation_handler.confirm(
                proposal.tool_name,
                proposal.args,
                context_dict,
            )
            if confirmed:
                pending = self._commitments.setdefault(proposal.tool_name, OrderedDict())
                pending[canonical_before] = None
                while len(pending) > self.MAX_PENDING_PER_TOOL:
                    pending.popitem(last=False)
            return confirmed

        # No handler configured -- deny by default
        return False
