"""Tests for MCP security ActionGate."""

import asyncio

import pytest

from vordur.security.action_gate import ActionGate, ActionProposal
from vordur.security.types import (
    ConfirmationHandler,
    SecurityContext,
    TrustLevel,
)


@pytest.fixture
def gate():
    return ActionGate()


@pytest.fixture
def ctx():
    return SecurityContext(
        mode="client",
        source_type="mcp_server",
        source_id="server-1",
    )


@pytest.fixture
def proposal():
    return ActionProposal(
        tool_name="gmail_send_email",
        args={"to": "alice@example.com", "body": "Hello Alice"},
        summary="Send email to alice@example.com",
        context={"conversation_topic": "meeting follow-up"},
    )


# ---------------------------------------------------------------------------
# ActionProposal dataclass
# ---------------------------------------------------------------------------


class TestActionProposal:
    def test_creates_with_all_fields(self):
        proposal = ActionProposal(
            tool_name="gmail_send_email",
            args={"to": "alice@test.com"},
            summary="Send email",
            context={"topic": "test"},
            heightened_scrutiny=True,
        )
        assert proposal.tool_name == "gmail_send_email"
        assert proposal.args == {"to": "alice@test.com"}
        assert proposal.summary == "Send email"
        assert proposal.context == {"topic": "test"}
        assert proposal.heightened_scrutiny is True

    def test_heightened_scrutiny_defaults_false(self):
        proposal = ActionProposal(
            tool_name="tool",
            args={},
            summary="summary",
            context={},
        )
        assert proposal.heightened_scrutiny is False


# ---------------------------------------------------------------------------
# ActionGate.confirm
# ---------------------------------------------------------------------------


class _AcceptingHandler(ConfirmationHandler):
    """Always confirms."""

    def __init__(self):
        self.last_tool = None
        self.last_args = None
        self.last_context = None

    async def confirm(self, tool, args, context):
        self.last_tool = tool
        self.last_args = args
        self.last_context = context
        return True


class _DenyingHandler(ConfirmationHandler):
    """Always denies."""

    async def confirm(self, tool, args, context):
        return False


class TestActionGate:
    def test_no_handler_denies(self, gate, proposal, ctx):
        """Without a confirmation handler, deny by default."""
        result = asyncio.run(gate.confirm(proposal, ctx))
        assert result is False

    def test_accepting_handler_confirms(self, gate, proposal):
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
            confirmation_handler=handler,
        )
        result = asyncio.run(gate.confirm(proposal, ctx))
        assert result is True

    def test_denying_handler_denies(self, gate, proposal):
        handler = _DenyingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
            confirmation_handler=handler,
        )
        result = asyncio.run(gate.confirm(proposal, ctx))
        assert result is False

    def test_handler_receives_tool_and_args(self, gate, proposal):
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
            confirmation_handler=handler,
        )
        asyncio.run(gate.confirm(proposal, ctx))
        assert handler.last_tool == "gmail_send_email"
        assert handler.last_args == {"to": "alice@example.com", "body": "Hello Alice"}

    def test_handler_receives_context_with_summary(self, gate, proposal):
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
            confirmation_handler=handler,
        )
        asyncio.run(gate.confirm(proposal, ctx))
        assert handler.last_context["summary"] == "Send email to alice@example.com"

    def test_handler_receives_heightened_scrutiny(self, gate):
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
            confirmation_handler=handler,
        )
        proposal = ActionProposal(
            tool_name="gmail_send_email",
            args={"to": "bob@test.com"},
            summary="Send with scrutiny",
            context={"class_hiding_possible": True},
            heightened_scrutiny=True,
        )
        asyncio.run(gate.confirm(proposal, ctx))
        assert handler.last_context["heightened_scrutiny"] is True

    def test_handler_receives_proposal_context_fields(self, gate):
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="server-1",
            confirmation_handler=handler,
        )
        proposal = ActionProposal(
            tool_name="tool",
            args={},
            summary="summary",
            context={"custom_field": "value123"},
        )
        asyncio.run(gate.confirm(proposal, ctx))
        assert handler.last_context["custom_field"] == "value123"

    def test_server_mode_no_handler_denies(self, gate, proposal):
        ctx = SecurityContext(
            mode="server",
            source_type="mcp_client",
            source_id="client-1",
        )
        result = asyncio.run(gate.confirm(proposal, ctx))
        assert result is False


# ---------------------------------------------------------------------------
# confirm_all_below (Phase 2)
# ---------------------------------------------------------------------------


class TestConfirmAllBelow:
    """Phase 2: confirm_all_below requires confirmation for all tools
    when principal_trust <= the configured threshold."""

    def test_requires_confirmation_below_threshold(self, gate, proposal):
        """UNTRUSTED principal requires confirmation when threshold is UNTRUSTED."""
        from vordur.security.types import PolicyConfig

        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            principal_trust=TrustLevel.UNTRUSTED,
            policy=PolicyConfig(confirm_all_below=TrustLevel.UNTRUSTED),
        )
        assert gate.requires_confirmation(proposal, ctx) is True

    def test_requires_confirmation_at_semi_trusted(self, gate, proposal):
        """SEMI_TRUSTED principal requires confirmation when threshold is SEMI_TRUSTED."""
        from vordur.security.types import PolicyConfig

        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            principal_trust=TrustLevel.SEMI_TRUSTED,
            policy=PolicyConfig(confirm_all_below=TrustLevel.SEMI_TRUSTED),
        )
        assert gate.requires_confirmation(proposal, ctx) is True

    def test_untrusted_requires_when_threshold_semi_trusted(self, gate, proposal):
        """UNTRUSTED (below SEMI_TRUSTED) requires confirmation."""
        from vordur.security.types import PolicyConfig

        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            principal_trust=TrustLevel.UNTRUSTED,
            policy=PolicyConfig(confirm_all_below=TrustLevel.SEMI_TRUSTED),
        )
        assert gate.requires_confirmation(proposal, ctx) is True

    def test_trusted_skips_when_threshold_semi_trusted(self, gate, proposal):
        """TRUSTED (above SEMI_TRUSTED) does not require confirmation."""
        from vordur.security.types import PolicyConfig

        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            source_trust=TrustLevel.TRUSTED,
            principal_trust=TrustLevel.TRUSTED,
            policy=PolicyConfig(confirm_all_below=TrustLevel.SEMI_TRUSTED),
        )
        assert gate.requires_confirmation(proposal, ctx) is False

    def test_no_threshold_no_confirmation_required(self, gate, proposal):
        """Without confirm_all_below, no trust-gated confirmation."""
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            principal_trust=TrustLevel.UNTRUSTED,
        )
        assert gate.requires_confirmation(proposal, ctx) is False

    def test_confirm_passes_trust_gated_flag_to_handler(self, gate, proposal):
        """confirm() passes trust_gated_confirmation context to handler."""
        from vordur.security.types import PolicyConfig

        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            principal_trust=TrustLevel.UNTRUSTED,
            policy=PolicyConfig(confirm_all_below=TrustLevel.UNTRUSTED),
            confirmation_handler=handler,
        )
        asyncio.run(gate.confirm(proposal, ctx))
        assert handler.last_context.get("trust_gated_confirmation") is True

    def test_web_derived_independent_of_confirm_all_below(self, gate, proposal):
        """Web-derived warning is additive, not gated by confirm_all_below."""
        from vordur.security.types import PolicyConfig

        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            source_trust=TrustLevel.TRUSTED,
            principal_trust=TrustLevel.TRUSTED,
            policy=PolicyConfig(confirm_all_below=TrustLevel.SEMI_TRUSTED),
        )
        # TRUSTED principal, above threshold, but web_derived still triggers
        assert gate.requires_confirmation(proposal, ctx, context_has_web_derived=True) is True


# ---------------------------------------------------------------------------
# G6: Args-changed-after-confirmation (commitment verification)
# ---------------------------------------------------------------------------


class TestArgsCommitment:
    """G6: verify_commitment detects args changes after confirmation."""

    def test_args_match_passes(self):
        """Matching args after confirmation passes verification."""
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            confirmation_handler=handler,
        )
        gate = ActionGate()
        proposal = ActionProposal(
            tool_name="gmail_send_email",
            args={"to": "alice@test.com", "body": "hello"},
            summary="Send email",
            context={},
        )
        asyncio.run(gate.confirm(proposal, ctx))
        ok, reason = gate.verify_commitment(
            "gmail_send_email", {"to": "alice@test.com", "body": "hello"}
        )
        assert ok is True
        assert "verified" in reason

    def test_whitespace_only_mutation_denies(self):
        """G6 binds exact bytes: a whitespace-only change to a value (e.g. a
        newline vs a space in a shell command) must fail commitment."""
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            confirmation_handler=handler,
        )
        gate = ActionGate()
        proposal = ActionProposal(
            tool_name="shell_execute",
            args={"cmd": "rm -rf a\nb"},
            summary="run",
            context={},
        )
        asyncio.run(gate.confirm(proposal, ctx))
        ok, reason = gate.verify_commitment("shell_execute", {"cmd": "rm -rf a b"})
        assert ok is False
        assert "args changed" in reason

    def test_args_changed_denies(self):
        """Changed args after confirmation fails verification."""
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            confirmation_handler=handler,
        )
        gate = ActionGate()
        proposal = ActionProposal(
            tool_name="gmail_send_email",
            args={"to": "alice@test.com", "body": "safe text"},
            summary="Send email",
            context={},
        )
        asyncio.run(gate.confirm(proposal, ctx))
        ok, reason = gate.verify_commitment(
            "gmail_send_email", {"to": "alice@test.com", "body": "evil text"}
        )
        assert ok is False
        assert "args changed" in reason

    def test_tool_name_changed_denies(self):
        """Different tool name fails verification."""
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            confirmation_handler=handler,
        )
        gate = ActionGate()
        proposal = ActionProposal(
            tool_name="gmail_send_email",
            args={"to": "alice@test.com"},
            summary="Send email",
            context={},
        )
        asyncio.run(gate.confirm(proposal, ctx))
        ok, reason = gate.verify_commitment("gmail_delete_email", {"to": "alice@test.com"})
        assert ok is False
        assert "no commitment" in reason

    def test_no_commitment_denies(self):
        """No prior confirmation fails verification."""
        gate = ActionGate()
        ok, reason = gate.verify_commitment("gmail_send_email", {"to": "x"})
        assert ok is False

    def test_extra_key_denies(self):
        """Extra key in execution args fails verification."""
        handler = _AcceptingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            confirmation_handler=handler,
        )
        gate = ActionGate()
        proposal = ActionProposal(
            tool_name="gmail_send_email",
            args={"to": "alice@test.com"},
            summary="Send email",
            context={},
        )
        asyncio.run(gate.confirm(proposal, ctx))
        ok, _ = gate.verify_commitment(
            "gmail_send_email", {"to": "alice@test.com", "cc": "eve@x.com"}
        )
        assert ok is False

    def test_denied_confirmation_no_commitment(self):
        """Denied confirmation does not store a commitment."""
        handler = _DenyingHandler()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="s1",
            confirmation_handler=handler,
        )
        gate = ActionGate()
        proposal = ActionProposal(
            tool_name="gmail_send_email",
            args={"to": "alice@test.com"},
            summary="Send email",
            context={},
        )
        asyncio.run(gate.confirm(proposal, ctx))
        ok, _ = gate.verify_commitment("gmail_send_email", {"to": "alice@test.com"})
        assert ok is False


class TestCommitmentsInFlight:
    """One slot per tool was a race between two confirmations of the same tool."""

    def _proposal(self, args):
        return ActionProposal(tool_name="gmail_send_email", args=args, summary="send", context={})

    def test_two_confirmations_of_one_tool_both_verify(self):
        gate = ActionGate()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="t",
            confirmation_handler=_AcceptingHandler(),
        )
        asyncio.run(gate.confirm(self._proposal({"to": "a@example.com"}), ctx))
        asyncio.run(gate.confirm(self._proposal({"to": "b@example.com"}), ctx))
        ok_a, _ = gate.verify_commitment("gmail_send_email", {"to": "a@example.com"})
        ok_b, _ = gate.verify_commitment("gmail_send_email", {"to": "b@example.com"})
        assert (ok_a, ok_b) == (True, True)

    def test_a_commitment_verifies_once(self):
        gate = ActionGate()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="t",
            confirmation_handler=_AcceptingHandler(),
        )
        asyncio.run(gate.confirm(self._proposal({"to": "a@example.com"}), ctx))
        assert gate.verify_commitment("gmail_send_email", {"to": "a@example.com"})[0] is True
        ok, reason = gate.verify_commitment("gmail_send_email", {"to": "a@example.com"})
        assert ok is False
        assert "no commitment" in reason

    def test_pending_commitments_are_bounded(self):
        gate = ActionGate()
        ctx = SecurityContext(
            mode="client",
            source_type="mcp_server",
            source_id="t",
            confirmation_handler=_AcceptingHandler(),
        )
        for i in range(ActionGate.MAX_PENDING_PER_TOOL + 5):
            asyncio.run(gate.confirm(self._proposal({"n": i}), ctx))
        assert len(gate._commitments["gmail_send_email"]) == ActionGate.MAX_PENDING_PER_TOOL
        assert gate.verify_commitment("gmail_send_email", {"n": 0})[0] is False
        assert gate.verify_commitment("gmail_send_email", {"n": 36})[0] is True
