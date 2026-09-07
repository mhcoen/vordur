"""New policy fields must preserve existing enforcement and call signatures."""

import asyncio
import inspect

import pytest

from vordur import Guard
from vordur.security.policy_engine import PolicyEngine
from vordur.security.types import (
    ContentType,
    PolicyConfig,
    PrivacyConfig,
    SecurityContext,
    SensitivityLevel,
    TrustLevel,
)


def test_positional_sensitive_context_still_protects_ingress_and_egress():
    ctx = SecurityContext(
        "client",
        "internal",
        "private",
        TrustLevel.TRUSTED,
        TrustLevel.UNTRUSTED,
        SensitivityLevel.SENSITIVE,
    )
    guard = Guard(privacy=PrivacyConfig())
    private = "The private release plan is to close the northern office after the spring meeting."
    inbound = guard.process_inbound("Contact alice@example.org. " + private, ctx)
    assert "alice@example.org" not in inbound.content
    guard.process_inbound(
        "An unrelated public weather report.", SecurityContext("client", "mcp_server", "web")
    )
    outbound = guard.check_outbound_content(
        private, SecurityContext("client", "mcp_server", "sink")
    )
    assert not outbound.allowed
    assert "sensitive" in outbound.reason


def test_all_old_security_context_positions_and_new_principal_keyword():
    policy = PolicyConfig()
    handler = _Confirmation(False)
    ctx = SecurityContext(
        "client",
        "internal",
        "private",
        TrustLevel.TRUSTED,
        TrustLevel.UNTRUSTED,
        SensitivityLevel.SENSITIVE,
        ContentType.STRUCTURED,
        policy,
        handler,
        principal_id="user:alice",
    )
    assert ctx.sensitivity is SensitivityLevel.SENSITIVE
    assert ctx.content_type is ContentType.STRUCTURED
    assert ctx.policy is policy
    assert ctx.confirmation_handler is handler
    assert ctx.principal_id == "user:alice"


@pytest.mark.parametrize("scopes", [{}, {"safe_read": {}}])
def test_positional_policy_scopes_still_deny_unlisted_tools(scopes):
    policy = PolicyConfig(None, {}, False, scopes)
    ctx = SecurityContext("server", "mcp_client", "u", policy=policy)
    result = Guard().check_tool_call("wire_funds", {"amount": 1}, ctx)
    assert not result.allowed
    assert "capability scopes" in result.reason
    assert policy.capability_scopes == scopes
    assert policy.destructive_tools is None


def test_policy_positions_after_scopes_and_new_destructive_keyword():
    policy = PolicyConfig(
        None,
        {},
        False,
        {"safe_read": {}},
        "client:alice",
        True,
        destructive_tools={"wire_funds"},
    )
    assert policy.capability_scopes == {"safe_read": {}}
    assert policy.client_id == "client:alice"
    assert policy.server_default_deny is True
    assert policy.destructive_tools == frozenset({"wire_funds"})


@pytest.mark.parametrize(
    "cls,name", [(SecurityContext, "principal_id"), (PolicyConfig, "destructive_tools")]
)
def test_only_new_fields_are_keyword_only(cls, name):
    params = inspect.signature(cls).parameters
    assert params[name].kind is inspect.Parameter.KEYWORD_ONLY
    assert all(
        p.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        for key, p in params.items()
        if key != name
    )


class _Confirmation:
    def __init__(self, decision):
        self.decision = decision
        self.calls = 0

    async def confirm(self, tool, args, context):
        self.calls += 1
        return self.decision


@pytest.mark.parametrize("mode", ["client", "server"])
@pytest.mark.parametrize("decision", [None, False, True])
def test_custom_destructive_tool_honors_automatic_confirmation(mode, decision):
    handler = None if decision is None else _Confirmation(decision)
    policy = PolicyConfig(
        destructive_tools={"wire_funds"},
        enable_destructive=True,
        auto_confirm_destructive=True,
    )
    ctx = SecurityContext(mode, "mcp_client", "u", policy=policy, confirmation_handler=handler)
    args = {"amount": 1}
    auth = Guard.authorize("wire_funds", args, message_hash="m")
    result = asyncio.run(
        Guard().guard_tool_call(
            "wire_funds",
            args,
            ctx,
            authorization=auth,
            message_hash="m",
        )
    )
    assert result.allowed is (decision is True)
    if handler is not None:
        assert handler.calls == 1
    else:
        assert "no confirmation handler" in result.reason


@pytest.mark.parametrize("declared", [None, frozenset(), frozenset({"wire_funds"})])
def test_confirmation_uses_replacement_not_union_or_truthiness(declared):
    handler = _Confirmation(False)
    ctx = SecurityContext(
        "client",
        "user",
        "u",
        policy=PolicyConfig(
            destructive_tools=declared,
            enable_destructive=True,
            auto_confirm_destructive=True,
        ),
        confirmation_handler=handler,
    )
    args = {"path": "report.txt"}
    auth = Guard.authorize("file_delete", args, message_hash="m")
    result = asyncio.run(
        Guard().guard_tool_call(
            "file_delete",
            args,
            ctx,
            authorization=auth,
            message_hash="m",
        )
    )
    assert result.allowed is (declared is not None)
    assert handler.calls == (1 if declared is None else 0)


@pytest.mark.parametrize("mode", ["client", "server"])
def test_policy_engine_constructor_default_and_explicit_empty_override(mode):
    engine = PolicyEngine(destructive_tools=frozenset({"wire_funds"}))
    ctx = SecurityContext(mode, "mcp_client", "u")
    assert not engine.check_tool_execution("wire_funds", {}, None, ctx).allowed
    ctx.policy = PolicyConfig(destructive_tools=frozenset())
    assert engine.check_tool_execution("wire_funds", {}, None, ctx).allowed
