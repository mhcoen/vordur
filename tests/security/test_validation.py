"""Tests for MCP security validation (spec tests 93-94).

Covers:
- Oversized message (>50000 chars) -> invalid
- Pattern violation on source_name (special chars) -> invalid
- Path traversal in source_name (../../etc/passwd) -> invalid
- Valid arguments -> valid
- Unknown extra fields silently ignored
- Missing required field (provenance with too many fields) -> invalid
"""

from vordur.security.validation import (
    validate_arguments,
)


class TestOversizedMessage:
    """Spec test 93: oversized message rejected."""

    def test_message_exceeds_50000_chars(self):
        """Message over 50000 chars is rejected."""
        result = validate_arguments(
            "any_tool",
            {
                "message": "x" * 50_001,
            },
        )
        assert result.valid is False
        assert len(result.errors) > 0
        assert any("message" in e.lower() for e in result.errors)

    def test_message_exactly_50000_chars_valid(self):
        """Message of exactly 50000 chars is valid."""
        result = validate_arguments(
            "any_tool",
            {
                "message": "x" * 50_000,
            },
        )
        assert result.valid is True

    def test_content_exceeds_500000_chars(self):
        """Content over 500000 chars is rejected."""
        result = validate_arguments(
            "any_tool",
            {
                "content": "y" * 500_001,
            },
        )
        assert result.valid is False
        assert any("content" in e.lower() for e in result.errors)

    def test_query_exceeds_1000_chars(self):
        """Query over 1000 chars is rejected."""
        result = validate_arguments(
            "any_tool",
            {
                "query": "q" * 1_001,
            },
        )
        assert result.valid is False


class TestPatternViolation:
    """Spec test 94: pattern violations on source_name."""

    def test_special_chars_rejected(self):
        """source_name with special characters fails pattern check."""
        result = validate_arguments(
            "any_tool",
            {
                "source_name": "test<script>alert(1)</script>",
            },
        )
        assert result.valid is False
        assert any("source_name" in e for e in result.errors)

    def test_semicolon_rejected(self):
        """source_name containing semicolons is rejected."""
        result = validate_arguments(
            "any_tool",
            {
                "source_name": "test;drop table",
            },
        )
        assert result.valid is False

    def test_backtick_rejected(self):
        """source_name containing backticks is rejected."""
        result = validate_arguments(
            "any_tool",
            {
                "source_name": "test`whoami`",
            },
        )
        assert result.valid is False

    def test_path_traversal_rejected(self):
        """source_name with path traversal (../../etc/passwd) is rejected."""
        result = validate_arguments(
            "any_tool",
            {
                "source_name": "../../etc/passwd",
            },
        )
        assert result.valid is False

    def test_path_traversal_with_dots(self):
        """source_name containing .. sequences is rejected by pattern."""
        result = validate_arguments(
            "any_tool",
            {
                "source_name": "../../../secret/key",
            },
        )
        assert result.valid is False

    def test_null_bytes_rejected(self):
        """source_name with null bytes fails pattern check."""
        result = validate_arguments(
            "any_tool",
            {
                "source_name": "test\x00evil",
            },
        )
        assert result.valid is False

    def test_valid_source_name(self):
        """Valid source_name with allowed characters passes."""
        result = validate_arguments(
            "any_tool",
            {
                "source_name": "my-source/path_name.txt",
            },
        )
        assert result.valid is True

    def test_source_name_with_spaces(self):
        """source_name with spaces is valid per the pattern."""
        result = validate_arguments(
            "any_tool",
            {
                "source_name": "my source file.txt",
            },
        )
        assert result.valid is True

    def test_source_name_exceeds_max_chars(self):
        """source_name over 200 chars is rejected."""
        result = validate_arguments(
            "any_tool",
            {
                "source_name": "a" * 201,
            },
        )
        assert result.valid is False


class TestThreadHandle:
    """Pattern validation for thread_handle."""

    def test_valid_thread_handle(self):
        """Alphanumeric thread handle with hyphens and underscores is valid."""
        result = validate_arguments(
            "any_tool",
            {
                "thread_handle": "abc-DEF_123",
            },
        )
        assert result.valid is True

    def test_thread_handle_with_spaces_rejected(self):
        """Thread handle with spaces fails pattern check."""
        result = validate_arguments(
            "any_tool",
            {
                "thread_handle": "has space",
            },
        )
        assert result.valid is False

    def test_thread_handle_with_special_chars_rejected(self):
        """Thread handle with special characters fails."""
        result = validate_arguments(
            "any_tool",
            {
                "thread_handle": "handle@#$",
            },
        )
        assert result.valid is False

    def test_thread_handle_exceeds_max_chars(self):
        """Thread handle over 100 chars is rejected."""
        result = validate_arguments(
            "any_tool",
            {
                "thread_handle": "a" * 101,
            },
        )
        assert result.valid is False


class TestValidArguments:
    """Valid arguments pass all checks."""

    def test_all_valid_arguments(self):
        """A request with valid values for all known fields passes."""
        result = validate_arguments(
            "tool_x",
            {
                "message": "Hello, how are you?",
                "source_name": "my-source",
                "thread_handle": "handle-123",
                "query": "search query",
            },
        )
        assert result.valid is True
        assert result.errors == []

    def test_empty_args_valid(self):
        """Empty args dict is valid (no arguments to validate)."""
        result = validate_arguments("tool_x", {})
        assert result.valid is True

    def test_message_at_limit(self):
        """Message exactly at the character limit is valid."""
        result = validate_arguments(
            "tool_x",
            {
                "message": "a" * 50_000,
            },
        )
        assert result.valid is True


class TestUnknownFields:
    """Unknown extra fields are silently ignored."""

    def test_unknown_field_ignored(self):
        """An unrecognized argument name does not cause rejection."""
        result = validate_arguments(
            "tool_x",
            {
                "message": "valid message",
                "totally_unknown_field": "anything at all <script>evil</script>",
            },
        )
        assert result.valid is True

    def test_multiple_unknown_fields(self):
        """Multiple unknown fields all ignored."""
        result = validate_arguments(
            "tool_x",
            {
                "foo": "bar",
                "baz": 12345,
                "qux": {"nested": True},
            },
        )
        assert result.valid is True

    def test_unknown_fields_do_not_leak(self):
        """Unknown field names do not appear in error messages."""
        result = validate_arguments(
            "tool_x",
            {
                "unknown_secret_probe": "test",
            },
        )
        assert result.valid is True
        assert result.errors == []


class TestProvenance:
    """Provenance field validation (structured dict)."""

    def test_provenance_too_many_fields(self):
        """Provenance dict with >10 fields is rejected."""
        prov = {f"field_{i}": f"value_{i}" for i in range(11)}
        result = validate_arguments(
            "tool_x",
            {
                "provenance": prov,
            },
        )
        assert result.valid is False
        assert any("provenance" in e for e in result.errors)

    def test_provenance_value_too_long(self):
        """Provenance dict with a value exceeding 500 chars is rejected."""
        result = validate_arguments(
            "tool_x",
            {
                "provenance": {"key": "v" * 501},
            },
        )
        assert result.valid is False

    def test_provenance_valid(self):
        """Provenance dict within limits is valid."""
        result = validate_arguments(
            "tool_x",
            {
                "provenance": {"source": "user", "action": "send"},
            },
        )
        assert result.valid is True

    def test_provenance_exactly_10_fields(self):
        """Provenance dict with exactly 10 fields is valid."""
        prov = {f"field_{i}": f"value_{i}" for i in range(10)}
        result = validate_arguments(
            "tool_x",
            {
                "provenance": prov,
            },
        )
        assert result.valid is True

    def test_provenance_non_dict_skipped(self):
        """Non-dict provenance value is not validated (skipped)."""
        result = validate_arguments(
            "tool_x",
            {
                "provenance": "just a string",
            },
        )
        # The string form is not a dict, so dict-specific validation is skipped,
        # then the string check would apply max_chars/pattern if present.
        # Since provenance has no max_chars or pattern, it should pass.
        assert result.valid is True


class TestValidationResult:
    """Tests for the ValidationResult structure on failure."""

    def test_field_name_set_on_error(self):
        """field_name is populated from the first error message."""
        result = validate_arguments(
            "tool_x",
            {
                "message": "x" * 50_001,
            },
        )
        assert result.valid is False
        assert result.field_name is not None

    def test_multiple_errors(self):
        """Multiple invalid arguments produce multiple errors."""
        result = validate_arguments(
            "tool_x",
            {
                "message": "x" * 50_001,
                "source_name": "<script>evil</script>",
            },
        )
        assert result.valid is False
        assert len(result.errors) >= 2

    def test_non_string_values_skipped(self):
        """Non-string values for string-validated fields are skipped."""
        result = validate_arguments(
            "tool_x",
            {
                "message": 12345,  # Not a string
                "source_name": None,  # Not a string
            },
        )
        assert result.valid is True


class TestUniversalSafetyChecks:
    """H4 regression: path traversal / null bytes are caught on EVERY
    argument, not just the six named ones, and inside nested containers.

    Previously unknown argument names (e.g. the `path` argument of
    file_delete/file_write) skipped validation entirely, so a traversal
    payload passed as valid.
    """

    def test_traversal_on_unknown_path_arg_rejected(self):
        result = validate_arguments("file_delete", {"path": "../../../../etc/passwd"})
        assert result.valid is False
        assert any("traversal" in e.lower() for e in result.errors)

    def test_traversal_on_second_unknown_arg_rejected(self):
        result = validate_arguments(
            "file_write", {"file_path": "/a/../../etc/shadow", "content": "x"}
        )
        assert result.valid is False

    def test_traversal_nested_in_list_rejected(self):
        """Type-confusion via a list value is still caught."""
        result = validate_arguments("file_delete", {"path": ["../../etc/passwd"]})
        assert result.valid is False

    def test_traversal_nested_in_dict_rejected(self):
        result = validate_arguments("tool_x", {"opts": {"target": "../secret"}})
        assert result.valid is False

    def test_null_byte_rejected(self):
        result = validate_arguments("file_write", {"path": "ok\x00.txt"})
        assert result.valid is False
        assert any("null byte" in e.lower() for e in result.errors)

    def test_field_name_points_at_offending_arg(self):
        result = validate_arguments("file_delete", {"path": "../../etc/passwd"})
        assert result.field_name == "path"

    def test_benign_absolute_path_allowed(self):
        result = validate_arguments(
            "file_write", {"path": "/home/user/report.txt", "content": "hello"}
        )
        assert result.valid is True

    def test_benign_unknown_scalars_allowed(self):
        result = validate_arguments("tool_x", {"limit": 10, "name": "alice"})
        assert result.valid is True

    def test_deeply_nested_input_rejected_not_crash(self):
        """Recursion must be depth-bounded: deep nesting is rejected, not a
        RecursionError out of the first gate."""
        v = "p"
        for _ in range(3000):
            v = [v]
        result = validate_arguments("file_write", {"path": v})
        assert result.valid is False
        assert any("deep" in e.lower() for e in result.errors)

    def test_self_referential_structure_does_not_crash(self):
        d: dict = {}
        d["a"] = d
        result = validate_arguments("t", {"x": d})
        assert result.valid is False

    def test_traversal_in_dict_key_rejected(self):
        """Dict keys are checked, not just values (a key can be a path)."""
        result = validate_arguments("file_write", {"files": {"../../etc/passwd": "data"}})
        assert result.valid is False

    def test_reasonable_nesting_still_valid(self):
        result = validate_arguments("t", {"opts": {"a": {"b": {"c": "/safe/path/here"}}}})
        assert result.valid is True


class TestPolicyArgumentLimits:
    """`argument_limits` was accepted, documented, and read by nothing.

    A policy setting `query.max_chars` to 1 accepted a two-character query
    with no error anywhere. A security setting that is accepted and not
    enforced is worse than one that is refused.
    """

    def test_a_policy_limit_is_enforced(self):
        from vordur.security.validation import validate_arguments

        assert validate_arguments("search", {"query": "ab"}).valid
        tightened = validate_arguments("search", {"query": "ab"}, {"query": {"max_chars": 1}})
        assert not tightened.valid
        assert "exceeds maximum size" in tightened.errors[0]

    def test_it_reaches_the_gate(self):
        from vordur import Guard
        from vordur.security.types import PolicyConfig

        guard = Guard()
        policy = PolicyConfig(argument_limits={"query": {"max_chars": 1}})
        context = Guard.context_mcp_server(server_id="s", policy=policy)
        assert not guard.check_tool_call("search", {"query": "ab"}, context).allowed
        assert guard.check_tool_call(
            "search", {"query": "ab"}, Guard.context_mcp_server(server_id="s")
        ).allowed

    def test_a_partial_override_keeps_its_siblings(self):
        from vordur.security.validation import _merged_limits

        merged = _merged_limits({"query": {"max_chars": 1}})
        assert merged["query"] == {"max_chars": 1, "strip_unicode": True}

    def test_it_can_add_an_argument_the_defaults_do_not_know(self):
        from vordur.security.validation import validate_arguments

        result = validate_arguments("t", {"ticket": "AB-1234"}, {"ticket": {"pattern": r"^\d+$"}})
        assert not result.valid

    def test_the_defaults_are_never_mutated(self):
        from vordur.security.validation import ARGUMENT_LIMITS, _merged_limits

        _merged_limits({"query": {"max_chars": 1}})
        assert ARGUMENT_LIMITS["query"]["max_chars"] == 1_000


class TestArgumentNamesAreNotEchoed:
    """Argument names are attacker-influenced and travel further than the call.

    A validation error quoting one verbatim reaches the audit stream and the
    sanitized outward error, and the outbound DLP that catches a credential in
    a *value* never inspects a *key*. Naming a parameter with a token therefore
    wrote that token into the audit log.
    """

    CREDENTIALS = [
        "ghp_R7kQm2XvB9nZtL4wHc6JyE1sPaGdUf3oIbNr",  # 40 chars, identifier-legal
        "AKIAIOSFODNN7EXAMPLE",  # 20 chars, defeats any length bound
        "sk-live-9f3aQ2m7Xb4TzR8kLp0WvYc6NdJ1sE5H",
    ]

    def test_a_credential_argument_name_is_not_quoted_back(self):
        from vordur.security.validation import validate_arguments

        for secret in self.CREDENTIALS:
            result = validate_arguments("file_write", {secret: "../etc/passwd"})
            assert not result.valid, "the control itself must still fire"
            assert secret not in result.errors[0], f"{secret[:8]}... echoed"
            assert "<argument:" in result.errors[0]

    def test_it_does_not_reach_the_audit_record(self):
        import json

        from vordur import Guard

        class Capture:
            def __init__(self):
                self.rows = []

            def log(self, event):
                self.rows.append(event)

        for secret in self.CREDENTIALS:
            capture = Capture()
            Guard(audit_logger=capture).validate_tool_args("file_write", {secret: "../etc/passwd"})
            blob = json.dumps([getattr(e, "__dict__", str(e)) for e in capture.rows], default=str)
            assert secret not in blob

    def test_an_ordinary_name_stays_readable(self):
        """The common error must not become unreadable to fix the rare one."""
        from vordur.security.validation import validate_arguments

        assert "Parameter path" in validate_arguments("file_write", {"path": "../x"}).errors[0]
        long_name = "expect_any_anomaly_contains"
        assert long_name in validate_arguments("t", {long_name: "../x"}).errors[0]

    def test_the_digest_is_stable_so_reports_correlate(self):
        from vordur.security.validation import _safe_arg_label

        secret = self.CREDENTIALS[0]
        assert _safe_arg_label(secret) == _safe_arg_label(secret)
        assert _safe_arg_label(secret) != _safe_arg_label(self.CREDENTIALS[1])


class TestPatternsMatchTheWholeValue:
    """`$` also matches before a trailing newline; fullmatch does not."""

    def test_a_trailing_newline_fails_the_pattern(self):
        from vordur.security.validation import validate_arguments

        assert validate_arguments("t", {"thread_handle": "abc"}).valid is True
        result = validate_arguments("t", {"thread_handle": "abc\n"})
        assert result.valid is False
        assert any("thread_handle" in e for e in result.errors)
