"""Server-mode input validation (spec §12.2).

Validates tool arguments before any security layer processes them.
Rejects the entire request if any argument fails validation.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from vordur.security.types import ValidationResult

# Argument limits from spec §12.2
ARGUMENT_LIMITS: dict[str, dict[str, Any]] = {
    "message": {"max_chars": 50_000, "strip_unicode": True},
    "content": {"max_chars": 500_000, "strip_unicode": True},
    "query": {"max_chars": 1_000, "strip_unicode": True},
    "source_name": {"max_chars": 200, "pattern": r"^[\w\-. /]+$"},
    "thread_handle": {"max_chars": 100, "pattern": r"^[A-Za-z0-9_\-]+$"},
    "provenance": {"max_fields": 10, "max_value_chars": 500},
}


#: A parameter name we are willing to quote back verbatim. Real tool schemas
#: use short identifiers; the longest in this repository's own case corpus is
#: 27 characters, so 32 is generous of them and of nothing else.
_PLAIN_ARG_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,31}$")


def _looks_like_a_secret(text: str) -> bool:
    """True when the credential scanner recognizes anything in ``text``.

    Imported lazily: validation is the first and cheapest gate, and the DLP
    module is large. By the time a parameter name is odd enough to reach here
    the module is loaded anyway, because the pipeline imports it.
    """
    from vordur.security.outbound_dlp import _scan_secrets

    return bool(_scan_secrets(text))


def _safe_arg_label(arg_name: str) -> str:
    """A parameter name safe to put in an error, an audit record, or a response.

    Argument names are attacker-influenced. They arrive from a model-proposed
    tool call, and validation errors quoting them verbatim travel further than
    the call does: into the audit stream, and out through the sanitized error
    path. A caller that names a parameter with a credential therefore wrote
    that credential into the audit log, and the outbound DLP that would have
    caught it in a *value* never sees a *key*. Reproduced with a GitHub token
    as the argument name; the whole token appeared in both.

    Names that look like ordinary identifiers pass through, so the common error
    stays readable. Anything else is replaced by a stable digest reference,
    which still lets an operator correlate repeated reports without the library
    republishing content it was handed.

    Two gates, because neither alone is enough. The shape test cannot separate
    a credential from an identifier on its own: a GitHub token is exactly 40
    characters of identifier-legal text, and an AWS access key ID is 20, so any
    length bound loose enough for real parameter names admits some secret. The
    credential scan cannot stand alone either, since it answers "does this look
    like a secret" when the safe question is the narrower "is this a plausible
    parameter name". A name must pass both to be echoed.
    """
    if _PLAIN_ARG_NAME.match(arg_name) and not _looks_like_a_secret(arg_name):
        return arg_name
    digest = hashlib.sha256(arg_name.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    return f"<argument:{digest}>"


def _string_safety_errors(arg_name: str, value: str) -> list[str]:
    """Universal safety checks applied to every string argument.

    These are not tied to a specific named parameter: path traversal and
    null-byte injection are dangerous in any argument, including the
    path/filename arguments of destructive tools (file_write, file_delete)
    that are absent from ARGUMENT_LIMITS.
    """
    errors: list[str] = []
    label = _safe_arg_label(arg_name)
    if ".." in value:
        errors.append(f"Parameter {label} contains path traversal")
    if "\x00" in value:
        errors.append(f"Parameter {label} contains a null byte")
    return errors


# Maximum container nesting inspected before a request is rejected. Well
# above any legitimate tool-argument shape, but low enough that a maliciously
# deep (or self-referential) structure cannot exhaust the Python stack.
_MAX_WALK_DEPTH = 64


def _walk_value(arg_name: str, value: Any, _depth: int = 0) -> list[str]:
    """Recurse into containers, applying string-safety checks to leaves.

    Guards against type-confusion evasion where a payload is nested inside
    a list/dict/tuple/set (e.g. ``{"path": ["../../etc/passwd"]}``) to skip
    a check that only looked at top-level strings. Both dict keys and values
    are checked. Recursion is depth-bounded so deeply nested or cyclic input
    is rejected rather than raising RecursionError out of the first gate.
    """
    if _depth > _MAX_WALK_DEPTH:
        return [f"Parameter {_safe_arg_label(arg_name)} nesting too deep"]
    if isinstance(value, str):
        return _string_safety_errors(arg_name, value)
    if isinstance(value, dict):
        errors: list[str] = []
        for k, v in value.items():
            if isinstance(k, str):
                errors.extend(_string_safety_errors(arg_name, k))
            errors.extend(_walk_value(arg_name, v, _depth + 1))
        return errors
    if isinstance(value, list | tuple | set):
        errors = []
        for v in value:
            errors.extend(_walk_value(arg_name, v, _depth + 1))
        return errors
    return []


def _merged_limits(overrides: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """ARGUMENT_LIMITS with a policy's overrides applied, per argument name.

    Merged per name rather than replaced, so ``{"query": {"max_chars": 1}}``
    tightens the size of ``query`` without discarding the ``strip_unicode``
    that sat beside it. A name absent from ARGUMENT_LIMITS is simply added.

    Never mutates ARGUMENT_LIMITS: it is module state shared by every caller.
    """
    if not overrides:
        return ARGUMENT_LIMITS
    merged = {name: dict(limits) for name, limits in ARGUMENT_LIMITS.items()}
    for name, limits in overrides.items():
        if isinstance(limits, dict):
            merged.setdefault(name, {}).update(limits)
    return merged


def validate_arguments(
    tool: str, args: dict[str, Any], limits: dict[str, Any] | None = None
) -> ValidationResult:
    """Validate all arguments for a tool invocation.

    No partial acceptance: if any argument fails, the entire request is
    rejected. Validation runs before any security layer.

    ``limits`` is ``PolicyConfig.argument_limits``, merged over the defaults
    per argument name. It was a documented setting that nothing read: a policy
    setting ``query.max_chars`` to 1 accepted a two-character query with no
    error anywhere. Optional here so the universal safety checks -- path
    traversal, null bytes -- stay callable with no policy in hand.

    Args:
        tool: Tool name (for context in error messages).
        args: Argument dict from the MCP request.
        limits: Optional per-argument overrides from the active policy.

    Returns:
        ValidationResult with valid=True if all checks pass.
    """
    errors: list[str] = []
    table = _merged_limits(limits)

    for arg_name, value in args.items():
        limits_for_arg = table.get(arg_name)

        # Universal safety checks run on EVERY argument (known or unknown),
        # including strings nested inside containers. Unknown argument names
        # no longer skip validation: path traversal / null bytes must be
        # caught even on arguments (e.g. `path`) that have no size/pattern
        # limits declared.
        errors.extend(_walk_value(arg_name, value))

        if arg_name == "provenance":
            # Special handling for structured provenance field
            if isinstance(value, dict):
                max_fields = limits_for_arg.get("max_fields", 10) if limits_for_arg else 10
                max_val = limits_for_arg.get("max_value_chars", 500) if limits_for_arg else 500
                if len(value) > max_fields:
                    errors.append(
                        f"Parameter {_safe_arg_label(arg_name)} exceeds maximum fields "
                        f"({len(value)} > {max_fields})"
                    )
                for k, v in value.items():
                    if isinstance(v, str) and len(v) > max_val:
                        errors.append(
                            f"Parameter {_safe_arg_label(arg_name)}.{_safe_arg_label(str(k))} exceeds maximum size"
                        )
            continue

        # Named-argument limits (max_chars / pattern) apply only to declared
        # string arguments.
        if limits_for_arg is None or not isinstance(value, str):
            continue

        # Check max_chars
        max_chars = limits_for_arg.get("max_chars")
        if max_chars is not None and len(value) > max_chars:
            errors.append(f"Parameter {_safe_arg_label(arg_name)} exceeds maximum size")

        # Check pattern
        # fullmatch, not match: the declared patterns end in "$", and "$"
        # also matches before a trailing newline, so "abc\n" passed a pattern
        # written to admit "abc". The newline then reached the tool.
        pattern = limits_for_arg.get("pattern")
        if pattern is not None and not re.fullmatch(pattern, value):
            errors.append(f"Parameter {_safe_arg_label(arg_name)} exceeds limits")

    if errors:
        return ValidationResult(
            valid=False,
            errors=errors,
            field_name=errors[0].split()[1] if errors else None,
        )

    return ValidationResult(valid=True)
