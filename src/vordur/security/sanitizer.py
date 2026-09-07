"""Content sanitization module for the MCP security library (Spec Part 1).

Provides HTML-to-plaintext extraction, Unicode sanitization, encoded payload
detection, email header sanitization, and display-parity summaries.

Dependencies: stdlib + beautifulsoup4.  No Episodic-specific imports.
"""

from __future__ import annotations

import base64
import re
import unicodedata
import urllib.parse

from bs4 import BeautifulSoup, Comment

from vordur.security.prompt_injection_detector import detect_prompt_injection
from vordur.security.types import ContentType, SanitizationResult

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STRIP_ELEMENTS = {"style", "script", "head", "meta", "link", "noscript"}

_ALLOWED_TAGS = frozenset(
    {
        "p",
        "div",
        "span",
        "br",
        "hr",
        "b",
        "strong",
        "i",
        "em",
        "u",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "a",
        "ul",
        "ol",
        "li",
        "table",
        "tr",
        "td",
        "th",
        "blockquote",
        "pre",
        "code",
    }
)

_EVENT_HANDLER_RE = re.compile(r"^on[a-z]+$", re.IGNORECASE)

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_URL_ENCODED_RE = re.compile(r"(%[0-9A-Fa-f]{2}){4,}")

# Unicode: zero-width and invisible characters
_ZERO_WIDTH_RE = re.compile(
    "["
    "\u200b-\u200d"  # Zero-width space / non-joiner / joiner
    "\u2060"  # Word joiner
    "\ufeff"  # BOM / zero-width no-break space
    "\u00ad"  # Soft hyphen
    "]"
)

_BIDI_RE = re.compile(
    "["
    "\u202a-\u202e"  # LRE, RLE, PDF, LRO, RLO
    "\u2066-\u2069"  # LRI, RLI, FSI, PDI
    "]"
)

_TAG_CHAR_RE = re.compile(r"[\U000E0001-\U000E007F]")

_INTERLINEAR_RE = re.compile("[\ufff9-\ufffb]")

_OBJECT_REPLACEMENT_RE = re.compile("\ufffc")

# Mixed script detection: a word containing both Latin and Cyrillic characters
_LATIN_RE = re.compile(r"[\u0041-\u024F]")
_CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")

# Email headers to preserve
_ALLOWED_HEADERS = frozenset({"from", "to", "cc", "subject", "date"})

# ---------------------------------------------------------------------------
# CSS hidden-style detection (section 1.1)
# ---------------------------------------------------------------------------

_HIDDEN_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"display\s*:\s*none", re.I), "display:none"),
    (re.compile(r"visibility\s*:\s*hidden", re.I), "visibility:hidden"),
    (re.compile(r"opacity\s*:\s*0(?:[;\s\"]|$)", re.I), "opacity:0"),
    (re.compile(r"font-size\s*:\s*0", re.I), "font-size:0"),
    (re.compile(r"clip\s*:\s*rect\s*\(\s*0", re.I), "clip:rect(0,...)"),
    (re.compile(r"clip-path\s*:\s*inset\s*\(\s*100\s*%", re.I), "clip-path:inset(100%)"),
    (re.compile(r"filter\s*:\s*opacity\s*\(\s*0\s*\)", re.I), "filter:opacity(0)"),
]


def _parse_css_value(style: str, prop: str) -> str | None:
    """Extract the value of a CSS property from an inline style string."""
    m = re.search(rf"{prop}\s*:\s*([^;\"']+)", style, re.I)
    return m.group(1).strip() if m else None


def _px_val(val: str | None) -> float | None:
    """Parse a CSS length value to pixels (very rough: treats bare numbers and px)."""
    if val is None:
        return None
    m = re.match(r"(-?[\d.]+)\s*(px)?", val.strip(), re.I)
    return float(m.group(1)) if m else None


def _is_hidden_style(style: str) -> tuple[bool, str | None]:
    """Check if an inline style uses CSS hiding techniques.

    Returns (is_hidden, reason) where reason describes the technique.
    """
    if not style:
        return False, None

    # Direct pattern matches
    for pattern, reason in _HIDDEN_PATTERNS:
        if pattern.search(style):
            return True, reason

    # Zero-size with overflow:hidden
    w = _parse_css_value(style, "width")
    h = _parse_css_value(style, "height")
    overflow = _parse_css_value(style, "overflow")
    w_px = _px_val(w)
    h_px = _px_val(h)
    if overflow and "hidden" in overflow.lower():
        if w_px is not None and h_px is not None and w_px == 0 and h_px == 0:
            return True, "zero-size with overflow:hidden"

    # 1x1 pixel trick: width:1px; height:1px; overflow:hidden
    if overflow and "hidden" in overflow.lower():
        if w_px is not None and h_px is not None and w_px <= 1 and h_px <= 1:
            return True, "1x1 pixel with overflow:hidden"

    # Positioned elements with negative offsets
    position = _parse_css_value(style, "position")
    if position and position.lower() in ("absolute", "fixed", "relative"):
        for offset_prop in ("left", "top", "right", "bottom"):
            offset = _parse_css_value(style, offset_prop)
            offset_px = _px_val(offset)
            if offset_px is not None and offset_px < -9000:
                return True, f"negative {offset_prop} offset"

        # Negative z-index on positioned small elements
        z = _parse_css_value(style, "z-index")
        if z is not None:
            try:
                z_val = int(z)
            except ValueError:
                z_val = 0
            if z_val < 0 and w_px is not None and h_px is not None:
                if w_px <= 1 and h_px <= 1:
                    return True, "negative z-index on small positioned element"

    # Transform with large negative translate
    transform = _parse_css_value(style, "transform")
    if transform:
        m = re.search(r"translate[XY]?\s*\(\s*(-[\d.]+)", transform, re.I)
        if m:
            val = float(m.group(1))
            if val < -9000:
                return True, "transform with negative translate"

    return False, None


# ---------------------------------------------------------------------------
# HTML sanitization (section 1.1)
# ---------------------------------------------------------------------------


_CLASS_OPENER_RE = re.compile(r"\.([A-Za-z0-9_-]+)\s*\{")
_HIDDEN_DECLARATION_RE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.I)


def _hidden_classes(style_blob: str) -> set[str]:
    """Class names whose rule block hides the element.

    A class is hidden when a ``display: none`` or ``visibility: hidden``
    declaration follows its ``.name {`` opener before the next ``}``. That is
    the relation the single regex this replaced expressed with a lazy
    ``[^}]*?``, and the regex walked to the closing brace once per opener, so
    a block with many openers and no close, which untrusted HTML can contain
    at will, cost the product of the two. Splitting on ``}`` first and finding
    the last hidden declaration in each block once makes it a single pass.
    """
    hidden: set[str] = set()
    for block in style_blob.split("}"):
        last = max((m.start() for m in _HIDDEN_DECLARATION_RE.finditer(block)), default=-1)
        if last < 0:
            continue
        for m in _CLASS_OPENER_RE.finditer(block):
            if m.end() <= last:
                hidden.add(m.group(1).lower())
    return hidden


def _sanitize_html(html: str) -> tuple[str, list[str], int, bool]:
    """Extract plaintext from HTML, stripping dangerous elements.

    Returns (plaintext, warnings, chars_stripped, class_hiding_possible).
    """
    warnings: list[str] = []
    chars_stripped = 0
    class_hiding_possible = False

    soup = BeautifulSoup(html, "html.parser")

    hidden_classes: set[str] = set()
    # Track whether <style> blocks existed (class-based hiding possible)
    style_tags = soup.find_all("style")
    if style_tags:
        class_hiding_possible = True
        style_blob = "\n".join(tag.get_text(" ", strip=True) for tag in style_tags)
        hidden_classes = _hidden_classes(style_blob)

    # Remove forbidden elements
    for tag_name in _STRIP_ELEMENTS:
        for el in soup.find_all(tag_name):
            removed_text = el.get_text()
            chars_stripped += len(removed_text)
            el.decompose()

    # Remove HTML comments
    comment_count = 0
    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        comment_count += 1
        chars_stripped += len(str(comment))
        comment.extract()
    if comment_count:
        warnings.append(f"Removed {comment_count} HTML comment(s)")

    # Remove elements with hidden inline styles
    hidden_count = 0
    for el in soup.find_all(True):
        attrs = getattr(el, "attrs", None) or {}
        style = attrs.get("style", "")
        if style:
            is_hidden, reason = _is_hidden_style(style)
            if is_hidden:
                removed_text = el.get_text()
                chars_stripped += len(removed_text)
                hidden_count += 1
                el.decompose()
                continue

        # Class-based hidden patterns from inline style definitions.
        classes = attrs.get("class", [])
        if not isinstance(classes, list):
            classes = [str(classes)]
        if hidden_classes and any(str(c).lower() in hidden_classes for c in classes):
            removed_text = el.get_text()
            chars_stripped += len(removed_text)
            hidden_count += 1
            el.decompose()
    if hidden_count:
        warnings.append(f"Removed {hidden_count} CSS-hidden element(s)")

    # Remove <img> elements (including alt text)
    img_count = 0
    for img in soup.find_all("img"):
        img_count += 1
        img.decompose()
    if img_count:
        warnings.append(f"Removed {img_count} img element(s)")

    # Remove <svg> elements containing <text>
    svg_count = 0
    for svg in soup.find_all("svg"):
        if svg.find("text"):
            svg_count += 1
            chars_stripped += len(svg.get_text())
            svg.decompose()
    if svg_count:
        warnings.append(f"Removed {svg_count} svg element(s) with text")

    # Strip disallowed attributes and non-allowed tags
    removed_attr_payloads = 0
    for el in soup.find_all(True):
        tag_name = el.name.lower() if el.name else ""

        # Remove disallowed attributes
        attrs_to_remove = []
        el_attrs = getattr(el, "attrs", None) or {}
        for attr in list(el_attrs.keys()):
            attr_lower = attr.lower()
            # Keep href on <a> tags
            if tag_name == "a" and attr_lower == "href":
                continue
            # Remove data-*, title, aria-label, event handlers
            if (
                attr_lower.startswith("data-")
                or attr_lower == "title"
                or attr_lower == "alt"
                or attr_lower == "aria-label"
                or _EVENT_HANDLER_RE.match(attr_lower)
            ):
                value = el_attrs.get(attr)
                if value:
                    removed_attr_payloads += len(
                        " ".join(value) if isinstance(value, list) else str(value)
                    )
                attrs_to_remove.append(attr)
            # Remove style (already processed for hiding)
            elif attr_lower == "style":
                attrs_to_remove.append(attr)
            # Remove class (could be used for CSS hiding)
            elif attr_lower == "class":
                attrs_to_remove.append(attr)
            # Remove id, name, and other non-essential attributes
            elif attr_lower not in ("href",):
                attrs_to_remove.append(attr)

        for attr in attrs_to_remove:
            try:
                if getattr(el, "attrs", None) and attr in el.attrs:
                    del el[attr]
            except Exception:  # noqa: S110 - sanitizer must not fail closed on malformed tag attrs
                pass

        # Unwrap non-allowed tags (preserve inner content)
        if tag_name not in _ALLOWED_TAGS:
            el.unwrap()
    if removed_attr_payloads:
        warnings.append("Removed hidden text-bearing attributes (title/alt/data-*/aria-label)")
        chars_stripped += removed_attr_payloads

    text = soup.get_text(separator="\n")
    # Collapse excessive blank lines
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text, warnings, chars_stripped, class_hiding_possible


# ---------------------------------------------------------------------------
# Unicode sanitization (section 1.2)
# ---------------------------------------------------------------------------


def _sanitize_unicode(text: str) -> tuple[str, list[str], int, list[str]]:
    """Strip invisible Unicode and detect mixed-script words.

    Returns (cleaned, warnings, chars_stripped, mixed_script_words).
    """
    warnings: list[str] = []
    chars_stripped = 0

    # Strip zero-width characters
    new_text, n = _ZERO_WIDTH_RE.subn("", text)
    chars_stripped += n

    # Strip directional overrides
    new_text, n = _BIDI_RE.subn("", new_text)
    chars_stripped += n

    # Strip tag characters
    new_text, n = _TAG_CHAR_RE.subn("", new_text)
    chars_stripped += n

    # Strip interlinear annotation
    new_text, n = _INTERLINEAR_RE.subn("", new_text)
    chars_stripped += n

    # Strip object replacement character
    new_text, n = _OBJECT_REPLACEMENT_RE.subn("", new_text)
    chars_stripped += n

    if chars_stripped:
        warnings.append(f"Stripped {chars_stripped} invisible Unicode character(s)")

    # NFC normalization
    new_text = unicodedata.normalize("NFC", new_text)

    # Mixed-script detection (Latin + Cyrillic in same word)
    mixed_script_words: list[str] = []
    for word in re.findall(r"\S+", new_text):
        has_latin = bool(_LATIN_RE.search(word))
        has_cyrillic = bool(_CYRILLIC_RE.search(word))
        if has_latin and has_cyrillic:
            mixed_script_words.append(word)

    if mixed_script_words:
        warnings.append(
            f"Detected {len(mixed_script_words)} mixed-script word(s): "
            + ", ".join(mixed_script_words[:5])
        )

    return new_text, warnings, chars_stripped, mixed_script_words


# ---------------------------------------------------------------------------
# Encoded payload detection (section 1.3)
# ---------------------------------------------------------------------------


def _detect_encoded_payloads(text: str) -> tuple[list[str], bool]:
    """Detect base64 and URL-encoded suspicious payloads.

    Returns (warnings, encoded_detected). Detection only, no stripping.
    """
    warnings: list[str] = []
    detected = False

    # Base64 blocks
    for match in _BASE64_RE.finditer(text):
        candidate = match.group(0)
        try:
            # Pad to multiple of 4
            padded = candidate + "=" * (-len(candidate) % 4)
            decoded = base64.b64decode(padded, validate=True).decode("utf-8", errors="ignore")
            signal = detect_prompt_injection(decoded, ContentType.PLAINTEXT)
            if signal.score >= 0.25:
                detail = (
                    ", ".join(signal.matched_rules[:3])
                    if signal.matched_rules
                    else "suspicious directives"
                )
                warnings.append(f"Base64 decoded payload flagged ({detail})")
                detected = True
        except Exception:  # noqa: S112 - skip undecodable candidates; bypass would not improve detection
            continue

    # URL-encoded sequences
    for match in _URL_ENCODED_RE.finditer(text):
        candidate = match.group(0)
        try:
            decoded = urllib.parse.unquote(candidate)
            signal = detect_prompt_injection(decoded, ContentType.PLAINTEXT)
            if signal.score >= 0.25:
                detail = (
                    ", ".join(signal.matched_rules[:3])
                    if signal.matched_rules
                    else "suspicious directives"
                )
                warnings.append(f"URL-encoded payload flagged ({detail})")
                detected = True
        except Exception:  # noqa: S112 - skip undecodable candidates; bypass would not improve detection
            continue

    return warnings, detected


# ---------------------------------------------------------------------------
# Email header sanitization (section 1.5)
# ---------------------------------------------------------------------------


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Pass through only safe email headers.

    Preserves: From, To, Cc, Subject, Date.
    Strips: X-* headers, Received chains, and all others.
    """
    result: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _ALLOWED_HEADERS:
            result[key] = value
    return result


# ---------------------------------------------------------------------------
# Display parity / summary (section 1.7)
# ---------------------------------------------------------------------------


def _build_summary(
    html_chars_stripped: int,
    unicode_chars_stripped: int,
    warnings: list[str],
    class_hiding_possible: bool,
    encoded_detected: bool,
    mixed_script_words: list[str],
) -> str:
    """Build a human-readable sanitization summary."""
    parts: list[str] = []

    total_stripped = html_chars_stripped + unicode_chars_stripped
    if total_stripped:
        parts.append(f"Characters stripped: {total_stripped}")
        if html_chars_stripped:
            parts.append(f"  HTML content removed: {html_chars_stripped} chars")
        if unicode_chars_stripped:
            parts.append(f"  Invisible Unicode removed: {unicode_chars_stripped} chars")

    if class_hiding_possible:
        parts.append("CSS class-based hiding possible (style blocks were present)")

    if encoded_detected:
        parts.append("Encoded payloads with suspicious content detected")

    if mixed_script_words:
        parts.append(
            f"Mixed-script words: {len(mixed_script_words)} ({', '.join(mixed_script_words[:5])})"
        )

    warning_count = len(warnings)
    if warning_count:
        parts.append(f"Warnings: {warning_count}")
        for w in warnings:
            parts.append(f"  - {w}")

    return "\n".join(parts) if parts else "No issues detected"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def sanitize(content: str, content_type: ContentType) -> SanitizationResult:
    """Sanitize content based on its type.

    For HTML: runs full HTML pipeline then Unicode pipeline.
    For PLAINTEXT: skips HTML, runs Unicode pipeline only.
    """
    all_warnings: list[str] = []
    html_chars_stripped = 0
    class_hiding_possible = False
    text = content

    # HTML pipeline
    if content_type == ContentType.HTML:
        text, html_warnings, html_chars_stripped, class_hiding_possible = _sanitize_html(content)
        all_warnings.extend(html_warnings)

    # Unicode pipeline (always runs)
    text, unicode_warnings, unicode_chars_stripped, mixed_script_words = _sanitize_unicode(text)
    all_warnings.extend(unicode_warnings)

    # Encoded payload detection (always runs)
    encoded_warnings, encoded_detected = _detect_encoded_payloads(text)
    all_warnings.extend(encoded_warnings)

    total_stripped = html_chars_stripped + unicode_chars_stripped

    summary = _build_summary(
        html_chars_stripped=html_chars_stripped,
        unicode_chars_stripped=unicode_chars_stripped,
        warnings=all_warnings,
        class_hiding_possible=class_hiding_possible,
        encoded_detected=encoded_detected,
        mixed_script_words=mixed_script_words,
    )

    return SanitizationResult(
        cleaned_text=text,
        warnings=all_warnings,
        sanitization_summary=summary,
        chars_stripped=total_stripped,
        class_hiding_possible=class_hiding_possible,
        encoded_detected=encoded_detected,
        mixed_script_words=mixed_script_words,
    )
