"""L13 detection: structural identifiers and host-seeded values.

Two tiers, both deterministic and both local:

**Structural.** A pattern plus, wherever the identifier carries one, an
arithmetic validator: Luhn for card numbers, mod-97 for IBANs, the ABA
checksum for routing numbers, issued-range checks for SSNs. The validator is
what separates this from naive regex redaction, and it is why the
false-positive rate is low enough to substitute automatically. Identifiers
with no checksum (passport, driver's licence, national ID) are matched only
when a labelling context is present, because an unanchored pattern for them
is mostly false positives.

**Host-seeded.** Values the application already knows are private, because
they came out of a database row or a session record. This is the mechanism
for person names and street addresses. The library does not attempt to find a
name in free text on its own: doing so means inferring a label from content,
which is the thing this project declines to do everywhere else. An
application that needs free-text name coverage registers a tier-3 detector
(``types.Detector``), whose spans are validated here, marked ``inferred``, and
resolved against validated spans by the stricter rule in ``_resolve_overlaps``.

Everything runs in one pass over the input. The combined alternation is
compiled once; validators execute only on candidate matches, never on the
whole text.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
import unicodedata
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field

from vordur.security.types import DetectedSpan, Detector, PIIClass

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _digits(s: str) -> str:
    return "".join(ch for ch in s if ch.isdigit())


def luhn_valid(value: str) -> bool:
    """Luhn check. Rejects the vast majority of digit runs that look like cards."""
    ds = _digits(value)
    if not 13 <= len(ds) <= 19:
        return False
    total = 0
    parity = len(ds) % 2
    for i, ch in enumerate(ds):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


#: (low, high, prefix_digits, allowed PAN lengths) for UNLABELLED detection.
#: Deliberately restricted to the major schemes with stable, well-known ranges.
#: Successive attempts to enumerate every assigned range kept omitting some and
#: assigning wrong lengths to others, because the assignments change and a table
#: compiled into a library is stale on release. A PAN outside these is covered
#: when labelled, exactly as national phone formats outside the NANP are.
_IIN_RANGES: tuple[tuple[int, int, int, frozenset[int]], ...] = (
    (34, 34, 2, frozenset({15})),
    (37, 37, 2, frozenset({15})),
    (4, 4, 1, frozenset({13, 16, 19})),
    (51, 55, 2, frozenset({16})),
    (2221, 2720, 4, frozenset({16})),
    (6011, 6011, 4, frozenset({16, 19})),
    # Discover 8-digit ranges. Removing these in round six was wrong: they are
    # published assignments, not speculative additions, and dropping them made
    # legitimate 17 to 19 digit PANs invisible.
    (62212600, 62379699, 8, frozenset({16, 17, 18, 19})),
    (64400000, 65899999, 8, frozenset({16, 17, 18, 19})),
    (81000000, 81719999, 8, frozenset({16, 17, 18, 19})),
    (644, 649, 3, frozenset({16, 19})),
    (65, 65, 2, frozenset({16, 19})),
    (36, 36, 2, frozenset({14, 15, 16})),
    (300, 305, 3, frozenset({14, 16})),
    # Discover-acquired Diners ranges, from the Global Network IIN summary.
    # Where a range overlaps a classic Diners prefix the length sets are
    # unioned, because both assignments are live: 14 digits as Diners, 16 to 19
    # as Discover. Letting the more specific range replace rather than extend
    # would make one of the two invisible.
    (30000000, 30599999, 8, frozenset({14, 16, 17, 18, 19})),
    (38000000, 39999999, 8, frozenset({14, 16, 17, 18, 19})),
    (60110000, 60119999, 8, frozenset({16, 17, 18, 19})),
    (30880000, 30949999, 8, frozenset({16, 17, 18, 19})),
    (30950000, 30959999, 8, frozenset({16, 17, 18, 19})),
    (30960000, 31029999, 8, frozenset({16, 17, 18, 19})),
    (31120000, 31209999, 8, frozenset({16, 17, 18, 19})),
    (31580000, 31599999, 8, frozenset({16, 17, 18, 19})),
    (33370000, 33499999, 8, frozenset({16, 17, 18, 19})),
    (3528, 3589, 4, frozenset({16, 17, 18, 19})),
    # MIR, Elo, Hipercard, RuPay, UATP. Added in round four on evidence that
    # they were crossing in plaintext; dropping them in round six under a
    # "restriction" rationale was the error, not their inclusion.
    #
    # UATP (1xxx, 15 digits) is deliberately NOT here. Its prefix is one digit
    # wide, so it claimed any Luhn-valid 15-digit run, which is roughly one in
    # ten: "asset107977945423854archive" became a card token. Excluding
    # letter-adjacent digits would have fixed that, but it also rejected real
    # PANs glued to a payment code, which is how records actually carry them.
    # UATP is covered by the labelled path instead.
    (2200, 2204, 4, frozenset({16, 17, 18, 19})),
    (506699, 506699, 6, frozenset({16, 17, 18, 19})),
    (509000, 509999, 6, frozenset({16, 17, 18, 19})),
    (606282, 606282, 6, frozenset({16, 17, 18, 19})),
    (637095, 637095, 6, frozenset({16})),
    (508, 508, 3, frozenset({16})),
    (82, 82, 2, frozenset({16, 17, 18, 19})),
    (62, 62, 2, frozenset({16, 17, 18, 19})),
    (50, 50, 2, frozenset({12, 13, 14, 15, 16, 17, 18, 19})),
    (56, 58, 2, frozenset({12, 13, 14, 15, 16, 17, 18, 19})),
    (67, 67, 2, frozenset({12, 13, 14, 15, 16, 17, 18, 19})),
)


def _allowed_lengths(ds: str) -> frozenset[int] | None:
    """Most specific matching IIN range wins."""
    best: tuple[int, frozenset[int]] | None = None
    for low, high, width, lengths in _IIN_RANGES:
        if len(ds) < width:
            continue
        if low <= int(ds[:width]) <= high and (best is None or width > best[0]):
            best = (width, lengths)
    return best[1] if best else None


def labelled_card_valid(value: str) -> bool:
    """A labelled PAN needs only Luhn: the label supplies the intent."""
    return luhn_valid(value)


def card_valid(value: str) -> bool:
    """Luhn, a recognized IIN range, and a length that range assigns."""
    ds = _digits(value)
    if not 12 <= len(ds) <= 19:
        return False
    lengths = _allowed_lengths(ds)
    if lengths is None or len(ds) not in lengths:
        return False
    return luhn_valid(value)


def iban_valid(value: str) -> bool:
    """ISO 13616 mod-97 check."""
    compact = re.sub(r"[\s-]", "", value).upper()
    if not 15 <= len(compact) <= 34:
        return False
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def routing_valid(value: str) -> bool:
    """ABA routing transit number checksum."""
    ds = _digits(value)
    if len(ds) != 9:
        return False
    w = (3, 7, 1, 3, 7, 1, 3, 7, 1)
    return sum(int(d) * k for d, k in zip(ds, w, strict=True)) % 10 == 0


def ssn_valid(value: str) -> bool:
    """Reject SSN area/group/serial combinations the SSA never issues.

    Area 000, 666, and 900-999 are unissued; group 00 and serial 0000 are
    unissued. Screening these out is what keeps ordinary 3-2-4 digit runs
    (part numbers, phone fragments) from being vaulted.
    """
    ds = _digits(value)
    if len(ds) != 9:
        return False
    area, group, serial = int(ds[:3]), int(ds[3:5]), int(ds[5:])
    if area == 0 or area == 666 or area >= 900:
        return False
    return group != 0 and serial != 0


def ipv4_valid(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 and (p == "0" or not p.startswith("0")) for p in parts)
    except ValueError:
        return False


#: Assigned E.164 country calling codes, longest first so "1" does not shadow
#: "1876". A compact international number is otherwise indistinguishable from a
#: signed integer, and treating every "+" followed by digits as a phone number
#: tokenizes counters, deltas, and version strings in code and logs.
_E164_COUNTRY_CODES = (
    "998 996 995 994 993 992 977 976 975 974 973 972 971 970 968 967 966 965 964 963 962 961 960 "
    "886 880 878 875 874 873 872 871 870 856 855 853 852 850 800 692 691 690 689 688 687 686 685 "
    "683 682 681 680 679 678 677 676 675 674 673 672 670 599 598 597 596 595 594 593 592 591 590 "
    "509 508 507 506 505 504 503 502 501 500 423 421 420 389 387 386 385 383 382 381 380 378 377 "
    "376 375 374 373 372 371 370 359 358 357 356 355 354 353 352 351 350 299 298 297 291 290 269 "
    "268 267 266 265 264 263 262 261 260 258 257 256 255 254 253 252 251 250 249 248 246 245 244 "
    "243 242 241 240 239 238 237 236 235 234 233 232 231 230 229 228 227 226 225 224 223 222 221 "
    "220 218 216 213 212 211 98 95 94 93 92 91 90 86 84 82 81 66 65 64 63 62 61 60 58 57 56 55 54 "
    "991 979 888 883 882 881 878 870 808 800 297 290 269 268 247 246 "
    "53 52 51 49 48 47 46 45 44 43 41 40 39 36 34 33 32 31 30 27 20 7 1"
).split()


def e164_valid(value: str) -> bool:
    """Accept an international number on deterministic evidence.

    Requires an assigned country calling code and a length E.164 permits. A
    *compact* number additionally needs 11 digits, because a bare "+" followed
    by a short digit run is indistinguishable from a signed integer and
    tokenizing "+123456789" in a diff corrupts content the model was asked to
    reason about. Separated forms carry that evidence in their punctuation, so
    they are accepted from 8 digits: "+47 22 59 13 00" and "+65 6123 4567" are
    ordinary numbers that a universal 11-digit floor rejected.
    """
    ds = _digits(value)
    compact = not any(c in value for c in " .-()")
    floor = 11 if compact else 8
    if not floor <= len(ds) <= 15:
        return False
    if not any(ds.startswith(cc) for cc in _E164_COUNTRY_CODES):
        return False
    # A numeric list such as "+1 2 3 4 5 678" satisfies country code plus digit
    # groups. Real plans put at most one single-digit group after the country
    # code (a national trunk or area digit), never a run of them.
    groups = [g for g in re.split(r"[ .\-()]+", value.lstrip("+")) if g]
    return sum(1 for g in groups if len(g) == 1) <= 1


def phone_valid(value: str) -> bool:
    """Validate a candidate against a numbering plan.

    Unlabelled national detection covers the NANP only, where ten digits is a
    reliable signal. Requiring exactly ten digits *everywhere* was a NANP
    assumption applied globally, and it silently missed ordinary numbers from
    the UK, Norway, Denmark, Singapore, Ireland, New Zealand, Germany, and
    India, each of which then crossed the model boundary in plaintext.

    Numbers outside the NANP are covered by their international form, by a
    "tel"/"phone"/"mobile" label, or by host seeding. That boundary is stated
    rather than implied, because the alternative is a hand-maintained table of
    every national plan that silently rots.
    """
    if value.lstrip().startswith("+"):
        return e164_valid(value)
    return len(_digits(value)) == 10


def labelled_phone_valid(value: str) -> bool:
    """A labelled number needs only a plausible length, not a known plan."""
    return 7 <= len(_digits(value)) <= 15


#: Label keywords, normalized. A field whose value *is* its own key name is a
#: schema declaration, not an identifier.
_LABEL_WORDS = frozenset(
    {
        "passport",
        "passportno",
        "passportnumber",
        "medicalrecord",
        "medicalrecordnumber",
        "mrn",
        "nationalid",
        "nationalidentity",
        "driverslicense",
        "driverlicence",
        "driverslicence",
        "dl",
        "ssn",
        "socialsecurity",
        "socialsecuritynumber",
        "none",
        "null",
        "redacted",
        "unknown",
        "string",
        "example",
    }
)


def opaque_id_valid(value: str) -> bool:
    """Accept an opaque identifier that a label has already declared.

    These classes carry no checksum, so requiring a digit was the previous
    guard. That invented a constraint the identifier types do not impose: ICAO
    permits alphabetic passport numbers and FHIR treats an MRN as an opaque
    string, so "Passport: ABCDEFG" and "MRN: ALPHAONE" were silently missed.

    The label plus a mandatory separator is the declaration. What still has to
    be excluded is a field whose value repeats its own key, which is how
    ``PASSPORT = "passport"`` and ``MEDICAL_RECORD = "medical_record"``, both
    real lines in this library, were rewritten as tokens.
    """
    normalized = "".join(c for c in value.casefold() if c.isalnum())
    return bool(normalized) and normalized not in _LABEL_WORDS


def ipv6_valid(value: str) -> bool:
    """Delegate to ipaddress so compressed forms ("2001:db8::1") are accepted.

    The previous pattern required all eight groups written out, so every
    compressed address, which is the form people actually write, went
    undetected and crossed the boundary in plaintext.
    """
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


def dob_valid(value: str) -> bool:
    """Accept only dates whose year is plausible for a date of birth.

    The ceiling is the current year, read at call time. It was a literal
    once, and a literal is right for one year: a child born after it had
    no date of birth as far as this detector was concerned.
    """
    years = re.findall(r"\d{4}", value)
    if not years:
        return False
    return 1900 <= int(years[0]) <= datetime.date.today().year


# ---------------------------------------------------------------------------
# Structural detectors
# ---------------------------------------------------------------------------


#: Opens a label: word boundary plus an optional opening quote, so a JSON key
#: such as {"ssn": ...} is recognized as the same label as prose "SSN:".
_LO = r"(?i:(?<![A-Za-z0-9_])[\"'\u2018\u201c]?"
#: Closes a label: optional quote, then a REQUIRED ':' '=' or 'is', then an
#: optional quote. The separator is mandatory. With it optional, the next
#: ordinary word became the identifier: "routing 021000021 requests" and "The
#: service was born 2019-06-12" both produced tokens, and so did two real
#: lines of this library's own source.
#:
#: Classes whose value grammar supplies its own evidence (a number noun, or a
#: distinctive shape) relax this individually; see the passport spec.
_LC = r"[\"'\u2019\u201d]?\s*(?:[:=]|\bis\b)\s*[\"'\u2018\u201c]?)"
#: Relaxed closer for labels that are not ordinary English words. "MRN 4471902"
#: and "SSN 078051120" are unambiguous without punctuation; "routing 021000021
#: requests" and "The service was born 2019-06-12" are not, which is why the
#: strict closer above is the default and this one is opt-in per label.
_LC_ACRONYM = r"[\"'\u2019\u201d]?\s*(?:[:=]|\bis\b)?\s*[\"'\u2018\u201c]?)"
#: A number noun ("number", "no.", "#") separates a label from its value on
#: its own. Requiring punctuation *after* the noun as well is what made
#: "Routing number 021000021" and "DL no. A1234567" invisible.
#: But a noun standing alone as the separator leaves the next word looking like
#: a value, and these classes have no checksum to reject it, so "Medical record
#: number required" tokenized the word "required". Where an explicit ``:`` or
#: ``=`` follows the noun, the value is whatever was written. Where it does not,
#: the value must at least be shaped like an identifier: containing a digit, or
#: written as an uppercase code. That is the "stronger evidence" an all
#: lowercase English word cannot supply, and it costs only the unpunctuated
#: all-alphabetic-lowercase form, which no issuing authority uses.
#: ``(?-i:`` is load bearing. This is spliced inside the ``(?i:`` group that
#: _LO opens, so an uppercase class here matches lowercase too, and "required"
#: satisfied the uppercase-code alternative exactly as before the guard existed.
_CODE_SHAPED = r"(?=\S*\d|(?-i:[A-Z][A-Z0-9]{2,})(?![A-Za-z]))"
#: Three ways past a number noun, in decreasing order of evidence. An explicit
#: ``:`` or ``=`` takes the value as written. A quote is structural delimiting
#: and does the same, which is what carries the lowercase opaque identifiers
#: that hospitals and host applications really do issue: "Patient medical
#: record number 'abcdefg'". With neither, the value must at least be shaped
#: like an identifier, or the word after the noun in "Medical record number
#: required" becomes the value. The bare lowercase alphabetic form is NOT
#: covered and is not claimed to be; see SeededValues for declaring those.
_SEP_NOUN = (
    r"[\s_]*(?:number|no\.?|#)[\"'’”]?\s*"
    r"(?:[:=]\s*[\"'‘“]?"
    r"|[\"'‘“]"
    r"|" + _CODE_SHAPED + r")"
)
_SEP_STRICT = r"[\"'’”]?\s*(?:[:=]|\bis\b)\s*[\"'‘“]?"


#: Which closer each label keyword takes, declared once so the choice cannot
#: drift out of sync with the patterns that use it. A source-integrity test can
#: confirm the two closers differ; only a table like this lets a behavioural
#: test check every label with and without punctuation, which is how DOB, ABA,
#: RTN, and DL were found still requiring a colon after the fix that was
#: supposed to relax them.
#:
#: ACRONYM: not an ordinary English word, so whitespace alone is evidence.
#: STRICT:  also an ordinary word, so punctuation is required, or "routing 3
#:          packets" and "The service was born 2019-06-12" become findings.
LABEL_CLOSERS: dict[str, str] = {
    # acronyms and unambiguous keyword labels
    "ssn": "acronym",
    "social security": "acronym",
    "mrn": "acronym",
    "dob": "acronym",
    "date of birth": "acronym",
    "aba": "acronym",
    "rtn": "acronym",
    # Strict despite being an acronym: two letters that appear constantly in
    # build configuration, where an optional separator matched INCLDIR and
    # LLIBRARY as licence numbers.
    "dl": "strict",
    "tel": "acronym",
    "telephone": "acronym",
    "phone": "acronym",
    "mobile": "acronym",
    "fax": "acronym",
    "cardnumber": "acronym",
    "credit card": "acronym",
    # also ordinary English words
    "routing": "strict",
    "born": "strict",
    "birth date": "strict",
    "medical record": "strict",
    "contact": "strict",
    "card": "strict",
    "pan": "strict",
    "passport": "strict",
    "national id": "strict",
    "drivers license": "strict",
}


@dataclass(frozen=True)
class DetectorSpec:
    pii_class: PIIClass
    group: str
    pattern: str
    validator: object | None = None


#: Order matters only for tie-breaking inside `re`'s alternation; genuine
#: overlap is resolved structurally in `_resolve_overlaps`, not by this order.
_DETECTORS: tuple[DetectorSpec, ...] = (
    # The lookbehind is what keeps this linear. Without it, every position
    # inside a long run of local-part characters is a fresh start for the
    # greedy class, which then walks to the end of the run looking for an
    # "@" and backtracks: quadratic in the run, and a base64 blob is one run.
    # Measured at 1.0s for 40,000 characters. Leftmost matching already
    # began every match at the start of its run, so refusing to start inside
    # one changes no result, only the cost.
    DetectorSpec(
        PIIClass.EMAIL,
        "email",
        r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    ),
    DetectorSpec(
        PIIClass.IBAN,
        "iban",
        r"(?i:\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{4}){2,7}[ -]?[A-Z0-9]{1,4})\b",
        iban_valid,
    ),
    DetectorSpec(
        PIIClass.CREDIT_CARD,
        "credit_card",
        # (3) Enumerating layouts missed valid grouped lengths: 4-4-4-1 for a
        # 13-digit Visa, 4-4-4-4-3 for a 19-digit one, 4-5-6 for UATP. Match
        # any consistently separated run of digit groups instead and let
        # card_valid judge the reconstructed digits.
        #
        # (5) The left and right guards exclude letters as well as digits and
        # separators. Excluding only digits let a Luhn-valid 15-digit run
        # inside a larger identifier match: "asset107977945423854archive"
        # became a card token.
        r"(?<![.\d\-])(?:"
        r"\d{12,19}"
        # Separators must be consistent within a grouping. Allowing them to mix
        # let "3892 713-853-3989", a street number followed by a phone number,
        # match the Diners 4-3-3-4 form and become one card token: 127 such
        # matches in the benign corpus. Written out per separator rather than
        # with a backreference, because a named backreference inside this
        # combined alternation would confuse the lastgroup dispatch in detect().
        # Consistently separated groups, one separator kind per candidate.
        # Mixing them let "3892 713-853-3989", a street number and a phone
        # number, merge into one Luhn-valid Diners card 127 times in the
        # benign corpus.
        # The first group is always four digits in a real presentation
        # (4-4-4-4, 4-6-5 Amex, 4-3-3-4 Diners, 4-5-6 UATP, 4-4-4-4-3). Letting
        # it be any width re-merged "580832 580137 580136", three deal numbers,
        # into one Luhn-valid 18-digit Maestro.
        # Groups after the first are three to six digits, with at most a short
        # trailing group (the 13-digit Visa 4-4-4-1). Allowing one and two
        # digit groups anywhere merged numeric tables: "1100 1 2 1200 3 1200"
        # became a Luhn-valid 15-digit UATP account.
        r"|\d{4}(?: \d{3,6}){1,4}(?: \d{1,2})?"
        r"|\d{4}(?:-\d{3,6}){1,4}(?:-\d{1,2})?"
        r")(?![.\d\-])",
        card_valid,
    ),
    DetectorSpec(
        PIIClass.CREDIT_CARD,
        "credit_card_labelled",
        # A number noun is its own separator, so "card number 9468..." works.
        # Bare "card" and "pan" are ordinary English words and need an explicit
        # one, or "the card is 12 of 52" becomes a candidate.
        # UATP belongs on this branch too. It is absent from the unlabelled IIN
        # table on purpose (a one digit prefix over-matches), so the labelled
        # path is its only detector, and without the number nouns here "UATP
        # account number 1354..." was a plaintext PAN.
        rf"(?:{_LO}(?:card|credit[\s_]card|uatp(?:[\s_]*(?:card|account))?)"
        r"[\s_]*(?:number|no\.?|#)"
        r"[\"'’”]?\s*[:=]?\s*[\"'‘“]?)"
        rf"|{_LO}(?:cardnumber|credit[\s_]card|uatp(?:[\s_]*account)?){_LC_ACRONYM}"
        rf"|{_LO}(?:card|pan){_LC})"
        r"(?P<credit_card_labelled_v>(?:\d[ -]?){12,18}\d)",
        labelled_card_valid,
    ),
    DetectorSpec(
        PIIClass.SSN,
        "ssn",
        rf"(?:{_LO}(?:ssn|ss[#_]?no|social[\s_]*security)(?:[\s_]*(?:number|no\.?|#))?{_LC_ACRONYM}"
        r"(?P<ssn_v>\d{3}[-\s]?\d{2}[-\s]?\d{4})\b"
        r"|\b\d{3}-\d{2}-\d{4}\b)",
        ssn_valid,
    ),
    DetectorSpec(
        PIIClass.ROUTING_NUMBER,
        "routing_number",
        rf"(?:{_LO}(?:aba|rtn)(?:[\s_]*(?:number|no\.?|#))?{_LC_ACRONYM}"
        rf"|{_LO}routing(?:{_SEP_NOUN}|{_SEP_STRICT})))"
        r"(?P<routing_number_v>\d{9})\b",
        routing_valid,
    ),
    DetectorSpec(
        PIIClass.IPV6,
        "ipv6",
        r"(?<![:.\w])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![:.\w])",
        ipv6_valid,
    ),
    DetectorSpec(
        PIIClass.IPV4,
        "ipv4",
        r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
        ipv4_valid,
    ),
    DetectorSpec(
        PIIClass.MAC,
        "mac",
        r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
    ),
    DetectorSpec(
        PIIClass.PHONE,
        "phone",
        r"(?:\+\d{1,4}(?:[ .\-]\(?\d{1,9}\)?){1,6}\b"
        r"|(?:\+\d{1,3}[ .\-]?)?\(\d{3}\)[ .\-]?\d{3}[ .\-]\d{4}\b"
        r"|(?:\+\d{1,3}[ .\-]?)?\b\d{3}[.\-]\d{3}[.\-]\d{4}\b"
        r"|(?<![\w.+-])\+\d{11,15}(?![\d.]))",
        phone_valid,
    ),
    DetectorSpec(
        PIIClass.PHONE,
        "phone_labelled",
        # "contact" is an ordinary verb and noun, so it needs a real separator:
        # "contact 1234567 customers" was a false positive. The rest are used
        # as labels far more often than as prose before a long digit run, and
        # labelled_phone_valid still requires 7 to 15 digits.
        rf"(?:{_LO}(?:tel|telephone|phone|mobile|cell[\s_]?phone|fax)"
        rf"(?:[\s_]*(?:number|no\.?|#))?{_LC_ACRONYM}"
        rf"|{_LO}contact(?:{_SEP_NOUN}|{_SEP_STRICT})))"
        r"(?P<phone_labelled_v>\+?[\d][\d .()\-]{5,19}\d)",
        labelled_phone_valid,
    ),
    DetectorSpec(
        PIIClass.DATE_OF_BIRTH,
        "date_of_birth",
        rf"(?:{_LO}(?:dob|date[\s_]*of[\s_]*birth){_LC_ACRONYM}"
        rf"|{_LO}(?:birth[\s_]*date|born){_LC})"
        r"(?P<date_of_birth_v>\d{4}-\d{2}-\d{2}|\d{1,2}[/-]\d{1,2}[/-]\d{4}|"
        r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4})",
        dob_valid,
    ),
    DetectorSpec(
        PIIClass.MEDICAL_RECORD,
        "medical_record",
        # "MRN" is an acronym, so whitespace alone is enough evidence.
        # "medical record" is an ordinary phrase and needs a real separator,
        # or "The medical record contains allergies" becomes a finding.
        rf"(?:{_LO}mrn{_LC_ACRONYM}"
        rf"|{_LO}medical[\s_]*record(?:{_SEP_NOUN}|{_SEP_STRICT})))"
        r"(?P<medical_record_v>[A-Za-z0-9][A-Za-z0-9\-_]{3,19})",
        opaque_id_valid,
    ),
    # No checksum exists for these, so they are matched only with a labelling
    # context. An unanchored pattern would be mostly false positives, and a
    # detector that fires on ordinary text is worse than no detector: it
    # substitutes values the model needed and teaches operators to disable it.
    DetectorSpec(
        PIIClass.PASSPORT,
        "passport",
        rf"{_LO}passport(?:[\s_]*(?:number|no\.?|#)[\"'’”]?\s*[:=]?\s*[\"'‘“]?"
        r"|[\"'’”]?\s*[:=]\s*[\"'‘“]?))"
        r"(?P<passport_v>[A-Za-z0-9]{6,9})\b",
        opaque_id_valid,
    ),
    DetectorSpec(
        PIIClass.DRIVERS_LICENSE,
        "drivers_license",
        rf"(?:{_LO}dl(?:{_SEP_NOUN}|{_SEP_STRICT}))"
        rf"|{_LO}driver'?s?[\s_]*licen[cs]e(?:{_SEP_NOUN}|{_SEP_STRICT})))"
        r"(?P<drivers_license_v>[A-Za-z0-9][A-Za-z0-9\-_]{4,19})\b",
        opaque_id_valid,
    ),
    DetectorSpec(
        PIIClass.NATIONAL_ID,
        "national_id",
        rf"{_LO}national[\s_]*id(?:entity)?(?:{_SEP_NOUN}|{_SEP_STRICT}))"
        r"(?P<national_id_v>[A-Za-z0-9][A-Za-z0-9\-_]{4,19})\b",
        opaque_id_valid,
    ),
    DetectorSpec(
        PIIClass.URL,
        "url",
        r"https?://[^\s<>\"']+",
    ),
)


#: Classes the shipped structural patterns can find unaided. Every other member
#: of ``PIIClass`` needs a host-seeded value (tier 2) or a registered
#: ``Detector`` (tier 3) before anything looks for it at all. PERSON and ADDRESS
#: are the two that matter in practice: the module docstring above explains why
#: the library declines to infer them from free text, and ``_uncovered_classes``
#: in privacy_vault reports when a deployment has enabled one anyway.
STRUCTURAL_CLASSES: frozenset[PIIClass] = frozenset(d.pii_class for d in _DETECTORS)


#: Maps every group name in a compiled alternation, both the detector group and
#: its optional inner value group, to the spec and the value group to read.
#: Precomputed so the match loop does no string building and no membership test
#: per match; on a PII-dense document that loop runs tens of thousands of times.
def _group_info(pattern: re.Pattern[str]) -> dict[str, tuple[DetectorSpec, str | None]]:
    info: dict[str, tuple[DetectorSpec, str | None]] = {}
    for d in _DETECTORS:
        if d.group not in pattern.groupindex:
            continue
        vgroup = f"{d.group}_v"
        vgroup = vgroup if vgroup in pattern.groupindex else None
        info[d.group] = (d, vgroup)
        if vgroup:
            info[vgroup] = (d, vgroup)
    return info


#: Compiling only the requested classes skips whole detectors rather than
#: matching and discarding them. The default class set omits IPv4, IPv6, MAC,
#: and URL, which is four of fifteen alternatives and two of the more expensive
#: ones. Cached because a session's class set does not change between calls.
#:
#: This replaced a single alternation over every detector, compiled at import.
#: That one, its group map, and a by-group index of the registry were left
#: behind unreferenced when the cache landed, and are gone: one compiled
#: alternation nothing consulted, built at import for every process that
#: imported the module.
_SUBSET_CACHE: dict[frozenset[PIIClass], tuple[re.Pattern[str], dict]] = {}


def _compiled_for(classes: frozenset[PIIClass]) -> tuple[re.Pattern[str], dict]:
    hit = _SUBSET_CACHE.get(classes)
    if hit is not None:
        return hit
    wanted = [d for d in _DETECTORS if d.pii_class in classes]
    if not wanted:
        compiled = re.compile(r"(?!x)x")  # matches nothing
        entry = (compiled, {})
    else:
        compiled = re.compile("|".join(f"(?P<{d.group}>{d.pattern})" for d in wanted))
        entry = (compiled, _group_info(compiled))
    _SUBSET_CACHE[classes] = entry
    return entry


# ---------------------------------------------------------------------------
# Seeded values
# ---------------------------------------------------------------------------


class _AhoCorasick:
    """Multi-pattern exact matcher, built once and reused across calls.

    Used above _SEEDED_AUTOMATON_THRESHOLD entries so a large roster stays a
    single pass rather than N independent scans.
    """

    __slots__ = ("_goto", "_fail", "_out")

    def __init__(self, patterns: dict[str, PIIClass]) -> None:
        self._goto: list[dict[str, int]] = [{}]
        self._fail: list[int] = [0]
        self._out: list[list[tuple[str, PIIClass]]] = [[]]
        for pat, cls in patterns.items():
            node = 0
            for ch in pat:
                nxt = self._goto[node].get(ch)
                if nxt is None:
                    nxt = len(self._goto)
                    self._goto.append({})
                    self._fail.append(0)
                    self._out.append([])
                    self._goto[node][ch] = nxt
                node = nxt
            self._out[node].append((pat, cls))
        queue: deque[int] = deque()
        for nxt in self._goto[0].values():
            queue.append(nxt)
        while queue:
            node = queue.popleft()
            for ch, nxt in self._goto[node].items():
                queue.append(nxt)
                f = self._fail[node]
                while f and ch not in self._goto[f]:
                    f = self._fail[f]
                cand = self._goto[f].get(ch, 0)
                self._fail[nxt] = cand if cand != nxt else 0
                self._out[nxt].extend(self._out[self._fail[nxt]])

    def find(self, haystack: str) -> list[tuple[int, int, PIIClass]]:
        hits: list[tuple[int, int, PIIClass]] = []
        node = 0
        for i, ch in enumerate(haystack):
            while node and ch not in self._goto[node]:
                node = self._fail[node]
            node = self._goto[node].get(ch, 0)
            for pat, cls in self._out[node]:
                hits.append((i - len(pat) + 1, i + 1, cls))
        return hits


_SEEDED_AUTOMATON_THRESHOLD = 100


def _fold_with_offsets(text: str) -> tuple[str, list[int] | None]:
    """Case-fold, returning an index map only when folding changes length.

    Almost all text folds one-to-one, so the common path returns ``None`` and
    the caller uses folded offsets directly. Building one Python integer per
    character unconditionally cost ~84MB on a 1MB input, and there is no
    inbound size limit, so a multi-megabyte document in a deployment using
    seeded names could exhaust memory.
    """
    folded = text.casefold()
    if len(folded) == len(text):
        return folded, None
    out: list[str] = []
    offsets: list[int] = []
    for i, ch in enumerate(text):
        f = ch.casefold()
        out.append(f)
        offsets.extend([i] * len(f))
    return "".join(out), offsets


def _standalone(text: str, start: int, end: int) -> bool:
    """True when the span is not embedded inside a longer alphanumeric run."""
    if start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
        return False
    if end < len(text) and (text[end].isalnum() or text[end] == "_"):
        return False
    return True


class SeededValues:
    """Host-declared private values, matched exactly after normalization."""

    def __init__(self) -> None:
        self._values: dict[str, PIIClass] = {}
        self._classes: set[PIIClass] = set()
        self._automaton: _AhoCorasick | None = None
        self._dirty = False

    def __len__(self) -> int:
        return len(self._values)

    def add(self, values: dict[str, PIIClass]) -> None:
        for raw, cls in values.items():
            norm = raw.strip().casefold()
            if norm:
                self._values[norm] = cls
                self._classes.add(cls)
        self._dirty = True

    def classes(self) -> frozenset[PIIClass]:
        """Which classes any declared value could match.

        Tracked as values are added rather than derived on demand: this is read
        once per de-identification call to decide whether a configured class has
        anything looking for it, and a deployment can seed thousands of values.
        """
        return frozenset(self._classes)

    def clear(self) -> None:
        self._values.clear()
        self._classes.clear()
        self._automaton = None
        self._dirty = False

    def items(self) -> tuple[tuple[str, PIIClass], ...]:
        """The declared values and their classes, for persistence.

        Normalized rather than as the host wrote them: ``add`` folds on the way
        in and the original casing is not kept, so this is what a reload has to
        restore to reproduce the same matches.
        """
        return tuple(self._values.items())

    def find(self, text: str) -> list[tuple[int, int, PIIClass]]:
        """Locate seeded values, returning offsets into the ORIGINAL text.

        Case folding is not length preserving: ``"\u00df".casefold()`` is
        ``"ss"``, so every match after one in the text would be reported at a
        shifted offset and the substitution would cut the wrong characters.
        A per-character fold with an index map avoids that.

        Matches must also stand alone. Unrestricted substring matching means
        seeding a real short surname such as "Li" tokenizes the middle of
        "Alice", corrupting content the model needed and leaving the actual
        name in place.
        """
        if not self._values:
            return []
        folded, offsets = _fold_with_offsets(text)
        if len(self._values) > _SEEDED_AUTOMATON_THRESHOLD:
            if self._automaton is None or self._dirty:
                self._automaton = _AhoCorasick(self._values)
                self._dirty = False
            raw = self._automaton.find(folded)
        else:
            raw = []
            for needle, cls in self._values.items():
                start = folded.find(needle)
                while start != -1:
                    raw.append((start, start + len(needle), cls))
                    start = folded.find(needle, start + 1)

        hits: list[tuple[int, int, PIIClass]] = []
        for fs, fe, cls in raw:
            if not _standalone(folded, fs, fe):
                continue
            if offsets is None:
                hits.append((fs, fe, cls))
                continue
            if fs >= len(offsets) or fe - 1 >= len(offsets):
                continue
            hits.append((offsets[fs], offsets[fe - 1] + 1, cls))
        return hits


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RawMatch:
    pii_class: PIIClass
    start: int
    end: int
    value: str
    inferred: bool = False


@dataclass
class DetectionResult:
    matches: list[RawMatch]
    #: Spans that overlap partially without containment. Reported rather than
    #: resolved: inventing a precedence rule to break a genuine ambiguity is
    #: how a detector quietly substitutes the wrong span.
    ambiguous: list[tuple[RawMatch, RawMatch]]
    #: Credentials detectable only in a deobfuscated form, so they have no
    #: faithful span to substitute. The caller must refuse the content.
    unlocatable_credentials: list[str] = field(default_factory=list)
    #: Per-detector rejection and failure reasons, for warnings and audit.
    #: Never carries a span or a value, only a detector id and a cause.
    detector_warnings: list[str] = field(default_factory=list)
    #: True when at least one registered detector could not be run. Distinct
    #: from finding nothing: the caller decides what that means for its entry
    #: point, because refusing untrusted inbound content on a flaky detector
    #: would let any web page take out the host's pipeline.
    detection_incomplete: bool = False


def _spans_overlap(a: RawMatch, b: RawMatch) -> bool:
    return a.start < b.end and b.start < a.end


def _contains(outer: RawMatch, inner: RawMatch) -> bool:
    return outer.start <= inner.start and inner.end <= outer.end


def _resolve_overlaps(matches: list[RawMatch]) -> DetectionResult:
    """Keep containing spans, drop contained ones, flag partial overlaps.

    A validated structural span that contains another wins: a card number
    inside a longer identifier, an email that swallows a bare domain. Partial
    overlap without containment is genuinely ambiguous and is surfaced instead
    of being decided by a made-up class-priority table.

    Inferred spans resolve by a stricter rule: an inferred span overlapping a
    validated one loses outright, contained, containing, or partial. A checksum
    beats a model. Without this, a tier-3 detector returning a generous PERSON
    span across "Dana, SSN 123-45-6789" would evict the validated SSN and get
    the digits vaulted as PERSON, and restoration reads the class recorded at
    issuance, so a destination entitled to names would receive an SSN. Two
    inferred spans that overlap remain ambiguous, exactly as two validated ones.
    """
    # Validated spans are placed first so an inferred span can never be the
    # incumbent that a validated one has to displace.
    ordered = sorted(matches, key=lambda m: (m.inferred, m.start, -(m.end - m.start)))
    validated = [m for m in ordered if not m.inferred]
    # An inferred span overlapping a validated one is trimmed to its
    # non-overlapping remainder rather than discarded. Dropping it outright
    # meant a detector marking "Jane Doe <jane@example.com>" as PERSON lost the
    # whole span to the validated email, so the name crossed in plaintext while
    # the address was protected. A checksum still beats a model on the bytes
    # they disagree about; it says nothing about the bytes it never covered.
    trimmed: list[RawMatch] = []
    for cand in ordered:
        if not cand.inferred:
            trimmed.append(cand)
            continue
        # Subtract every validated span from the inferred one and keep all
        # surviving pieces. Keeping only the left remainder lost the second
        # name in "Jane Doe <jane@example.com> Smith".
        pieces = [(cand.start, cand.end)]
        for v in validated:
            nxt: list[tuple[int, int]] = []
            for lo, hi in pieces:
                if v.end <= lo or hi <= v.start:
                    nxt.append((lo, hi))
                    continue
                if lo < v.start:
                    nxt.append((lo, v.start))
                if v.end < hi:
                    nxt.append((v.end, hi))
            pieces = nxt
        for lo, hi in pieces:
            raw_text = cand.value[lo - cand.start : hi - cand.start]
            stripped = raw_text.strip()
            if len(stripped) < 2:
                continue
            lead = len(raw_text) - len(raw_text.lstrip())
            trimmed.append(
                RawMatch(
                    cand.pii_class,
                    lo + lead,
                    lo + lead + len(stripped),
                    stripped,
                    inferred=True,
                )
            )

    kept: list[RawMatch] = []
    ambiguous: list[tuple[RawMatch, RawMatch]] = []
    for cand in trimmed:
        replaced = False
        drop = False
        for i, existing in enumerate(kept):
            if not _spans_overlap(cand, existing):
                continue
            if cand.inferred and not existing.inferred:
                # Trimming above removed any overlap with a validated span, so
                # reaching here means the remainder still touches one. Drop it.
                drop = True
                break
            if (
                cand.inferred
                and existing.inferred
                and cand.start == existing.start
                and cand.end == existing.end
            ):
                if cand.pii_class is existing.pii_class:
                    drop = True  # identical span and class: deduplicate
                else:
                    # Two detectors claiming the same span under different
                    # classes is ambiguous, and registration order must not
                    # decide it: the class chosen governs restoration, so a
                    # field permitting PERSON but not ADDRESS would admit the
                    # value purely because detectors were registered in a
                    # different order.
                    ambiguous.append((existing, cand))
                    drop = True
                break
            if _contains(existing, cand):
                drop = True
                break
            if _contains(cand, existing):
                kept[i] = cand
                replaced = True
                break
            ambiguous.append((existing, cand))
            drop = True
            break
        if not drop and not replaced:
            kept.append(cand)
    kept.sort(key=lambda m: m.start)
    return DetectionResult(kept, ambiguous)


def _run_detector(detector: Detector, text: str) -> tuple[list[DetectedSpan], str | None]:
    """Run one tier-3 detector and validate every span it returns.

    Returns ``(spans, None)`` on success, or ``([], reason)`` when the detector
    could not be used at all. A detector that raises is a failure, not an empty
    result: "we do not know what is in this text" is a different state from "the
    text is clean", and conflating them is how a misconfigured detector turns
    into silent non-coverage.

    Individual malformed spans are dropped, not repaired. The two available
    repairs, widening and narrowing, leak in opposite directions, and a wrong
    ``end`` offset raises nothing on its own: it substitutes a token over the
    wrong span, leaving the tail of a real identifier in text bound for the
    provider. Dropping is the only choice that fails in a direction we can name.
    """
    detector_id = getattr(detector, "id", None)
    if not isinstance(detector_id, str) or not detector_id:
        return [], "detector rejected: missing a string `id`"

    declared = getattr(detector, "classes", None)
    if not isinstance(declared, frozenset | set) or not declared:
        return [], f"detector {detector_id!r} rejected: no declared `classes`"

    find = getattr(detector, "find", None)
    if not callable(find):
        # The previous duck-typed check silently skipped an object with no
        # `find`, so a misconfigured detector produced zero coverage and zero
        # warnings. Registration is an assertion that detection will happen.
        return [], f"detector {detector_id!r} rejected: no callable `find`"

    # Materialize inside the boundary. Catching only the call left three
    # escapes: a generator that raises after yielding, a non-iterable return,
    # and an attribute read that raises. The first two propagated out of the
    # library; all three mean coverage is unknown, not clean.
    try:
        raw = find(text)
        if raw is None:
            return [], f"detector {detector_id!r} returned None"
        raw = list(raw)
    except Exception as exc:  # noqa: BLE001 - host code, any failure is ours to report
        return [], f"detector {detector_id!r} raised {type(exc).__name__}"

    limit = len(text)
    kept: list[DetectedSpan] = []
    rejected = 0
    seen: set[tuple[int, int, PIIClass]] = set()
    for span in raw:
        try:
            start = getattr(span, "start", None)
            end = getattr(span, "end", None)
            cls = getattr(span, "pii_class", None)
            confidence = getattr(span, "confidence", None)
        except Exception:  # noqa: BLE001 - a property that raises is a failure
            rejected += 1
            continue
        # bool is an int subclass; a True offset is a bug, not a position.
        if not isinstance(start, int) or isinstance(start, bool):
            rejected += 1
            continue
        if not isinstance(end, int) or isinstance(end, bool):
            rejected += 1
            continue
        if not isinstance(cls, PIIClass):
            rejected += 1
            continue
        if not (0 <= start < end <= limit):
            rejected += 1
            continue
        if cls not in declared:
            # A detector may not widen its own remit at runtime.
            rejected += 1
            continue
        key = (start, end, cls)
        if key in seen:
            continue
        seen.add(key)
        kept.append(DetectedSpan(start, end, cls, confidence))

    if raw and not kept:
        # Every span rejected. Returning an empty success here reported clean
        # coverage for a detector that produced nothing usable, which is the
        # silent non-coverage this protocol exists to prevent.
        return [], (f"detector {detector_id!r} returned {len(raw)} span(s), none valid")
    if rejected:
        return kept, f"detector {detector_id!r}: {rejected} invalid span(s) dropped"
    return kept, None


def credential_spans(text: str) -> tuple[list[tuple[int, int]], list[str]]:
    """Locate credentials using L3's complete scanner, not a subset of it.

    Delegates to ``outbound_dlp.scan_secret_spans`` so the model-boundary
    denier and the egress blocker consume the same findings. Reusing only the
    regex table left high-entropy and hex-encoded secrets crossing inbound
    while L3 blocked the identical values outbound.
    """
    from vordur.security.outbound_dlp import scan_secret_spans

    return scan_secret_spans(text)


def _normalize_for_detection(text: str) -> tuple[str, list[int] | None]:
    """Fold Unicode digits and drop invisible characters for the regex pass.

    Two evasions defeat detection that runs on raw text, and both are the same
    shape: the pattern is written for ASCII and the identifier is not.

    - A zero-width space inside ``jane<ZWSP>@example.com`` breaks the email
      pattern, so the address reached the model with no finding.
    - Arabic-Indic digits are ``isdigit()``-true but are not ``[0-9]``, so a
      PAN written in them never matched the credit-card pattern, and the Luhn
      validator's ``ord(ch) - 48`` was ASCII-only regardless.

    Returns ``(normalized, offsets)`` where ``offsets[k]`` is the ORIGINAL
    index of ``normalized[k]``. Detection runs on the normalized copy and every
    span is mapped back through ``offsets``, so a match spanning a removed
    invisible maps to an original span that still contains it: substitution
    cuts the whole run, token and hidden character together, and no orphan is
    left behind.

    The transform is per character, so the map is exact: a decimal digit
    becomes one ASCII digit (length preserved), a format character (category
    ``Cf``: zero-width, bidi, tag-plane, soft hyphen) is dropped, anything else
    is kept. Deliberately not NFC or confusable folding, which are the outbound
    normalizer's job and are not length-per-character; this closes exactly the
    two evasion classes above and nothing that would complicate the offset map.

    ``offsets`` is ``None`` when nothing changed, the ASCII fast path, so an
    all-ASCII document runs the detector on itself with no allocation.
    """
    out: list[str] = []
    offsets: list[int] = []
    changed = False
    for i, ch in enumerate(text):
        if unicodedata.category(ch) == "Cf":
            changed = True
            continue
        digit = unicodedata.decimal(ch, None)
        if digit is not None and ch != str(digit):
            out.append(str(digit))
            offsets.append(i)
            changed = True
        else:
            out.append(ch)
            offsets.append(i)
    if not changed:
        return text, None
    return "".join(out), offsets


def detect(
    text: str,
    *,
    classes: frozenset[PIIClass],
    seeded: SeededValues | None = None,
    detectors: Sequence[Detector] = (),
    masked_spans: list[tuple[int, int]] | None = None,
) -> DetectionResult:
    """Find identifiers in ``text``.

    ``masked_spans`` are regions to skip, used to carry already-issued tokens
    through untouched. Without it, de-identification would not be idempotent:
    a second pass would try to vault the tokens the first pass produced.
    """
    masked = masked_spans or []

    def _is_masked(start: int, end: int) -> bool:
        return any(ms < end and start < me for ms, me in masked)

    matches: list[RawMatch] = []
    compiled, group_info = _compiled_for(classes)

    # The structural detectors run on a normalized copy, so a Unicode-digit PAN
    # and an invisible-split identifier are seen. Spans are mapped straight back
    # to original coordinates; everything below this block is in original space.
    scan_text, offsets = _normalize_for_detection(text)

    def _to_original(start: int, end: int) -> tuple[int, int]:
        if offsets is None:
            return start, end
        # end is exclusive; map the last included index and add one. A match
        # spanning a dropped invisible maps to an original span that still
        # contains it, so substitution cuts the hidden character too.
        return offsets[start], offsets[end - 1] + 1

    for m in compiled.finditer(scan_text):
        info = group_info.get(m.lastgroup or "")
        if info is None:
            continue
        spec, value_group = info
        # Context-anchored detectors capture the identifier in a named value
        # group so the label ("MRN:", "Passport No.") is not swallowed into the
        # span and replaced along with the value.
        # A detector may offer a value group on only one branch of its
        # alternation (labelled compact SSN vs. separated SSN). When that
        # branch did not participate, fall back to the whole match instead of
        # dropping the hit, which would silently disable the other form.
        norm_value = m.group(value_group) if value_group is not None else None
        if norm_value is not None:
            start, end = m.start(value_group), m.end(value_group)
        else:
            start, end, norm_value = m.start(), m.end(), m.group()
        start, end = _to_original(start, end)
        # Validate on the normalized value (ASCII digits, so Luhn is defined),
        # but store the original substring so the token replaces exactly the
        # characters that were there, Unicode digits and all.
        if masked and _is_masked(start, end):
            continue
        if spec.validator is not None and not spec.validator(norm_value):
            continue
        matches.append(RawMatch(spec.pii_class, start, end, text[start:end]))

    unlocatable_credentials: list[str] = []
    if PIIClass.CREDENTIAL in classes:
        # On original text, not the normalized copy: the credential scanner has
        # its own invisible handling that separates a secret split by a
        # zero-width character from ordinary prose split by one. Feeding it the
        # stripped copy merged joined prose into one long run and read it as a
        # high-entropy token. The regex pass above is where the invisible and
        # Unicode-digit evasions live; credentials are already covered.
        spans, unlocatable_credentials = credential_spans(text)
        for start, end in spans:
            if not _is_masked(start, end):
                matches.append(RawMatch(PIIClass.CREDENTIAL, start, end, text[start:end]))

    if seeded is not None:
        for start, end, cls in seeded.find(text):
            if cls in classes and not _is_masked(start, end):
                matches.append(RawMatch(cls, start, end, text[start:end]))

    detector_warnings: list[str] = []
    detection_failed = False
    for detector in detectors:
        spans, failure = _run_detector(detector, text)
        if failure is not None:
            detector_warnings.append(failure)
            # Any rejection means coverage is incomplete, even when other spans
            # survived. Treating a partial rejection as complete let a valid
            # span be vaulted while the identifier in the rejected span reached
            # the provider in plaintext, with the library already knowing its
            # detector output had been dropped.
            detection_failed = True
            if not spans:
                continue
        for span in spans:
            if span.pii_class in classes and not _is_masked(span.start, span.end):
                matches.append(
                    RawMatch(
                        span.pii_class,
                        span.start,
                        span.end,
                        text[span.start : span.end],
                        inferred=True,
                    )
                )

    resolved = _resolve_overlaps(matches)
    resolved.unlocatable_credentials = unlocatable_credentials
    resolved.detector_warnings = detector_warnings
    resolved.detection_incomplete = detection_failed
    return resolved
