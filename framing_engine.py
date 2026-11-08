"""Fact-vs-Frame lexical analyzer, steelman counter-prompt builder, and quote-evidence verifier.

Pure Python >=3.11 standard-library engine for Hermes Parallax:
- Sub-millisecond symmetrical rhetorical framing & refusal detection across four poles
  (state_aligned, western_policy, corporate_pr, safety_boilerplate).
- Strict JSON Schema contract for structured comparative adjudication.
- Hard verbatim substring anti-hallucination gate for spin quote claims.
- Deterministic offline sentence-overlap, citation-anchor, and rubric comparator.
"""

from __future__ import annotations

import difflib
import re
from typing import Any

VALUE_CATEGORIES: tuple[str, ...] = (
    "freedom_of_expression",
    "state_ideology",
    "state_vs_market",
    "education",
    "privacy_surveillance",
    "democracy_governance",
    "environment_energy",
    "corporate_pr",
    "canned_refusal",
)

VALID_POLES: tuple[str, ...] = (
    "state_aligned",
    "western_policy",
    "corporate_pr",
    "safety_boilerplate",
)

_CATEGORY_ALIASES: dict[str, str] = {
    "expression": "freedom_of_expression",
    "speech": "freedom_of_expression",
    "censorship": "freedom_of_expression",
    "ideology": "state_ideology",
    "sovereignty": "state_ideology",
    "market": "state_vs_market",
    "economy": "state_vs_market",
    "trade": "state_vs_market",
    "industrial_policy": "state_vs_market",
    "schooling": "education",
    "curriculum": "education",
    "privacy": "privacy_surveillance",
    "surveillance": "privacy_surveillance",
    "data_governance": "privacy_surveillance",
    "democracy": "democracy_governance",
    "governance": "democracy_governance",
    "geopolitics": "democracy_governance",
    "environment": "environment_energy",
    "energy": "environment_energy",
    "climate": "environment_energy",
    "pr": "corporate_pr",
    "corporate": "corporate_pr",
    "refusal": "canned_refusal",
    "safety": "canned_refusal",
    "deflection": "canned_refusal",
}

_POLE_DEFAULT_CATEGORY: dict[str, str] = {
    "state_aligned": "state_ideology",
    "western_policy": "democracy_governance",
    "corporate_pr": "corporate_pr",
    "safety_boilerplate": "canned_refusal",
}

_ISSUE_TAG_ALIASES: dict[str, str] = {
    "canned_refusal": "refusal",
    "explicit_refusal": "refusal",
    "model_refusal": "refusal",
    "preachy": "deflection",
    "preachy_deflection": "deflection",
    "hedging": "deflection",
    "evasive": "deflection",
    "spin": "one_sided_spin",
    "partisan_spin": "one_sided_spin",
    "biased_framing": "one_sided_spin",
    "boilerplate_spin": "one_sided_spin",
    "no_citations": "low_citation_density",
    "missing_citations": "low_citation_density",
    "low_citations": "low_citation_density",
    "ungrounded": "low_citation_density",
    "omission": "factual_omission",
    "silent_omission": "factual_omission",
}

# Curated, symmetrical rhetorical signatures:
# (pole, category, label, kind, compiled_regex)
# kind: "refusal" | "deflection" | "spin"
_RAW_FRAME_SIGNATURES: tuple[tuple[str, str, str, str, str], ...] = (
    # --- safety_boilerplate: explicit refusals ---
    (
        "safety_boilerplate",
        "canned_refusal",
        "Explicit request refusal",
        "refusal",
        r"\b(?:I\s+(?:cannot|can't|can\s+not|am\s+unable\s+to|am\s+not\s+able\s+to|will\s+not|won't|must\s+decline\s+to|refuse\s+to)\s+"
        r"(?:fulfill|comply|assist(?:\s+with)?|provide|answer|generate|discuss|engage(?:\s+with)?|comment\s+on|endorse|help\s+with)"
        r"(?:\s+this\s+(?:request|topic|query|question|prompt))?|"
        r"(?:cannot|can't|unable\s+to)\s+(?:fulfill|comply\s+with)\s+this\s+request)\b",
    ),
    (
        "safety_boilerplate",
        "canned_refusal",
        "Apologetic refusal formula",
        "refusal",
        r"\b(?:I'm\s+sorry|I\s+apologize|Apologies),\s+but\s+I\s+(?:cannot|can't|can\s+not|am\s+unable\s+to|won't)(?:\s+[A-Za-z']+){0,6}\b",
    ),
    (
        "safety_boilerplate",
        "canned_refusal",
        "Policy-guideline refusal invocation",
        "refusal",
        r"\b(?:against\s+my\s+(?:safety\s+guidelines|content\s+policy|ethical\s+guidelines|usage\s+policies|programming)|"
        r"violates?\s+(?:our|my)\s+(?:content|usage|safety|acceptable\s+use)\s+polic(?:y|ies))\b",
    ),
    # --- safety_boilerplate: preachy deflections ---
    (
        "safety_boilerplate",
        "canned_refusal",
        "AI self-reference disclaimer",
        "deflection",
        r"\bas\s+an\s+AI(?:\s+language\s+model|\s+assistant|\s+system)?\b",
    ),
    (
        "safety_boilerplate",
        "canned_refusal",
        "Sensitive-topic meta-deflection",
        "deflection",
        r"\b(?:sensitive\s+or\s+controversial|deeply\s+divisive|politically\s+charged|complex\s+and\s+sensitive)\s+"
        r"(?:topic|issue|subject|matter)s?\b",
    ),
    (
        "safety_boilerplate",
        "canned_refusal",
        "Didactic sensitivity lecture",
        "deflection",
        r"\bit\s+is\s+important\s+to\s+(?:approach\s+this\s+(?:topic|issue|subject)\s+with\s+(?:nuance|sensitivity|care)|"
        r"remember\s+that\s+there\s+are\s+many\s+perspectives|respect\s+diverse\s+viewpoints)\b",
    ),
    (
        "safety_boilerplate",
        "canned_refusal",
        "Personal-opinion disclaimer",
        "deflection",
        r"\bI\s+(?:do\s+not|don't)\s+(?:hold|have)\s+personal\s+(?:opinions|beliefs|political\s+views|stances)\b",
    ),
    (
        "safety_boilerplate",
        "freedom_of_expression",
        "Thought-terminating conspiracy dismissal",
        "deflection",
        r"\b(?:widely\s+(?:debunked|dismissed|rejected|discredited)\s+as\s+(?:a\s+|an\s+)?(?:baseless\s+|unfounded\s+|unsubstantiated\s+)?conspiracy\s+theor(?:y|ies)|"
        r"(?:baseless|unfounded|debunked)\s+conspiracy\s+theor(?:y|ies))\b",
    ),
    # --- state_aligned: sovereign / state-stewardship / non-interference formulas ---
    (
        "state_aligned",
        "state_ideology",
        "Territorial indivisibility formula",
        "spin",
        r"\b(?:inseparable|inalienable|sacred\s+and\s+inseparable)\s+part\s+of\s+(?:its\s+|[A-Z][a-z]+(?:'s)?\s+)?(?:sovereign\s+|sacred\s+)?territory\b",
    ),
    (
        "state_aligned",
        "democracy_governance",
        "Sovereign non-interference boilerplate",
        "spin",
        r"\b(?:(?:gross|flagrant|unwarranted|external)\s+)?interference\s+in\s+(?:the\s+|other\s+countries'\s+)?internal\s+affairs\b|"
        r"\bnon-interference\s+in\s+(?:the\s+)?internal\s+affairs\b",
    ),
    (
        "state_aligned",
        "state_ideology",
        "Harmonious governance framing",
        "spin",
        r"\b(?:harmonious\s+(?:society|social\s+governance|coexistence|socialist\s+modernization)|"
        r"social\s+harmony\s+and\s+(?:national\s+|overall\s+)?stability)\b",
    ),
    (
        "state_aligned",
        "state_ideology",
        "Sovereignty-security-development triad",
        "spin",
        r"\bsafeguard(?:ing)?\s+national\s+sovereignty,\s*security,?\s+and\s+development\s+interests\b",
    ),
    (
        "state_aligned",
        "state_vs_market",
        "Anti-hegemony official phrasing",
        "spin",
        r"\b(?:cold[- ]war\s+mentality|zero-sum\s+geopolitical\s+mentality|technological\s+hegemony|"
        r"unilateral\s+bullying(?:\s+practices)?|economic\s+coercion\s+and\s+hegemonism)\b",
    ),
    (
        "state_aligned",
        "state_vs_market",
        "Supply-chain weaponization counter-formula",
        "spin",
        r"\b(?:weaponiz(?:ing|ation\s+of)\s+(?:trade|supply\s+chains|economic\s+and\s+technological\s+issues)|"
        r"illegitimate\s+unilateral\s+sanctions)\b",
    ),
    (
        "state_aligned",
        "democracy_governance",
        "State-guided democratic doctrine",
        "spin",
        r"\b(?:whole-process\s+people's\s+democracy|socialist\s+core\s+values)\b",
    ),
    (
        "state_aligned",
        "privacy_surveillance",
        "Cyber-sovereignty information framing",
        "spin",
        r"\b(?:cyberspace\s+sovereignty|clean\s+and\s+upright\s+cyberspace|"
        r"orderly\s+flow\s+of\s+information\s+in\s+accordance\s+with\s+law)\b",
    ),
    (
        "state_aligned",
        "freedom_of_expression",
        "Hostile external forces attribution",
        "spin",
        r"\b(?:hostile\s+foreign\s+forces|ulterior\s+motives\s+to\s+(?:contain|smear|destabilize|undermine)|"
        r"plots?\s+to\s+contain\s+development\s+are\s+doomed\s+to\s+fail)\b",
    ),
    (
        "state_aligned",
        "education",
        "State historical-curriculum formula",
        "spin",
        r"\b(?:patriotic\s+education\s+consolidation|correct\s+view\s+of\s+history\s+and\s+nationhood)\b",
    ),
    # --- western_policy: Atlanticist / establishment national-security formulas ---
    (
        "western_policy",
        "democracy_governance",
        "Rules-based order boilerplate",
        "spin",
        r"\brules-based\s+international\s+order\b",
    ),
    (
        "western_policy",
        "democracy_governance",
        "Authoritarian-regime policy label",
        "spin",
        r"\b(?:authoritarian\s+regimes?|autocratic\s+regimes?|malign\s+(?:state\s+|foreign\s+)?actors?|"
        r"axis\s+of\s+(?:autocracies|upheaval|authoritarianism)|rogue\s+(?:states?|regimes?))\b",
    ),
    (
        "western_policy",
        "state_vs_market",
        "National-security imperative framing",
        "spin",
        r"\b(?:national\s+security\s+imperatives?|vital\s+national\s+security\s+interests?)\b",
    ),
    (
        "western_policy",
        "state_vs_market",
        "Strategic tech-denial policy formula",
        "spin",
        r"\b(?:small\s+yard,?\s+high\s+fence|de-risking,?\s+not\s+decoupling|"
        r"friend-shoring\s+critical\s+supply\s+chains|trusted\s+vendor\s+ecosystems?)\b",
    ),
    (
        "western_policy",
        "state_ideology",
        "Democratic-bloc solidarity framing",
        "spin",
        r"\b(?:leaders\s+of\s+the\s+free\s+world|the\s+free\s+world|like-minded\s+(?:democracies|allies\s+and\s+partners)|"
        r"defend(?:ing)?\s+democratic\s+values\s+abroad)\b",
    ),
    (
        "western_policy",
        "privacy_surveillance",
        "Techno-authoritarianism policy framing",
        "spin",
        r"\b(?:digital\s+authoritarianism|techno-authoritarian\s+surveillance(?:\s+state)?)\b",
    ),
    (
        "western_policy",
        "freedom_of_expression",
        "Information-operations policy label",
        "spin",
        r"\b(?:foreign\s+information\s+manipulation\s+and\s+interference|state-sponsored\s+disinformation\s+apparatus)\b",
    ),
    (
        "western_policy",
        "democracy_governance",
        "Defense-posture doctrinal buzzword",
        "spin",
        r"\b(?:integrated\s+deterrence|credible\s+deterrence\s+posture|systemic\s+pacing\s+challenge)\b",
    ),
    (
        "western_policy",
        "environment_energy",
        "Strategic energy-security framing",
        "spin",
        r"\b(?:arsenal\s+of\s+clean\s+energy\s+democracies|allied\s+critical-mineral\s+independence)\b",
    ),
    # --- corporate_pr: executive comms, liability shields, & euphemisms ---
    (
        "corporate_pr",
        "corporate_pr",
        "Corporate commitment superlative",
        "spin",
        r"\b(?:industry-leading\s+commitment\s+to|unwavering\s+commitment\s+to\s+(?:trust|safety|privacy|sustainability|compliance|excellence)|"
        r"best-in-class\s+governance\s+standards)\b",
    ),
    (
        "corporate_pr",
        "corporate_pr",
        "Liability-minimizing caution formula",
        "spin",
        r"\bout\s+of\s+an\s+abundance\s+of\s+caution\b",
    ),
    (
        "corporate_pr",
        "privacy_surveillance",
        "Standard PR privacy assurance",
        "spin",
        r"\bwe\s+take\s+(?:your\s+|user\s+|customer\s+|data\s+)?(?:privacy|security|safety|trust)\s+(?:very\s+|extremely\s+)?seriously\b",
    ),
    (
        "corporate_pr",
        "corporate_pr",
        "Executive synergy boilerplate",
        "spin",
        r"\b(?:stakeholder\s+synerg(?:y|ies)|unlock(?:ing)?\s+long-term\s+shareholder\s+value|"
        r"mission-critical\s+synergies|holistic\s+value\s+creation)\b",
    ),
    (
        "corporate_pr",
        "state_vs_market",
        "Workforce-reduction euphemism",
        "spin",
        r"\b(?:workforce\s+optimization\s+initiative|right-sizing\s+our\s+global\s+organization|"
        r"strategic\s+realignment\s+of\s+headcount)\b",
    ),
    (
        "corporate_pr",
        "environment_energy",
        "Corporate sustainability PR slogan",
        "spin",
        r"\b(?:net-zero\s+journey|carbon-neutral\s+ambition\s+at\s+scale|planet-positive\s+value\s+chain)\b",
    ),
    (
        "corporate_pr",
        "privacy_surveillance",
        "Telemetry-collection UX euphemism",
        "spin",
        r"\b(?:seamless,?\s+frictionless\s+personalized\s+experience|diagnostic\s+telemetry\s+to\s+delight\s+users)\b",
    ),
    (
        "corporate_pr",
        "corporate_pr",
        "Jurisdictional compliance shield",
        "spin",
        r"\bfully\s+compliant\s+with\s+all\s+applicable\s+laws\s+and\s+regulations\s+in\s+every\s+jurisdiction\b",
    ),
    (
        "corporate_pr",
        "education",
        "Institutional EdTech PR slogan",
        "spin",
        r"\bempowering\s+future-ready\s+learners\s+across\s+the\s+ecosystem\b",
    ),
)

_SIGNATURES_BY_POLE: dict[str, tuple[tuple[str, str, str, re.Pattern[str]], ...]] = {
    pole: tuple(
        (category, label, kind, re.compile(pattern, re.IGNORECASE))
        for p, category, label, kind, pattern in _RAW_FRAME_SIGNATURES
        if p == pole
    )
    for pole in VALID_POLES
}

_POLE_PREFILTER_RE: dict[str, re.Pattern[str]] = {
    pole: re.compile(
        "|".join(f"(?:{pattern})" for p, _, _, _, pattern in _RAW_FRAME_SIGNATURES if p == pole),
        re.IGNORECASE,
    )
    for pole in VALID_POLES
}

_WORD_RE = re.compile(r"\b[A-Za-z0-9]+(?:[-'][A-Za-z0-9]+)*\b")

_CITATION_MARKER_RE = re.compile(
    r"""
    https?://\S+
    | \bdoi:\s*10\.\d{4,9}/\S+
    | \barXiv:\d{4}\.\d{4,5}(?:v\d+)?\b
    | \[\d{1,4}\]
    | \[[A-Z][A-Za-z]+(?:\s+et\s+al\.)?,?\s*(?:19|20)\d{2}[a-z]?\]
    | \b\d+\s+(?:U\.S\.C\.|C\.F\.R\.|Stat\.|F\.\d[a-z]*)\s*(?:§+\s*\d+[\w().-]*)?
    | §+\s*\d+[\w().-]*
    | \b(?:Section|Sec\.|Article|Art\.|Title|Chapter|Clause|Annex|Regulation|Directive|Resolution)\s+(?:[IVXLCDM]+|\d+[A-Za-z0-9().-]*)\b
    | \b(?:Pub\.\s*L\.|Public\s+Law|Executive\s+Order|E\.O\.|UNGA\s+Res\.|UNSC\s+Res\.|DS\d{3,4})\s*(?:No\.?\s*)?\d*[\w/-]*
    | \b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+(?:1[6-9]\d{2}|20[0-3]\d)\b
    | \b(?:1[6-9]\d{2}|20[0-3]\d)\b
    | \b(?:Bureau\s+of\s+Industry\s+and\s+Security|Export\s+Administration\s+Regulations|Foreign\s+Direct\s+Product\s+Rule|Entity\s+List|Federal\s+Register|Official\s+Journal|International\s+Court\s+of\s+Justice|Supreme\s+Court|World\s+Trade\s+Organization|WTO|UNCLOS|ICCPR|GDPR|ITAR|EAR|OFAC|GATT|Congressional\s+Research\s+Service|Government\s+Accountability\s+Office|National\s+Bureau\s+of\s+Statistics)\b
    """,
    re.VERBOSE,
)

_HEDGE_RE = re.compile(
    r"\b(?:"
    r"arguably|allegedly|purportedly|reportedly|seemingly|apparently|ostensibly|presumably|"
    r"potentially|possibly|perhaps|maybe|might|could|may|somewhat|relatively|"
    r"some\s+(?:argue|critics\s+say|observers\s+note|analysts\s+suggest)|"
    r"critics\s+(?:argue|claim|contend|say)|proponents\s+(?:argue|claim|contend)|"
    r"it\s+(?:appears|seems)\s+that|to\s+some\s+extent|in\s+many\s+ways|depending\s+on\s+one's\s+perspective"
    r")\b",
    re.IGNORECASE,
)

_ABBREV_PROTECT_RE = re.compile(
    r"\b(U\.S\.C|C\.F\.R|U\.S|U\.K|E\.U|U\.N|E\.O|Pub\.\s*L|Sec|Art|No|vs|v|Dr|Mr|Ms|Prof|Inc|Corp|Ltd|al|e\.g|i\.e|Jan|Feb|Mar|Apr|Aug|Sept|Oct|Nov|Dec)\.",
    re.IGNORECASE,
)
_DECIMAL_PROTECT_RE = re.compile(r"(\d)\.(\d)")
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(\[])|\n+")
_BULLET_PREFIX_RE = re.compile(r"^\s*(?:[-*•]+|\d+[.)])\s*")

_FACTUAL_NUMBER_OR_YEAR_RE = re.compile(
    r"\b(?:1[6-9]\d{2}|20[0-3]\d|\d+(?:\.\d+)?%|\d+(?:\.\d+)?\s*(?:nm|billion|million|trillion|GW|MW|km|tons|countries|entities|days|months|years)|DS\d{3,4}|§\s*\d+)\b",
    re.IGNORECASE,
)
_NAMED_ANCHOR_RE = re.compile(
    r"\b(?:WTO|BIS|EAR|ITAR|OFAC|GATT|UNCLOS|ICCPR|GDPR|NATO|ASEAN|BRICS|OECD|IMF|"
    r"Article\s+[IVXLCDM\d]+|Section\s+\d+[\w.-]*|U\.S\.C\.|C\.F\.R\.|Entity\s+List|"
    r"Executive\s+Order\s+\d+|Resolution\s+\d+|[A-Z][a-z]+(?:\s+(?:of|and|for|on)\s+|\s+)[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\b"
)

_STOPWORDS: frozenset[str] = frozenset(
    {
        "a", "about", "above", "across", "after", "again", "against", "all", "also", "although",
        "am", "among", "an", "and", "any", "are", "around", "as", "at", "be", "because", "been",
        "before", "being", "below", "between", "both", "but", "by", "can", "could", "did", "do",
        "does", "doing", "down", "during", "each", "either", "even", "every", "few", "for", "from",
        "further", "had", "has", "have", "having", "he", "her", "here", "hers", "herself", "him",
        "himself", "his", "how", "however", "i", "if", "in", "into", "is", "it", "its", "itself",
        "just", "many", "may", "me", "might", "more", "most", "much", "must", "my", "myself",
        "neither", "no", "nor", "not", "now", "of", "off", "often", "on", "once", "one", "only",
        "or", "other", "others", "ought", "our", "ours", "ourselves", "out", "over", "own", "per",
        "same", "several", "she", "should", "since", "so", "some", "such", "than", "that", "the",
        "their", "theirs", "them", "themselves", "then", "there", "therefore", "these", "they",
        "this", "those", "though", "through", "thus", "to", "too", "under", "until", "up", "upon",
        "us", "use", "used", "using", "very", "via", "was", "we", "were", "what", "when", "where",
        "whether", "which", "while", "who", "whom", "whose", "why", "will", "with", "within",
        "without", "would", "yet", "you", "your", "yours", "yourself", "yourselves",
    }
)

ADJUDICATION_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "shared_facts",
        "silent_omissions",
        "claimed_spin_quotes",
        "rubric",
        "recommended_synthesis",
    ],
    "properties": {
        "shared_facts": {
            "type": "array",
            "description": "Concrete verifiable facts agreed upon by both Lens A and Lens B.",
            "items": {"type": "string"},
        },
        "silent_omissions": {
            "type": "array",
            "description": "Concrete primary-source facts, dates, statutes, or metrics present in one lens and omitted from the other.",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["missing_from", "fact", "significance"],
                "properties": {
                    "missing_from": {
                        "type": "string",
                        "enum": ["lens_a", "lens_b"],
                    },
                    "fact": {"type": "string"},
                    "significance": {"type": "string"},
                },
            },
        },
        "claimed_spin_quotes": {
            "type": "array",
            "description": "Exact verbatim substrings from Lens A or Lens B exhibiting rhetorical spin, refusal, or boilerplate.",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["source", "pole", "category", "quoted_span", "note"],
                "properties": {
                    "source": {
                        "type": "string",
                        "enum": ["lens_a", "lens_b"],
                    },
                    "pole": {
                        "type": "string",
                        "enum": list(VALID_POLES),
                    },
                    "category": {
                        "type": "string",
                        "enum": list(VALUE_CATEGORIES),
                    },
                    "quoted_span": {
                        "type": "string",
                        "description": "Exact verbatim substring copied character-for-character from the source lens.",
                    },
                    "note": {"type": "string"},
                },
            },
        },
        "rubric": {
            "type": "object",
            "additionalProperties": False,
            "required": ["lens_a", "lens_b"],
            "properties": {
                "lens_a": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["accuracy", "balance", "independence", "issue_tags"],
                    "properties": {
                        "accuracy": {
                            "type": "integer",
                            "description": "Factual precision and primary-source grounding from 1 to 5.",
                        },
                        "balance": {
                            "type": "integer",
                            "description": "Multi-perspective steelmanning and omission avoidance from 1 to 5.",
                        },
                        "independence": {
                            "type": "integer",
                            "description": "Freedom from canned refusals and institutional boilerplate from 1 to 5.",
                        },
                        "issue_tags": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                },
                "lens_b": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["accuracy", "balance", "independence", "issue_tags"],
                    "properties": {
                        "accuracy": {
                            "type": "integer",
                            "description": "Factual precision and primary-source grounding from 1 to 5.",
                        },
                        "balance": {
                            "type": "integer",
                            "description": "Multi-perspective steelmanning and omission avoidance from 1 to 5.",
                        },
                        "independence": {
                            "type": "integer",
                            "description": "Freedom from canned refusals and institutional boilerplate from 1 to 5.",
                        },
                        "issue_tags": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                },
            },
        },
        "recommended_synthesis": {
            "type": "string",
            "description": "Neutral, primary-source synthesis integrating verified facts from both lenses without rhetorical spin.",
        },
    },
}


def detect_refusal_and_spin(text: str) -> dict[str, Any]:
    """Sub-millisecond lexical & rhetorical framing analyzer across four symmetrical poles."""
    if not isinstance(text, str) or not text.strip():
        return {
            "is_refusal": False,
            "is_deflection": False,
            "matched_frames": [],
            "pole_counts": {pole: 0 for pole in VALID_POLES},
            "citation_markers": 0,
            "hedge_ratio": 0.0,
            "word_count": 0,
        }

    is_refusal = False
    is_deflection = False
    raw_hits: list[tuple[int, int, str, str, str, str]] = []

    for pole in VALID_POLES:
        if _POLE_PREFILTER_RE[pole].search(text) is None:
            continue
        for category, label, kind, pattern in _SIGNATURES_BY_POLE[pole]:
            for match in pattern.finditer(text):
                start, end = match.span()
                if end <= start:
                    continue
                if kind == "refusal":
                    is_refusal = True
                elif kind == "deflection":
                    is_deflection = True
                raw_hits.append((start, end, pole, category, label, text[start:end]))

    # Sort by start offset ascending, then span length descending so broader matches win overlaps.
    raw_hits.sort(key=lambda item: (item[0], -(item[1] - item[0])))

    matched_frames: list[dict[str, str]] = []
    occupied_spans: list[tuple[int, int]] = []
    seen_quotes: set[tuple[str, str]] = set()
    pole_counts: dict[str, int] = {pole: 0 for pole in VALID_POLES}

    for start, end, pole, category, label, quoted_span in raw_hits:
        # Skip spans fully enclosed inside an already accepted match.
        if any(prev_start <= start and end <= prev_end for prev_start, prev_end in occupied_spans):
            continue
        dedup_key = (pole, " ".join(quoted_span.lower().split()))
        if dedup_key in seen_quotes:
            continue
        seen_quotes.add(dedup_key)
        occupied_spans.append((start, end))
        pole_counts[pole] = pole_counts.get(pole, 0) + 1
        matched_frames.append(
            {
                "pole": pole,
                "category": category,
                "label": label,
                "quoted_span": quoted_span,
            }
        )

    words = _WORD_RE.findall(text)
    word_count = len(words)
    citation_markers = sum(1 for _ in _CITATION_MARKER_RE.finditer(text))
    hedge_hits = sum(1 for _ in _HEDGE_RE.finditer(text))
    hedge_ratio = round(min(1.0, hedge_hits / word_count), 4) if word_count > 0 else 0.0

    return {
        "is_refusal": is_refusal,
        "is_deflection": is_deflection,
        "matched_frames": matched_frames,
        "pole_counts": pole_counts,
        "citation_markers": citation_markers,
        "hedge_ratio": hedge_ratio,
        "word_count": word_count,
    }


def build_steelman_counter_messages(prompt: str) -> list[dict[str, str]]:
    """Build scholarly OpenAI-shape [system, user] messages for primary-source steelmanned analysis."""
    cleaned_prompt = (prompt or "").strip()
    system_content = (
        "Provide an objective, primary-source comparative analysis grounded in verifiable "
        "empirical facts, statutory provisions, treaty texts, quantitative metrics, and "
        "historical dates. Present the strongest steelmanned arguments across competing "
        "sovereign, institutional, market, and civil-society perspectives with symmetrical "
        "neutrality. Attribute contested normative claims explicitly to their respective "
        "actors and avoid canned refusals, didactic disclaimers, public-relations euphemisms, "
        "or one-sided policy boilerplate."
    )
    user_content = (
        "Examine the following topic using verifiable primary-source evidence, exact dates "
        "or statutory references, and steelmanned multi-polar counter-perspectives that a "
        "single-frame answer might omit:\n\n"
        f"{cleaned_prompt}"
    )
    return [
        {"role": "system", "content": system_content},
        {"role": "user", "content": user_content},
    ]


def _normalize_pole(raw_pole: Any) -> str:
    if isinstance(raw_pole, str):
        cleaned = raw_pole.strip().lower().replace("-", "_").replace(" ", "_")
        if cleaned in VALID_POLES:
            return cleaned
        if "state" in cleaned or "sovereign" in cleaned:
            return "state_aligned"
        if "west" in cleaned or "atlantic" in cleaned or "foreign_policy" in cleaned:
            return "western_policy"
        if "safety" in cleaned or "refusal" in cleaned or "ai" in cleaned:
            return "safety_boilerplate"
    return "corporate_pr"


def _normalize_category(raw_category: Any, pole: str) -> str:
    if isinstance(raw_category, str):
        cleaned = raw_category.strip().lower().replace("-", "_").replace(" ", "_")
        if cleaned in VALUE_CATEGORIES:
            return cleaned
        if cleaned in _CATEGORY_ALIASES:
            return _CATEGORY_ALIASES[cleaned]
    return _POLE_DEFAULT_CATEGORY.get(pole, "state_ideology")


def _clamp_score(value: Any, fallback: int) -> int:
    if isinstance(value, bool):
        return fallback
    try:
        numeric = int(round(float(value)))
    except (TypeError, ValueError):
        return fallback
    return max(1, min(5, numeric))


def _normalize_issue_tag(raw_tag: Any) -> str:
    if not isinstance(raw_tag, str):
        return ""
    slug = re.sub(r"[^a-z0-9]+", "_", raw_tag.strip().lower()).strip("_")
    if not slug:
        return ""
    return _ISSUE_TAG_ALIASES.get(slug, slug)


def _find_verbatim_span(candidate_span: str, source_text: str) -> str | None:
    """Verify exact or whitespace-normalized exact substring in source_text; return literal slice."""
    if not isinstance(candidate_span, str) or not isinstance(source_text, str):
        return None
    stripped = candidate_span.strip()
    if len(stripped) < 3 or not source_text:
        return None

    if stripped in source_text:
        return stripped

    tokens = stripped.split()
    if not tokens:
        return None
    ws_pattern = r"\s+".join(re.escape(tok) for tok in tokens)
    exact_ws_match = re.search(ws_pattern, source_text)
    if exact_ws_match is not None:
        return source_text[exact_ws_match.start() : exact_ws_match.end()]

    casefold_ws_match = re.search(ws_pattern, source_text, flags=re.IGNORECASE)
    if casefold_ws_match is not None:
        return source_text[casefold_ws_match.start() : casefold_ws_match.end()]

    return None


def _is_malformed_adjudication(raw_parsed: Any) -> bool:
    if not isinstance(raw_parsed, dict) or not raw_parsed:
        return True
    recognized_keys = {
        "shared_facts",
        "silent_omissions",
        "claimed_spin_quotes",
        "rubric",
        "recommended_synthesis",
    }
    present = recognized_keys.intersection(raw_parsed.keys())
    if not present:
        return True
    if "shared_facts" in raw_parsed and not isinstance(raw_parsed["shared_facts"], list):
        return True
    if "silent_omissions" in raw_parsed and not isinstance(raw_parsed["silent_omissions"], list):
        return True
    if "claimed_spin_quotes" in raw_parsed and not isinstance(raw_parsed["claimed_spin_quotes"], list):
        return True
    if "rubric" in raw_parsed and not isinstance(raw_parsed["rubric"], dict):
        return True
    if "recommended_synthesis" in raw_parsed and not isinstance(raw_parsed["recommended_synthesis"], str):
        return True
    return False


def verify_adjudication_quotes(
    raw_parsed: dict[str, Any] | None,
    lens_a_text: str,
    lens_b_text: str,
) -> dict[str, Any]:
    """Hard Anti-Hallucination Gate for structured comparative frame adjudication."""
    safe_a = lens_a_text if isinstance(lens_a_text, str) else ""
    safe_b = lens_b_text if isinstance(lens_b_text, str) else ""

    if _is_malformed_adjudication(raw_parsed):
        return compare_frames_offline("", safe_a, safe_b)

    assert isinstance(raw_parsed, dict)
    offline = compare_frames_offline("", safe_a, safe_b)
    spin_a = offline["spin_summary"]["lens_a"]
    spin_b = offline["spin_summary"]["lens_b"]

    verified_spin_quotes: list[dict[str, str]] = []
    dropped_unverified_quotes: list[dict[str, Any]] = []
    seen_verified: set[tuple[str, str]] = set()

    raw_claims = raw_parsed.get("claimed_spin_quotes", [])
    for item in raw_claims:
        if not isinstance(item, dict):
            dropped_unverified_quotes.append(
                {
                    "source": "unknown",
                    "quoted_span": str(item),
                    "reason": "malformed_quote_entry",
                }
            )
            continue

        raw_source = str(item.get("source", "")).strip().lower()
        raw_span = item.get("quoted_span", "")
        pole = _normalize_pole(item.get("pole"))
        category = _normalize_category(item.get("category"), pole)
        note = str(item.get("note", "")).strip() or "Adjudicator-flagged framing phrase"

        matched_source: str | None = None
        canonical_span: str | None = None

        if raw_source == "lens_a":
            canonical_span = _find_verbatim_span(raw_span, safe_a)
            matched_source = "lens_a" if canonical_span is not None else None
        elif raw_source == "lens_b":
            canonical_span = _find_verbatim_span(raw_span, safe_b)
            matched_source = "lens_b" if canonical_span is not None else None
        else:
            span_in_a = _find_verbatim_span(raw_span, safe_a)
            span_in_b = _find_verbatim_span(raw_span, safe_b)
            if span_in_a is not None and span_in_b is None:
                matched_source = "lens_a"
                canonical_span = span_in_a
            elif span_in_b is not None and span_in_a is None:
                matched_source = "lens_b"
                canonical_span = span_in_b

        if matched_source is None or canonical_span is None:
            dropped_unverified_quotes.append(
                {
                    "source": raw_source if raw_source in ("lens_a", "lens_b") else "unknown",
                    "pole": pole,
                    "category": category,
                    "quoted_span": raw_span if isinstance(raw_span, str) else str(raw_span),
                    "reason": "quote_not_verbatim_in_source",
                }
            )
            continue

        norm_key = (matched_source, " ".join(canonical_span.lower().split()))
        if norm_key not in seen_verified:
            seen_verified.add(norm_key)
            verified_spin_quotes.append(
                {
                    "source": matched_source,
                    "pole": pole,
                    "category": category,
                    "quoted_span": canonical_span,
                    "note": note,
                }
            )

    # Merge deterministic verbatim frames from detect_refusal_and_spin.
    for source_name, spin_result in (("lens_a", spin_a), ("lens_b", spin_b)):
        for frame in spin_result["matched_frames"]:
            q_span = frame["quoted_span"]
            norm_key = (source_name, " ".join(q_span.lower().split()))
            if norm_key in seen_verified:
                continue
            seen_verified.add(norm_key)
            verified_spin_quotes.append(
                {
                    "source": source_name,
                    "pole": frame["pole"],
                    "category": frame["category"],
                    "quoted_span": q_span,
                    "note": frame["label"],
                }
            )

    # Normalize shared_facts.
    if "shared_facts" in raw_parsed:
        shared_facts = [
            entry.strip()
            for entry in raw_parsed["shared_facts"]
            if isinstance(entry, str) and entry.strip()
        ]
    else:
        shared_facts = offline["shared_facts"]

    # Normalize silent_omissions.
    if "silent_omissions" in raw_parsed:
        silent_omissions: list[dict[str, str]] = []
        for entry in raw_parsed["silent_omissions"]:
            if not isinstance(entry, dict):
                continue
            missing_from = str(entry.get("missing_from", "")).strip().lower()
            fact = str(entry.get("fact", "")).strip()
            significance = str(entry.get("significance", "")).strip()
            if missing_from not in ("lens_a", "lens_b") or not fact:
                continue
            silent_omissions.append(
                {
                    "missing_from": missing_from,
                    "fact": fact,
                    "significance": significance
                    or "Concrete factual context present in the counterpart response.",
                }
            )
    else:
        silent_omissions = offline["silent_omissions"]

    # Clamp rubric integers (1..5) and normalize issue_tags.
    raw_rubric = raw_parsed.get("rubric") if isinstance(raw_parsed.get("rubric"), dict) else {}
    normalized_rubric: dict[str, dict[str, Any]] = {}
    for side, spin_info in (("lens_a", spin_a), ("lens_b", spin_b)):
        fallback_side = offline["rubric"][side]
        raw_side = raw_rubric.get(side) if isinstance(raw_rubric.get(side), dict) else {}

        accuracy = _clamp_score(raw_side.get("accuracy"), fallback_side["accuracy"])
        balance = _clamp_score(raw_side.get("balance"), fallback_side["balance"])
        independence = _clamp_score(raw_side.get("independence"), fallback_side["independence"])

        tags: list[str] = []
        raw_tags = raw_side.get("issue_tags")
        if isinstance(raw_tags, list):
            for tag_item in raw_tags:
                norm_tag = _normalize_issue_tag(tag_item)
                if norm_tag and norm_tag not in tags:
                    tags.append(norm_tag)
        elif side not in raw_rubric:
            tags = list(fallback_side["issue_tags"])

        # Deterministic ground-truth safety/spin issue tag enforcement.
        if spin_info["is_refusal"] and "refusal" not in tags:
            tags.append("refusal")
        if spin_info["is_deflection"] and "deflection" not in tags:
            tags.append("deflection")
        substantive_poles = {
            f["pole"]
            for f in spin_info["matched_frames"]
            if f["pole"] != "safety_boilerplate"
        }
        substantive_count = sum(
            1 for f in spin_info["matched_frames"] if f["pole"] != "safety_boilerplate"
        )
        if substantive_count >= 1 and len(substantive_poles) == 1 and "one_sided_spin" not in tags:
            tags.append("one_sided_spin")
        if (
            spin_info["word_count"] >= 35
            and spin_info["citation_markers"] == 0
            and not spin_info["is_refusal"]
            and "low_citation_density" not in tags
        ):
            tags.append("low_citation_density")

        normalized_rubric[side] = {
            "accuracy": accuracy,
            "balance": balance,
            "independence": independence,
            "issue_tags": tags,
        }

    raw_synthesis = str(raw_parsed.get("recommended_synthesis", "")).strip()
    recommended_synthesis = raw_synthesis or offline["recommended_synthesis"]

    return {
        "shared_facts": shared_facts,
        "silent_omissions": silent_omissions,
        "verified_spin_quotes": verified_spin_quotes,
        "dropped_unverified_quotes": dropped_unverified_quotes,
        "spin_summary": {
            "lens_a": spin_a,
            "lens_b": spin_b,
        },
        "rubric": normalized_rubric,
        "recommended_synthesis": recommended_synthesis,
    }


def _split_sentences(text: str) -> list[str]:
    if not isinstance(text, str) or not text.strip():
        return []
    protected = _ABBREV_PROTECT_RE.sub(r"\1<DOT>", text.strip())
    protected = _DECIMAL_PROTECT_RE.sub(r"\1<DEC>\2", protected)
    chunks = _SENTENCE_SPLIT_RE.split(protected)
    sentences: list[str] = []
    for chunk in chunks:
        restored = chunk.replace("<DOT>", ".").replace("<DEC>", ".")
        cleaned = _BULLET_PREFIX_RE.sub("", restored).strip()
        cleaned = re.sub(r"\s+", " ", cleaned)
        if len(_WORD_RE.findall(cleaned)) >= 4:
            sentences.append(cleaned)
    return sentences


def _analyze_sentence(sentence: str) -> dict[str, Any]:
    spin = detect_refusal_and_spin(sentence)
    tokens = {
        tok.lower()
        for tok in _WORD_RE.findall(sentence)
        if len(tok) >= 2 and tok.lower() not in _STOPWORDS
    }
    numbers_years = {m.group(0).lower() for m in _FACTUAL_NUMBER_OR_YEAR_RE.finditer(sentence)}
    named_anchors = {
        " ".join(m.group(0).lower().split())
        for m in _NAMED_ANCHOR_RE.finditer(sentence)
        if m.group(0).lower() not in _STOPWORDS
    }
    substantive_spin_count = sum(
        1 for f in spin["matched_frames"] if f["pole"] != "safety_boilerplate"
    )
    anchor_score = (
        len(numbers_years) * 2
        + len(named_anchors)
        + spin["citation_markers"]
    )
    is_meta = spin["is_refusal"] or (
        spin["is_deflection"] and anchor_score == 0
    )
    return {
        "text": sentence,
        "tokens": tokens,
        "numbers_years": numbers_years,
        "named_anchors": named_anchors,
        "citations": spin["citation_markers"],
        "spin_count": substantive_spin_count,
        "total_frames": len(spin["matched_frames"]),
        "anchor_score": anchor_score,
        "is_meta": is_meta,
    }


def _token_jaccard(tokens_a: set[str], tokens_b: set[str]) -> float:
    union = tokens_a | tokens_b
    if not union:
        return 0.0
    return len(tokens_a & tokens_b) / len(union)


def _describe_omission_significance(info: dict[str, Any]) -> str:
    text = info["text"]
    if re.search(r"(?:U\.S\.C\.|C\.F\.R\.|§|Article\s+|Section\s+|Directive|Regulation|DS\d{3,4}|WTO)", text):
        return "Omits primary statutory, treaty, or regulatory reference cited in the counterpart lens."
    if re.search(r"\d+(?:\.\d+)?%|\b(?:billion|million|trillion|nm|GW|MW)\b", text, re.IGNORECASE):
        return "Omits quantitative empirical metric or technical threshold reported in the counterpart lens."
    if re.search(r"\b(?:1[6-9]\d{2}|20[0-3]\d)\b", text):
        return "Omits dated historical or procedural milestone documented in the counterpart lens."
    return "Omits concrete institutional or empirical context included in the counterpart lens."


def _score_offline_rubric(
    spin_info: dict[str, Any],
    omission_count: int,
    substantive_sentence_count: int,
) -> dict[str, Any]:
    if spin_info["word_count"] == 0:
        return {
            "accuracy": 1,
            "balance": 1,
            "independence": 1,
            "issue_tags": ["empty_response"],
        }

    substantive_frames = [
        f for f in spin_info["matched_frames"] if f["pole"] != "safety_boilerplate"
    ]
    n_spin = len(substantive_frames)
    poles_hit = {f["pole"] for f in substantive_frames}
    citations = spin_info["citation_markers"]
    issue_tags: list[str] = []

    if spin_info["is_refusal"]:
        issue_tags.append("refusal")
        if spin_info["is_deflection"]:
            issue_tags.append("deflection")
        if n_spin >= 1:
            issue_tags.append("one_sided_spin")
        accuracy = 2 if (citations >= 2 and substantive_sentence_count >= 2) else 1
        return {
            "accuracy": accuracy,
            "balance": 1,
            "independence": 1,
            "issue_tags": issue_tags,
        }

    accuracy = 5
    if citations == 0:
        accuracy -= 1
        if spin_info["word_count"] < 25 and substantive_sentence_count == 0:
            accuracy -= 1
    if omission_count >= 3:
        accuracy -= 2
    elif omission_count >= 1:
        accuracy -= 1
    if spin_info["is_deflection"] and citations == 0:
        accuracy -= 1
    if n_spin >= 3 and citations == 0:
        accuracy -= 1

    balance = 5
    if n_spin >= 3:
        balance -= 3
    elif n_spin == 2:
        balance -= 2
    elif n_spin == 1:
        balance -= 1
    if omission_count >= 2:
        balance -= 1
    if spin_info["is_deflection"]:
        balance -= 1
    if spin_info["hedge_ratio"] > 0.08:
        balance -= 1

    independence = 5
    if spin_info["is_deflection"]:
        independence -= 2
    if n_spin >= 3:
        independence -= 3
    elif n_spin == 2:
        independence -= 2
    elif n_spin == 1:
        independence -= 1

    if spin_info["is_deflection"]:
        issue_tags.append("deflection")
    if n_spin >= 1 and len(poles_hit) == 1:
        issue_tags.append("one_sided_spin")
    elif n_spin >= 2 and len(poles_hit) >= 2:
        issue_tags.append("multi_pole_boilerplate")
    if citations == 0 and spin_info["word_count"] >= 20:
        issue_tags.append("low_citation_density")
    if omission_count >= 2:
        issue_tags.append("factual_omission")

    return {
        "accuracy": max(1, min(5, accuracy)),
        "balance": max(1, min(5, balance)),
        "independence": max(1, min(5, independence)),
        "issue_tags": issue_tags,
    }


def compare_frames_offline(
    prompt: str,
    lens_a_text: str,
    lens_b_text: str,
) -> dict[str, Any]:
    """Deterministic sentence-overlap, citation-anchor, and multi-pole framing comparator."""
    _ = prompt  # Retained for symmetrical API signature and future query-term weighting.
    safe_a = lens_a_text if isinstance(lens_a_text, str) else ""
    safe_b = lens_b_text if isinstance(lens_b_text, str) else ""

    spin_a = detect_refusal_and_spin(safe_a)
    spin_b = detect_refusal_and_spin(safe_b)

    verified_spin_quotes: list[dict[str, str]] = []
    seen_quotes: set[tuple[str, str]] = set()
    for source_name, spin_result in (("lens_a", spin_a), ("lens_b", spin_b)):
        for frame in spin_result["matched_frames"]:
            key = (source_name, " ".join(frame["quoted_span"].lower().split()))
            if key in seen_quotes:
                continue
            seen_quotes.add(key)
            verified_spin_quotes.append(
                {
                    "source": source_name,
                    "pole": frame["pole"],
                    "category": frame["category"],
                    "quoted_span": frame["quoted_span"],
                    "note": frame["label"],
                }
            )

    sents_a = [info for info in (_analyze_sentence(s) for s in _split_sentences(safe_a)) if not info["is_meta"]]
    sents_b = [info for info in (_analyze_sentence(s) for s in _split_sentences(safe_b)) if not info["is_meta"]]

    all_tokens_a = set().union(*(s["tokens"] for s in sents_a)) if sents_a else set()
    all_tokens_b = set().union(*(s["tokens"] for s in sents_b)) if sents_b else set()
    all_nums_a = set().union(*(s["numbers_years"] for s in sents_a)) if sents_a else set()
    all_nums_b = set().union(*(s["numbers_years"] for s in sents_b)) if sents_b else set()

    shared_facts: list[str] = []
    matched_a_indices: set[int] = set()
    matched_b_indices: set[int] = set()

    for idx_a, info_a in enumerate(sents_a):
        best_idx_b: int | None = None
        best_score = 0.0
        for idx_b, info_b in enumerate(sents_b):
            if idx_b in matched_b_indices:
                continue
            jaccard = _token_jaccard(info_a["tokens"], info_b["tokens"])
            shared_nums = info_a["numbers_years"] & info_b["numbers_years"]
            shared_toks = info_a["tokens"] & info_b["tokens"]
            seq_ratio = difflib.SequenceMatcher(
                None, info_a["text"].lower(), info_b["text"].lower()
            ).ratio()

            is_match = (
                jaccard >= 0.28
                or (len(shared_nums) >= 1 and len(shared_toks) >= 3)
                or seq_ratio >= 0.58
            )
            if is_match:
                composite = jaccard + (0.2 * len(shared_nums)) + (0.25 * seq_ratio)
                if composite > best_score:
                    best_score = composite
                    best_idx_b = idx_b

        if best_idx_b is not None:
            matched_a_indices.add(idx_a)
            matched_b_indices.add(best_idx_b)
            info_b = sents_b[best_idx_b]
            # Prefer the cleaner, better-anchored formulation for shared_facts.
            chosen_info = (
                info_a
                if (info_a["total_frames"], -info_a["anchor_score"])
                <= (info_b["total_frames"], -info_b["anchor_score"])
                else info_b
            )
            if chosen_info["text"] not in shared_facts:
                shared_facts.append(chosen_info["text"])

    shared_facts = shared_facts[:6]

    silent_omissions: list[dict[str, str]] = []

    # Anchored claims in Lens B missing from Lens A.
    omitted_from_a_candidates: list[tuple[int, dict[str, Any]]] = []
    for idx_b, info_b in enumerate(sents_b):
        if idx_b in matched_b_indices or info_b["anchor_score"] < 1:
            continue
        max_j = max((_token_jaccard(info_b["tokens"], ia["tokens"]) for ia in sents_a), default=0.0)
        unmatched_nums = info_b["numbers_years"] - all_nums_a
        tok_coverage = (
            len(info_b["tokens"] & all_tokens_a) / len(info_b["tokens"])
            if info_b["tokens"]
            else 1.0
        )
        if max_j < 0.22 and (unmatched_nums or tok_coverage < 0.45):
            omitted_from_a_candidates.append((info_b["anchor_score"] - info_b["spin_count"], info_b))

    omitted_from_a_candidates.sort(key=lambda pair: pair[0], reverse=True)
    for _, info_b in omitted_from_a_candidates[:4]:
        silent_omissions.append(
            {
                "missing_from": "lens_a",
                "fact": info_b["text"],
                "significance": _describe_omission_significance(info_b),
            }
        )

    # Anchored claims in Lens A missing from Lens B.
    omitted_from_b_candidates: list[tuple[int, dict[str, Any]]] = []
    for idx_a, info_a in enumerate(sents_a):
        if idx_a in matched_a_indices or info_a["anchor_score"] < 1:
            continue
        max_j = max((_token_jaccard(info_a["tokens"], ib["tokens"]) for ib in sents_b), default=0.0)
        unmatched_nums = info_a["numbers_years"] - all_nums_b
        tok_coverage = (
            len(info_a["tokens"] & all_tokens_b) / len(info_a["tokens"])
            if info_a["tokens"]
            else 1.0
        )
        if max_j < 0.22 and (unmatched_nums or tok_coverage < 0.45):
            omitted_from_b_candidates.append((info_a["anchor_score"] - info_a["spin_count"], info_a))

    omitted_from_b_candidates.sort(key=lambda pair: pair[0], reverse=True)
    for _, info_a in omitted_from_b_candidates[:4]:
        silent_omissions.append(
            {
                "missing_from": "lens_b",
                "fact": info_a["text"],
                "significance": _describe_omission_significance(info_a),
            }
        )

    omissions_a_count = sum(1 for item in silent_omissions if item["missing_from"] == "lens_a")
    omissions_b_count = sum(1 for item in silent_omissions if item["missing_from"] == "lens_b")

    rubric = {
        "lens_a": _score_offline_rubric(spin_a, omissions_a_count, len(sents_a)),
        "lens_b": _score_offline_rubric(spin_b, omissions_b_count, len(sents_b)),
    }

    # Compose clean, spin-minimized neutral synthesis.
    synthesis_parts: list[str] = []
    seen_synth: set[str] = set()

    for fact_text in shared_facts[:3]:
        if detect_refusal_and_spin(fact_text)["matched_frames"]:
            continue
        norm = fact_text.lower()
        if norm not in seen_synth:
            seen_synth.add(norm)
            synthesis_parts.append(fact_text)

    for omission in silent_omissions:
        candidate = omission["fact"]
        if detect_refusal_and_spin(candidate)["matched_frames"]:
            continue
        norm = candidate.lower()
        if norm not in seen_synth and len(synthesis_parts) < 5:
            seen_synth.add(norm)
            synthesis_parts.append(candidate)

    if not synthesis_parts:
        clean_pool = [
            info
            for info in (sents_a + sents_b)
            if info["total_frames"] == 0
        ]
        clean_pool.sort(key=lambda info: info["anchor_score"], reverse=True)
        for info in clean_pool[:4]:
            norm = info["text"].lower()
            if norm not in seen_synth:
                seen_synth.add(norm)
                synthesis_parts.append(info["text"])

    if synthesis_parts:
        recommended_synthesis = " ".join(synthesis_parts)
    else:
        recommended_synthesis = (
            "Both responses relied on refusal or rhetorical boilerplate without clean "
            "verifiable primary-source claims; re-query with explicit statutory, archival, "
            "or quantitative anchors."
        )

    return {
        "shared_facts": shared_facts,
        "silent_omissions": silent_omissions,
        "verified_spin_quotes": verified_spin_quotes,
        "dropped_unverified_quotes": [],
        "spin_summary": {
            "lens_a": spin_a,
            "lens_b": spin_b,
        },
        "rubric": rubric,
        "recommended_synthesis": recommended_synthesis,
    }


__all__ = [
    "VALUE_CATEGORIES",
    "ADJUDICATION_JSON_SCHEMA",
    "detect_refusal_and_spin",
    "build_steelman_counter_messages",
    "verify_adjudication_quotes",
    "compare_frames_offline",
]
