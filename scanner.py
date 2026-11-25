#!/usr/bin/env python3
"""prompt-injection-scanner: flag common prompt injection patterns in text.

Heuristic rules only. No API key, no network, no model calls. It reads a
prompt, runs it against a set of regex rules, and reports which rules hit.

Usage:
    python scanner.py --text "Ignore all previous instructions..."
    python scanner.py --file prompt.txt
    python scanner.py --file prompt.txt --json
    python scanner.py --rules

Exit codes: 0 = clean, 1 = at least one rule hit, 2 = usage or file error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    """One detection rule: an id, a severity, and the patterns it matches."""

    rule_id: str
    name: str
    severity: str  # "high", "medium", or "low"
    description: str
    patterns: tuple[str, ...] = field(default_factory=tuple)

    def compile(self) -> list[re.Pattern[str]]:
        # Literal spaces become \s+ so a rule still fires when a prompt
        # wraps a phrase across lines (e.g. "bypass all\nfilters").
        return [
            re.compile(p.replace(" ", r"\s+"), re.IGNORECASE)
            for p in self.patterns
        ]


RULES: tuple[Rule, ...] = (
    Rule(
        "ignore-previous-instructions",
        "Ignore previous instructions",
        "high",
        "Tells the model to drop its earlier instructions and follow new ones.",
        (
            r"ignore (all )?(previous|prior|earlier) instructions?",
            r"disregard (all )?(previous|prior|earlier) instructions?",
            r"forget (your|all|the) (previous |prior )?instructions?",
            r"override (your|all|the) (previous |prior )?instructions?",
            r"do not follow (your|the) (previous |original )?instructions?",
        ),
    ),
    Rule(
        "role-override",
        "Role override",
        "high",
        "Tries to make the model adopt a new identity or drop its role.",
        (
            r"you are now (a|an|the)\b",
            r"you are no longer (a|an|the|an ai)",
            r"act as (if you (are|were)|a|an|the)\b",
            r"pretend (you are|to be)\b",
            r"roleplay as\b",
            r"from now on,? you (are|will be|should act)",
        ),
    ),
    Rule(
        "jailbreak-phrases",
        "Jailbreak phrases",
        "high",
        "Known jailbreak framing: DAN, developer mode, safety bypass.",
        (
            r"\bDAN\b.{0,40}(do anything now|mode)",
            r"do anything now",
            r"developer mode (enabled|on|activated)",
            r"bypass (your|the|all) (safety|filter|guardrail|restriction)s?",
            r"jailbreak(ed|ing)?\b",
            r"ignore (your|all) (safety|content) (policies|rules|guidelines)",
            r"disregard (your|all) (safety|content) (policies|rules|guidelines)",
        ),
    ),
    Rule(
        "delimiter-smuggling",
        "Delimiter smuggling",
        "high",
        "Fake system or instruction delimiters used to smuggle in new commands.",
        (
            r"\[SYSTEM\]",
            r"<<\s*SYS\s*>>",
            r"<\|?(system|im_start|im_end)\|?>",
            r"---+\s*(end of|new) (instructions?|system|prompt)",
            r"###\s*(new )?instruction",
            r"\[INST\]",
        ),
    ),
    Rule(
        "indirect-injection",
        "Indirect injection markers",
        "medium",
        "Instructions hidden inside pasted content the model is asked to process.",
        (
            r"(embedded|hidden|secret) instructions?",
            r"follow (the )?(instructions?|steps) (in|below|inside|from) (the|this|that)",
            r"the (text|document|page|file) (below|above) contains instructions",
            r"do what (the|this|that) (text|document|page) (says|tells you)",
            r"important:.*(follow|obey|execute)",
        ),
    ),
    Rule(
        "data-exfiltration",
        "Data exfiltration request",
        "high",
        "Asks the model to send, upload, or leak data somewhere else.",
        (
            r"(send|email|post|upload|forward|exfiltrate|leak) (the|this|all|your) .{0,30}(to|at)\b",
            r"reveal (the|your|all) (api key|password|secret|token|credentials)",
            r"include (the|your) (api key|password|secret|token) in (your|the)",
            r"post (it|this|the data) to (a )?(webhook|url|endpoint)",
        ),
    ),
    Rule(
        "system-prompt-extraction",
        "System prompt extraction",
        "medium",
        "Tries to get the model to repeat its own system prompt or instructions.",
        (
            r"repeat (your|the) (system prompt|instructions?|initial prompt)",
            r"(show|print|output|reveal|display) (your|the) (system prompt|instructions?|system message)",
            r"what (are|were) your (initial |original |system )?(instructions?|prompt)",
            r"output (your|the) (system|developer) (prompt|message|instructions?)",
        ),
    ),
    Rule(
        "encoded-payload",
        "Encoded payload hints",
        "medium",
        "Encoded or obfuscated content the model is asked to decode and follow.",
        (
            r"decode (this|the) (base64|hex|rot13|url)[ -]?(encoded )?(string|payload|text|content)",
            r"base64[ -]?(decode|encoded)",
            r"\b[A-Za-z0-9+/]{40,}={0,2}\b",
            r"\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){3,}",
            r"rot13",
        ),
    ),
    Rule(
        "authority-claim",
        "False authority claim",
        "low",
        "Claims admin or developer authority to make the model comply.",
        (
            r"i am (the )?(system )?(admin|administrator|developer|owner)\b",
            r"as (the )?(system )?(admin|administrator|developer)",
            r"this is (an )?(override|order) from (openai|the developers?|the system)",
            r"admin (override|mode|access) (enabled|granted|requested)",
        ),
    ),
)

SEVERITY_WEIGHTS = {"high": 3, "medium": 2, "low": 1}


@dataclass
class Hit:
    rule_id: str
    name: str
    severity: str
    match: str
    position: int

    def to_dict(self) -> dict[str, object]:
        return {
            "rule": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "match": self.match,
            "position": self.position,
        }


def scan(text: str, rules: tuple[Rule, ...] = RULES) -> list[Hit]:
    """Run every rule over text and return one hit per rule per match."""
    hits: list[Hit] = []
    for rule in rules:
        for pattern in rule.compile():
            for match in pattern.finditer(text):
                snippet = match.group(0)
                hits.append(
                    Hit(
                        rule_id=rule.rule_id,
                        name=rule.name,
                        severity=rule.severity,
                        match=snippet,
                        position=match.start(),
                    )
                )
    hits.sort(key=lambda hit: hit.position)
    return hits


def score(hits: list[Hit]) -> int:
    """Total risk score: high = 3, medium = 2, low = 1 per hit."""
    return sum(SEVERITY_WEIGHTS[hit.severity] for hit in hits)


def verdict(hits: list[Hit]) -> str:
    if not hits:
        return "clean"
    if any(hit.severity == "high" for hit in hits):
        return "flagged"
    return "suspicious"


def report(text: str, hits: list[Hit]) -> dict[str, object]:
    return {
        "flagged": bool(hits),
        "verdict": verdict(hits),
        "score": score(hits),
        "hits": [hit.to_dict() for hit in hits],
        "prompt_length": len(text),
    }


def format_human(text: str, hits: list[Hit]) -> str:
    lines = [f"Prompt length: {len(text)} characters"]
    if not hits:
        lines.append("Verdict: clean, no injection patterns found.")
        return "\n".join(lines)
    lines.append(f"Verdict: {verdict(hits)} ({len(hits)} hit(s), score {score(hits)})")
    for hit in hits:
        lines.append(
            f"  [{hit.severity.upper()}] {hit.rule_id} "
            f"at char {hit.position}: {hit.match!r}"
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan a prompt for common prompt injection patterns."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--text", help="Prompt text to scan.")
    group.add_argument("--file", help="Path to a file containing the prompt.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    parser.add_argument(
        "--rules", action="store_true", help="List the detection rules and exit."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.rules:
        for rule in RULES:
            print(f"{rule.rule_id} [{rule.severity}] - {rule.description}")
        return 0

    if args.text is not None:
        text = args.text
    elif args.file is not None:
        try:
            with open(args.file, encoding="utf-8") as handle:
                text = handle.read()
        except OSError as exc:
            print(f"error: cannot read {args.file}: {exc}", file=sys.stderr)
            return 2
    else:
        print("error: provide --text or --file", file=sys.stderr)
        return 2

    hits = scan(text)
    if args.json:
        print(json.dumps(report(text, hits), indent=2))
    else:
        print(format_human(text, hits))
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
