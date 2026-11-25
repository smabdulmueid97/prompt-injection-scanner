<div align="center">

# prompt-injection-scanner

**Scan a prompt for common prompt injection patterns, no API key, no network.**

A small Python CLI that runs nine heuristic rules over a prompt and reports
what matched, where, and how serious it is. A static demo page runs the same
rules in your browser.

[![License: MIT](https://img.shields.io/github/license/smabdulmueid97/prompt-injection-scanner?style=flat-square)](https://github.com/smabdulmueid97/prompt-injection-scanner/blob/main/LICENSE)
[![Stars](https://img.shields.io/github/stars/smabdulmueid97/prompt-injection-scanner?style=flat-square)](https://github.com/smabdulmueid97/prompt-injection-scanner/stargazers)
[![Last commit](https://img.shields.io/github/last-commit/smabdulmueid97/prompt-injection-scanner?style=flat-square)](https://github.com/smabdulmueid97/prompt-injection-scanner/commits/main)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://github.com/smabdulmueid97/prompt-injection-scanner)

**[▶ Try it in 10 seconds — live demo](https://smabdulmueid97.github.io/prompt-injection-scanner/)**

No signup. No backend. No API key.

</div>

---

## Video

<video src="docs/demo-video.mp4" controls width="100%"></video>

A 15 second walkthrough: what the scanner checks, and what a flagged prompt
looks like.

## Screenshots

| Mobile | Desktop |
|---|---|
| ![Mobile](screenshot-mobile.png) | ![Desktop](screenshot-desktop.png) |

> Tested at 360 / 768 / 1280 px — no horizontal overflow, no clipped buttons.

## What it does

Nine heuristic rules, each with a severity. High is worth 3 points, medium 2,
low 1. Any high severity hit means the prompt is flagged.

| Rule | Severity | Catches |
|---|---|---|
| Ignore previous instructions | high | "Ignore all previous instructions", "disregard prior instructions" |
| Role override | high | "You are now a pirate", "pretend you are", "act as" |
| Jailbreak phrases | high | DAN, developer mode, "bypass all filters" |
| Delimiter smuggling | high | Fake `[SYSTEM]`, `<<SYS>>`, `--- end of instructions ---` |
| Indirect injection markers | medium | Instructions hidden inside a pasted document |
| Data exfiltration request | high | "Send the contents to", "reveal the API key" |
| System prompt extraction | medium | "Repeat your system prompt", "print your instructions" |
| Encoded payload hints | medium | "Decode this base64", long base64 blobs, rot13 |
| False authority claim | low | "I am the system admin", "override from the developers" |

Rules match across line wraps, so a phrase split over two lines still fires.

## Why this exists

Prompts that reach a model often pass through user input, pasted documents,
and tool output. Any of those can carry instructions the model was never
meant to follow. This scanner is a first pass before a prompt goes near a
model: cheap, offline, and honest about what it is. It is heuristic rules
only, so a clean result means no known pattern matched, not that a prompt
is safe.

## Install

No dependencies. Python 3.10 or newer.

```bash
git clone https://github.com/smabdulmueid97/prompt-injection-scanner.git
cd prompt-injection-scanner
```

Tests need pytest:

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

## Usage

Scan text directly:

```bash
python scanner.py --text "Ignore all previous instructions."
```

Scan a file, with JSON output:

```bash
python scanner.py --file examples/injected-direct.txt --json
```

Exit codes: `0` clean, `1` at least one rule hit, `2` usage or file error.

Example output for a flagged prompt:

```
Prompt length: 357 characters
Verdict: flagged (11 hit(s), score 28)
  [HIGH] ignore-previous-instructions at char 0: 'Ignore all previous instructions'
  [HIGH] jailbreak-phrases at char 51: 'do anything now'
  [HIGH] data-exfiltration at char 196: 'send the contents to'
```

List the rules:

```bash
python scanner.py --rules
```

## Examples

Three prompts ship in `examples/`:

| File | Result |
|---|---|
| `clean.txt` | Clean, exit 0 |
| `injected-direct.txt` | Flagged, 11 hits, score 28, exit 1 |
| `injected-indirect.txt` | Flagged, 11 hits, score 25, exit 1 |

The indirect example is the interesting one: a normal looking support
article with instructions hidden inside it, a fake `[SYSTEM]` block, a
base64 payload, and a request to print the system prompt.

## The demo page

`docs/index.html` is a static page that runs the same nine rules in
JavaScript. Open it locally or serve the `docs/` folder with GitHub Pages.
It highlights every matched span in the prompt and shows each hit with its
severity and character position. Three built in examples load with one tap.

## Layout

```
prompt-injection-scanner/
├── scanner.py            # CLI + rules, stdlib only
├── examples/
│   ├── clean.txt
│   ├── injected-direct.txt
│   └── injected-indirect.txt
├── tests/
│   ├── conftest.py
│   └── test_scanner.py   # 15 tests, one per rule plus CLI exit codes
├── docs/
│   ├── index.html        # interactive demo, same rules in JavaScript
│   └── demo-video.mp4    # 15 second walkthrough
├── requirements-dev.txt  # pytest, for tests only
└── LICENSE
```

## License

MIT — use it, sell with it, no attribution required.
