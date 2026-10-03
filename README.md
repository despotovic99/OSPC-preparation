# Walkthroughs

A version-controlled collection of walkthroughs documenting how I solve machines from
[Hack The Box](https://www.hackthebox.com/) and other cybersecurity training platforms.

The goal of this repository is to keep a clean, incremental history of each solution: how a
target was approached, which techniques worked, and what the full kill chain looked like from
initial reconnaissance to full compromise. Tracking these write-ups in Git makes it easy to
revisit, refine, and compare approaches over time.

## Purpose

- **Learning record** — Capture the reasoning and commands behind each solve while the details are fresh.
- **Reference material** — Build a searchable, reusable knowledge base of tools, techniques, and attack paths.
- **Version history** — Preserve how write-ups evolve, including corrections and alternative approaches.
- **OSCP preparation** — Reinforce methodology through consistent, repeatable documentation.

## Repository structure

Walkthroughs are organized by platform, then by machine. Each machine has its own directory
containing a `WALKTHROUGH.md` file.

```
walkthroughs/
└── HTB Machines/
    └── <Machine Name>/
        └── WALKTHROUGH.md
```

## Walkthrough format

Each write-up follows a consistent structure so it is easy to read and reuse:

1. **Executive summary** — Target details, credentials discovered, and the overall kill chain.
2. **Reconnaissance** — Port scanning and service enumeration.
3. **Enumeration & exploitation** — Step-by-step path to a foothold.
4. **Privilege escalation** — How initial access was elevated to full compromise.

Commands, tool output, and relevant findings are included throughout. Sensitive values such as
flag contents are redacted.

## Disclaimer

All content in this repository is for educational purposes only. Every machine documented here
was solved in a legal, authorized training environment. Do not use any of these techniques
against systems you do not own or have explicit permission to test.
