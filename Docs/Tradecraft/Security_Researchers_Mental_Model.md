
# The Researcher's Mental Model

## A Paradigm Shift from Exploit-Runner to Vulnerability Researcher

## Framework for Any Target, Any Technology


> What it is, how it works, and how to adopt it.

> A short mental checklist for approaching any target — box, API, library, or protocol
> the same way a researcher does instead of the way a script-runner does.
> Work the five layers before writing exploit code, then run the inner monologue before pulling the trigger.
> The core idea: every vulnerability lives in the gap between what a system *assumes* and what reality *permits*
> your job is to find the assumption, not just the bug.

---

## Table of Contents

- [Phase 1 — Understand Before You Attack](#phase-1-understand-before-you-attack)
- [Phase 2 — The Five Layer Thought Process](#phase-2-the-five-layer-thought-process)
  - [Layer 1 — Intended Use](#layer-1-intended-use)
  - [Layer 2 — Developer Assumptions](#layer-2-developer-assumptions)
  - [Layer 3 — Where Assumptions Break](#layer-3-where-assumptions-break)
  - [Layer 4 — Blast Radius](#layer-4-blast-radius)
  - [Layer 5 — Vulnerability or Intended Behavior?](#layer-5-vulnerability-or-intended-behavior)
- [Phase 3 — The Inner Monologue](#phase-3-the-inner-monologue)
- [The One Sentence to Internalize](#the-one-sentence-to-internalize)
- [What This Looks Like in Practice](#what-this-looks-like-in-practice)

---

### Phase 1 — Understand Before You Attack

Before running a single tool against any technology, application, or service:

**Read the documentation like a lawyer reads a contract.** Look for what it doesn't say. Look for what it assumes without stating. Most vulnerabilities are in the whitespace between what the documentation describes and what the implementation enforces.

---

### Phase 2 — The Five Layer Thought Process

Work through these in order. Each layer feeds the next.

**Layer 1 — Intended Use**

> "What is this feature or system designed to do?"

Understand the legitimate purpose completely before looking for anything broken. You cannot find where a system fails if you don't first understand what it's trying to do.

**Layer 2 — Developer Assumptions**

> **"What did the developer assume would always be true when they built this?"**

This is **the most important layer**. **Developers** make implicit **assumptions** constantly:

- About who the caller is
- About what the input contains
- About what the environment looks like
- About what other components will enforce

Write the assumptions down explicitly. Most developers never do. That's why they get violated.

**Layer 3 — Where Assumptions Break**

> "Under what conditions does this assumption fail to hold?"

Not "is this assumption wrong" — that's too abstract. Ask: what specific input, caller, sequence, or environment would cause this assumption to be violated? Be concrete. Be adversarial.

**Layer 4 — Blast Radius**

> "If the assumption breaks — who executes the result, in what context, with what privileges?"

This is what converts a theoretical finding into an actual vulnerability. A broken assumption that executes in an unprivileged sandbox is low severity. The same broken assumption executing as root via a SUID binary or a server-side agent is critical. The blast radius determines the finding's value.

**Layer 5 — Vulnerability or Intended Behavior?**

> "Is this a bug, or is this the system working as designed with a broken trust model?"

This is the layer most players skip entirely. Some of the most powerful findings are not bugs. They are features with overprivileged callers and insufficient authorization boundaries. Knowing the difference matters because:

- It determines how you write the finding
- It predicts how the vendor will respond
- It tells you whether the fix is "patch the code" or "fix the architecture"

---

### Phase 3 — The Inner Monologue

Once you've found a candidate, run this before writing any exploit code:

```
What vulnerability class is this?
    → Establishes the mental model and transferable pattern

What does the system trust?
    → Identifies the assumption being violated

Where is the trust boundary drawn?
    → Defines what the system believes it controls

Does that boundary hold under adversarial conditions?
    → Confirms exploitability

What are the exact preconditions for exploitation?
    → Forces you to reason about dependencies before writing code

Who executes the payload and in what context?
    → Determines impact and shapes the exploit design
```

---

## The One Sentence to Internalize

> Every vulnerability lives in the gap between what a system **assumes** and what **reality permits**.

- Your job on every engagement, every box, every target is **not** to find bugs.
- Rather, your job is to find **assumptions** — and test whether adversarial reality respects them.

---

### What This Looks Like in Practice

```
Average player:   service + version → searchsploit → run → shell

Researcher:       documentation → assumptions → trust boundary →
                  preconditions → exploit design → shell
```

The average player finds what's already been found. The researcher finds what hasn't been found yet.

The difference is not just technical skill. It is the habit of asking why something exists before asking how to break it.

---

- The paradigm shift.
- The inner monologue.
- Internalize these five layers and the six inner monologue questions — run them on every technology you encounter.


