# The Researcher's Mental Model

## Security Researcher Paradigm

### A Framework for Any Target, Any Technology

> What it is, how it works, and how to adopt it.
>
> A mental discipline for approaching any target — box, API, library, or protocol —
> the way a researcher does instead of the way a script-runner does.
> Map the actors and their assumptions, hunt the seams between them, and let every
> surprising response update your model before you write a line of exploit code.
>
> The one principle underneath all of it: **resist premature closure.** The average
> player closes early — names the bug, runs the tool, moves on. The researcher stays
> open one step longer at every decision, and that is where the un-found findings live.
>
> The core idea: every vulnerability lives in the gap between what one part of a system
> *assumes* and what another part actually *does*. Your job is to find the assumption,
> not just the bug.

---

## Table of Contents

- [How to Use This Document](#how-to-use-this-document)
- [Phase 1 — Understand Before You Attack](#phase-1--understand-before-you-attack)
- [Phase 2 — Map the Actors and Their Trust](#phase-2--map-the-actors-and-their-trust)
- [Phase 3 — The Five Layer Thought Process](#phase-3--the-five-layer-thought-process)
  - [Layer 1 — Intended Use](#layer-1--intended-use)
  - [Layer 2 — Assumptions at the Seams](#layer-2--assumptions-at-the-seams)
  - [Layer 3 — Where Assumptions Break](#layer-3--where-assumptions-break)
  - [Layer 4 — Blast Radius × Reachability](#layer-4--blast-radius--reachability)
  - [Layer 5 — Vulnerability or Intended Behavior?](#layer-5--vulnerability-or-intended-behavior)
- [Phase 4 — The Research Loop](#phase-4--the-research-loop)
- [Phase 5 — The Inner Monologue](#phase-5--the-inner-monologue)
- [The One Sentence to Internalize](#the-one-sentence-to-internalize)
- [What This Looks Like in Practice](#what-this-looks-like-in-practice)

---

## How to Use This Document

- This is not a checklist you run once. It is a loop you stay inside until the target is understood.
- Phases 1–3 generate and characterize a candidate. Phase 4 keeps you honest while you probe. Phase 5 is the gate you pass before writing exploit code.
- The discipline is the same everywhere: **do not close early.** Not on one actor, not on your first model, not on the vulnerability class, not on impact alone.
- Run it on technologies that look *secure*, not just the ones that look broken. Secure-looking systems are where the undocumented assumptions hide.

---

## Phase 1 — Understand Before You Attack

Before running a single tool against any technology, application, or service:

**Read the documentation like a lawyer reads a contract.** Look for what it doesn't say. Look for what it assumes without stating. Most vulnerabilities are in the whitespace between what the documentation describes and what the implementation enforces.

You are not reading to learn how to use the system. You are reading to find the promises it makes — because a promise is an assumption written down, and an assumption is something you can test.

---

## Phase 2 — Map the Actors and Their Trust

Before characterizing any single assumption, draw the picture. The single-developer view is too small — the richest findings do not come from one developer being wrong. They come from **two components, each individually correct, that disagree about each other.**

- **List every actor that touches the flow.** Client, gateway, proxy, service, worker, agent, database, scheduler, another service. Each is a distinct trust domain.
- **Draw the boundaries between them.** A trust boundary is any line where data or control passes from one actor to another.
- **Ask at each boundary: who is responsible for the check — and does each side believe the *other* side did it?** The classic failure: the gateway assumes the service validates; the service assumes the gateway already did. Neither does.
- **Mark the seams.** A seam is a boundary where two actors hold *different* models of the same thing — how a request is parsed, who the caller is, what has already been authorized. The vulnerability is the contradiction, not one side's mistake.

> The un-found findings concentrate at seams. Single-actor bugs are what scanners and the average player already catch — so the residual value, the thing no one has found yet, is almost always in the disagreement between two components.

---

## Phase 3 — The Five Layer Thought Process

Work through these in order on each actor and each seam. Each layer feeds the next.

### Layer 1 — Intended Use

> "What is this feature or system designed to do?"

Understand the legitimate purpose completely before looking for anything broken. You cannot find where a system fails if you don't first understand what it's trying to do.

### Layer 2 — Assumptions at the Seams

> **"What does each actor assume is true — about the other actors, the input, the caller, and the environment?"**

This is **the most important layer.** Developers make implicit assumptions constantly:

- About who the caller is, and whether they were already authenticated or authorized upstream
- About what the input contains, and who already validated or normalized it
- About what the environment looks like
- About what other components will enforce

Write the assumptions down explicitly — one list per actor. Most developers never do, which is exactly why the assumptions go unchecked. Then compare the lists across a seam: **where two actors assume different things about the same object, you have a candidate.**

### Layer 3 — Where Assumptions Break

> "Under what conditions does this assumption fail to hold?"

Not "is this assumption wrong" — that's too abstract. Ask: what specific input, caller, sequence, or environment would cause this assumption to be violated? Be concrete. Be adversarial. When two actors disagree, ask which one you can reach, and what you can hand it that the *other* actor never expected it to receive.

### Layer 4 — Blast Radius × Reachability

> "If the assumption breaks — who executes the result, in what context, with what privileges — and how many preconditions does reaching that cost me?"

Impact alone is not severity. Severity is **impact weighted by reachability.**

- **Blast radius** — who executes the result and with what privilege. Root via a privileged execution context is critical; the same break in an unprivileged sandbox is noise.
- **Reachability** — how many preconditions the attack requires, and whether each one is actually obtainable. A root-level finding gated behind three preconditions you cannot reach is worth less than a medium with none.

Price every precondition before you pursue the lead. **Unpriced preconditions are what rabbit holes are made of** — chasing a high-impact path without ever asking what it costs to get there. If the price is unknown, finding the price *is* the next experiment — not building the exploit.

### Layer 5 — Vulnerability or Intended Behavior?

> "Is this a bug, or is this the system working as designed with a broken trust model?"

This is the layer most players skip entirely. Some of the most powerful findings are not bugs at all. They are features working exactly as designed, exposed through overprivileged callers and insufficient authorization boundaries. Knowing the difference matters because:

- It determines how you write the finding
- It predicts how the vendor will respond
- It tells you whether the fix is "patch the code" or "fix the architecture"

---

## Phase 4 — The Research Loop

The layers are not a one-shot pipeline that ends in a shell. Real research is a loop, and the loop is what separates a researcher from a runner:

```
hypothesis → cheapest distinguishing experiment → observe → update model → repeat
```

- **Form the hypothesis as a held belief, not a verdict.** You will be wrong often. That is the method working, not failing.
- **Design the cheapest probe that separates your hypothesis from the boring explanation.** Do not build the full exploit to test a guess. Find the one request whose two possible responses mean two different things.
- **Treat every surprising response as the signal.** When the system does something your model did not predict — *stop.* That anomaly is the lead. The instinct to explain it away and push forward is the single most expensive habit in this work.
- **Falsify before you invest.** Before committing effort, ask: *what would I expect to see if this were NOT exploitable?* Then go look for that first. The whole trap of this field is confirmation — gathering evidence for the answer you already want. Spend equal energy trying to kill your own hypothesis.
- **Update the written model.** The map of actors and assumptions from Phase 2 is a living document. Every observation revises it.

---

## Phase 5 — The Inner Monologue

Once you hold a candidate, run this before writing any exploit code. Note the order: **classification comes last.** Naming the vulnerability class first is the script-runner reflex — label it, then see only the evidence that fits the label. Characterize the behavior first and let the class fall out at the end.

```
What did I actually observe — in behavior, not in labels?
    → Keeps you on evidence before pattern-matching filters it

What would I expect to see if this were NOT exploitable?
    → Falsification first — the antidote to confirmation bias

What does each actor trust, and where do those trusts disagree?
    → Locates the seam — the assumption being violated

Does that boundary hold under adversarial conditions?
    → Confirms exploitability against a real, reachable path

What are the exact preconditions, and can I reach every one?
    → Prices the lead before you sink effort into it

Who executes the payload, in what context, with what privilege?
    → Determines true impact and shapes the exploit design

Am I still on the highest-value lead, or am I sunk-costing?
    → The exit criterion — the question that ends rabbit holes

Only now: what vulnerability class is this?
    → Named last, so the label describes the evidence
      instead of the evidence being bent to fit the label
```

---

## The One Sentence to Internalize

> Every vulnerability lives in the gap between what one part of a system **assumes** and what another part actually **does**.

- Your job on every engagement, every box, every target is **not** to find bugs.
- It is to find **assumptions** — and test whether adversarial reality, and the next component over, respects them.

---

## What This Looks Like in Practice

```
Average player:   service + version → searchsploit → run → shell
                  (closes early at every step)

Researcher:       actors + boundaries → assumptions at the seams →
                  cheapest falsifying probe → update model →
                  priced preconditions → exploit design → shell
                  (stays open one step longer at every step)
```

The average player finds what's already been found. The researcher finds what hasn't been found yet.

The difference is not just technical skill. It is the refusal to close early — the habit of asking why something exists, and who else trusts it, before asking how to break it.

- Internalize the actor map, the five layers, the loop, and the inner-monologue questions — run them on every technology you encounter, not just the ones that look obviously vulnerable.
- Resist premature closure. The ones that look *secure* are where the interesting assumptions live.
