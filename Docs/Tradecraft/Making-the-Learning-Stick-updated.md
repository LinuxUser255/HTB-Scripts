
# Making the Learning Stick

---

# Learning Science for Offensive Security Training

This is both a learning science question and a security training question. Below is a structured, practical guide based on how the brain actually retains complex skills and rewires mental models.

## On Cognitive Fatigue and Breaks

The fatigue you’re experiencing after 2–4 hours of preflight followed by active hacking is real. It doesn’t primarily come from the difficulty of individual tasks, but from the **cognitive mode switching** required:

- **Preflight** → Generative, hypothesis-forming, forward-projecting
- **Active hacking** → Analytical, evidence-interpreting, decision-making under uncertainty
- **Socratic dialogue** → Metacognitive (thinking about your own thinking in real time)

Switching between these modes within a single session is what drains mental resources.

### The Break Structure That Actually Works

Traditional Pomodoro (25 minutes) is poorly suited for deep security work. You spend the first 10+ minutes loading context into working memory — interrupting at 25 minutes destroys that investment.

**Recommended structure:**

| Work Block     | Break              | Notes                                      | Max per Session |
|----------------|--------------------|--------------------------------------------|-----------------|
| **90 minutes** | 15–20 minutes      | Real break (see below)                     | 2 blocks        |
| **90 minutes** | —                  | Hard stop after second block               | —               |

- Use **90-minute work blocks** (aligns with natural ultradian rhythms).
- Take **real breaks** — not doom-scrolling or watching security content.
- **Maximum two blocks per session**. Three blocks often leads to diminishing (or negative) returns and cements bad habits rather than good ones.

### What Counts as a Real Break

| Counts as a Break                  | Does **Not** Count as a Break          |
|------------------------------------|----------------------------------------|
| Walking (even 10 minutes)          | Scrolling Twitter, Reddit, or security Twitter |
| Eating away from screens           | Watching security YouTube              |
| Eyes closed, no audio              | Reading write-ups or technical content |
| Physical movement / stretching     | Switching to another technical task    |

**Why this matters:** During a real break, your brain consolidates what you just learned. Filling the break with more input interrupts this process.

---

## On Retention — What the Research Actually Says

Four key mechanisms drive durable, long-term retention. You are already using two of them effectively.

### 1. Generation Effect (You’re already doing this)

You retain information much better when you **generate** it yourself rather than passively receive it. This is why the Socratic method is powerful — being asked what you think *before* being told the answer forces generation.

Every time you write a preflight, hand-roll an exploit, or are asked a leading question instead of being given the answer, you are leveraging the Generation Effect.

### 2. Desirable Difficulty (You’re already doing this)

Learning that *feels* difficult produces stronger, longer-lasting encoding. The 2–4 hour preflights that feel exhausting are actually more effective than quick tool runs. The difficulty is a feature, not a bug.

### 3. Spaced Retrieval (Highest-leverage mechanism you’re likely underusing)

This is one of the most powerful tools for long-term retention.

**What it is:** Actively recalling information from memory at increasing intervals — without looking at your notes.

**How to apply it:**

| Interval | Activity |
|----------|----------|
| **Day 1**    | Complete the box + write debrief |
| **Day 2**    | Close everything. Reconstruct from memory: vulnerability class, developer assumption, exploit chain, generalizations |
| **Day 7**    | Repeat the recall exercise |
| **Day 14**   | Repeat again |
| **Day 30**   | Repeat again |

The act of *trying to recall* builds much stronger memory traces than re-reading notes.

**Weekly Paradigm Shift Practice:**
Once a week, with no notes and no Claude, write:

> “Here is how I would approach [technology X] if I saw it for the first time.”

Then compare it against the five-layer mental model. Identify where you skipped layers — those gaps reveal where your old amateur habits are still dominant.

### 4. Interleaving (Worth adding deliberately)

Doing the same type of task repeatedly (*blocked practice*) feels productive but produces shallow learning. Mixing different problem types (*interleaved practice*) feels harder but builds deeper, more flexible expertise.

**Example for your curriculum:**

Instead of:
> Deserialization box → Deserialization box → Deserialization box

Try:
> Deserialization box → PortSwigger lab (different class) → CVE research → Next box

The context switching forces your brain to retrieve and re-apply the mental model in new situations — which is exactly what builds transferable skill.

---

## On the Paradigm Shift — How to Actually Rewire Mental Models

A paradigm shift is not about replacing your old mental model. It’s about building a **new, faster pathway** through repetition until it becomes automatic.

**Current state:**
See a service → Amateur pathway fires first → Researcher pathway requires conscious effort.

**Target state:**
See a service → Researcher pathway fires first (“What does this system trust?” is the automatic first question).

### What Accelerates Rewiring

| Technique              | How to Apply It                                                                 | Why It Works |
|------------------------|----------------------------------------------------------------------------------|--------------|
| **Verbalization**      | After every box, explain the kill chain and Layer 2 analysis **out loud** (alone, no notes) | Engages different encoding pathways than writing |
| **Catch & Name**       | When you notice yourself using old habits (e.g., googling version before hypothesizing), stop and say: “I just skipped Layer 2.” | Interrupts the old pattern and weakens it over time |
| **Teach It**           | Explain your reasoning (in writing or verbally) to someone who doesn’t already know it | Forces implicit knowledge to become explicit and coherent |
| **Apply Outside HTB**  | Once a week, pick a real CVE disclosure. Before reading the details, ask: “What assumption did the developer make?” | Builds the habit of applying the model in real-world contexts |

---

## On the Preflight Taking Too Long

The preflight currently serves two purposes with very different time costs:

1. **Forcing commitment before engagement** — High value, relatively fast
2. **Demonstrating deep understanding to Claude** — Lower marginal value, time-consuming

### Recommended Time Boxes

| Mode              | Hard Time Cap | Action When Time Is Up |
|-------------------|---------------|------------------------|
| **Mode 1 (Full Depth)**   | 90 minutes    | Commit to current hypotheses and begin enumeration. Flag gaps for Claude to review. |
| **Mode 2 (Targeted Depth)** | 45 minutes    | Same as above |
| **Mode 3 (Speed Run)**    | 20 minutes    | Same as above |

**The goal of the preflight is not perfect understanding** — it is to form a committed hypothesis *before* reality influences your thinking. Perfect understanding comes from the box itself.

---

## What to Stop Doing

| Stop Doing                              | Replace With |
|-----------------------------------------|--------------|
| Re-reading notes to review              | Attempt recall from memory first, *then* check notes |
| Running consecutive boxes in the same vulnerability class | Interleave with different classes (e.g., PortSwigger labs or CVE research) |
| Treating the flag as the main deliverable | Treat the debrief and corrected mental models as the deliverable |
| Pushing through fatigue past block 3    | Hard stop — fatigued practice cements errors |
| Filling breaks with security content    | Use breaks for silence, movement, or food to allow consolidation |
| Trying to complete the preflight perfectly before starting | Time-box it, commit to hypotheses, start, and update as you go |

---

## The One Habit That Ties Everything Together

If you only implement **one thing** from this entire guide, make it this:

### Weekly Recall Session (30 minutes)

Once a week, pick any completed box or CVE at random. With **no notes and no Claude**, reconstruct from memory:

- What was the vulnerability class?
- What developer assumption was violated?
- What was the exploit chain?
- What does this generalize to?
- How would I find this without a CVE number?

Then open your notes and identify the gaps.

**Those gaps represent your actual current skill level** — not what you can produce with support, but what fires automatically when you’re alone in front of an unfamiliar target.

Closing that gap is the real work of the paradigm shift.

---

This document is now structured for easy reading and future reference. Would you like me to save this as a standalone file (e.g., `Learning-Science-for-Security-Training.md`)?
