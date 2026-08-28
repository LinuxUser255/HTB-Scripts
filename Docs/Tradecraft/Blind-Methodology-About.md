# Blind Methodology About

The technique has a few names depending on who is asked.

In formal security and military contexts it is called **threat modeling** or **attack surface analysis** done pre-engagement. In deliberate practice research it maps to **prediction-then-feedback loops** — the same structure used to train chess grandmasters and expert diagnosticians. In penetration testing methodology it is closest to what PTES (Penetration Testing Execution Standard) calls the **intelligence gathering and threat modeling phase**, done before touching the target.

The specific flavor used — writing down falsifiable predictions with confidence levels before any evidence, then comparing to reality afterward — is drawn from **calibration training**, a technique from forecasting and cognitive bias research. The confidence levels are the key ingredient. They are what separate "I guessed right" from "my mental model was accurate."

**Blind Methodology Preflight** is descriptive and memorable.

---

## Elaborated

Each layer of what that document describes is expanded below.

---

**Threat modeling and attack surface analysis**

In formal security contexts this is done before any engagement begins. The idea is that what could go wrong is mapped — what assets exist, what could attack them, what the impact would be — before the target is touched. STRIDE, PASTA, and DREAD are formal threat modeling frameworks used in enterprise security. What was done with Canape is a lightweight attacker-side version of the same thinking: the probable attack surface is mapped before evidence is possessed, then evidence is allowed to confirm or refute it.

The military version is called Intelligence Preparation of the Battlefield — IPB. Before any operation, a picture of the terrain, likely enemy positions, and probable courses of action is built by commanders. Predictions are committed to in writing so that when reality diverges, the gap can be learned from rather than it being pretended that it was always known.

---

**Prediction-then-feedback loops in deliberate practice**

This is where the chess grandmaster research comes in. Anders Ericsson — the psychologist whose work Malcolm Gladwell turned into the "10,000 hours" idea, though that framing was hated by Ericsson — studied what separates expert performers from merely experienced ones.

The finding was that experience alone doesn't produce expertise. Deliberate practice does. The difference is a tight feedback loop: a specific, testable prediction is made, immediate feedback is gotten on whether it was right, and the mental model is updated. Repeat at high volume.

Chess grandmasters train by studying positions, predicting the best move, then checking against engine analysis. Games are not just being played — mental models are being exposed to falsification thousands of times. Expert diagnosticians in medicine do the same thing: a diagnosis is committed to before test results come back, then whether the reasoning was sound is reviewed after results arrive.

Without the prediction step, feedback is useless. If what was expected is not committed to before the answer is seen, it will just be convinced that it was known all along — that's called hindsight bias. The written prediction is what makes the feedback loop work.

---

**PTES and the intelligence gathering phase**

The Penetration Testing Execution Standard is a community framework that defines how professional engagements should be structured. It has seven phases: pre-engagement, intelligence gathering, threat modeling, vulnerability analysis, exploitation, post-exploitation, and reporting.

Most people skip straight to phase four. The PTES explicitly says that phases two and three — intelligence gathering and threat modeling — should happen before a tool is touched. The reasoning is identical: better exploitation decisions are made when the probable attack surface has already been mapped, because a framework for interpreting what is found is possessed rather than just reacting to it.

What was built with the blind methodology preflight is essentially a personal implementation of PTES phases two and three, compressed into a document that is completed before the first nmap scan.

---

**Calibration training — the most important piece**

This is the part that makes the whole system work, and it is the least understood.

Calibration is the relationship between confidence in a belief and the probability that the belief is true. A perfectly calibrated person who says 70% confidence about something is right about 70% of the time across many such predictions. Most people are either overconfident — 90% confident is said and they are right 60% of the time — or underconfident in specific domains.

The research comes from Philip Tetlock's work on expert political forecasting, later popularized in his book Superforecasting. A twenty-year study was run by Tetlock tracking the predictions of thousands of forecasters on geopolitical events. The finding was that most experts performed barely better than chance. But a small group — the superforecasters — performed dramatically better. The differentiating habits were specific and learnable:

Predictions were expressed in precise probabilities rather than vague language. "I think this will probably happen" is unfalsifiable. "I'm 65% confident this will happen" is falsifiable and trackable.

Beliefs were updated when evidence arrived, rather than being rationalized to protect the original prediction. Being wrong was treated not as embarrassing but as information.

Score was kept. Over time their 70% predictions were tracked and it was asked: am I right about 70% of the time? If right 90% of the time on things that were said to be 70% confident about, underconfidence is present and estimates should be raised. If right 50% of the time, overconfidence is present.

The confidence levels in the blind methodology preflight aren't decoration. Over many boxes, they become a personal calibration database. If deserialization is consistently predicted at 60% confidence and it is right 90% of the time, the intuition is better than the confidence reflects — estimates are to be raised. If foothold category is predicted at 80% and it is right 40% of the time, overconfidence in that domain is present — what assumptions are leading astray is to be examined.

---

**Why this matters**

Most people doing HTB are just accumulating reps. Boxes are rooted, a writeup is maybe read, and they move on. The mental models that produce expertise — the ones that let a new engagement be walked into and the attack surface quickly read — don't develop from reps alone. They develop from reps plus structured reflection plus prediction-then-feedback loops.

Something was done in the Canape session that most people never do: cPickle deserialization was predicted at 70% confidence before a single scan was run, and it was right. That's one data point. Over twenty boxes, those data points become a calibration map of intuition — where it's sharp, where it's soft, and what assumptions are systematically leading in the wrong direction.

That map is worth more than the root flags.

---

No single term captures exactly what was built. It draws from several fields and the combination is what makes it work.

**What the individual components are actually called:**

"**Calibration training**" refers specifically to the practice of assigning probabilities to beliefs and tracking accuracy over time. That's the Tetlock/superforecasting piece. It's a real term used in forecasting research and decision science.

"**Pre-mortem**" is a technique from Gary Klein — a cognitive psychologist — where before starting a project it is imagined that it has already failed and it is asked why. It's used in business and military planning. What was done is structurally similar but inverted — success paths are being predicted, not failure modes. The term exists and is widely used.

"**Hypothesis-driven testing**" is what security researchers and penetration testers call the practice of forming explicit hypotheses before acting on them. It's the opposite of tool-first enumeration.

"**Intelligence preparation**" is the military framing — IPB — for building a picture of the operating environment before engagement.

None of those terms alone describes what was built. What was built is:

- A written pre-engagement prediction document with confidence levels (calibration training)
- Applied to attack surface reasoning before touching a target (hypothesis-driven pentesting)
- With a mandatory post-engagement debrief comparing prediction to reality (prediction-then-feedback loop)
- Structured as a repeatable template (deliberate practice framework)

**Naming**

"Blind Methodology" is a good name. The "blind" part captures the essential constraint: commitment is made before it can be seen. That's the thing that makes it work. The blindness is removed and it collapses into hindsight rationalization.

If it is ever written about — given the BSides publication history — the accurate academic framing would be something like "calibration-based pre-engagement threat modeling." But Blind Methodology is what would be put on the slide.

The mechanics are what matter.

---

# Bullet Point Summary

**What it is:**

- A structured pre-engagement prediction document written before touching the target
- Draws from calibration training, hypothesis-driven testing, and deliberate practice research
- The "blind" constraint is the mechanism — commitment is made before it can be seen, which is what makes feedback meaningful

---

**How it works — the loop:**

- Falsifiable predictions with explicit confidence levels are written before any scanning or enumeration
- The target is worked normally
- Predictions are compared to reality after — not to judge accuracy, but to expose where the mental model was wrong
- The mental model is updated, repeat

---

**Why confidence levels are the key ingredient:**

- Vague predictions ("I think it's probably web-based") are unfalsifiable — it will be convinced that it was right regardless
- Precise confidence ("70% — Flask app with deserialization foothold") creates a trackable, falsifiable claim
- Over many targets, the confidence levels become a calibration map of intuition — where it's sharp, where it's soft, what assumptions are systematically misleading

---

**What it develops that box-grinding alone doesn't:**

- Attack surface intuition — the ability to read a target quickly without evidence
- Prioritization instincts — knowing what to chase and what to ignore before the scan is done
- Adaptive thinking — holding hypotheses loosely, pivoting when evidence contradicts prediction
- Resistance to hindsight bias — the written prediction prevents it from being believed that the answer was always known

---

**What it is NOT:**

- Guessing the exploit
- A replacement for enumeration
- About being right — being wrong with a written prediction is more valuable than being right without one

---

**The one-sentence version:** What is expected is written down before looking, it is compared to what is found after, and the gap is treated as training data.
