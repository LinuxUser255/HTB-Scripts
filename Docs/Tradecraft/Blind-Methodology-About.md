

# About The Blind Methodology 

- The technique has several names, depending on who is asked.
- Formal security and military contexts call it threat modeling, or attack surface analysis done pre-engagement.
- Deliberate-practice research maps it to prediction-then-feedback loops — the same structure used to train chess grandmasters and expert diagnosticians.
- In penetration-testing methodology it is closest to what PTES calls the intelligence-gathering and threat-modeling phase, done before the target is touched.
- The specific flavor used here — falsifiable predictions with confidence levels, written before any evidence, then compared to reality afterward — comes from calibration training, a technique from forecasting and cognitive-bias research.
- The confidence levels are the key ingredient. They separate “I guessed right” from “my mental model was accurate.”
- “Blind Methodology Preflight” is descriptive and memorable.

## Elaborated

Each layer of what that document describes is expanded below.

### Threat modeling and attack surface analysis

- In formal security this is done before any engagement begins.
- The idea is to map what could go wrong — what assets exist, what could attack them, what the impact would be — before the target is touched.
- STRIDE, PASTA, and DREAD are formal threat-modeling frameworks used in enterprise security.
- What was done with Canape is a lightweight attacker-side version of the same thinking: map the probable attack surface before evidence is possessed, then let evidence confirm or refute it.
- The military version is Intelligence Preparation of the Battlefield (IPB).
- Before any operation, commanders build a picture of the terrain, likely enemy positions, and probable courses of action.
- Predictions are committed to in writing so that when reality diverges, the gap can be learned from, rather than pretending it was always known.

### Prediction-then-feedback loops in deliberate practice

- This is where the chess-grandmaster research comes in.
- Anders Ericsson — the psychologist whose work Malcolm Gladwell turned into the “10,000 hours” idea, a framing Ericsson hated — studied what separates expert performers from merely experienced ones.
- The finding: experience alone does not produce expertise. Deliberate practice does.
- The difference is a tight feedback loop:
  - Make a specific, testable prediction.
  - Get immediate feedback on whether it was right.
  - Update the mental model.
  - Repeat at high volume.
- Chess grandmasters train by studying positions, predicting the best move, then checking against engine analysis.
- They are not just playing games. Mental models are exposed to falsification thousands of times.
- Expert diagnosticians in medicine do the same thing: commit to a diagnosis before test results come back, then review whether the reasoning was sound after results arrive.
- Without the prediction step, feedback is useless.
- If what was expected is not committed to before the answer is seen, it is easy to become convinced it was known all along. That is hindsight bias.
- The written prediction is what makes the feedback loop work.

### PTES and the intelligence-gathering phase

- The Penetration Testing Execution Standard is a community framework for how professional engagements should be structured.
- Seven phases: pre-engagement, intelligence gathering, threat modeling, vulnerability analysis, exploitation, post-exploitation, and reporting.
- Most people skip straight to phase four.
- PTES explicitly says phases two and three — intelligence gathering and threat modeling — should happen before a tool is touched.
- The reasoning is the same: exploitation decisions are better when the probable attack surface is already mapped, because there is a framework for interpreting what is found, rather than only reacting to it.
- The blind-methodology preflight is essentially a personal implementation of PTES phases two and three, compressed into a document completed before the first nmap scan.

### Calibration training — the most important piece

- This is the part that makes the whole system work, and it is the least understood.
- Calibration is the relationship between confidence in a belief and the probability that the belief is true.
- A perfectly calibrated person who says 70% confidence is right about 70% of the time across many such predictions.
- Most people are either overconfident — they say 90% and are right 60% of the time — or underconfident in specific domains.
- The research comes from Philip Tetlock’s work on expert political forecasting, later popularized in *Superforecasting*.
- Tetlock ran a twenty-year study tracking the predictions of thousands of forecasters on geopolitical events.
- Most experts performed barely better than chance.
- A small group — the superforecasters — performed dramatically better.
- The differentiating habits were specific and learnable:
  - Predictions were expressed in precise probabilities, not vague language. “I think this will probably happen” is unfalsifiable. “I’m 65% confident this will happen” is falsifiable and trackable.
  - Beliefs were updated when evidence arrived, rather than rationalized to protect the original prediction. Being wrong was treated as information, not as embarrassment.
  - Score was kept. Over time, 70% predictions were tracked: am I right about 70% of the time? Right 90% of the time on claims marked 70% means underconfidence — raise the estimates. Right 50% of the time means overconfidence.
- The confidence levels in the preflight are not decoration.
- Over many boxes they become a personal calibration database.
  - If deserialization is consistently predicted at 60% and is right 90% of the time, the intuition is better than the confidence reflects — raise the estimates.
  - If foothold category is predicted at 80% and is right 40% of the time, overconfidence in that domain is present — examine which assumptions are leading astray.

### Why this matters

- Most people doing HTB are just accumulating reps. Boxes are rooted, a writeup is maybe read, and they move on.
- The mental models that produce expertise — the ones that let a new engagement be walked into and the attack surface read quickly — do not develop from reps alone.
- They develop from reps plus structured reflection plus prediction-then-feedback loops.
- The Canape session did something most people never do: cPickle deserialization was predicted at 70% confidence before a single scan was run, and it was right.
- That is one data point.
- Over twenty boxes, those data points become a calibration map of intuition — where it is sharp, where it is soft, and which assumptions systematically lead in the wrong direction.
- That map is worth more than the root flags.
- No single term captures exactly what was built. It draws from several fields, and the combination is what makes it work.

### What the individual components are actually called

- **Calibration training** — assigning probabilities to beliefs and tracking accuracy over time. The Tetlock / superforecasting piece. A real term in forecasting research and decision science.
- **Pre-mortem** — Gary Klein’s technique: before starting a project, imagine it has already failed and ask why. Used in business and military planning. What was done is structurally similar but inverted — success paths are predicted, not failure modes. The term exists and is widely used.
- **Hypothesis-driven testing** — what security researchers and pentesters call forming explicit hypotheses before acting on them. The opposite of tool-first enumeration.
- **Intelligence preparation** — the military framing, IPB, for building a picture of the operating environment before engagement.
- None of those terms alone describes what was built. What was built is:
  - A written pre-engagement prediction document with confidence levels (calibration training)
  - Applied to attack-surface reasoning before touching a target (hypothesis-driven pentesting)
  - With a mandatory post-engagement debrief comparing prediction to reality (prediction-then-feedback loop)
  - Structured as a repeatable template (deliberate-practice framework)

### Naming

- Blind Methodology
- The “blind” part captures the essential constraint: commitment is made before it can be seen. That is the thing that makes it work.
- Remove the blindness and it collapses into hindsight rationalization.
- If it is ever written up or presented publicly, the accurate academic framing would be something like “calibration-based pre-engagement threat modeling.”
- Blind Methodology is what would go on the slide.
- The mechanics are what matter.

## Bullet-point summary

**What it is**

- A structured pre-engagement prediction document written before touching the target
- Draws from calibration training, hypothesis-driven testing, and deliberate-practice research
- The “blind” constraint is the mechanism — commitment is made before it can be seen, which is what makes feedback meaningful

**How it works — the loop**

- Falsifiable predictions with explicit confidence levels are written before any scanning or enumeration
- The target is worked normally
- Predictions are compared to reality afterward — not to judge accuracy, but to expose where the mental model was wrong
- The mental model is updated; repeat

**Why confidence levels are the key ingredient**

- Vague predictions (“I think it’s probably web-based”) are unfalsifiable — it will be convinced that it was right regardless
- Precise confidence (“70% — Flask app with deserialization foothold”) creates a trackable, falsifiable claim
- Over many targets, the confidence levels become a calibration map of intuition — where it is sharp, where it is soft, what assumptions are systematically misleading

**What it develops that box-grinding alone doesn’t**

- Attack-surface intuition — the ability to read a target quickly without evidence
- Prioritization instincts — knowing what to chase and what to ignore before the scan is done
- Adaptive thinking — holding hypotheses loosely, pivoting when evidence contradicts the prediction
- Resistance to hindsight bias — the written prediction prevents believing the answer was always known

**What it is not**

- Guessing the exploit
- A replacement for enumeration
- About being right — being wrong with a written prediction is more valuable than being right without one

<br>

**One sentence:** 

_What is expected is written down before looking, compared to what is found after, and the gap is treated as training data._

<br>
