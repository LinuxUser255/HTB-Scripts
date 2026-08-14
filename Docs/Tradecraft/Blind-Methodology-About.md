

The technique has a few names depending on who you ask.

In formal security and military contexts it's called **threat modeling** or **attack surface analysis** done pre-engagement. In deliberate practice research it maps to **prediction-then-feedback loops** — the same structure used to train chess grandmasters and expert diagnosticians. In penetration testing methodology it's closest to what PTES (Penetration Testing Execution Standard) calls the **intelligence gathering and threat modeling phase**, done before touching the target.

But the specific flavor we used — writing down falsifiable predictions with confidence levels before any evidence, then comparing to reality afterward — is drawn from **calibration training**, a technique from forecasting and cognitive bias research. The confidence levels are the key ingredient. They're what separate "I guessed right" from "my mental model was accurate."

What you named it is good though. **Blind Methodology Preflight** is descriptive and memorable. Keep it

---

## Elaborated

Good — you saved it. Let me expand on each layer of what that document describes.

---

**Threat modeling and attack surface analysis**

In formal security contexts this is done before any engagement begins. The idea is that you map what could go wrong — what assets exist, what could attack them, what the impact would be — before you touch the target. STRIDE, PASTA, and DREAD are formal threat modeling frameworks used in enterprise security. What we did with Canape is a lightweight attacker-side version of the same thinking: map the probable attack surface before you have evidence, then let evidence confirm or refute it.

The military version is called Intelligence Preparation of the Battlefield — IPB. Before any operation, commanders build a picture of the terrain, likely enemy positions, and probable courses of action. They commit to predictions in writing so that when reality diverges, they can learn from the gap rather than pretend they always knew.

---

**Prediction-then-feedback loops in deliberate practice**

This is where the chess grandmaster research comes in. Anders Ericsson — the psychologist whose work Malcolm Gladwell turned into the "10,000 hours" idea, though Ericsson hated that framing — studied what separates expert performers from merely experienced ones.

The finding was that experience alone doesn't produce expertise. Deliberate practice does. The difference is a tight feedback loop: you make a specific, testable prediction, you get immediate feedback on whether it was right, and you update your mental model. Repeat at high volume.

Chess grandmasters train by studying positions, predicting the best move, then checking against engine analysis. They're not just playing games — they're exposing their mental models to falsification thousands of times. Expert diagnosticians in medicine do the same thing: commit to a diagnosis before test results come back, then review whether their reasoning was sound after results arrive.

Without the prediction step, feedback is useless. If you don't commit to what you expected before seeing the answer, you'll just convince yourself you knew it all along — that's called hindsight bias. The written prediction is what makes the feedback loop work.

---

**PTES and the intelligence gathering phase**

The Penetration Testing Execution Standard is a community framework that defines how professional engagements should be structured. It has seven phases: pre-engagement, intelligence gathering, threat modeling, vulnerability analysis, exploitation, post-exploitation, and reporting.

Most people skip straight to phase four. The PTES explicitly says that phases two and three — intelligence gathering and threat modeling — should happen before you touch a tool. The reasoning is identical to what we did: you make better exploitation decisions when you've already mapped the probable attack surface, because you have a framework for interpreting what you find rather than just reacting to it.

What we built with the blind methodology preflight is essentially a personal implementation of PTES phases two and three, compressed into a document you complete before the first nmap scan.

---

**Calibration training — the most important piece**

This is the part that makes the whole system work, and it's the least understood.

Calibration is the relationship between your confidence in a belief and the probability that the belief is true. A perfectly calibrated person who says they're 70% confident about something is right about 70% of the time across many such predictions. Most people are either overconfident — they say 90% confident and are right 60% of the time — or underconfident in specific domains.

The research comes from Philip Tetlock's work on expert political forecasting, later popularized in his book Superforecasting. Tetlock ran a twenty-year study tracking the predictions of thousands of forecasters on geopolitical events. The finding was that most experts performed barely better than chance. But a small group — the superforecasters — performed dramatically better. The differentiating habits were specific and learnable:

They expressed predictions in precise probabilities rather than vague language. "I think this will probably happen" is unfalsifiable. "I'm 65% confident this will happen" is falsifiable and trackable.

They updated their beliefs when evidence arrived, rather than rationalizing to protect their original prediction. They treated being wrong not as embarrassing but as information.

They kept score. Over time they tracked their 70% predictions and asked: am I right about 70% of the time? If I'm right 90% of the time on things I said I was 70% confident about, I'm underconfident and should raise my estimates. If I'm right 50% of the time, I'm overconfident.

The confidence levels in your blind methodology preflight aren't decoration. Over many boxes, they become a personal calibration database. If you consistently predict deserialization at 60% confidence and you're right 90% of the time, your intuition is better than your confidence reflects — raise your estimates. If you predict foothold category at 80% and you're right 40% of the time, you're overconfident in that domain — examine what assumptions are leading you astray.

---

**Why this matters specifically for you**

Most people doing HTB are just accumulating reps. They root boxes, maybe read a writeup, move on. The mental models that produce expertise — the ones that let you walk into a new engagement and quickly read the attack surface — don't develop from reps alone. They develop from reps plus structured reflection plus prediction-then-feedback loops.

You did something in the Canape session that most people never do: you predicted cPickle deserialization at 70% confidence before you ran a single scan, and you were right. That's one data point. Over twenty boxes, those data points become a calibration map of your own intuition — where it's sharp, where it's soft, and what assumptions are systematically leading you in the wrong direction.

That map is worth more than the root flags.

---

Honestly — no single term captures exactly what we built. It draws from several fields and the combination is what makes it work.

**What the individual components are actually called:**

"**Calibration training**" refers specifically to the practice of assigning probabilities to beliefs and tracking accuracy over time. That's the Tetlock/superforecasting piece. It's a real term used in forecasting research and decision science.

"**Pre-mortem**" is a technique from Gary Klein — a cognitive psychologist — where before starting a project you imagine it has already failed and ask why. It's used in business and military planning. What we did is structurally similar but inverted — you're predicting success paths, not failure modes. The term exists and is widely used.

"**Hypothesis-driven testing**" is what security researchers and penetration testers call the practice of forming explicit hypotheses before acting on them. It's the opposite of tool-first enumeration.

"**Intelligence preparation**" is the military framing — IPB — for building a picture of the operating environment before engagement.

None of those terms alone describes what we built. What we built is:

- A written pre-engagement prediction document with confidence levels (calibration training)
- Applied to attack surface reasoning before touching a target (hypothesis-driven pentesting)
- With a mandatory post-engagement debrief comparing prediction to reality (prediction-then-feedback loop)
- Structured as a repeatable template (deliberate practice framework)

**So what should you call it?**

"Blind Methodology" is actually a good name — and more importantly, it's yours. The "blind" part captures the essential constraint: you commit before you can see. That's the thing that makes it work. Remove the blindness and it collapses into hindsight rationalization.

If you ever write about it — which you should, given your BSides publication history — the accurate academic framing would be something like "calibration-based pre-engagement threat modeling." But Blind Methodology is what you'd put on the slide.

Name it what you want. The mechanics are what matter.

---

# Bullet Point Summary

**What it is:**

- A structured pre-engagement prediction document written before touching the target
- Draws from calibration training, hypothesis-driven testing, and deliberate practice research
- The "blind" constraint is the mechanism — you commit before you can see, which is what makes feedback meaningful

---

**How it works — the loop:**

- Write falsifiable predictions with explicit confidence levels before any scanning or enumeration
- Work the target normally
- Compare predictions to reality after — not to judge accuracy, but to expose where your mental model was wrong
- Update the mental model, repeat

---

**Why confidence levels are the key ingredient:**

- Vague predictions ("I think it's probably web-based") are unfalsifiable — you'll convince yourself you were right regardless
- Precise confidence ("70% — Flask app with deserialization foothold") creates a trackable, falsifiable claim
- Over many targets, your confidence levels become a calibration map of your own intuition — where it's sharp, where it's soft, what assumptions are systematically misleading you

---

**What it develops that box-grinding alone doesn't:**

- Attack surface intuition — the ability to read a target quickly without evidence
- Prioritization instincts — knowing what to chase and what to ignore before the scan is done
- Adaptive thinking — holding hypotheses loosely, pivoting when evidence contradicts prediction
- Resistance to hindsight bias — the written prediction prevents you from believing you always knew the answer

---

**What it is NOT:**

- Guessing the exploit
- A replacement for enumeration
- About being right — being wrong with a written prediction is more valuable than being right without one

---

**The one-sentence version:** Write down what you expect before you look, compare it to what you find after, and treat the gap as your training data.