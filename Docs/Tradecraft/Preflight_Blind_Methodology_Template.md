# Blind Methodology Preflight

## Target: [Name] — Pre-Engagement Prediction

> Complete this entire document BEFORE launching any scan, tool, or browser.
> The value is in committing predictions to writing before reality can influence them.
> Accuracy is not the goal. Calibration is.

---

## 0. Target Metadata
*Fill from public information only — HTB card, scope document, or engagement brief.*

```
Name:
Difficulty / Scope:
OS / Platform:
Known tags or categories:
Any other public metadata:
```

---

## 1. Shape of the Box
*Infrastructure-heavy or application-heavy? Why?*
*Infrastructure = network services, AD, protocols. Application = web app, code, logic.*

**Assessment:**

**Reasoning:**

---

## 2. Tech Stack Hypothesis
*What languages, frameworks, services, or platforms do you expect to find?*
*Form hypotheses before you see a single banner or response header.*

| Layer | Hypothesis | Confidence |
|---|---|---|
| OS | | % |
| Language | | % |
| Framework | | % |
| Database | | % |
| Other services | | % |

---

## 3. Enumeration Priorities
*Rank what you'll investigate first and why. Force yourself to commit to an order.*
*What evidence would cause you to change this ranking?*

1.
2.
3.
4.
5.

**Pivot trigger:** What single finding would cause me to reorder these completely?

---

## 4. Foothold Theory
*Don't guess the exact exploit. Predict the category and reasoning.*

**Category:** (auth / logic / deserialization / injection / credential / file / misconfiguration / CVE)

**Specific hypothesis:**

**Confidence:** %

**Reasoning:** Why this category given what you know so far?

**What would confirm it:** What evidence during enumeration would raise your confidence?

**What would refute it:** What evidence would cause you to abandon this theory?

---

## 5. Privesc Theory
*Same discipline — category and reasoning, not a specific exploit.*

**Category:** (sudo / SUID / service / credential / misconfiguration / kernel / internal service)

**Specific hypothesis:**

**Confidence:** %

**Reasoning:**

**What would confirm it:**

**What would refute it:**

---

## 6. Predicted Rabbit Holes
*What will waste time for less disciplined operators on this specific target?*
*What looks like signal but is probably noise given what you know?*

-
-
-

---

## 7. What Source Access Would Change
*If you got code visibility — what would you inspect first and in what order?*
*Entry point → imports → architecture → individual functions.*

1.
2.
3.
4.

---

## 8. Confidence Summary
*Write these out explicitly before you start. Forces you to hold hypotheses loosely.*

| Prediction | Confidence | Key assumption that could be wrong |
|---|---|---|
| Shape (infra vs app) | % | |
| Tech stack | % | |
| Foothold category | % | |
| Privesc category | % | |

---

## 9. Session Notes
*Running notes during the engagement. Observations, dead ends, pivots.*
*Each entry: what you saw → what you interpreted → what action followed.*

### [Time] — Phase: [Recon / Enumeration / Foothold / Post-Exploit / Privesc]

**Observed:**

**Interpreted:**

**Hypothesis:**

**Action taken:**

**Result:**

**Dead ends logged:**

---

## 10. Post-Root Debrief
*Complete this after rooting. This section is the primary learning output.*
*The root flag is secondary. This document is the deliverable.*

### 10.1 Prediction vs Reality

| Prediction | Actual | Accurate? | Why it was wrong (if applicable) |
|---|---|---|---|
| Shape | | | |
| Stack | | | |
| Foothold category | | | |
| Privesc category | | | |
| Rabbit holes predicted | | | |

### 10.2 Enumeration Quality Assessment

- What did I find quickly vs. find late?
- What signals did I observe but interpret incorrectly?
- What rabbit holes did I chase? What made them look credible?
- What would I enumerate differently?

### 10.3 Technique Gap Analysis

- What techniques appeared that I hadn't used before or executed poorly?
- What is the underlying mechanism of each — not just the tool, but why it works?
- What related techniques should I study before the next target?

### 10.4 Transferable Lessons

- What does this target teach about real-world attack surface?
- What class of vulnerability does this represent and where else would it appear?
- How would this look in a production environment vs. a lab?
- What defensive control would have stopped this, and how would an attacker recognize its absence?

### 10.5 Calibration Review

- Which confidence levels were accurate?
- Which were overconfident or underconfident?
- What does this tell me about my current mental models?

### 10.6 Next Target Calibration

- What did this target reveal about my current skill gaps?
- What specific technique or vulnerability class needs deliberate practice next?
- What should the next target prioritize to address that gap?

---

*Template: Blind Methodology Preflight v1.0*
*Technique: Prediction-then-feedback calibration training applied to offensive security*
*Use for: HTB, OSCP labs, bug bounty recon, real engagements*
