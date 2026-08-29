## Security Researcher's Mental Model

**Phase 1**
- Read the docs like a contract — look for what they don’t say and what they assume
- Bugs live in the gap between documented behavior and what the code actually enforces

**Phase 2 — Five layers**
- **L1 Intended use:** what is this feature *for*?
- **L2 Assumptions:** who is the caller, what is the input, what is the environment, what will other components enforce — write them down
- **L3 Break conditions:** concrete input, caller, sequence, or environment that violates those assumptions
- **L4 Blast radius:** who runs the result, in what context, with what privileges
- **L5 Bug vs design:** broken code, or a feature with a broken trust model? That decides the write-up, the vendor response, and whether the fix is a patch or an architecture change

**Phase 3 — Inner monologue (before exploit code)**
- What class is this?
- What does the system trust?
- Where is the trust boundary?
- Does that boundary hold under attack?
- What are the exact preconditions?
- Who executes the payload, and in what context?

**Core line**
- Every vulnerability is the gap between what a system assumes and what reality permits
- Job: find assumptions and test them
- Path: docs → assumptions → boundary → preconditions → exploit design → shell
- Ask why it exists before asking how to break it — especially on things that look secure
