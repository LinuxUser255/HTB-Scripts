
## useful commands when working on a box

#### - adding a box to `/etc/hosts/`

- example: adding the cohort box to `/etc/hosts`
```bash
echo "10.129.54.211 cohort.htb" | sudo tee -a /etc/hosts
```
- Formula

```
echo "<box_number> box_name.htb" | sudo tee -a /etc/hosts
```

`tee -a` appends (writes to the file and echoes to stdout) — the `-a` matters, without it tee overwrites
`/etc/hosts` entirely, which would nuke your existing localhost entries.
`sudo` goes before `tee`, not before `echo`, since it's the write to `/etc/hosts` that needs root, not the echo itself —
piping into `sudo echo >> file` is a classic mistake because the redirect happens in your unprivileged shell, not sudo's.

Quick sanity check after:

```bash
cat /etc/hosts | grep cohort
```
