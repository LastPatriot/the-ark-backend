# Deploying Ark

Build first: `cargo build --release` (Pi: `cross build --release --target aarch64-unknown-linux-gnu`).

## Linux (demo PC or Raspberry Pi)

```bash
sudo ./deploy/linux/install.sh            # installs /usr/local/bin/ark and ark.service
sudo journalctl -u ark -n 50 | grep 'setup code'
```

- Config: `/etc/ark/ark.env` (then `sudo systemctl restart ark`). Data: `/var/lib/ark`.
- Runs as the `ark` user; `CAP_NET_BIND_SERVICE` lets it use ports 80 and 53.
- Starts on boot, restarts 2 s after a crash. Logs: `journalctl -u ark -f`.
- Remove: `sudo ./deploy/linux/uninstall.sh [--purge]`.

## Windows (demo PC)

From an elevated PowerShell in the repo:

```powershell
powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1 -Dns -DnsUpstream 192.168.1.1
```

- Registers a Scheduled Task "Ark" that runs `C:\Program Files\Ark\ark.exe` as SYSTEM at
  startup and restarts it on failure. Not a Windows (SCM) service: it shows up in Task
  Scheduler, not in services.msc.
- Config: `C:\ProgramData\Ark\ark.toml`; rerun the script to restart after editing.
  Log (and the first-run setup code): `C:\ProgramData\Ark\ark.log`.
- Adds firewall rules for the Private/Domain profiles only. The script warns if the
  network is marked Public, which blocks phones.
- Remove: `deploy\windows\uninstall.ps1 [-Purge]`.

## Local DNS (for phones without mDNS)

Older Android phones don't resolve `ark.local` by themselves. With `ARK_DNS=true`
(`dns = true` on Windows), Ark answers `ark` and `ark.local` with the host's LAN
address and forwards every other name to `ARK_DNS_UPSTREAM`.

1. Reserve the Ark host's IP in the router.
2. In the router's DHCP settings, set the DNS server to the Ark host's IP.
3. Set `ARK_DNS_UPSTREAM` to the router's own IP, so normal browsing keeps working.
4. Phones pick up the new DNS when they reconnect to Wi-Fi.

If the upstream is unreachable, other names fail after 3 s (SERVFAIL) but `ark.local`
still resolves, so Ark works with no internet.

Port 53 conflicts: Ubuntu's systemd-resolved (install.sh offers to disable its stub
listener); on Windows, Internet Connection Sharing or Hyper-V's default switch.
Check with `sudo ss -lunp 'sport = :53'` / `Get-NetUDPEndpoint -LocalPort 53`.

## Checks before the demo

```bash
dig @<ark-ip> ark.local +short                    # local DNS answers
./scripts/load_test.sh http://ark.local sunday-service <contributor-pin> 15 50
```
