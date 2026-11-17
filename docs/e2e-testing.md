# End-to-end testing on Ubuntu + a Windows VM

This guide runs the full product: the server and database on an Ubuntu machine, and the real agent (Vijay's MSI) on a Windows test VM. Then it walks through every use case.

```
Ubuntu: Aegis server + PostgreSQL/TimescaleDB  <── gRPC :50051 / HTTPS :8080 ──  Windows VM: agent (MSI, service)
```

**Rules:**
- The agent only runs on Windows. Reboot, patch install, uninstall and tamper tests change the machine, so run them on a **disposable Windows VM**. Never run them on a work laptop.
- **Snapshot the VM** before you install the agent, and revert to the snapshot after destructive tests.
- Use a **separate database** (`aegis_e2e`) so the dev database is not touched.
- Passwords, passphrases and tokens live only in `/opt/aegis-e2e/e2e.env` and `/opt/aegis-e2e/tokens/`, both `chmod 600`. Never put them in Git, chat or tickets. The examples below use placeholders like `<DEVICE_ID>`.

Scripts used here: [scripts/e2e/](../scripts/e2e/)

| Script | What it does |
|---|---|
| `build-linux.ps1` | builds the Linux binaries on Windows |
| `e2e.env.example` | environment template |
| `start-server.sh` | starts the server |
| `api.sh` | calls the API with a stored token |

---

## 1. Build on Windows and copy to Ubuntu

From the repo root on Windows:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\e2e\build-linux.ps1
ssh <UBUNTU_USER>@<UBUNTU_IP> "sudo mkdir -p /opt/aegis-e2e && sudo chown $USER /opt/aegis-e2e"
scp -r dist-linux\* <UBUNTU_USER>@<UBUNTU_IP>:/opt/aegis-e2e/
```
Re-run both lines after every server code change. Only the binaries change; the keys and the DB stay.

## 2. One-time setup on Ubuntu

```bash
cd /opt/aegis-e2e && chmod +x server migrate apitoken enrolltoken cagen keygen secretskey syncpatchfeed *.sh
sudo apt install -y libarchive-tools            # bsdtar: opens the Microsoft scan cab
cp e2e.env.example e2e.env && chmod 600 e2e.env && nano e2e.env    # fill in every <PLACEHOLDER>
set -a; . ./e2e.env; set +a

# Database: create it, run all migrations as the owner, then add the app login
sudo -u postgres psql -c "CREATE DATABASE aegis_e2e;"
AEGIS_MIGRATE_DATABASE_URL="$E2E_PG_OWNER_URL" ./migrate up
sudo -u postgres psql -c "CREATE ROLE aegis_e2e_app LOGIN PASSWORD '<APP_PASSWORD>' IN ROLE aegis_app;"

# Keys, once each:
./cagen -out certs -dns aegis-server,localhost -ip "$E2E_SERVER_IP"   # enrollment CA + server TLS cert
./keygen secrets/command_signing.key                                  # prints PUBLIC_KEY=...  (note it)
./secretskey -out secrets/secrets.key.enc                             # tamper passcode master key

sudo ufw allow 50051/tcp && sudo ufw allow 8080/tcp
```

**About the keys:**
- `keygen` overwrites its output file. Run it only once; a new key means every agent needs the new `PUBLIC_KEY`.
- `cagen` and `secretskey` refuse to overwrite.
- The app role uses the same `<APP_PASSWORD>` as `AEGIS_DATABASE_URL` in `e2e.env`. Type it in the command; don't keep it in shell history (`history -d` or a leading space with `HISTCONTROL=ignorespace`).

**Start the server:**
```bash
./start-server.sh
```
The log should show these lines:
- `enrollment enabled`
- `command signing key loaded`
- `secrets key loaded; tamper protection available`
- `grpc server listening`

**Tokens.** Use a second terminal on the same machine:
```bash
cd /opt/aegis-e2e && set -a; . ./e2e.env; set +a && mkdir -p tokens && chmod 700 tokens
./apitoken mint -client e2e-admin -role admin    -scopes '*' -days 14   # copy the aeg_... value into tokens/admin
./apitoken mint -client e2e-op    -role operator -scopes '*' -days 14   # copy it into tokens/op
chmod 600 tokens/*
./enrolltoken mint -max-uses 5 -days 14                                  # agent enrollment token (shown once)
./api.sh admin GET /internal/devices/summary                             # expect [200]
```

## 3. Install the agent on the Windows VM

1. Take a snapshot of the VM ("clean").
2. Copy `/opt/aegis-e2e/certs/ca.crt` to the VM as `C:\aegis\ca.crt`.
3. Get the MSI from the agent repo: `dist/AegisOneClient.msi`.
4. In an **elevated** cmd:
   ```cmd
   reg add HKLM\SOFTWARE\AegisOne\Client\Settings /v AEGIS_CMD_VERIFY_KEY /t REG_SZ /d <PUBLIC_KEY> /f
   msiexec /i AegisOneClient.msi /qn /l*v C:\aegis\install.log SERVERADDRESS=<UBUNTU_IP>:50051 SERVERNAME=aegis-server ENROLLTOKEN=<ENROLL_TOKEN> CACERTFILE=C:\aegis\ca.crt
   ```
   - The MSI does not write the command verify key. Without it the agent rejects every signed command (`rejected_signature`).
   - `SERVERNAME` must be a name in the server certificate (`aegis-server`).
5. On Ubuntu:
   ```bash
   ./api.sh admin GET '/internal/devices?state=online'
   ```
   Note the VM's `device_id`: it is `<DEVICE_ID>` below.

Agent log on the VM: `C:\Program Files\AegisOne\Client\SKVC\logs\agent.log`.

## 4. Use-case checklist

Run each row and tick it off. "Result" means `./api.sh admin GET '/internal/actions?command_id=<COMMAND_ID>'` for the command id the call returned. Full request formats: [agent-operations-api.md](agent-operations-api.md).

### 4.1 Enrollment, identity, inventory

| # | Do | Expect |
|---|---|---|
| 1 | `./api.sh admin GET '/internal/devices?id=<DEVICE_ID>'` | `online`, certificate expiry, hardware (CPU MHz, disks, OS build), `patch` block |
| 2 | `./api.sh admin GET /internal/devices/summary` | 1 online |
| 3 | Disconnect the VM network for 20 min, then reconnect | `offline` after 15 min, `online` again within a minute of reconnecting |
| 4 | Revert the VM to "clean" and install again with a new enroll token | the same device record comes back, or a duplicate shows in `GET /internal/devices/duplicates` |
| 5 | `./api.sh admin POST /internal/devices/retire '{"device_ids":["<DEVICE_ID>"],"reason":"e2e"}'` (do this last) | agent disconnected; state `retired` |

### 4.2 Patch management

| # | Do | Expect |
|---|---|---|
| 6 | Feed: leave `AEGIS_FEED_SCHEDULER=on` (needs internet), or run `./syncpatchfeed` with `AEGIS_DATABASE_URL` set | `patch_catalog` has rows |
| 7 | `./api.sh admin POST /internal/actions '{"action":"report_device_state","device_ids":["<DEVICE_ID>"]}'` | patch diff runs; missing KBs in `GET /internal/compliance` |
| 8 | `./api.sh admin POST /internal/actions '{"action":"scan_now","device_ids":["<DEVICE_ID>"]}'` | result shows `scan_run` (or `scan_note` if no cab yet) |
| 9 | Stage only: `./api.sh admin POST '/internal/deploy?device_id=<DEVICE_ID>&kb=<KB>&mode=stage'` | download, then stage, then done; nothing installed |
| 10 | Push with reboot: `./api.sh admin POST '/internal/deploy?device_id=<DEVICE_ID>&kb=<KB>&reboot=if_required&reboot_delay_seconds=300'` | `GET /internal/deploy?id=<ID>` goes through download, stage, install, then rebooting if needed; `reboot_outcome` set |
| 11 | Maintenance window: publish a policy with a `maintenance` window that is closed now (schema: agent repo `docs/agent-policy-capabilities.md`), then push | agent defers (QUEUED "deferred to maintenance window"); the deployment waits instead of timing out |
| 12 | `./api.sh admin POST /internal/actions '{"action":"uninstall_patch","device_ids":["<DEVICE_ID>"],"kb":"<KB>"}'` | succeeded, or Windows' refusal reason |
| 13 | `reboot` with `"delay_seconds":600`, then `cancel_reboot` | Windows shows a pending restart, and the cancel removes it |

### 4.3 Software distribution

| # | Do | Expect |
|---|---|---|
| 14 | Upload an MSI: `curl -sS --cacert certs/ca.crt --resolve aegis-server:8080:127.0.0.1 -H "Authorization: Bearer $(cat tokens/admin)" -F name=7zip -F version=1 -F installer_type=msi -F product_code=<PRODUCT_CODE> -F file=@7z.msi https://aegis-server:8080/internal/software/packages` | package id returned |
| 15 | `./api.sh admin POST /internal/software/deploy '{"package_id":"<PKG>","action":"install","device_ids":["<DEVICE_ID>"]}'` | installed; `GET /internal/software/deploy?id=` per-device progress |
| 16 | The same with `"action":"uninstall"` | removed without sending the file again (fileless uninstall) |
| 17 | Optional: bundles, detection, dependencies, run-as | follow the agent repo's `docs/softdist-*-testing.md` |

### 4.4 Remote operations

| # | Do | Expect |
|---|---|---|
| 18 | `./api.sh admin POST /internal/remote/run '{"device_ids":["<DEVICE_ID>"],"command":"hostname","timeout_seconds":60}'` | result has the output |
| 19 | `./api.sh admin POST /internal/remote/collect '{"device_ids":["<DEVICE_ID>"],"paths":["C:\\Windows\\System32\\drivers\\etc\\hosts"]}'` | file in `GET /internal/remote/uploads?command_id=` |
| 20 | `./api.sh admin POST /internal/remote/files '{"device_ids":["<DEVICE_ID>"],"operation":"list_directory","path":"C:\\Temp"}'` | listing in the result |
| 21 | Shell: `POST /internal/remote/shell`, then `shell/input` and `shell/output` (see agent-operations-api.md) | interactive output; transcript saved |
| 22 | Operator token: `./api.sh op POST /internal/remote/run '{...}'` | 403 (needs `agent.command`) |

### 4.5 Agent policy

| # | Do | Expect |
|---|---|---|
| 23 | `./api.sh admin PUT /internal/policy '{"policy":{"modules":{"deny":["run_command"]}},"note":"e2e"}'` | `GET /internal/policy` shows `applied` 1 |
| 24 | Repeat test 18 | agent refuses `run_command` |
| 25 | On the VM (elevated), delete `C:\Program Files\AegisOne\Client\SKVC\policy.json` and restart the service (or wait) | alert `agent_policy_tampered`, policy re-sent, back to `applied` |
| 26 | Put back an empty policy: `'{"policy":{},"note":"reset"}'` | run_command works again |

### 4.6 Tamper protection

Enable it and note the passcode:
```bash
./api.sh admin PUT /internal/tamper/settings '{"enabled":true}'
./api.sh admin GET /internal/tamper/devices/<DEVICE_ID>          # status "applied"
./api.sh admin POST /internal/tamper/devices/<DEVICE_ID>/reveal  # passcode (audited)
./api.sh op POST /internal/tamper/devices/<DEVICE_ID>/reveal     # 403
```

On the VM, in an **elevated** cmd. `"%SKVC%"` = `C:\Program Files\AegisOne\Client\SKVC`.

| # | Attack / action | Expect |
|---|---|---|
| 27 | `sc stop aegisoneclient` | error 1052 |
| 28 | `sc config aegisoneclient start= disabled` and `sc delete aegisoneclient` | access denied (5) |
| 29 | regedit `HKLM\SYSTEM\CurrentControlSet\Services\aegisoneclient` → `Start=4` | denied, or restored within 30 s + `service_tampered` alert |
| 30 | `taskkill /f /im AegisOneClient.exe` | process back in about 5 s |
| 31 | delete `"%SKVC%\AegisOneClient.exe"` | restored within 30 s; alert `binary_tampered` (high) |
| 32 | copy `notepad.exe` over the agent exe | restored within about 5 min; alert `binary_tampered` |
| 33 | `"%SKVC%\AegisOneClient.exe" stop --passcode WRONG123` | refused. Known agent gap: no alert reaches the server for a local CLI attempt |
| 34 | Server: `POST /internal/tamper/devices/<DEVICE_ID>/rotate`, then test 33 with the OLD passcode | refused |
| 35 | `"%SKVC%\AegisOneClient.exe" stop --passcode <NEW_PASSCODE>` | agent stops. Start it again with `sc start aegisoneclient` (start is never gated) |
| 36 | Server: `POST /internal/tamper/devices/<DEVICE_ID>/stop` | agent stops; `agent_stop_authorized` in the device's tamper events |
| 37 | Server: `POST .../token '{"ttl_minutes":15}'`, then on the VM `stop --token <TOKEN>` | agent stops |
| 38 | Add/Remove Programs → uninstall, wrong passcode | red "incorrect", blocked after `max_tries` |
| 39 | `msiexec /x AegisOneClient.msi UNINSTALLPASSCODE=<PASSCODE> /qn` | clean uninstall (revert the snapshot afterwards) |
| 40 | Power the VM off for over 60 min while a tamper alert is open | alert becomes `critical`, with `silent_escalated_at` |
| 41 | `./api.sh admin PUT /internal/tamper/settings '{"enabled":false}'` | status `cleared`; `sc stop` works normally again |

**Checks on Ubuntu:**
```bash
./api.sh admin GET /internal/tamper/devices/<DEVICE_ID>     # state, open alerts, agent events
sudo -u postgres psql aegis_e2e -c "SELECT action, actor_label, created_at FROM audit_log WHERE action LIKE 'agent_tamper.%' ORDER BY id DESC LIMIT 20;"
sudo -u postgres psql aegis_e2e -c "SELECT count(*) FROM agent_commands WHERE payload::text LIKE '%<PASSCODE>%';"   # must be 0
```

## 5. After each round

- `grep '"level":"ERROR"' /opt/aegis-e2e/server.log` should be empty, or every line explained.
- Revert the VM to "clean" after patch, uninstall and tamper tests.
- For a failure, keep `server.log`, `C:\Program Files\AegisOne\Client\SKVC\logs\agent.log` and the command id. Remove passcodes and tokens before you share them.
- To start over: stop the server, `sudo -u postgres psql -c "DROP DATABASE aegis_e2e;"`, then step 2 from "CREATE DATABASE". Keys and certs can stay. This deletes all test data, so double-check the database name.

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Agent never shows up | firewall, wrong `SERVERADDRESS`, or `SERVERNAME` not in the cert | `ufw status`; `Test-NetConnection <UBUNTU_IP> -Port 50051` on the VM; reinstall with `SERVERNAME=aegis-server` |
| Enrollment refused | token used up or expired | `./enrolltoken list`, then mint a new one |
| Every command `rejected_signature` | `AEGIS_CMD_VERIFY_KEY` missing or not the `PUBLIC_KEY` from `keygen` | fix the registry value, restart the service |
| Command `unsupported` | the agent doesn't list that command type | expected for some types; see agent-operations-api.md |
| `stop --passcode` can't reach the agent | port 50080 reserved by Windows (`netsh int ipv4 show excludedportrange protocol=tcp`) | set `AEGIS_HEALTH_ADDR` under `HKLM\SOFTWARE\AegisOne\Client\Settings` to a free port, e.g. `127.0.0.1:50380`, and restart |
| Server won't start: secrets key | wrong `AEGIS_SECRETS_KEY_PASSPHRASE` | fix the passphrase; don't re-create the key (stored passcodes would become unreadable) |
| Patches never detected | no feed yet (offline) or no device state | run `syncpatchfeed`, then `report_device_state` |
