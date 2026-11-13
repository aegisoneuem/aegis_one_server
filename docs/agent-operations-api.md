# Agent operations API

These endpoints send signed commands to agents (contract: `proto/aegisone/v1`,
agent zip 4). Every command is recorded in `agent_commands` and `audit_log` before
it is sent. All endpoints need an API token (`Authorization: Bearer <API_TOKEN>`).

**Online devices only.** Direct commands (actions, remote operations, shells) are
sent only to devices that are connected right now. The response gives each device's
status: `dispatched`, `offline`, `unknown_device`, `unsupported` (the agent does not
advertise that command type) or `failed`. Nothing is queued because these agent
commands carry no expiry; a reboot or script must not run days later. Software
deployments, patch deployments and file transfers are the exception: they are jobs
that wait for the device to come online.

**Results:** `GET /internal/actions?command_id=<id>` returns the status and the
agent's result. Reading a result needs the same permission as sending that command
type, because results can hold command output.

## Permissions

| Permission | Default role | Covers |
|---|---|---|
| `devices.view` | operator | device list / detail / summary, `scan_now`, `report_device_state` |
| `devices.manage` | admin | retire devices |
| `patch.deploy` | operator | `uninstall_patch`, patch deployments |
| `software.deploy` | operator | packages and deployments (msi/exe/inf/msix, bundles with an installer entry point) |
| `software.script` | admin | script packages, bundle commands, deployment steps |
| `software.runas` | admin | run as logged-in user / specified account, secure parameters |
| `device.reboot` | admin | `reboot`, `cancel_reboot` |
| `files.collect` | admin | `collect_file`, downloading uploads |
| `files.manage` | admin | `file_operation`, transfers between devices |
| `agent.command` | admin | `run_command` (runs as SYSTEM) |
| `agent.shell` | admin | interactive shell (SYSTEM, recorded) |

"admin" means only the admin role (`*`) has it until you grant it to a role.

## Actions: `POST /internal/actions`

```json
{"action": "reboot", "device_ids": ["<DEVICE_ID>"], "delay_seconds": 600, "message": "Patching tonight"}
{"action": "cancel_reboot", "device_ids": ["<DEVICE_ID>"]}
{"action": "uninstall_patch", "device_ids": ["<DEVICE_ID>"], "kb": "KB5034441"}
{"action": "scan_now", "device_ids": ["<DEVICE_ID>"]}
{"action": "report_device_state", "device_ids": ["<DEVICE_ID>"]}
```

- `delay_seconds`: 0..86400. `message`: at most 512 characters, no double quotes.
- `cancel_reboot` cancels any pending Windows shutdown, not only one we scheduled. If nothing is pending it returns FAILED.
- `uninstall_patch`: the device's build is sent so the agent can find a cumulative update's package. Windows refuses to remove some LCU/SSU updates; that comes back as FAILED with the reason.
- `report_device_state` forces a DeviceStateReport, so the server-side patch diff runs again.

## Devices: `/internal/devices`

| Call | Body / query |
|---|---|
| `GET /internal/devices` | `state` (online, offline, stale, stale_alert, retired, merged, unmanaged, all), `q` (hostname prefix or exact device_id), `limit` (1..1000, default 100), `after` (the previous page's `next_after`) |
| `GET /internal/devices?id=` | one device, plus agent enrollment time and certificate expiry |
| `GET /internal/devices/summary` | count per state, plus the `stale_alert` count |
| `POST /internal/devices/retire` | `{"device_ids": [...], "reason": "..."}`; reason is required, at most 256 characters |
| `GET /internal/devices/duplicates` | possible duplicates; `status` (pending (default), confirmed, rejected, all), `limit` (1..500) |
| `POST /internal/devices/duplicates/confirm` | `{"id": "...", "reason": "..."}` merges the pair (`devices.manage`) |
| `POST /internal/devices/duplicates/reject` | `{"id": "...", "reason": "..."}` keeps both records (`devices.manage`) |

- **State:**
  - `online`: last heartbeat within `agent.offline_after_minutes` (default 15).
  - `offline`: older than that, but within `device.stale_after_days` (default 30).
  - `stale`: older than that, or never seen.
  - `retired`: retired by an admin.
  - `merged`: an admin confirmed this record is the same machine as another one; `merged_into_device_id` names it.
  - `stale_alert: true`: no heartbeat for `device.stale_alert_days` (default 60). A device is flagged, never deleted.
  - The settings live in `system_settings`. `connected` shows whether the agent has a live stream right now.
- **Renames:** a hostname change (heartbeat or enrollment) writes `audit_log` `device.rename` ("Device renamed from X to Y"). Hostname is never used to identify a device.
- **Retire**, per device:
  - Revokes the agent and its certificates.
  - Fails the device's open commands (`device retired`), so deployments and transfers move on.
  - Ends the live stream and writes `audit_log` (`device.retire`).
  - The result is `retired`, `already_retired` or `unknown_device`.
- After retiring:
  - The agent is refused at every reconnect.
  - The device leaves compliance reports and frees its license seat.
  - Nothing is deleted.
- **Coming back:** only by enrolling again with an enrollment token, which checks the license again. With trust-on-first-use (dev, no enrollment CA), a retired device can't bind a new certificate.

**Returning devices (reimage / reinstall).** Enrollment matches the request to an existing record. The match only picks the record; it never grants trust, which stays with mTLS and signed commands.

| Signal | Result |
|---|---|
| TPM EK, or the agent's own device_id | The existing record is reactivated with its history and `computer_id`. Audit `device.reactivate`: "Device reactivated via TPM match - previous status: X". Commands still open for the old install are failed (`device re-enrolled`). |
| Same, but that record's agent is connected right now (cloned VM, copied identity) | Not reactivated. New record, and a duplicate (`tpm_ek_conflict` / `device_id_conflict`) for review. |
| SMBIOS UUID or MachineGuid only, matching exactly one record | Never merged automatically. New record, and a duplicate (`system_uuid` / `machine_guid`) for review. Audit `device.duplicate_flagged`. |
| Nothing | New record. |

- **Confirming a duplicate** moves the new record's agent onto the existing record:
  - The existing record keeps its history and `computer_id`, and takes over the agent's `device_id` and TPM EK.
  - The new record becomes `merged` and frees its seat.
  - The existing record's old agent is revoked, and its open commands are failed.
  - The agent is disconnected; it reconnects as the existing record and reports again. Data it reported under the new record stays there.
  - Refused (409) while the existing record's agent is connected.
  - Audit `device.merge`, with both ids. Other pending duplicates of either record are rejected as superseded.
- **Rejecting** keeps both records, and writes audit `device.duplicate_rejected`.
- **Not verified yet:** the TPM EK is the agent's claim, not proven by attestation.

## Patch push: `/internal/deploy` (`patch.deploy`)

- `POST /internal/deploy?device_id=<DEVICE_ID>&kb=KB5066835` pushes one missing patch to one device.
- `GET /internal/deploy?id=<deployment_id>` shows progress.

**Several files per push.** A 24H2+ cumulative update ships its own `.msu` plus the checkpoint `.msu` file(s) it builds on. The agent installs one file per `install_patch`, so the server takes each file through stage → install in turn:
- **Order:** checkpoints first, oldest KB first, then the pushed KB.
- **Where the files come from:** the update the device reported. With the server-side diff (no UpdateID), the update that lists the KB's own file.
- **Already installed:** a checkpoint the device already has comes back `NOT_APPLICABLE` and the push moves on.
- **Failure:** any failed file fails the push, and the error names it (`file 1/2 (KB5043080): ...`).
- **Reboot:** a reboot a file asks for does not stop the next file; it shows in `file_results`.
- **Limit:** at most 6 files per push.

The status shows:
- `files`: the install order.
- `file_number`: the file being worked on.
- `file_results`: one entry per finished file, with `phase`, `reboot_required` and `reason`.

## Software distribution v2

`POST /internal/software/packages` (multipart) accepts these fields on top of v1:

- A `.zip` file is a **bundle**. Its root must hold `aegis-package.json` listing every file with its size and SHA-256 (checked at upload). Then set:
  - `bundle_entry_point` (e.g. `setup/app.msi`, run as `installer_type`), **or** `bundle_command` (a command line run in the extracted folder; needs `software.script`).
  - optional `bundle_destination` (an absolute local path) and `bundle_cleanup` (`always` or `retain`).
- `steps` (bundles only), as JSON: `{"before":[...],"after":[...],"rollback":[...]}`.
  - Each step: `{name, command, arguments, timeout_seconds, success_exit_codes, use_secure_parameters}`.
  - No implicit shell: use `cmd.exe /D /C ...`.
- `detection`, as JSON: `{"mode":"all|any","rules":[{kind, path, minimum_version, hive, key, view, value_name, value_type, expected_value}]}`.
  - `kind` is one of `file_exists`, `file_version`, `registry_key`, `registry_value`.
  - Detection replaces `product_code` / `uninstall_key` / `display_name`.
- `parameters`, as a JSON object of strings: `${name}` in arguments, plus the `AEGIS_PARAM_<NAME>` environment variable.
- `requires`: comma-separated `package_id`s installed first. Each must be detectable.
- `require_ac_power`, `capture_script_content`: `true` or `false`.
- `installer_type` also accepts `inf` (driver, install only) and `msix`.

`POST /internal/software/deploy` adds:

```json
{"package_id": "<PACKAGE_ID>", "device_ids": ["<DEVICE_ID>"],
 "execution": {"mode": "specified_account", "username": "<USER>", "domain": ".", "password": "<PASSWORD>", "detection_scope": "user"},
 "secure_parameters": {"LicenseKey": "<SECRET>"},
 "max_fetch_bytes_per_second": 5000000}
```

- **Install plan:** dependencies first, then the package. A failed dependency, or one that needs a reboot, blocks the packages after it on that device.
- **Command type:** derived from the package (`software_deploy`, `_v2`, `_bundle`, `_workflow` or `_detect`). The agent never falls back to an older type.
- **Secrets:** the password and secure parameter values are kept **in server memory only**, never in the database or logs. The audit shows `<sensitive — secure parameters in use>`. If the server restarts, or 24 hours pass, before a device gets the command, that device fails with a clear reason; create the deployment again. A secret may not appear in any public field (arguments, steps, parameters, names).
- The agent hands secure parameters to the installer on stdin as JSON: `{"version":1,"secure_parameters":{...}}`.
- **Requirement:** v2 command types need the agent to run as the LocalSystem service.

## Remote operations: `/internal/remote/...`

| Call | Body / query |
|---|---|
| `POST collect` | `{device_ids, paths[] (globs), max_bytes_each, tail_bytes, max_total_bytes, max_upload_bytes_per_second}` |
| `GET uploads?command_id=` | the files a command uploaded |
| `GET uploads/download?id=` | one file; the `X-Content-SHA256` header carries its digest |
| `POST run` | `{device_ids, command, shell: cmd\|powershell\|pwsh, timeout_seconds, max_output_bytes, working_dir, parameters, upload_output}`. The result `detail` holds stdout/stderr. With `upload_output`, the full stdout is also uploaded |
| `POST files` | `{device_ids, operation, ...}`: `mkdir` / `touch` / `delete` / `list_directory` take `path`; `write_bytes` takes `destination`, `content_base64` (≤10 MiB) and `append`; `copy` / `move` on the same device take `source`, `destination` and `destination_dir` |
| `POST transfers` | `{source_device_id, source_path, recursive, destination_device_ids[], destination, overwrite, move}` copies or moves between devices. `GET transfers?id=` shows progress |
| `POST shell` | `{device_id, ttl_seconds, idle_timeout_seconds, max_duration_seconds}` returns a `session_id` |
| `POST shell/input` | `{session_id, stdin \| stdin_base64, control: close\|break}` |
| `GET shell/output?session_id=&after=&wait_seconds=` | long poll. Pass `next_after` back as `after` |
| `GET shell/transcript?session_id=` | the recorded session |

- **Uploads** are accepted only for an open command of the uploading agent that may upload (collect_file, run_command with `upload_output`, a transfer's pack). Each is size-capped per command and SHA-256 checked.
- **Transfers:**
  - The source packs and uploads, and the server checks that the archive digest matches.
  - Each destination fetches the archive with a random content id that works only for that device.
  - The source folder lands inside `destination` under its own name (`C:\src` copied to `D:\dst` gives `D:\dst\src\...`).
  - A move deletes the source files only after every destination has them, and the agent re-checks hashes first.
  - A move cannot list the source device as a destination; for a move on one device use `POST files` with `move`.
  - The temporary archive is deleted at the end.
- **Shells:**
  - The session id is random and single-use, and must be attached within its TTL.
  - Only the agent it was sent to can attach.
  - Only the API client that opened the session can use it.
  - Input, output and controls are recorded in the transcript; operators should not type secrets.
  - The agent ends the shell on idle or max duration.
