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
| `devices.view` | operator | `scan_now`, `report_device_state` |
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
  - A move deletes the source files only after every destination has them, and the agent re-checks hashes first.
  - The temporary archive is deleted at the end.
- **Shells:**
  - The session id is random and single-use, and must be attached within its TTL.
  - Only the agent it was sent to can attach.
  - Only the API client that opened the session can use it.
  - Input, output and controls are recorded in the transcript; operators should not type secrets.
  - The agent ends the shell on idle or max duration.
