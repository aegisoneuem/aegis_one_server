# Agent: downloading the offline scan cab from the server

The agent's offline patch scan (`internal/patch/scan_offline_windows.go`) reads
`wsusscn2.cab` from the local path in `AEGIS_WSUS_SCAN_CAB`, but nothing puts the
file there today. The server now keeps a current copy of Microsoft's cab and
serves it to agents. This describes the agent side. **No proto change is
needed:** it is plain HTTPS.

## Endpoint and authentication

- Server: same host as gRPC, HTTPS port `8080` (server setting `AEGIS_HTTP_ADDR`).
- TLS 1.2 or newer. Verify the server against the same CA and server name you
  use for gRPC (`TLSCAFile`, `TLSServerName`).
- Present the **same client certificate and key you use for gRPC**
  (`TLSCertFile`, `TLSKeyFile`). The server identifies the agent by that cert.
- The agent must have connected over gRPC at least once first. The server binds
  a cert to a device on its first gRPC connection, and an unbound or revoked
  cert gets `403`.

## Endpoints

`GET /content/wsusscn2.json` returns the current cab's details:

```json
{
  "sha256": "5c1f...",
  "size_bytes": 674424266,
  "source_last_modified": "2026-10-03T01:08:04Z",
  "downloaded_at": "2026-10-07T10:47:12Z",
  "url": "/content/wsusscn2.cab"
}
```

`GET /content/wsusscn2.cab` returns the file. It supports `Range` (resume) and
`If-Range`. The `ETag` header is the quoted SHA-256 (`"5c1f..."`), and
`X-Content-SHA256` repeats it unquoted.

## Flow

1. Fetch `wsusscn2.json`. A `404` means the server has no cab yet: keep the cab
   you have and try again later.
2. If the cab you already have has the same SHA-256, stop.
3. Download to a temporary file next to the final path, for example
   `<SecureDir>\cab\wsusscn2.cab.part`:
   - Fresh start: plain `GET`.
   - Resume: send `Range: bytes=<size of .part>-` and `If-Range: "<sha256>"`.
     A `206` means append to the `.part` file. A `200` means the server's cab
     changed since you started: truncate the `.part` file and write the new
     body from the beginning.
4. Check that the file size equals `size_bytes` and the SHA-256 equals `sha256`.
   If either check fails, delete the `.part` file, do not use it, and retry
   later with backoff.
5. Atomically replace the cab at `AEGIS_WSUS_SCAN_CAB` with the verified file
   (`MoveFileEx` with `MOVEFILE_REPLACE_EXISTING`). Never overwrite the working
   cab before the new one is verified, and never swap it while
   `ScanOffline` is using it.

## When to check

- Check `wsusscn2.json` about every 24 hours with random jitter, and before a
  scheduled scan if the last check is older than that.
- Microsoft republishes the cab every few weeks. Each new version is about
  640 MB per endpoint. Spread the download out: wait a random 0–12 hours after
  first seeing a new SHA-256 before downloading. At 50,000 endpoints a
  simultaneous pull would be about 32 TB from one server. Peer-cache and site
  distribution are planned to fix this properly.

## Responses

| Status | Meaning | Action |
|---|---|---|
| 200 / 206 | OK | continue |
| 401 / 403 | cert not accepted (unknown or revoked agent) | log loudly; don't retry in a tight loop |
| 404 | server has no cab yet | keep the current cab, retry later |
| 503 | server problem | retry later with backoff |
| TLS error | wrong CA or cert | configuration problem; log it |

## What the checksum does and doesn't protect

The SHA-256, received over a mutually authenticated TLS connection, catches
truncated, corrupted, or mixed-up downloads. It is **not** a signed manifest:
it is only as trustworthy as the server. The cab itself is Authenticode-signed
by Microsoft. The server can't check that signature (it runs on Linux), so the
agent should check it before swapping the file in, using `WinVerifyTrust`, and
reject any file that isn't validly signed by Microsoft.
