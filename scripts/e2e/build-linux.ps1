# Build the Linux binaries for the end-to-end test server (docs/e2e-testing.md)
# on Windows, into dist-linux\ next to the e2e scripts. Run from the repo root:
#
#   powershell -ExecutionPolicy Bypass -File scripts\e2e\build-linux.ps1
#   scp -r dist-linux\* <UBUNTU_USER>@<UBUNTU_IP>:/opt/aegis-e2e/
$ErrorActionPreference = "Stop"
$out = "dist-linux"
New-Item -ItemType Directory -Force $out | Out-Null

$env:GOOS = "linux"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
try {
    foreach ($c in "server", "migrate", "apitoken", "enrolltoken", "cagen", "keygen", "secretskey", "syncpatchfeed") {
        Write-Host "building $c"
        go build -trimpath -o "$out\$c" ".\cmd\$c"
        if ($LASTEXITCODE -ne 0) { throw "go build $c failed" }
    }
} finally {
    Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
}
Copy-Item scripts\e2e\api.sh, scripts\e2e\start-server.sh, scripts\e2e\e2e.env.example $out
Write-Host "done: $out"
