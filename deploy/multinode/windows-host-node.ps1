# windows-host-node.ps1 —— a one-shot Windows-host (non-Docker) network node: for
# the real-machine checklist (not executed in this session: non-elevated).
#
# Goal: join "this local Windows host" as one node of the scenario 1 [single
# server · Direct] network:
#   1. Get flock-client.exe (host target\release\ preferred; otherwise
#      cargo build --release);
#   2. Generate %ProgramData%\FlockVPN\client.toml (endpoint pointing at the
#      scenario-1 server = jowency:9443);
#   3. Bootstrap (gen-keys → ssh via jowency to run device-add/invite against
#      flock-s1 → ingest → vip; if ssh is unreachable, print the two manual
#      commands and exit);
#   4. Run flock-client run elevated (wintun/route writes need an
#      administrator; when not elevated, re-enter via a UAC prompt);
#   5. Once tun is ready, ping the server VIP + the known client VIPs and print
#      the result matrix.
#
# Usage (admin PowerShell, a real-machine checklist step):
#   powershell -ExecutionPolicy Bypass -File deploy\multinode\windows-host-node.ps1 `
#       -JowHost jowency@192.168.31.221 -ServerVip 100.64.0.1 -PeerVips 100.64.0.2,100.64.0.3
# Exit codes: 0 = onboarded + all pings pass; 1 = any ping failed;
# 2 = bootstrap failed; 3 = elevation refused.
#
# Note: the server/peer VIP values come from the measured assignment table in
# docs/manual/multinode-test.md (when replicating, take the actual device-add
# output as authoritative). For the scenario-2 topology just swap the endpoints
# (the 24000 relay port or the server-1 direct port).

param(
    [string]$JowHost   = "jowency@192.168.31.221",   # the host of the scenario-1 server (ssh target)
    [string]$ServerEp  = "192.168.31.221:9443",       # scenario-1 access endpoint (the LXD proxy publish port)
    [string]$ServerVip = "100.64.0.1",
    [string[]]$PeerVips = @(),                        # other client VIPs (optional, ping each)
    [string]$Username  = "mn-win-host",
    [string]$Password  = "flock-mn-win-host"
)

$ErrorActionPreference = "Stop"

# —— 0. Elevate (wintun/route writes need an administrator; re-enter via UAC) ——
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[elevate] not an administrator —— re-entering with UAC self-elevation ..."
    $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File', $PSCommandPath,
                 '-JowHost',$JowHost,'-ServerEp',$ServerEp,'-ServerVip',$ServerVip,
                 '-Username',$Username,'-Password',$Password)
    if ($PeerVips.Count -gt 0) { $argList += @('-PeerVips', ($PeerVips -join ',')) }
    try { Start-Process powershell -Verb RunAs -ArgumentList $argList -Wait }
    catch { Write-Host "elevation refused: $($_.Exception.Message)"; exit 3 }
    exit $LASTEXITCODE
}
Write-Host "[admin] elevated: $env:USERNAME @ $env:COMPUTERNAME"

# —— 1. Get/build flock-client.exe (Windows target) ——
$repo = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))  # repo root
$exe  = Join-Path $repo "target\release\flock-client.exe"
if (-not (Test-Path $exe)) {
    Write-Host "[build] missing $exe —— cargo build --release -p flock-client (the host needs Rust MSVC)"
    Push-Location $repo
    cargo build --release -p flock-client
    if ($LASTEXITCODE -ne 0) { Write-Host "cargo build failed"; exit 2 }
    Pop-Location
}
Write-Host "[bin] $exe"

# —— 2. Config (%ProgramData%\FlockVPN) ——
$cfgDir = "$env:ProgramData\FlockVPN"
New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
$stateDir = "$cfgDir\state"
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
$cfg = "$cfgDir\client.toml"
@"
state_dir = "$($stateDir -replace '\\','\\')"
tun_name = "Flock VPN"
mtu = 1280

endpoints = ["$ServerEp"]

[auth]
username = "$Username"
"@ | Set-Content -Encoding ascii $cfg
Write-Host "[cfg] $cfg -> $ServerEp"

# —— 3. Bootstrap (idempotent: skip if state\ready exists) ——
if (Test-Path "$stateDir\ready") {
    Write-Host "[boot] already ready (idempotent skip)"
} else {
    $keys = & $exe --config $cfg gen-keys
    $dx = ($keys | Select-String '^device-x=').Line.Substring(9)
    $de = ($keys | Select-String '^device-ed=').Line.Substring(11)
    if (-not $dx -or -not $de) { Write-Host "gen-keys output abnormal: $keys"; exit 2 }
    Write-Host "[boot] device-add (via $JowHost → flock-s1 admin)"
    $add = ssh -o BatchMode=yes $JowHost `
        "lxc exec flock-s1 -- flock-server --config /etc/flock/server.toml device-add --user $Username --device-x $dx --device-ed $de"
    if ($LASTEXITCODE -ne 0) { Write-Host "device-add failed: $add"; exit 2 }
    $vip = ($add | Select-String '^vip=').Line.Substring(4).Trim()
    Write-Host "[boot] local VIP = $vip"
    $inv = ssh -o BatchMode=yes $JowHost `
        "lxc exec flock-s1 -- flock-server --config /etc/flock/server.toml invite --ttl-secs 86400" |
        Select-Object -Last 1
    [IO.File]::WriteAllText("$stateDir\invite.b64", $inv)
    & $exe --config $cfg invite "$stateDir\invite.b64"
    [IO.File]::WriteAllText("$stateDir\vip", "$vip`n")
    $Password | & $exe --config $cfg login
    New-Item -ItemType File -Path "$stateDir\ready" -Force | Out-Null
}

# —— 4. Run (foreground debug mode run: tun+routes+access supervision; keep the window alive) ——
Write-Host "[run] flock-client run (started in the background, log $cfgDir\client.log)"
$proc = Start-Process -FilePath $exe -ArgumentList @('--config', $cfg, 'run') `
        -WindowStyle Hidden -RedirectStandardError "$cfgDir\client.log" -PassThru

# —— 5. Wait for tun + ping matrix ——
$deadline = (Get-Date).AddSeconds(90)
$vipSelf = (Get-Content "$stateDir\vip" -ErrorAction SilentlyContinue)
do {
    Start-Sleep -Seconds 3
    $ok = Get-NetAdapter -ErrorAction SilentlyContinue |
          Where-Object { $_.InterfaceDescription -like '*WireGuard*VPN*' -or $_.Name -like '*Flock*' }
} until ($ok -or ((Get-Date) -gt $deadline))
if (-not $ok) {
    Write-Host "tun not ready within 90s (see $cfgDir\client.log)"; Stop-Process -Id $proc.Id -Force; exit 2
}
Write-Host "[tun] ready: $($ok.Name) (local VIP $vipSelf)"

$targets = @($ServerVip) + $PeerVips
$fail = 0
foreach ($t in $targets) {
    $r = ping.exe -n 3 -w 2000 $t
    $lossLine = ($r | Select-String '\((\d+)% .*\)').Matches[0].Groups[1].Value
    $rttLine  = ($r | Select-String '=\s*(\d+)ms').Line
    $status = if ($lossLine -eq '0') { 'PASS' } else { $fail = 1; 'FAIL' }
    Write-Host ("[ping] {0,-14} loss {1,3}%  {2,-24} {3}" -f $t, $lossLine, $rttLine, $status)
}
Write-Host "done: client process pid=$($proc.Id) (Stop-Process to take it down). Any FAIL ⇒ exit code 1."
exit $fail
