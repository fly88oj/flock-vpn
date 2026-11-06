# windows-host-node.ps1 —— Windows 宿主（非 Docker）一键入网节点：真机清单用（本会话非提升，未执行）。
#
# 目标：把「本机 Windows 宿主」作为一节点加入场景一【单 Server · Direct】网：
#   1. 取 flock-client.exe（宿主 target\release\ 优先；缺则 cargo build --release）；
#   2. 生成 %ProgramData%\FlockVPN\client.toml（端点指向场景一 server = jowency:9443）；
#   3. 引导（gen-keys → ssh 经 jowency 对 flock-s1 执行 device-add/invite → ingest → vip；
#      ssh 不可达则打印手工两行命令后退出）；
#   4. 提权运行 flock-client run（wintun/路由需管理员；未提权时自 UAC 弹窗再入）；
#   5. 等 tun 就绪后 ping server VIP + 已知客户端 VIP，输出结果矩阵。
#
# 用法（管理员 PowerShell，真机清单步骤）：
#   powershell -ExecutionPolicy Bypass -File deploy\multinode\windows-host-node.ps1 `
#       -JowHost jowency@192.168.31.221 -ServerVip 100.64.0.1 -PeerVips 100.64.0.2,100.64.0.3
# 退出码：0 = 入网+ping 全通；1 = 任一 ping 失败；2 = 引导失败；3 = 提权被拒。
#
# 注：server/peer VIP 值取自 docs/manual/multinode-test.md 的实测分配表（复刻时以
# device-add 实际输出为准）。场景二拓扑同理换端点即可（24000 中转口或 server-1 直连口）。

param(
    [string]$JowHost   = "jowency@192.168.31.221",   # 场景一 server 所在宿主（ssh 目标）
    [string]$ServerEp  = "192.168.31.221:9443",       # 场景一接入端点（LXD proxy 发布口）
    [string]$ServerVip = "100.64.0.1",
    [string[]]$PeerVips = @(),                        # 其余客户端 VIP（可选，逐个 ping）
    [string]$Username  = "mn-win-host",
    [string]$Password  = "flock-mn-win-host"
)

$ErrorActionPreference = "Stop"

# —— 0. 提权（wintun/路由写入需管理员；自 UAC 再入）——
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[elevate] 非管理员——UAC 自提升重入 ..."
    $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File', $PSCommandPath,
                 '-JowHost',$JowHost,'-ServerEp',$ServerEp,'-ServerVip',$ServerVip,
                 '-Username',$Username,'-Password',$Password)
    if ($PeerVips.Count -gt 0) { $argList += @('-PeerVips', ($PeerVips -join ',')) }
    try { Start-Process powershell -Verb RunAs -ArgumentList $argList -Wait }
    catch { Write-Host "提权被拒：$($_.Exception.Message)"; exit 3 }
    exit $LASTEXITCODE
}
Write-Host "[admin] 已提权：$env:USERNAME @ $env:COMPUTERNAME"

# —— 1. 取/编译 flock-client.exe（Windows 目标）——
$repo = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))  # repo 根
$exe  = Join-Path $repo "target\release\flock-client.exe"
if (-not (Test-Path $exe)) {
    Write-Host "[build] 缺 $exe —— cargo build --release -p flock-client（宿主需 Rust MSVC）"
    Push-Location $repo
    cargo build --release -p flock-client
    if ($LASTEXITCODE -ne 0) { Write-Host "cargo build 失败"; exit 2 }
    Pop-Location
}
Write-Host "[bin] $exe"

# —— 2. 配置（%ProgramData%\FlockVPN）——
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

# —— 3. 引导（幂等：state\ready 存在即跳过）——
if (Test-Path "$stateDir\ready") {
    Write-Host "[boot] 已就绪（幂等跳过）"
} else {
    $keys = & $exe --config $cfg gen-keys
    $dx = ($keys | Select-String '^device-x=').Line.Substring(9)
    $de = ($keys | Select-String '^device-ed=').Line.Substring(11)
    if (-not $dx -or -not $de) { Write-Host "gen-keys 输出异常：$keys"; exit 2 }
    Write-Host "[boot] device-add（经 $JowHost → flock-s1 admin）"
    $add = ssh -o BatchMode=yes $JowHost `
        "lxc exec flock-s1 -- flock-server --config /etc/flock/server.toml device-add --user $Username --device-x $dx --device-ed $de"
    if ($LASTEXITCODE -ne 0) { Write-Host "device-add 失败：$add"; exit 2 }
    $vip = ($add | Select-String '^vip=').Line.Substring(4).Trim()
    Write-Host "[boot] 本机 VIP = $vip"
    $inv = ssh -o BatchMode=yes $JowHost `
        "lxc exec flock-s1 -- flock-server --config /etc/flock/server.toml invite --ttl-secs 86400" |
        Select-Object -Last 1
    [IO.File]::WriteAllText("$stateDir\invite.b64", $inv)
    & $exe --config $cfg invite "$stateDir\invite.b64"
    [IO.File]::WriteAllText("$stateDir\vip", "$vip`n")
    $Password | & $exe --config $cfg login
    New-Item -ItemType File -Path "$stateDir\ready" -Force | Out-Null
}

# —— 4. 运行（前台调试档 run：tun+路由+接入守护；窗口保活）——
Write-Host "[run] flock-client run（后台起，日志 $cfgDir\client.log）"
$proc = Start-Process -FilePath $exe -ArgumentList @('--config', $cfg, 'run') `
        -WindowStyle Hidden -RedirectStandardError "$cfgDir\client.log" -PassThru

# —— 5. 等 tun + ping 矩阵 ——
$deadline = (Get-Date).AddSeconds(90)
$vipSelf = (Get-Content "$stateDir\vip" -ErrorAction SilentlyContinue)
do {
    Start-Sleep -Seconds 3
    $ok = Get-NetAdapter -ErrorAction SilentlyContinue |
          Where-Object { $_.InterfaceDescription -like '*WireGuard*VPN*' -or $_.Name -like '*Flock*' }
} until ($ok -or ((Get-Date) -gt $deadline))
if (-not $ok) {
    Write-Host "tun 90s 未就绪（见 $cfgDir\client.log）"; Stop-Process -Id $proc.Id -Force; exit 2
}
Write-Host "[tun] 就绪：$($ok.Name)（本机 VIP $vipSelf）"

$targets = @($ServerVip) + $PeerVips
$fail = 0
foreach ($t in $targets) {
    $r = ping.exe -n 3 -w 2000 $t
    $lossLine = ($r | Select-String '\((\d+)% .*\)').Matches[0].Groups[1].Value
    $rttLine  = ($r | Select-String '=\s*(\d+)ms').Line
    $status = if ($lossLine -eq '0') { 'PASS' } else { $fail = 1; 'FAIL' }
    Write-Host ("[ping] {0,-14} 丢包 {1,3}%  {2,-24} {3}" -f $t, $lossLine, $rttLine, $status)
}
Write-Host "完成：客户端进程 pid=$($proc.Id)（Stop-Process 可下线）。任一 FAIL ⇒ 退出码 1。"
exit $fail
