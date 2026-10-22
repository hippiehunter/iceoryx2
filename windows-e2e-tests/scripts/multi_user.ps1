param([string]$Exe = "$PSScriptRoot\win-e2e-mu.exe", [int]$Count = 3, [ValidateSet("A", "B")][string]$Variant = "A")
# Multi-user secured-mode run of win-e2e-mu: the broker runs as the plain user sipbroker,
# writer1 and writer2 (members of SIPWriters) publish, and outsider must be refused by IAM.
# Variant A shares the root and the IAM pipe with everybody ("1777", "0666"); variant B with
# SIPWriters only ("2770", "0660", shared-group SIPWriters, the broker a member), so outsider
# must not even reach the services.
#
# Run it as an administrator on a throwaway machine or container: it creates local accounts
# and grants Users "Log on as a batch job", since every role runs as a scheduled task under its
# own account. For example, in a Windows Server Core container started with containerd:
#   ctr run -d --mount "type=bind,src=C:\Temp\mu,dst=C:\work,options=rbind:ro" `
#       mcr.microsoft.com/windows/servercore:ltsc2025 mu ping -t localhost
#   ctr task exec --exec-id run mu powershell -ExecutionPolicy Bypass -File C:\work\multi_user.ps1
$ErrorActionPreference = "Stop"
function Ensure-User($name, $pw, $group) {
    if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) { net user $name $pw /add | Out-Null }
    if ($group) { cmd /c "net localgroup $group $name /add >nul 2>&1" }
}
if (-not (Get-LocalGroup -Name SIPWriters -ErrorAction SilentlyContinue)) { net localgroup SIPWriters /add | Out-Null }
Ensure-User sipbroker "P@ssw0rd-3x" $(if ($Variant -eq "B") { "SIPWriters" } else { $null })
Ensure-User writer1 "P@ssw0rd-1x" SIPWriters
Ensure-User writer2 "P@ssw0rd-4x" SIPWriters
Ensure-User outsider "P@ssw0rd-2x" $null

# Scheduled tasks with a stored password need SeBatchLogonRight, which plain users lack.
secedit /export /cfg C:\mu-secpol.cfg /areas USER_RIGHTS | Out-Null
$cfg = Get-Content C:\mu-secpol.cfg
if (-not ($cfg -match '^SeBatchLogonRight.*S-1-5-32-545')) {
    if ($cfg -match '^SeBatchLogonRight') {
        $cfg = $cfg -replace '^(SeBatchLogonRight\s*=\s*.*)$', '$1,*S-1-5-32-545'
    } else {
        $cfg = $cfg -replace '^\[Privilege Rights\]$', "[Privilege Rights]`r`nSeBatchLogonRight = *S-1-5-32-545"
    }
    $cfg | Set-Content C:\mu-secpol.cfg
    secedit /configure /db C:\mu-secpol.sdb /cfg C:\mu-secpol.cfg /areas USER_RIGHTS | Out-Null
}

$base = "C:\sipiox"
if (Test-Path $base) { Remove-Item -Recurse -Force $base }
New-Item -ItemType Directory -Force "$base\bin", "$base\policies", "$base\out", "$base\audit" | Out-Null
Copy-Item $Exe "$base\bin\"
icacls $base /grant "Users:(OI)(CI)M" | Out-Null

$prefix = "mu" + (Get-Random -Maximum 99999) + "_"
$sharing = if ($Variant -eq "B") { "--shared-mode 2770 --shared-group SIPWriters --endpoint-mode 0660" } else { "--shared-mode 1777 --endpoint-mode 0666" }
$common = "--root-path $base\root\ --prefix $prefix --policy-dir $base\policies --quit-file $base\quit $sharing"
@"
[service]
name = "DeltaReplicator"

[[allow]]
principal = { user = "sipbroker" }
roles = ["subscriber"]

[[allow]]
principal = { group = "SIPWriters" }
roles = ["publisher"]
"@ | Set-Content "$base\policies\DeltaReplicator.toml"
@"
[service]
name = "DeltaReplicator/events"

[[allow]]
principal = { user = "sipbroker" }
roles = ["listener"]

[[allow]]
principal = { group = "SIPWriters" }
roles = ["notifier"]
"@ | Set-Content "$base\policies\DeltaReplicator_events.toml"
@"
[service]
name = "DeltaReplicator/space"

[[allow]]
principal = { user = "sipbroker" }
roles = ["notifier"]

[[allow]]
principal = { group = "SIPWriters" }
roles = ["listener"]
"@ | Set-Content "$base\policies\DeltaReplicator_space.toml"

$tasks = @{}
function Start-As($label, $user, $pw, $argline) {
    $out = "$base\out\$label.log"
    $cmd = "set IOX2_LOG_LEVEL=$env:IOX2_LOG_LEVEL&& $base\bin\win-e2e-mu.exe $argline > `"$out`" 2>&1"
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $cmd"
    $name = "mu-$label-" + [guid]::NewGuid().ToString("N").Substring(0,6)
    Register-ScheduledTask -TaskName $name -Action $action -User $user -Password $pw -RunLevel Limited | Out-Null
    Start-ScheduledTask -TaskName $name
    $script:tasks[$label] = $name
}
function Wait-Line($label, $pattern, $seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        $f = "$base\out\$label.log"
        if ((Test-Path $f) -and (Select-String -Path $f -Pattern $pattern -SimpleMatch -Quiet)) { return $true }
        $t = Get-ScheduledTask -TaskName $script:tasks[$label]
        if ($t.State -ne "Running" -and $t.State -ne "Queued") { Start-Sleep -Milliseconds 300; return [bool]((Test-Path $f) -and (Select-String -Path $f -Pattern $pattern -SimpleMatch -Quiet)) }
        Start-Sleep -Milliseconds 200
    }
    return $false
}
function Wait-Exit($label, $seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    do { Start-Sleep -Milliseconds 300; $t = Get-ScheduledTask -TaskName $script:tasks[$label] } while (($t.State -eq "Running" -or $t.State -eq "Queued") -and (Get-Date) -lt $deadline)
    $info = Get-ScheduledTaskInfo -TaskName $script:tasks[$label]
    return $info.LastTaskResult
}

$total = 2 * $Count
Start-As broker sipbroker "P@ssw0rd-3x" "--role broker $common --count $total --audit-log $base\audit\audit.log"
$ready = Wait-Line broker "BROKER: ready" 30
"broker ready=$ready"
if ($ready) {
    Start-As writer1 writer1 "P@ssw0rd-1x" "--role writer $common --count $Count --id 1"
    Start-As writer2 writer2 "P@ssw0rd-4x" "--role writer $common --count $Count --id 2"
    Start-As outsider outsider "P@ssw0rd-2x" "--role intruder $common"
    "all received=" + (Wait-Line broker "BROKER: received all" 60)
}
New-Item -ItemType File "$base\quit" | Out-Null
foreach ($label in @($tasks.Keys)) { "$label exit=" + (Wait-Exit $label 30) }
foreach ($label in @($tasks.Keys)) { "----- $label"; if (Test-Path "$base\out\$label.log") { Get-Content "$base\out\$label.log" } }
"----- audit"; if (Test-Path "$base\audit\audit.log") { Get-Content "$base\audit\audit.log" | Select-Object -Last 30 }
foreach ($name in $tasks.Values) { Unregister-ScheduledTask -TaskName $name -Confirm:$false }
$received = Select-String -Path "$base\out\broker.log" -Pattern "BROKER: received all" -SimpleMatch -Quiet
$denied = Select-String -Path "$base\out\outsider.log" -Pattern "INTRUDER: all ports denied" -SimpleMatch -Quiet
# Variant B: outsider cannot reach the root or the pipe, so it fails before IAM decides.
$unreachable = ($Variant -eq "B") -and
    -not (Select-String -Path "$base\out\outsider.log" -Pattern "INTRUDER: opened all services" -SimpleMatch -Quiet) -and
    (Select-String -Path "$base\out\outsider.log" -Pattern "Intruder: ERROR" -SimpleMatch -Quiet)
if ($Variant -eq "B") {
    "--- root ACL (variant B)"; icacls "$base\root"
}
if ($received -and ($denied -or $unreachable)) { "MULTI-USER RESULT: PASS (variant $Variant)" } else { "MULTI-USER RESULT: FAIL (variant $Variant)"; exit 1 }
