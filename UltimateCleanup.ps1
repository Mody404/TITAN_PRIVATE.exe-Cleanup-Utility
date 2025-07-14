<#
.SYNOPSIS
  Interactive “nuke” of TITAN malware plus system repair, with logging and user-driven cleanup.

.DESCRIPTION
  - Logs to Desktop\cleanup_YYYYMMDD_HHMMSS.log
  - Shows all local users and lets you delete any you don’t recognize
  - Detects non-built-in, enabled local users and asks you whether to delete each
  - Terminates/removes any process or service matching “TITAN”
  - Blocks d3co4r.duckdns.org and 79.124.62.122
  - Nukes profiles server, moda, moba
  - Removes known malware files
  - Cleans IFEO hijacks and Debugger settings
  - Cleans ScheduledTasks, Run-keys for “Titan”
  - Restores TaskMgr, Quick Access
  - Repairs Windows Defender

.CREATED BY
  Mody404 – https://github.com/Mody404
#>

# --- Setup logging ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$desktop   = [Environment]::GetFolderPath("Desktop")
$logFile   = Join-Path $desktop "cleanup_$timestamp.log"
function Write-Log {
    param([string]$msg)
    $ts = Get-Date -Format "HH:mm:ss"
    "$ts`t$msg" | Tee-Object -FilePath $logFile -Append
    Write-Host $msg
}

# --- 1) Require elevation ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Log "ERROR: Please re-run this script as Administrator."
    exit 1
}
Write-Log "Running as user: $env:USERNAME"
Write-Log "Starting cleanup log at $logFile"

# --- 2) Show all local users for manual review ---
Write-Log "Listing all local users..."
Get-LocalUser | Select-Object Name,Enabled | Format-Table | Out-String | Write-Host
$delList = Read-Host "Enter any usernames (comma-separated) you don't recognize to delete, or press Enter to skip"
if ($delList) {
    $names = $delList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    foreach ($n in $names) {
        try {
            Remove-LocalUser -Name $n -ErrorAction Stop
            Write-Log "Manually deleted user $n"
        } catch {
            Write-Log ("Failed to delete {0}: {1}" -f $n, $_.Exception.Message)
        }
    }
}

# --- 3) Detect and optionally delete non-built-in enabled users ---
Write-Log "Detecting non-built-in, enabled local users..."
$builtIns = 'Administrator','Guest','DefaultAccount','WDAGUtilityAccount'
$customUsers = Get-LocalUser |
    Where-Object { $_.Enabled -and ($builtIns -notcontains $_.Name) } |
    Select-Object -ExpandProperty Name

foreach ($u in $customUsers) {
    $answer = Read-Host "  Delete local user '$u'? (Y/N)"
    if ($answer -match '^[Yy]') {
        try {
            Remove-LocalUser -Name $u -ErrorAction Stop
            Write-Log "Deleted user $u"
        } catch {
            Write-Log ("Failed to delete {0}: {1}" -f $u, $_.Exception.Message)
        }
    } else {
        Write-Log "Left user $u intact"
    }
}

# --- 4) Kill / remove any TITAN* processes & services ---
Write-Log "Stopping any process or service matching 'TITAN'..."
Get-Process | Where-Object Name -match 'TITAN' |
    ForEach-Object { Stop-Process $_ -Force -ErrorAction SilentlyContinue; Write-Log "Stopped process $($_.Name)" }
Get-Service | Where-Object Name -match 'TITAN' |
    ForEach-Object {
        try {
            Stop-Service $_.Name -Force -ErrorAction Stop
            sc.exe delete $_.Name | Out-Null
            Write-Log "Removed service $($_.Name)"
        } catch {
            Write-Log "No service $($_.Name) or failed to remove"
        }
    }

# --- 5) Block domain & IP ---
Write-Log "Blocking d3co4r.duckdns.org and 79.124.62.122..."
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
if (-not (Select-String -Path $hosts -Pattern 'd3co4r\.duckdns\.org' -Quiet)) {
    Add-Content -Path $hosts -Value "`n127.0.0.1 d3co4r.duckdns.org"
    Write-Log "Added hosts entry for d3co4r.duckdns.org"
}
if (-not (Get-NetFirewallRule -DisplayName 'Block inbound 79.124.62.122' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'Block inbound 79.124.62.122' `
        -Direction Inbound -RemoteAddress '79.124.62.122' -Action Block
    Write-Log "Created firewall block for 79.124.62.122"
}

# --- 6) Stop Explorer & CDPUserSvc to free profiles ---
Write-Log "Stopping Explorer and CDPUserSvc_*..."
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Get-Service CDPUserSvc_* -ErrorAction SilentlyContinue |
    Stop-Service -Force -ErrorAction SilentlyContinue

# --- 7) Fast-nuke known profiles ---
$profiles = @('server','moda','moba') | ForEach-Object { "C:\Users\$_" }
foreach ($p in $profiles) {
    if (Test-Path $p) {
        try {
            Remove-Item -Path $p -Recurse -Force -ErrorAction Stop
            Write-Log "Deleted profile folder $p"
        } catch {
            Write-Log "Could not delete $p now; scheduling on reboot"
            $entry = "\??\$p",""
            $reg   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
            $old   = (Get-ItemProperty -Path $reg -Name PendingFileRenameOperations `
                       -ErrorAction SilentlyContinue).PendingFileRenameOperations
            $new   = @(); if ($old) { $new += $old }; $new += $entry
            Set-ItemProperty -Path $reg -Name PendingFileRenameOperations -Value $new -Type MultiString
        }
    } else {
        Write-Log "Profile folder $p not found"
    }
}

# --- 8) Remove known malware files ---
Write-Log "Removing known TITAN_PRIVATE malware files..."
$malwareFiles = @(
    "C:\Users\server\Desktop\1\TITAN_PRIVAT.EXE",
    "C:\Users\server\Desktop\2\TITAN_PRIVAT.EXE",
    "C:\Users\server\Downloads\NL_BRUTE_PRIVAT_TITAN (1).ZIP",
    "C:\Users\server\AppData\Roaming\Microsoft\Windows\Recent\NL_Brute_PRIVAT_TITAN (1).lnk"
)
foreach ($f in $malwareFiles) {
    if (Test-Path $f) {
        Write-Log "Deleting file: $f"
        Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
    }
}

# --- 9) Clean IFEO hijack & Debugger keys ---
Write-Log "Cleaning IFEO hijack and Debugger registry keys..."
$ifeoKeys = @(
    "HKLM:\SOFTWARE\WOW6432NODE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\procexp.exe",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\procexp.exe",
    "HKLM:\SOFTWARE\WOW6432NODE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\processhacker.exe",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\processhacker.exe"
)
foreach ($k in $ifeoKeys) {
    if (Test-Path $k) {
        Remove-Item -Path $k -Recurse -Force
        Write-Log "Removed IFEO key $k"
    }
}

# --- 10) Clean ScheduledTasks named *Titan* ---
Write-Log "Scanning Scheduled Tasks for 'Titan'..."
Get-ScheduledTask |
  Where-Object TaskName -Match 'Titan' |
  ForEach-Object {
    $tn = $_.TaskName
    $answer = Read-Host "  Remove scheduled task '$tn'? (Y/N)"
    if ($answer -match '^[Yy]') {
      Unregister-ScheduledTask -TaskName $tn -Confirm:$false
      Write-Log "Removed task $tn"
    } else {
      Write-Log "Kept task $tn"
    }
  }

# --- 11) Clean Run keys containing “Titan” ---
Write-Log "Scanning registry Run keys for 'Titan'..."
$runPaths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($rp in $runPaths) {
  if (Test-Path $rp) {
    $props = (Get-ItemProperty -Path $rp).PSObject.Properties |
             Where-Object { $_.MemberType -eq 'NoteProperty' -and $_.Name -notmatch '^PS' } |
             Select-Object -ExpandProperty Name
    foreach ($name in $props) {
        $val = (Get-ItemProperty -Path $rp -Name $name).$name
        if ($val -match 'Titan') {
            $answer = Read-Host "  Remove Run-key '$name' -> $val ? (Y/N)"
            if ($answer -match '^[Yy]') {
                Remove-ItemProperty -Path $rp -Name $name
                Write-Log "Removed Run entry $name"
            } else {
                Write-Log "Kept Run entry $name"
            }
        }
    }
  }
}

# --- 12) Restore Task Manager ---
Write-Log "Restoring Task Manager..."
Get-ChildItem 'Registry::HKEY_USERS' |
  Where-Object Name -Match '\\S-1-5-21-.*-500$' |
  ForEach-Object {
    $k = "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    if (Test-Path $k) {
      Remove-ItemProperty -Path $k -Name DisableTaskMgr -ErrorAction SilentlyContinue
      Write-Log "Enabled TaskMgr for SID $($_.PSChildName)"
    }
  }

# --- 13) Restore Quick Access ---
Write-Log "Resetting Quick Access..."
$auto   = Join-Path $env:APPDATA 'Microsoft\Windows\Recent\AutomaticDestinations\*'
$custom = Join-Path $env:APPDATA 'Microsoft\Windows\Recent\CustomDestinations\*'
Remove-Item -Path $auto,$custom -Recurse -Force -ErrorAction SilentlyContinue
$advKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-ItemProperty -Path $advKey -Name LaunchTo     -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path $advKey -Name HubMode      -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path $advKey -Name ShowFrequent -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path $advKey -Name ShowRecent   -Value 1 -ErrorAction SilentlyContinue

# --- 14) Repair Windows Defender ---
Write-Log "Repairing Windows Defender..."
foreach ($p in @(
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
)) {
  if (Test-Path $p) {
    Remove-Item -Path $p -Recurse -Force
    Write-Log "Removed policy $p"
  }
}
$dk = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
'DisableAntiSpyware','DisableRealtimeMonitoring','PUAProtection' |
  ForEach-Object {
    if (Get-ItemProperty -Path $dk -Name $_ -ErrorAction SilentlyContinue) {
      Remove-ItemProperty -Path $dk -Name $_
      Write-Log "Removed Defender value $_"
    }
  }
try {
  Set-Service WinDefend -StartupType Automatic -ErrorAction Stop
  Start-Service WinDefend -ErrorAction Stop
  Write-Log "WinDefend started"
} catch {
  sc.exe config WinDefend start= auto | Out-Null
  sc.exe start WinDefend         | Out-Null
  Write-Log "WinDefend started via sc.exe"
}

# --- 15) Restart Explorer ---
Write-Log "Restarting Explorer..."
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Process explorer

Write-Log "=== Cleanup complete! Please reboot to finalize any pending deletions. ==="
Write-Host "`nLog saved to $logFile" -ForegroundColor Green
