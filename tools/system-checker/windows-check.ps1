<#
    windows-check - what is this machine, and is anything wrong with it?
                    Reported in plain English.

    The Windows half of system-checker. plain-check.c does this for Linux;
    this asks Windows the same questions and prints the same report, so the
    two are readable side by side and a technician does not have to learn
    two tools.

    Two jobs in one run, in the order you actually need them:

      1. What am I looking at.  Make and model, Windows version, processor,
         memory, graphics, disks, network, and whether this is real hardware
         or a virtual machine.

      2. Is anything wrong.  Full disks, listening ports, accounts with no
         password, whether the firewall and BitLocker are on, how long since
         the machine was patched.

    It only ever READS. It changes nothing, installs nothing, and sends
    nothing anywhere.

    Run:
        powershell -ExecutionPolicy Bypass -File windows-check.ps1
        powershell -ExecutionPolicy Bypass -File windows-check.ps1 -What
        powershell -ExecutionPolicy Bypass -File windows-check.ps1 -Check

    Run it as Administrator for the account and BitLocker checks. Without
    that it says which parts it could not see rather than quietly skipping.

    Nothing here needs installing. It uses the CIM classes that ship with
    Windows, so it works on a machine you are not allowed to put software on,
    which is usually the machine that needs looking at most.

    DhWonder, Plaintext IT - MIT license.
#>

[CmdletBinding()]
param(
    [switch]$What,      # just the inventory
    [switch]$Check      # just the health and security checks
)

$script:nOk   = 0
$script:nLook = 0
$script:nRisk = 0

# Three kinds of line: fine, worth a look, and a real risk. The wording
# matters more than the checks. The report should read like a calm person
# explaining, not like an alarm going off.
function Write-Ok   { param($m) Write-Host "  [ OK ]  $m"; $script:nOk++ }
function Write-Look { param($m) Write-Host "  [LOOK]  $m"; $script:nLook++ }
function Write-Risk { param($m) Write-Host "  [RISK]  $m"; $script:nRisk++ }

# A plain fact, with no judgement attached. The inventory half is all
# facts: it describes the machine, it does not grade it.
function Write-Fact {
    param($label, $value)
    Write-Host ("  {0,-14} {1}" -f $label, $value)
}

function Write-Section { param($t) Write-Host ""; Write-Host $t }

# Every lookup goes through here. A machine that will not answer one
# question should not take the whole report down with it, and a gap that
# says "could not tell" is worth more than a number that was guessed.
function Get-Safely {
    param([scriptblock]$Body, $Fallback = $null)
    try { & $Body } catch { $Fallback }
}

# The same, for anything that should come back as a list.
#
# This exists because of a PowerShell trap worth knowing: @($null).Count is
# 1, not 0. So the obvious `@(Get-Safely {...})` followed by a `.Count -eq 0`
# guard silently passes, and the next line reads item [0] of a list whose
# only element is nothing. On a Windows machine where a CIM class returns
# nothing - an old build, a locked down box, a missing service - that is a
# crash in the middle of the report rather than a polite "could not tell".
# It also records whether the lookup failed, as opposed to succeeding and
# finding nothing. Those are different answers and the report must not
# confuse them: "this machine has no antivirus" and "I could not ask about
# antivirus" lead somewhere completely different.
$script:lookupFailed = $false

function Get-Many {
    param([scriptblock]$Body)
    $script:lookupFailed = $false
    try {
        $result = & $Body
        return @($result | Where-Object { $null -ne $_ })
    } catch {
        $script:lookupFailed = $true
        return @()
    }
}

function Format-Size {
    param([double]$bytes)
    if ($bytes -ge 1TB) { return "{0:N1} TB" -f ($bytes / 1TB) }
    if ($bytes -ge 1GB) { return "{0:N1} GB" -f ($bytes / 1GB) }
    if ($bytes -ge 1MB) { return "{0:N0} MB" -f ($bytes / 1MB) }
    return "{0:N0} KB" -f ($bytes / 1KB)
}

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

# ================================================================
# PART ONE: what is this machine.
# ================================================================

function Report-OS {
    Write-Section "Operating system"

    $os = Get-Safely { Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
    if ($null -eq $os) {
        Write-Fact "windows" "could not tell (Windows would not answer)"
        return
    }

    Write-Fact "edition" $os.Caption
    Write-Fact "version" ("{0} (build {1})" -f $os.Version, $os.BuildNumber)
    Write-Fact "architecture" $os.OSArchitecture
    Write-Fact "hostname" $env:COMPUTERNAME

    $installed = Get-Safely { $os.InstallDate }
    if ($installed) {
        $age = [int]((Get-Date) - $installed).TotalDays
        Write-Fact "installed" ("{0:yyyy-MM-dd} ({1} days ago)" -f $installed, $age)
    }

    # Which Windows this really is matters more than the version number:
    # a Home edition cannot join a domain or use BitLocker properly, and
    # that decides half of what you can do for the client.
    if ($os.Caption -match "Home") {
        Write-Fact "note" "this is a Home edition, so no domain join and limited BitLocker"
    }
}

function Report-Machine {
    Write-Section "The machine itself"

    $cs   = Get-Safely { Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
    $bios = Get-Safely { Get-CimInstance Win32_BIOS -ErrorAction Stop }

    if ($cs) {
        Write-Fact "make and model" ("{0} {1}" -f $cs.Manufacturer, $cs.Model).Trim()
        if ($cs.Domain -and $cs.PartOfDomain) {
            Write-Fact "domain" $cs.Domain
        } else {
            Write-Fact "domain" "not joined to a domain (workgroup: $($cs.Workgroup))"
        }
    }
    if ($bios) {
        Write-Fact "serial" $(if ($bios.SerialNumber) { $bios.SerialNumber } else { "not published" })
        Write-Fact "firmware" ("{0} {1}" -f $bios.Manufacturer, $bios.SMBIOSBIOSVersion).Trim()
    }
    if (-not $cs -and -not $bios) {
        Write-Fact "hardware" "nothing published"
    }
}

function Report-Virtual {
    Write-Section "Real or virtual"

    $cs = Get-Safely { Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
    if ($null -eq $cs) {
        Write-Fact "running on" "could not tell"
        return
    }

    $model = "$($cs.Model) $($cs.Manufacturer)"
    $found = switch -Regex ($model) {
        "VMware"          { "VMware"; break }
        "VirtualBox"      { "VirtualBox"; break }
        "Virtual Machine" { "Hyper-V"; break }
        "KVM|QEMU"        { "KVM or QEMU"; break }
        "Xen"             { "Xen"; break }
        "Google"          { "Google Cloud"; break }
        "Amazon|EC2"      { "Amazon EC2"; break }
        default           { $null }
    }

    if ($found) {
        Write-Fact "running on" "a virtual machine on $found"
    } else {
        Write-Fact "running on" "real hardware, as far as this can tell"
    }
}

function Report-CPU {
    Write-Section "Processor"

    $cpus = Get-Many { Get-CimInstance Win32_Processor -ErrorAction Stop }
    if ($cpus.Count -eq 0) {
        Write-Fact "model" "could not tell"
        return
    }

    Write-Fact "model" $cpus[0].Name.Trim()

    $cores   = ($cpus | Measure-Object -Property NumberOfCores -Sum).Sum
    $logical = ($cpus | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    if ($cpus.Count -gt 1) {
        Write-Fact "count" "$logical logical processors, $cores cores across $($cpus.Count) physical chips"
    } else {
        Write-Fact "count" "$logical logical processors, $cores cores"
    }
    Write-Fact "speed" "$($cpus[0].MaxClockSpeed) MHz maximum"

    # Can this machine host virtual machines? Worth knowing before you
    # promise a client it can.
    $cs = Get-Safely { Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
    if ($cs -and $null -ne $cs.HypervisorPresent) {
        if ($cs.HypervisorPresent) {
            Write-Fact "virtualisation" "in use (a hypervisor is running, or Windows is using one)"
        } else {
            Write-Fact "virtualisation" "supported but no hypervisor running"
        }
    }
}

function Report-Memory {
    Write-Section "Memory"

    $os = Get-Safely { Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
    if ($null -eq $os) {
        Write-Fact "fitted" "could not tell"
        return
    }

    $totalKb = [double]$os.TotalVisibleMemorySize
    $freeKb  = [double]$os.FreePhysicalMemory
    Write-Fact "fitted" (Format-Size ($totalKb * 1KB))

    if ($totalKb -gt 0) {
        $pct = 100.0 * $freeKb / $totalKb
        Write-Fact "free right now" ("{0} ({1:N0}% of the total)" -f (Format-Size ($freeKb * 1KB)), $pct)

        # A machine with almost nothing left is slow in a way people
        # describe as "the computer is old". Usually it is not.
        if ($pct -lt 10) {
            Write-Look ("only {0:N0}% of memory is free. This machine will feel slow, and it is memory, not age." -f $pct)
        }
    }

    # The sticks themselves, because "can I add more" is the next question.
    $sticks = Get-Many { Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop }
    if ($sticks.Count -gt 0) {
        $desc = ($sticks | ForEach-Object { "$(Format-Size ([double]$_.Capacity)) @ $($_.Speed)MHz" }) -join ", "
        Write-Fact "sticks" "$($sticks.Count) fitted: $desc"
    }
    $slots = Get-Safely { (Get-CimInstance Win32_PhysicalMemoryArray -ErrorAction Stop).MemoryDevices }
    if ($slots) { Write-Fact "slots" "$slots on the board" }
}

function Report-GPU {
    Write-Section "Graphics"

    $gpus = Get-Many { Get-CimInstance Win32_VideoController -ErrorAction Stop }
    if ($gpus.Count -eq 0) {
        Write-Fact "display" $(if ($script:lookupFailed) { "could not tell" } else { "none found" })
        return
    }

    $first = $true
    foreach ($g in $gpus) {
        $bits = @($g.Name)
        if ($g.AdapterRAM -and $g.AdapterRAM -gt 0) {
            $bits += Format-Size ([double]$g.AdapterRAM)
        }
        if ($g.DriverVersion) { $bits += "driver $($g.DriverVersion)" }
        Write-Fact $(if ($first) { "display" } else { "also" }) ($bits -join ", ")
        $first = $false
    }
}

function Report-Storage {
    Write-Section "Storage"

    # The physical drives first: what is fitted, and whether it is a
    # spinning disk, which is usually the answer to "why is it so slow".
    $disks = Get-Many { Get-PhysicalDisk -ErrorAction Stop }
    if ($disks.Count -gt 0) {
        $first = $true
        foreach ($d in $disks) {
            $line = "{0}, {1}, {2}" -f $d.FriendlyName, (Format-Size ([double]$d.Size)), $d.MediaType
            if ($d.HealthStatus -and $d.HealthStatus -ne "Healthy") {
                Write-Risk "drive '$($d.FriendlyName)' reports health '$($d.HealthStatus)'. Back it up today and plan to replace it."
            }
            Write-Fact $(if ($first) { "drives" } else { "" }) $line
            $first = $false
        }
    } else {
        # Get-PhysicalDisk is not on older Windows. Fall back to the
        # class that has been there since forever.
        $drives = Get-Many { Get-CimInstance Win32_DiskDrive -ErrorAction Stop }
        $first = $true
        foreach ($d in $drives) {
            Write-Fact $(if ($first) { "drives" } else { "" }) ("{0}, {1}" -f $d.Model, (Format-Size ([double]$d.Size)))
            $first = $false
        }
        if ($drives.Count -eq 0) {
            Write-Fact "drives" $(if ($script:lookupFailed) { "could not tell" } else { "none found" })
        }
    }

    # Then the volumes people actually run out of room on.
    $vols = Get-Many { Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop }
    $first = $true
    foreach ($v in $vols) {
        if (-not $v.Size) { continue }
        $usedPct = 100.0 - (100.0 * $v.FreeSpace / $v.Size)
        Write-Fact $(if ($first) { "volumes" } else { "" }) `
            ("{0}  {1}, {2:N0}% used  ({3})" -f $v.DeviceID, (Format-Size ([double]$v.Size)), $usedPct, $v.FileSystem)
        $first = $false
    }
}

function Report-Network {
    Write-Section "Network"

    $adapters = Get-Many {
        Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop
    }
    if ($adapters.Count -eq 0) {
        Write-Fact "interfaces" $(if ($script:lookupFailed) { "could not tell" } else { "none with an address" })
        return
    }

    $first = $true
    foreach ($a in $adapters) {
        $ips = @($a.IPAddress) -join ", "
        $line = "{0}  {1}" -f $a.Description, $ips
        if ($a.MACAddress) { $line += "  ($($a.MACAddress))" }
        if ($a.DefaultIPGateway) { $line += "  <- the way out" }
        Write-Fact $(if ($first) { "interfaces" } else { "" }) $line
        $first = $false
    }

    $dns = @($adapters | ForEach-Object { $_.DNSServerSearchOrder } | Where-Object { $_ }) | Select-Object -Unique
    if ($dns) { Write-Fact "dns" ($dns -join ", ") }
}

# ================================================================
# PART TWO: is anything wrong.
# ================================================================

function Check-Disk {
    Write-Section "Disk space"

    $vols = Get-Many { Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop }
    if ($vols.Count -eq 0) {
        Write-Look "could not read disk usage."
        return
    }

    foreach ($v in $vols) {
        if (-not $v.Size) { continue }
        $usedPct = 100.0 - (100.0 * $v.FreeSpace / $v.Size)
        $msg = "{0} is {1:N0}% full." -f $v.DeviceID, $usedPct
        if ($usedPct -ge 95) {
            Write-Risk "$msg Above 95% things start breaking quietly. Free space soon."
        } elseif ($usedPct -ge 85) {
            Write-Look "$msg Not urgent, but plan a cleanup before it becomes urgent."
        } else {
            Write-Ok "$msg Plenty of room."
        }
    }
}

function Check-Uptime {
    Write-Section "Restarts and updates"

    $os = Get-Safely { Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
    if ($null -eq $os) { Write-Look "could not read system uptime."; return }

    $days = [int]((Get-Date) - $os.LastBootUpTime).TotalDays
    $msg = "last restart was $days day(s) ago."
    if ($days -ge 60) {
        Write-Look "$msg Months without a restart usually means updates aren't being applied. Pick a quiet evening and reboot."
    } else {
        Write-Ok "$msg Restarting now and then lets updates actually take effect."
    }

    # When was this machine last patched? A quiet machine and an
    # abandoned one look identical until you ask this.
    $hotfix = Get-Safely { Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1 }
    if ($hotfix -and $hotfix.InstalledOn) {
        $patchDays = [int]((Get-Date) - $hotfix.InstalledOn).TotalDays
        if ($patchDays -ge 90) {
            Write-Risk "the last update was installed $patchDays days ago ($($hotfix.HotFixID)). Three months unpatched is how machines get taken."
        } elseif ($patchDays -ge 45) {
            Write-Look "the last update was installed $patchDays days ago ($($hotfix.HotFixID)). Worth checking Windows Update is actually running."
        } else {
            Write-Ok "last update installed $patchDays days ago ($($hotfix.HotFixID))."
        }
    } else {
        Write-Look "could not tell when this machine was last updated."
    }
}

function Check-Ports {
    Write-Section "Open network doors (listening ports)"

    $known = @{
        21   = "FTP (21) - passwords travel unencrypted. Retire it if possible"
        23   = "Telnet (23) - decades obsolete and unsafe. Should be closed"
        3389 = "Remote Desktop (3389) - a favourite target. Should never face the internet directly"
        5900 = "VNC (5900) - remote control, often weakly protected. Check who needs it"
        445  = "Windows file sharing (445) - fine inside an office, dangerous exposed to the internet"
    }

    $listeners = Get-Many {
        Get-NetTCPConnection -State Listen -ErrorAction Stop
    }
    if ($listeners.Count -eq 0) {
        # Older Windows has no Get-NetTCPConnection. netstat is always there.
        $listeners = Get-Many {
            netstat -an | Select-String "LISTENING" | ForEach-Object {
                if ($_ -match ":(\d+)\s") { [pscustomobject]@{ LocalPort = [int]$Matches[1] } }
            }
        }
    }
    if ($listeners.Count -eq 0) {
        Write-Look "could not read the listening ports."
        return
    }

    $ports = $listeners | ForEach-Object { $_.LocalPort } | Sort-Object -Unique
    $flagged = 0
    foreach ($p in $ports) {
        if ($known.ContainsKey([int]$p)) {
            Write-Look ($known[[int]$p] + ".")
            $flagged++
        }
    }

    $msg = "$($ports.Count) port(s) are listening in total."
    if ($flagged -eq 0) {
        Write-Ok "$msg None of them are on my known-trouble list."
    } else {
        Write-Look "$msg The flagged ones above deserve a conversation."
    }
}

function Check-Accounts {
    Write-Section "User accounts"

    $users = Get-Many { Get-LocalUser -ErrorAction Stop }
    if ($users.Count -eq 0) {
        Write-Look "could not read the local accounts (this needs Administrator on some systems)."
        return
    }

    # An enabled account with no password is the Windows equivalent of an
    # empty field in /etc/shadow, and it is just as bad.
    $noPassword = @($users | Where-Object { $_.Enabled -and -not $_.PasswordRequired })
    foreach ($u in $noPassword) {
        Write-Risk "account '$($u.Name)' does not require a password. Anyone at the keyboard can become them. Set a password or disable the account today."
    }
    if ($noPassword.Count -eq 0) {
        Write-Ok "every enabled account requires a password."
    }

    # Who is an administrator. On a machine handed to you, this is the
    # single most useful list there is.
    $admins = Get-Many {
        Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    }
    if ($admins.Count -gt 0) {
        $names = ($admins | ForEach-Object { $_.Name }) -join ", "
        if ($admins.Count -gt 3) {
            Write-Look "$($admins.Count) accounts have administrator rights: $names. On a small office machine that is usually more than needed."
        } else {
            Write-Ok "administrators: $names."
        }
    }

    # Accounts nobody has used for a year are accounts nobody is watching.
    $stale = @($users | Where-Object {
        $_.Enabled -and $_.LastLogon -and ((Get-Date) - $_.LastLogon).TotalDays -gt 365
    })
    foreach ($u in $stale) {
        Write-Look "account '$($u.Name)' is enabled but has not been used for over a year. Disable it if nobody needs it."
    }
}

function Check-Protection {
    Write-Section "Firewall, antivirus and encryption"

    # The firewall, per profile, because being on for "Domain" and off
    # for "Public" is the combination that actually hurts.
    $profiles = Get-Many { Get-NetFirewallProfile -ErrorAction Stop }
    if ($profiles.Count -gt 0) {
        $off = @($profiles | Where-Object { -not $_.Enabled })
        if ($off.Count -gt 0) {
            Write-Risk "the firewall is off for: $(($off | ForEach-Object { $_.Name }) -join ', '). Turn it back on unless somebody can say exactly why it is off."
        } else {
            Write-Ok "the firewall is on for every network type."
        }
    } else {
        Write-Look "could not read the firewall state."
    }

    # Antivirus. Windows has had one built in for years, so "none" almost
    # always means somebody turned it off.
    $av = Get-Many {
        Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
    }
    if ($av.Count -gt 0) {
        Write-Ok "antivirus present: $(($av | ForEach-Object { $_.displayName }) -join ', ')."
    } elseif ($script:lookupFailed) {
        Write-Look "could not ask Windows about antivirus. That is not the same as there being none, so check it by hand."
    } else {
        Write-Look "no antivirus product registered with Windows. On a server that can be deliberate; on a desktop it is not."
    }

    # Disk encryption. The question that matters the day a laptop is left
    # on a train, and the one nobody asks before then.
    $bl = Get-Many { Get-BitLockerVolume -ErrorAction Stop }
    if ($bl.Count -gt 0) {
        $sys = $bl | Where-Object { $_.MountPoint -eq $env:SystemDrive }
        if ($sys -and $sys.ProtectionStatus -eq "On") {
            Write-Ok "the system drive is encrypted with BitLocker."
        } else {
            Write-Risk "the system drive is not encrypted. If this machine is ever lost or stolen, everything on it is readable. On a laptop this is the first thing to fix."
        }
    } else {
        Write-Look "could not read BitLocker status (needs Administrator, and is not on Home editions)."
    }
}

# ================================================================
function Show-Usage {
    Write-Host "windows-check - what is this machine, and is anything wrong with it?"
    Write-Host ""
    Write-Host "  windows-check.ps1          both halves: what it is, then what is wrong"
    Write-Host "  windows-check.ps1 -What    just the inventory"
    Write-Host "  windows-check.ps1 -Check   just the health and security checks"
    Write-Host ""
    Write-Host "Run it as Administrator for the account and BitLocker checks."
    Write-Host "It only reads. Nothing on this machine is changed."
}

# Neither switch means both halves. Both switches also means both halves,
# rather than the nothing-at-all that the obvious reading would give.
$wantWhat  = $What -or -not $Check
$wantCheck = $Check -or -not $What

Write-Host "windows-check: a look at this machine, in plain English."
Write-Host "(read-only - nothing on the system is changed)"
if (-not (Test-Admin)) {
    Write-Host "(not running as Administrator, so some checks will say so)"
}

if ($wantWhat) {
    Report-OS
    Report-Machine
    Report-Virtual
    Report-CPU
    Report-Memory
    Report-GPU
    Report-Storage
    Report-Network
}

if ($wantCheck) {
    Check-Disk
    Check-Uptime
    Check-Ports
    Check-Accounts
    Check-Protection
}

Write-Host ""
Write-Host "----------------------------------------------------------"

if (-not $wantCheck) {
    Write-Host "That is what this machine is. Run without -What to check it too."
    exit 0
}

Write-Host ("Summary: {0} fine, {1} worth a look, {2} real risk(s)." -f $nOk, $nLook, $nRisk)

if ($nRisk -gt 0) {
    Write-Host "The [RISK] lines above are the ones to act on this week."
    exit 2
} elseif ($nLook -gt 0) {
    Write-Host "Nothing alarming. The [LOOK] items are worth ten minutes sometime soon."
    exit 1
} else {
    Write-Host "This machine looks healthy. Check again in a month."
    exit 0
}
