<#
.SYNOPSIS
    Windows PC audit. Writes report.html and audit.log next to this script.

.DESCRIPTION
    Read only by default: it looks, measures and reports, and changes nothing.
    Run with -Fix to be offered three kinds of cleanup, each confirmed one at a time:
      * disable a startup item (reversible in Task Manager, Startup apps)
      * clear temp files older than one day (your temp folder and the Windows temp folder)
      * empty the recycle bin
    It never touches personal files, never edits the registry beyond startup approval
    entries, never installs anything and never sends data off this PC.

    Works on PowerShell 7 and on Windows PowerShell 5.1 (built into Windows).

.EXAMPLE
    .\audit.ps1
.EXAMPLE
    .\audit.ps1 -Fix
#>
[CmdletBinding()]
param([switch]$Fix)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$Here       = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$LogPath    = Join-Path $Here 'audit.log'
$ReportPath = Join-Path $Here 'report.html'
$IsAdmin    = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Started    = Get-Date
$Errors     = New-Object System.Collections.Generic.List[string]
$Recs       = New-Object System.Collections.Generic.List[object]
$S          = @{}   # section results

# ---------------------------------------------------------------- helpers

function Write-Log([string]$Message, [string]$Level = 'INFO') {
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    try { Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8 -ErrorAction Stop } catch { Write-Warning "Could not write to audit.log: $_" }
}

function Format-Size($Bytes) {
    if ($null -eq $Bytes) { return 'not reported' }
    $b = [double]$Bytes
    if ($b -ge 1TB) { return '{0:N2} TB' -f ($b / 1TB) }
    if ($b -ge 1GB) { return '{0:N1} GB' -f ($b / 1GB) }
    if ($b -ge 1MB) { return '{0:N0} MB' -f ($b / 1MB) }
    if ($b -ge 1KB) { return '{0:N0} KB' -f ($b / 1KB) }
    return '{0:N0} bytes' -f $b
}

function Format-Date($d) { if ($d) { ([datetime]$d).ToString('d MMM yyyy') } else { 'unknown' } }

function Add-Rec([int]$Priority, [string]$Title, [string]$Detail) {
    $Recs.Add([pscustomobject]@{ Priority = $Priority; Title = $Title; Detail = $Detail })
}

function Enc($v) { [System.Net.WebUtility]::HtmlEncode([string]$v) }

# Folder sizing and safe temp cleaning, compiled once. Never follows junctions or symbolic links,
# skips cloud only (OneDrive placeholder) files because they use no disk space.
Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
public static class AuditFs {
    // Empties the recycle bin without Windows' own prompt (the script asks first). Clear-RecycleBin is missing in PowerShell 7.
    [System.Runtime.InteropServices.DllImport("shell32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    public static extern int SHEmptyRecycleBin(IntPtr hwnd, string root, uint flags);

    static bool IsLink(FileSystemInfo i) { return (i.Attributes & FileAttributes.ReparsePoint) != 0; }
    static bool IsCloudOnly(FileSystemInfo i) { int a = (int)i.Attributes; return (a & 0x400000) != 0 || (a & 0x1000) != 0; }

    // returns { bytes, files, unreadable folders }
    public static long[] Measure(string root) {
        long bytes = 0, files = 0, errs = 0;
        var stack = new Stack<DirectoryInfo>();
        try { var r = new DirectoryInfo(root); if (!r.Exists) return new long[] {0,0,0}; stack.Push(r); } catch { return new long[] {0,0,1}; }
        while (stack.Count > 0) {
            var d = stack.Pop();
            try {
                foreach (var i in d.EnumerateFileSystemInfos()) {
                    if (IsLink(i)) continue;
                    if ((i.Attributes & FileAttributes.Directory) != 0) stack.Push((DirectoryInfo)i);
                    else if (!IsCloudOnly(i)) { bytes += ((FileInfo)i).Length; files++; }
                }
            } catch { errs++; }
        }
        return new long[] { bytes, files, errs };
    }

    // Deletes files older than cutoff under root. Never enters links, never touches anything under protect.
    // Removes folders only when they are empty and were created before cutoff. Returns { bytes freed, files deleted, failures }.
    public static long[] CleanOld(string root, DateTime cutoff, string protect) {
        long freed = 0, deleted = 0, failed = 0;
        string p = string.IsNullOrEmpty(protect) ? null : protect.TrimEnd('\\') + "\\";
        var all = new List<DirectoryInfo>();
        var stack = new Stack<DirectoryInfo>();
        stack.Push(new DirectoryInfo(root));
        while (stack.Count > 0) {
            var d = stack.Pop();
            List<FileSystemInfo> items;
            try { items = new List<FileSystemInfo>(d.EnumerateFileSystemInfos()); } catch { failed++; continue; }
            foreach (var i in items) {
                if (IsLink(i)) continue;
                if (p != null && (i.FullName + "\\").StartsWith(p, StringComparison.OrdinalIgnoreCase)) continue;
                if ((i.Attributes & FileAttributes.Directory) != 0) { stack.Push((DirectoryInfo)i); all.Add((DirectoryInfo)i); continue; }
                var f = (FileInfo)i;
                if (f.LastWriteTime > cutoff) continue;
                try { long len = f.Length; f.Delete(); freed += len; deleted++; } catch { failed++; }
            }
        }
        for (int k = all.Count - 1; k >= 0; k--) {
            try { var d = all[k]; d.Refresh(); if (d.CreationTime <= cutoff && !d.EnumerateFileSystemInfos().GetEnumerator().MoveNext()) d.Delete(false); } catch { }
        }
        return new long[] { freed, deleted, failed };
    }
}
'@

$Hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
$Hkcu = [Microsoft.Win32.RegistryKey]::OpenBaseKey('CurrentUser', 'Registry64')

function Get-RegValue($Root, [string]$SubKey, [string]$Name) {
    $k = $Root.OpenSubKey($SubKey)
    if ($k) { try { return $k.GetValue($Name) } finally { $k.Close() } }
}

$Step = 0
$Total = 12
function Invoke-Section([string]$Key, [string]$Title, [scriptblock]$Code) {
    $script:Step++
    Write-Host ("[{0}/{1}] {2}..." -f $script:Step, $Total, $Title)
    Write-Log "Started check: $Title"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $script:S[$Key] = & $Code
        Write-Log ("Finished check: {0} ({1:N1}s)" -f $Title, $sw.Elapsed.TotalSeconds)
    } catch {
        $msg = "$Title could not complete: $($_.Exception.Message)"
        $script:Errors.Add($msg)
        Write-Log $msg 'ERROR'
        Write-Host "    $msg" -ForegroundColor Yellow
    }
}

Write-Log ('==== Audit started. Mode: {0}. Administrator: {1}. PowerShell {2}. Folder: {3}' -f $(if ($Fix) { 'FIX (changes offered, each confirmed)' } else { 'READ ONLY' }), $IsAdmin, $PSVersionTable.PSVersion, $Here)
Write-Host ''
Write-Host 'Windows PC audit' -ForegroundColor Cyan
Write-Host $(if ($Fix) { 'Fix mode: you will be asked before every change.' } else { 'Read only mode: nothing on this PC will be changed.' })
if (-not $IsAdmin) { Write-Host 'Not running as administrator, so a few checks will show less detail.' -ForegroundColor Yellow }
Write-Host ''

# ---------------------------------------------------------------- 1 system summary

Invoke-Section 'System' 'Reading basic system details' {
    $os  = Get-CimInstance Win32_OperatingSystem
    $cs  = Get-CimInstance Win32_ComputerSystem
    $cpu = @(Get-CimInstance Win32_Processor)[0]
    $ver = Get-RegValue $Hklm 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion'
    $up  = (Get-Date) - $os.LastBootUpTime
    $build = [int]$os.BuildNumber
    if ($build -lt 22000) { Add-Rec 1 'Windows 10 no longer gets security updates' 'This PC runs Windows 10, which stopped receiving free security updates in October 2025. Upgrade to Windows 11 if the PC supports it, or enrol in Extended Security Updates.' }
    if ($up.TotalDays -ge 7) { Add-Rec 3 'Restart the PC' ("It has been running for {0} days without a full restart. A restart finishes updates and clears out memory. Note that Shut down with Fast Startup on is not a full restart; use Restart." -f [int]$up.TotalDays) }
    [pscustomobject]@{
        'Windows'         = "$($os.Caption) $ver (build $($os.BuildNumber))"
        'Computer model'  = "$($cs.Manufacturer) $($cs.Model)"
        'Processor'       = ($cpu.Name -replace '\s+', ' ').Trim()
        'Cores / threads' = "$($cpu.NumberOfCores) / $($cpu.NumberOfLogicalProcessors)"
        'Memory (RAM)'    = Format-Size $cs.TotalPhysicalMemory
        'Last restart'    = "$(Format-Date $os.LastBootUpTime) ($([int]$up.TotalDays) days, $($up.Hours) hours ago)"
        'Audit run as administrator' = $(if ($IsAdmin) { 'Yes' } else { 'No (some details limited)' })
        'PowerShell'      = "$($PSVersionTable.PSVersion)"
    }
}

# ---------------------------------------------------------------- 2 RAM and CPU snapshot (early, before our own scanning loads the PC)

Invoke-Section 'Perf' 'Taking a memory and processor snapshot' {
    $os = Get-CimInstance Win32_OperatingSystem
    $totalKb = [double]$os.TotalVisibleMemorySize; $freeKb = [double]$os.FreePhysicalMemory
    $usedPct = [math]::Round(100 * ($totalKb - $freeKb) / $totalKb)
    $cores = [Environment]::ProcessorCount
    $a = @{}; Get-Process | ForEach-Object { try { $a[$_.Id] = $_.TotalProcessorTime.TotalMilliseconds } catch {} }
    $t0 = Get-Date; Start-Sleep -Seconds 3
    $procs = Get-Process
    $secs = ((Get-Date) - $t0).TotalMilliseconds
    $rows = foreach ($p in $procs) {
        $cpu = $null
        try { if ($a.ContainsKey($p.Id)) { $cpu = ($p.TotalProcessorTime.TotalMilliseconds - $a[$p.Id]) / $secs / $cores * 100 } } catch {}
        [pscustomobject]@{ Name = $p.ProcessName; Mem = [double]$p.WorkingSet64; Cpu = [double]$cpu }
    }
    $grouped = $rows | Group-Object Name | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Count = $_.Count; Mem = ($_.Group | Measure-Object Mem -Sum).Sum; Cpu = ($_.Group | Measure-Object Cpu -Sum).Sum }
    } | Where-Object { $_.Name -ne 'Idle' }
    $cpuTotal = [math]::Round((@(Get-CimInstance Win32_Processor) | Measure-Object LoadPercentage -Average).Average)

    if ($usedPct -ge 85) { Add-Rec 2 'Memory is nearly full' "About $usedPct% of RAM was in use during the audit. The PC will slow down when it runs out. Close programs you are not using, cut down startup programs, or consider adding more RAM." }
    if ($totalKb * 1KB -lt 7.5GB) { Add-Rec 3 'Low amount of memory' ("This PC has {0} of RAM. 8 GB is the practical minimum for Windows 11 with a modern web browser; 16 GB is comfortable." -f (Format-Size ($totalKb * 1KB))) }
    if ($cpuTotal -ge 80) { Add-Rec 3 'Processor was very busy' "The processor was at about $cpuTotal% during the audit. If this happens when you are not doing anything, check the busiest programs listed in the report." }

    $fmt = { param($g) [pscustomobject]@{ 'Program' = $g.Name; 'Copies running' = $g.Count; 'Memory' = Format-Size $g.Mem; 'Processor' = ('{0:N1}%' -f $g.Cpu) } }
    [pscustomobject]@{
        Summary = [pscustomobject]@{
            'Memory in use'    = "$usedPct% ($(Format-Size (($totalKb - $freeKb) * 1KB)) of $(Format-Size ($totalKb * 1KB)))"
            'Processor in use' = "$cpuTotal%"
            'Programs running' = @($procs).Count
        }
        TopMem = $grouped | Sort-Object Mem -Descending | Select-Object -First 10 | ForEach-Object { & $fmt $_ }
        TopCpu = $grouped | Sort-Object Cpu -Descending | Select-Object -First 5  | ForEach-Object { & $fmt $_ }
        MemByName = $grouped
    }
}

# ---------------------------------------------------------------- 3 startup programs

$StartupLocations = @(
    @{ Root = $Hkcu; RootName = 'HKCU'; Key = 'Software\Microsoft\Windows\CurrentVersion\Run';             Approved = 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run';   Scope = 'This user' }
    @{ Root = $Hklm; RootName = 'HKLM'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run';             Approved = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run';   Scope = 'All users' }
    @{ Root = $Hklm; RootName = 'HKLM'; Key = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Approved = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'; Scope = 'All users' }
)

function Get-ExePath([string]$Command) {
    $c = [Environment]::ExpandEnvironmentVariables($Command).Trim()
    if ($c -match '^"([^"]+)"') { return $Matches[1] }
    if ($c -match '^(.+?\.(exe|cmd|bat|com))(\s|$)') { return $Matches[1] }
    return ($c -split '\s')[0]
}

Invoke-Section 'Startup' 'Listing startup programs' {
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($loc in $StartupLocations) {
        $k = $loc.Root.OpenSubKey($loc.Key)
        if (-not $k) { continue }
        foreach ($n in $k.GetValueNames()) {
            if (-not $n) { continue }
            $cmd = [string]$k.GetValue($n)
            $items.Add([pscustomobject]@{ Name = $n; Command = $cmd; Exe = (Get-ExePath $cmd); Scope = $loc.Scope; Where = "Registry ($($loc.RootName) Run)"; ApprovedRoot = $loc.Root; ApprovedKey = $loc.Approved })
        }
        $k.Close()
    }
    $shell = New-Object -ComObject WScript.Shell
    foreach ($f in @(@{ P = [Environment]::GetFolderPath('Startup'); Root = $Hkcu; Scope = 'This user' }, @{ P = [Environment]::GetFolderPath('CommonStartup'); Root = $Hklm; Scope = 'All users' })) {
        if (-not $f.P -or -not (Test-Path -LiteralPath $f.P)) { continue }
        foreach ($file in Get-ChildItem -LiteralPath $f.P -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' }) {
            $target = $file.FullName
            if ($file.Extension -eq '.lnk') { try { $t = $shell.CreateShortcut($file.FullName).TargetPath; if ($t) { $target = $t } } catch {} }  # reads the shortcut only
            $items.Add([pscustomobject]@{ Name = $file.Name; Command = $target; Exe = $target; Scope = $f.Scope; Where = 'Startup folder'; ApprovedRoot = $f.Root; ApprovedKey = 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder' })
        }
    }

    $memByName = @{}
    if ($S['Perf']) { foreach ($g in $S['Perf'].MemByName) { $memByName[$g.Name] = $g.Mem } }

    $rows = foreach ($i in $items) {
        $v = Get-RegValue $i.ApprovedRoot $i.ApprovedKey $i.Name
        $enabled = -not ($v -is [byte[]] -and $v.Length -gt 0 -and ($v[0] -band 1))
        $publisher = ''
        if ($i.Exe -and (Test-Path -LiteralPath $i.Exe -PathType Leaf -ErrorAction SilentlyContinue)) { $publisher = (Get-Item -LiteralPath $i.Exe).VersionInfo.CompanyName }
        $proc = [IO.Path]::GetFileNameWithoutExtension($i.Exe)
        $mem = if ($proc -and $memByName.ContainsKey($proc)) { $memByName[$proc] } else { $null }
        $impact = if (-not $enabled) { 'None (disabled)' }
                  elseif ($null -eq $mem) { 'Unknown (not running now)' }
                  elseif ($mem -ge 250MB) { 'High' } elseif ($mem -ge 75MB) { 'Medium' } else { 'Low' }
        [pscustomobject]@{
            Name = $i.Name; Publisher = $publisher; Status = $(if ($enabled) { 'Enabled' } else { 'Disabled' })
            Impact = $impact; 'Memory now' = $(if ($null -ne $mem) { Format-Size $mem } else { '' })
            For = $i.Scope; Where = $i.Where; Command = $i.Command
            ApprovedRoot = $i.ApprovedRoot; ApprovedKey = $i.ApprovedKey; Enabled = $enabled
        }
    }
    $rows = @($rows | Sort-Object @{ e = { switch ($_.Impact) { 'High' { 0 } 'Medium' { 1 } 'Low' { 2 } default { 3 } } } }, Name)
    $on = @($rows | Where-Object Enabled)
    $high = @($on | Where-Object { $_.Impact -eq 'High' })
    if ($on.Count -ge 8) { Add-Rec 2 'Too many programs start with Windows' "$($on.Count) programs start automatically when you sign in. Each one slows startup and uses memory in the background. Disable the ones you do not need in Task Manager, Startup apps (they will still work when you open them yourself)." }
    elseif ($high.Count -ge 1) { Add-Rec 3 'Heavy programs start with Windows' ("These start automatically and are using a lot of memory: {0}. Consider disabling them at startup if you do not need them running all the time." -f (($high | ForEach-Object Name) -join ', ')) }
    $rows
}

# ---------------------------------------------------------------- 4 Defender

Invoke-Section 'Defender' 'Checking Windows Security and antivirus' {
    $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object {
        $hex = '{0:X6}' -f [int]$_.productState
        [pscustomobject]@{ Product = $_.displayName; On = ($hex.Substring(2, 2) -in '10', '11'); UpToDate = ($hex.Substring(4, 2) -eq '00') }
    })
    $mp = $null; try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch {}
    $threats = $null; try { $threats = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-30) }).Count } catch {}

    $activeAv = @($av | Where-Object On)
    if ($activeAv.Count -eq 0) { Add-Rec 1 'No active antivirus' 'Windows reports no antivirus switched on. Open Windows Security, Virus and threat protection, and turn on real time protection.' }
    if ($activeAv.Count -gt 1) { Add-Rec 3 'More than one antivirus is active' ("Windows reports several active antivirus products: {0}. Running two at once can slow the PC and cause conflicts. Keep one." -f (($activeAv | ForEach-Object Product) -join ', ')) }
    foreach ($a in $activeAv | Where-Object { -not $_.UpToDate }) { Add-Rec 2 "$($a.Product) is out of date" 'Its virus definitions are not up to date. Open it and run an update.' }

    $info = [ordered]@{ 'Antivirus products Windows knows about' = $(if ($av) { ($av | ForEach-Object { "$($_.Product) ($(if ($_.On) { 'on' } else { 'off' }), $(if ($_.UpToDate) { 'up to date' } else { 'out of date' }))" }) -join '; ' } else { 'none reported' }) }
    if ($mp) {
        $info['Defender mode'] = $mp.AMRunningMode
        $info['Real time protection'] = $(if ($mp.RealTimeProtectionEnabled) { 'On' } else { 'Off' })
        $info['Virus definitions last updated'] = "$(Format-Date $mp.AntivirusSignatureLastUpdated) ($($mp.AntivirusSignatureAge) days ago)"
        $info['Last quick scan'] = $(if ($mp.QuickScanAge -lt 10000) { "$($mp.QuickScanAge) days ago" } else { 'never' })
        $info['Last full scan'] = $(if ($mp.FullScanAge -lt 10000) { "$($mp.FullScanAge) days ago" } else { 'never' })
        $info['Tamper protection'] = $(if ($mp.IsTamperProtected) { 'On' } else { 'Off' })
        if ($mp.AMRunningMode -eq 'Normal') {
            if (-not $mp.RealTimeProtectionEnabled) { Add-Rec 1 'Defender real time protection is off' 'Microsoft Defender is the active antivirus but real time protection is switched off, so threats are not blocked as they arrive. Turn it on in Windows Security, Virus and threat protection settings.' }
            if ($mp.AntivirusSignatureAge -gt 7) { Add-Rec 2 'Defender virus definitions are out of date' "They were last updated $($mp.AntivirusSignatureAge) days ago. Open Windows Security and click Check for updates under Virus and threat protection updates." }
            if (-not $mp.IsTamperProtected) { Add-Rec 3 'Turn on Tamper Protection' 'Tamper Protection stops malicious software from switching Defender off. Turn it on in Windows Security, Virus and threat protection settings.' }
            if ($mp.QuickScanAge -gt 30) { Add-Rec 4 'Run a quick virus scan' 'No quick scan has run in the last month. Open Windows Security and click Quick scan.' }
        }
    } else { $info['Microsoft Defender'] = 'Not available (usually means another antivirus has replaced it)' }
    $info['Threats found in last 30 days'] = $(if ($null -ne $threats) { $threats } else { 'needs administrator to check' })
    if ($threats -gt 0) { Add-Rec 1 'Defender found threats recently' "Microsoft Defender detected $threats threat(s) in the last 30 days. Open Windows Security, Protection history, and check each one has been removed." }
    [pscustomobject]$info
}

# ---------------------------------------------------------------- 5 Windows updates

Invoke-Section 'Updates' 'Checking for pending Windows updates (offline, using Windows'' last check)' {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $searcher.Online = $false   # uses what Windows already downloaded; nothing is fetched or sent
    $res = $searcher.Search('IsInstalled=0 and IsHidden=0')
    $au = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results
    $reboot = $false; try { $reboot = (New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired } catch {}
    if (-not $reboot) { $reboot = [bool]($Hklm.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) }
    $list = @(foreach ($u in $res.Updates) {
        [pscustomobject]@{ 'Update' = $u.Title; 'Type' = (@($u.Categories | ForEach-Object Name) -join ', '); 'Severity' = $(if ($u.MsrcSeverity) { $u.MsrcSeverity } else { '' }); 'Downloaded' = $(if ($u.IsDownloaded) { 'Yes' } else { 'No' }) }
    })
    $lastCheck = $au.LastSearchSuccessDate
    $daysSince = if ($lastCheck) { ((Get-Date) - [datetime]$lastCheck).TotalDays } else { 999 }
    $security = @($list | Where-Object { $_.Severity -or $_.Type -match 'Security|Critical' })
    if ($reboot) { Add-Rec 2 'Restart to finish installing updates' 'Windows has installed updates that only take effect after a restart.' }
    if ($security.Count) { Add-Rec 2 'Install pending security updates' "$($security.Count) security or critical update(s) are waiting. Open Settings, Windows Update, and click Install." }
    elseif ($list.Count) { Add-Rec 4 'Install pending updates' "$($list.Count) update(s) are waiting, mostly optional or driver updates. Open Settings, Windows Update to review them." }
    if ($daysSince -gt 7) { Add-Rec 2 'Windows Update has not checked recently' ("Windows last checked for updates on {0}. Open Settings, Windows Update and click Check for updates. If it fails, note the error code for your technician." -f (Format-Date $lastCheck)) }
    [pscustomobject]@{
        Summary = [pscustomobject]@{
            'Last successful check'   = $(if ($lastCheck) { Format-Date $lastCheck } else { 'unknown' })
            'Last successful install' = $(if ($au.LastInstallationSuccessDate) { Format-Date $au.LastInstallationSuccessDate } else { 'unknown' })
            'Updates waiting'         = $list.Count
            'Restart needed'          = $(if ($reboot) { 'Yes' } else { 'No' })
        }
        List = $list
    }
}

# ---------------------------------------------------------------- 6 SMART / drive health

Invoke-Section 'Disks' 'Checking drive health (SMART)' {
    $predict = @{}
    try { Get-CimInstance -Namespace root/wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop | ForEach-Object { $predict[$_.InstanceName] = $_.PredictFailure } } catch {}
    if (@($predict.Values | Where-Object { $_ }).Count) { Add-Rec 1 'A drive is predicting its own failure' 'The SMART self check on at least one drive says it expects to fail soon. Back up anything important today and replace the drive.' }
    @(Get-PhysicalDisk | Sort-Object DeviceId | ForEach-Object {
        $d = $_
        $rc = $null; try { $rc = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch {}
        if ($d.HealthStatus -ne 'Healthy') { Add-Rec 1 "Drive $($d.FriendlyName) is reporting a problem" "Its health status is $($d.HealthStatus). Back up anything important on this PC today, then have the drive checked or replaced." }
        if ($rc -and $rc.Wear -ge 80) { Add-Rec 2 "Drive $($d.FriendlyName) is worn" "This SSD reports $($rc.Wear)% of its rated life used. Plan to replace it and keep backups current." }
        if ($rc -and $rc.Temperature -ge 65) { Add-Rec 3 "Drive $($d.FriendlyName) is running hot" "It reported $($rc.Temperature) C. Check the PC's fans and airflow." }
        [pscustomobject]@{
            'Drive' = $d.FriendlyName; 'Type' = "$($d.MediaType) ($($d.BusType))"; 'Size' = Format-Size $d.Size
            'Health' = $d.HealthStatus; 'Status' = ($d.OperationalStatus -join ', ')
            'Temperature' = $(if ($rc -and $rc.Temperature) { "$($rc.Temperature) C" } elseif ($IsAdmin) { 'not reported' } else { 'needs administrator' })
            'Life used' = $(if ($rc -and $null -ne $rc.Wear) { "$($rc.Wear)%" } elseif ($IsAdmin) { 'not reported' } else { 'needs administrator' })
            'Hours powered on' = $(if ($rc -and $rc.PowerOnHours) { '{0:N0}' -f $rc.PowerOnHours } elseif ($IsAdmin) { 'not reported' } else { 'needs administrator' })
            'Read errors' = $(if ($rc -and $null -ne $rc.ReadErrorsUncorrected) { $rc.ReadErrorsUncorrected } elseif ($IsAdmin) { 'not reported' } else { 'needs administrator' })
        }
    })
}

# ---------------------------------------------------------------- 7 disk usage

Invoke-Section 'Usage' 'Measuring disk usage by folder (this can take a few minutes)' {
    $vols = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Sort-Object DeviceID)
    $volRows = foreach ($v in $vols) {
        $pct = if ($v.Size) { [math]::Round(100 * $v.FreeSpace / $v.Size) } else { 0 }
        if ($v.Size -and ($pct -lt 10 -or $v.FreeSpace -lt 15GB)) { Add-Rec $(if ($pct -lt 5) { 1 } else { 2 }) "Drive $($v.DeviceID) is nearly full" ("Only {0} ({1}%) is free. Windows needs free space for updates and runs slowly when the drive is full. Clear temporary files and remove large programs or files you no longer need." -f (Format-Size $v.FreeSpace), $pct) }
        [pscustomobject]@{ 'Drive' = $v.DeviceID; 'Name' = $v.VolumeName; 'Size' = Format-Size $v.Size; 'Used' = Format-Size ($v.Size - $v.FreeSpace); 'Free' = "$(Format-Size $v.FreeSpace) ($pct%)" }
    }
    $folders = New-Object System.Collections.Generic.List[object]
    $measure = {
        param($dir, $label)
        $r = [AuditFs]::Measure($dir.FullName)
        $folders.Add([pscustomobject]@{ Folder = $label; Bytes = $r[0]; Files = $r[1]; Unreadable = $r[2] })
    }
    foreach ($v in $vols) {
        $root = "$($v.DeviceID)\"
        foreach ($d in Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue) {
            if ($d.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            & $measure $d $d.FullName
        }
        $rootFiles = @(Get-ChildItem -LiteralPath $root -File -Force -ErrorAction SilentlyContinue)
        if ($rootFiles) { $folders.Add([pscustomobject]@{ Folder = "$root (files in the top of the drive, such as the page file and hibernation file)"; Bytes = ($rootFiles | Measure-Object Length -Sum).Sum; Files = $rootFiles.Count; Unreadable = 0 }) }
    }
    $profileRows = New-Object System.Collections.Generic.List[object]
    foreach ($d in Get-ChildItem -LiteralPath $env:USERPROFILE -Directory -Force -ErrorAction SilentlyContinue) {
        if ($d.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
        $r = [AuditFs]::Measure($d.FullName)
        if ($r[0] -gt 0) { $profileRows.Add([pscustomobject]@{ Folder = $d.FullName; Bytes = $r[0]; Files = $r[1]; Unreadable = $r[2] }) }
    }
    $dl = $profileRows | Where-Object { $_.Folder -like '*\Downloads' }
    if ($dl -and $dl.Bytes -ge 10GB) { Add-Rec 4 'Large Downloads folder' ("Your Downloads folder holds {0}. Old installers and files you have already used can usually be deleted by you; this script never deletes personal files." -f (Format-Size $dl.Bytes)) }
    if (Test-Path -LiteralPath "$env:SystemDrive\Windows.old") { Add-Rec 3 'Old copy of Windows is taking up space' 'A Windows.old folder from a previous upgrade is still on the drive. If everything works, remove it with Settings, System, Storage, Temporary files, Previous Windows installation(s).' }
    $fmt = { param($f) [pscustomobject]@{ 'Folder' = $f.Folder; 'Size' = Format-Size $f.Bytes; 'Files' = '{0:N0}' -f $f.Files; 'Notes' = $(if ($f.Unreadable) { "$($f.Unreadable) subfolder(s) could not be read$(if (-not $IsAdmin) { ' without administrator rights' })" } else { '' }) } }
    [pscustomobject]@{
        Volumes = $volRows
        Top     = @($folders | Sort-Object Bytes -Descending | ForEach-Object { & $fmt $_ })
        Profile = @($profileRows | Sort-Object Bytes -Descending | Select-Object -First 15 | ForEach-Object { & $fmt $_ })
    }
}

# ---------------------------------------------------------------- 8 installed programs

$KnownUnwanted = 'McAfee LiveSafe|McAfee WebAdvisor|OneLaunch|Wave Browser|WebDiscover|Shift Browser|Segurazo|SAntivirus|ByteFence|Restoro|Reimage|Advanced SystemCare|Driver Booster|Driver Easy|DriverPack|PC Accelerate|MyPC Utilities|Slimware|Total AV|PC HelpSoft|Web Companion|Yontoo|Conduit|Ask Toolbar|WildTangent'

Invoke-Section 'Programs' 'Listing installed programs' {
    $paths = @(
        @{ Root = $Hklm; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' }
        @{ Root = $Hklm; Key = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' }
        @{ Root = $Hkcu; Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall' }
    )
    $seen = @{}
    $rows = foreach ($p in $paths) {
        $k = $p.Root.OpenSubKey($p.Key); if (-not $k) { continue }
        foreach ($sub in $k.GetSubKeyNames()) {
            $e = $k.OpenSubKey($sub); if (-not $e) { continue }
            $name = [string]$e.GetValue('DisplayName')
            if (-not $name -or $e.GetValue('SystemComponent') -eq 1 -or $e.GetValue('ParentKeyName') -or $e.GetValue('ReleaseType') -match 'Update|Hotfix') { $e.Close(); continue }
            $ver = [string]$e.GetValue('DisplayVersion')
            if ($seen.ContainsKey("$name|$ver")) { $e.Close(); continue }; $seen["$name|$ver"] = 1
            $size = $null; $sizeNote = ''
            $est = $e.GetValue('EstimatedSize'); if ($est) { $size = [double]$est * 1KB }
            $loc = [string]$e.GetValue('InstallLocation')
            if (-not $size -and $loc) {
                $loc = $loc.Trim('"', ' ')
                if (($loc -split '\\' | Where-Object { $_ }).Count -ge 3 -and (Test-Path -LiteralPath $loc -PathType Container)) { $size = [double]([AuditFs]::Measure($loc)[0]); $sizeNote = ' (measured)' }
            }
            $date = $null; $raw = [string]$e.GetValue('InstallDate')
            if ($raw -match '^\d{8}$') { try { $date = [datetime]::ParseExact($raw, 'yyyyMMdd', $null) } catch {} }
            $pub = [string]$e.GetValue('Publisher')
            $e.Close()
            [pscustomobject]@{ Name = $name; Version = $ver; Publisher = $pub; Bytes = $size; SizeNote = $sizeNote; Date = $date }
        }
        $k.Close()
    }
    $rows = @($rows)
    $bad = @($rows | Where-Object { $_.Name -match $KnownUnwanted })
    if ($bad) { Add-Rec 2 'Programs that are often unwanted' ("These are commonly bundled with other downloads or are not needed on Windows 11: {0}. Uninstall them in Settings, Apps, Installed apps unless you chose them on purpose." -f (($bad | ForEach-Object Name) -join ', ')) }
    $rows | Sort-Object @{ e = { if ($_.Bytes) { $_.Bytes } else { -1 } } } -Descending | ForEach-Object {
        [pscustomobject]@{ 'Program' = $_.Name; 'Version' = $_.Version; 'Publisher' = $_.Publisher; 'Size' = $(if ($_.Bytes) { (Format-Size $_.Bytes) + $_.SizeNote } else { 'not reported' }); 'Installed' = Format-Date $_.Date }
    }
}

# ---------------------------------------------------------------- 9 temp and cache sizes

Invoke-Section 'Temp' 'Measuring temporary files and caches' {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $la = $env:LOCALAPPDATA
    $targets = @(
        @{ Name = 'Your temporary files';                 Paths = @([IO.Path]::GetTempPath());                                 Fix = 'Yes, with -Fix' }
        @{ Name = 'Windows temporary files';              Paths = @("$env:SystemRoot\Temp");                                  Fix = 'Yes, with -Fix' }
        @{ Name = 'Recycle bin';                          Paths = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { "$($_.DeviceID)\`$Recycle.Bin\$sid" }); Fix = 'Yes, with -Fix' }
        @{ Name = 'Google Chrome cache';                  Paths = @(Get-ChildItem "$la\Google\Chrome\User Data\*\Cache", "$la\Google\Chrome\User Data\*\Code Cache" -Directory -ErrorAction SilentlyContinue | ForEach-Object FullName); Fix = 'No: clear it in Chrome settings' }
        @{ Name = 'Microsoft Edge cache';                 Paths = @(Get-ChildItem "$la\Microsoft\Edge\User Data\*\Cache", "$la\Microsoft\Edge\User Data\*\Code Cache" -Directory -ErrorAction SilentlyContinue | ForEach-Object FullName); Fix = 'No: clear it in Edge settings' }
        @{ Name = 'Firefox cache';                        Paths = @(Get-ChildItem "$la\Mozilla\Firefox\Profiles\*\cache2" -Directory -ErrorAction SilentlyContinue | ForEach-Object FullName); Fix = 'No: clear it in Firefox settings' }
        @{ Name = 'Windows Update downloads';             Paths = @("$env:SystemRoot\SoftwareDistribution\Download");         Fix = 'No: use Disk Cleanup' }
        @{ Name = 'Delivery Optimisation cache';          Paths = @("$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"); Fix = 'No: use Disk Cleanup' }
        @{ Name = 'Thumbnail cache';                      Paths = @("$la\Microsoft\Windows\Explorer");                        Fix = 'No: use Disk Cleanup' }
        @{ Name = 'Crash dumps and error reports';        Paths = @("$la\CrashDumps", "$env:ProgramData\Microsoft\Windows\WER"); Fix = 'No: use Disk Cleanup' }
    )
    $total = 0
    $rows = foreach ($t in $targets) {
        $b = 0; $f = 0; $u = 0; $exists = $false
        foreach ($p in $t.Paths) {
            if (-not $p) { continue }
            $denied = $null
            if (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue -ErrorVariable denied) { $exists = $true; $r = [AuditFs]::Measure($p); $b += $r[0]; $f += $r[1]; $u += $r[2] }
            elseif ($denied) { $exists = $true; $u++ }
        }
        $total += $b
        [pscustomobject]@{ 'What' = $t.Name; 'Size' = $(if ($u -and $f -eq 0 -and -not $IsAdmin) { 'needs administrator' } elseif ($exists) { Format-Size $b } else { 'none found' }); 'Files' = '{0:N0}' -f $f; 'Cleared by this script' = $t.Fix; 'Notes' = $(if ($u) { "some parts could not be read$(if (-not $IsAdmin) { ' without administrator rights' })" } else { '' }); Bytes = $b; Key = $t.Name }
    }
    $rows = @($rows)
    $tmp = ($rows | Where-Object { $_.Key -like '*temporary files' } | Measure-Object Bytes -Sum).Sum
    $bin = ($rows | Where-Object { $_.Key -eq 'Recycle bin' }).Bytes
    if ($tmp -ge 1GB) { Add-Rec 3 'Clear temporary files' ("Temporary files take up {0}. They are safe to remove; this script can do it when run with -Fix, or use Settings, System, Storage, Temporary files." -f (Format-Size $tmp)) }
    if ($bin -ge 1GB) { Add-Rec 4 'Empty the recycle bin' ("The recycle bin holds {0}. Check nothing in it is needed, then empty it." -f (Format-Size $bin)) }
    if ($total -ge 10GB) { Add-Rec 3 'Caches are using a lot of space' ("Temporary files and caches add up to {0}. Run Disk Cleanup (search the Start menu) and tick Windows Update Cleanup and Delivery Optimisation Files." -f (Format-Size $total)) }
    $rows
}

# ---------------------------------------------------------------- 10 browser extensions

function Get-ExtName($Dir, $Manifest) {
    $n = [string]$Manifest.name
    if ($n -match '^__MSG_(.+)__$') {
        $key = $Matches[1]
        foreach ($loc in @($Manifest.default_locale, 'en_GB', 'en', 'en_US') | Where-Object { $_ }) {
            $mf = Join-Path $Dir "_locales\$loc\messages.json"
            if (Test-Path -LiteralPath $mf) {
                try { $m = Get-Content -LiteralPath $mf -Raw -Encoding UTF8 | ConvertFrom-Json; $hit = $m.PSObject.Properties | Where-Object { $_.Name -eq $key } | Select-Object -First 1; if ($hit) { return [string]$hit.Value.message } } catch {}
            }
        }
    }
    return $n
}

Invoke-Section 'Extensions' 'Listing Chrome, Edge and Brave extensions' {
    $browsers = @(
        @{ Name = 'Google Chrome';  Root = "$env:LOCALAPPDATA\Google\Chrome\User Data" }
        @{ Name = 'Microsoft Edge'; Root = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" }
        @{ Name = 'Brave';          Root = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" }
    )
    $broad = '^(<all_urls>|\*://\*/\*|https?://\*/\*|\*://\*/|https?://\*/)$'
    $rows = foreach ($b in $browsers) {
        if (-not (Test-Path -LiteralPath $b.Root)) { continue }
        $names = @{}
        try { $ls = Get-Content -LiteralPath (Join-Path $b.Root 'Local State') -Raw -Encoding UTF8 | ConvertFrom-Json; foreach ($p in $ls.profile.info_cache.PSObject.Properties) { $names[$p.Name] = $p.Value.name } } catch {}
        foreach ($prof in Get-ChildItem -LiteralPath $b.Root -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'Extensions') }) {
            foreach ($ext in Get-ChildItem -LiteralPath (Join-Path $prof.FullName 'Extensions') -Directory -ErrorAction SilentlyContinue) {
                $verDir = Get-ChildItem -LiteralPath $ext.FullName -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'manifest.json') } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if (-not $verDir) { continue }
                $man = $null; try { $man = Get-Content -LiteralPath (Join-Path $verDir.FullName 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
                if (-not $man) { [pscustomobject]@{ Browser = $b.Name; Profile = $prof.Name; Extension = $ext.Name; Version = ''; AllSites = $false; Id = $ext.Name }; continue }
                $hosts = @($man.permissions) + @($man.host_permissions) + @($man.content_scripts | ForEach-Object { $_.matches })
                $all = [bool](@($hosts | Where-Object { $_ -is [string] -and $_ -match $broad }).Count)
                $pn = if ($names[$prof.Name]) { "$($names[$prof.Name]) ($($prof.Name))" } else { $prof.Name }
                [pscustomobject]@{ Browser = $b.Name; Profile = $pn; Extension = (Get-ExtName $verDir.FullName $man); Version = [string]$man.version; AllSites = $all; Id = $ext.Name }
            }
        }
    }
    $rows = @($rows | Sort-Object Browser, Profile, Extension)
    $wide = @($rows | Where-Object AllSites)
    if ($wide.Count) { Add-Rec 3 'Review browser extensions that can read every website' ("{0} extension(s) can read and change data on every site you visit: {1}. Remove any you do not recognise or no longer use (browser menu, Extensions)." -f $wide.Count, (($wide | ForEach-Object Extension | Select-Object -Unique) -join ', ')) }
    $rows | ForEach-Object { [pscustomobject]@{ 'Browser' = $_.Browser; 'Profile' = $_.Profile; 'Extension' = $_.Extension; 'Version' = $_.Version; 'Can read every website' = $(if ($_.AllSites) { 'Yes' } else { 'No' }); 'ID' = $_.Id } }
}

# ---------------------------------------------------------------- 11 old drivers

Invoke-Section 'Drivers' 'Looking for drivers older than 2 years' {
    $cut = (Get-Date).AddYears(-2)
    $all = @(Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName -and $_.DriverDate })
    $old = @($all | Where-Object { $_.DriverDate -lt $cut })
    $third = @($old | Where-Object { $_.DriverProviderName -notmatch '^Microsoft' } | Sort-Object DeviceName, DriverVersion -Unique | Sort-Object DriverDate)
    $important = @($third | Where-Object { $_.DeviceClass -in 'DISPLAY', 'NET', 'SYSTEM', 'HDC', 'SCSIADAPTER', 'MEDIA', 'BLUETOOTH' })
    if ($important.Count) { Add-Rec 4 'Some important drivers are old' ("{0} graphics, network, chipset, storage, sound or Bluetooth driver(s) are over 2 years old. Old does not always mean broken, but if you have problems with these devices, get the latest driver from the PC or part maker's website, or check Settings, Windows Update, Advanced options, Optional updates." -f $important.Count) }
    [pscustomobject]@{
        MicrosoftOld = @($old | Where-Object { $_.DriverProviderName -match '^Microsoft' }).Count
        Total = $all.Count
        List = @($third | ForEach-Object { [pscustomobject]@{ 'Device' = $_.DeviceName; 'Kind' = $_.DeviceClass; 'Maker' = $_.DriverProviderName; 'Version' = $_.DriverVersion; 'Driver date' = Format-Date $_.DriverDate } })
    }
}

# ---------------------------------------------------------------- 12 HTML report

Write-Host ("[{0}/{0}] Writing report..." -f $Total)

function ConvertTo-HtmlTable($Rows, [string[]]$Columns) {
    $Rows = @($Rows | Where-Object { $_ })
    if (-not $Rows.Count) { return '<p class="muted">Nothing found.</p>' }
    if (-not $Columns) { $Columns = @($Rows[0].PSObject.Properties | ForEach-Object Name) }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table><thead><tr>')
    foreach ($c in $Columns) { [void]$sb.Append("<th>$(Enc $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) { $v = $r.$c; $cls = if ("$v" -match '^(High|Unhealthy|Warning|Yes|Off|Unknown)$' -and $c -in 'Impact', 'Health', 'Can read every website', 'Real time protection') { ' class="warn"' } else { '' }; [void]$sb.Append("<td$cls>$(Enc $v)</td>") }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    $sb.ToString()
}

function ConvertTo-HtmlList($Obj) {
    if (-not $Obj) { return '<p class="muted">Not available.</p>' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table class="kv"><tbody>')
    foreach ($p in $Obj.PSObject.Properties) { [void]$sb.Append("<tr><th>$(Enc $p.Name)</th><td>$(Enc $p.Value)</td></tr>") }
    [void]$sb.Append('</tbody></table>')
    $sb.ToString()
}

# Builds the report from $S, $Recs, $Errors and $Fix. Also used by make_example.ps1 with sample data.
function New-ReportHtml([datetime]$Created, [int]$Duration, [string]$Banner = '') {
$pname = @{ 1 = 'Urgent'; 2 = 'High'; 3 = 'Medium'; 4 = 'Low' }
$recHtml = if ($Recs.Count) {
    $n = 0
    '<ol class="recs">' + (($Recs | Sort-Object Priority | ForEach-Object { $n++; "<li class=""p$($_.Priority)""><span class=""tag"">$($pname[$_.Priority])</span> <strong>$(Enc $_.Title)</strong><br>$(Enc $_.Detail)</li>" }) -join '') + '</ol>'
} else { '<p>No problems found. This PC looks in good shape.</p>' }

$errHtml = if ($Errors.Count) { '<div class="box warnbox"><strong>Some checks could not finish:</strong><ul>' + (($Errors | ForEach-Object { "<li>$(Enc $_)</li>" }) -join '') + '</ul></div>' } else { '' }

$st = $S['Startup']; $pf = $S['Perf']; $up = $S['Updates']; $us = $S['Usage']; $dr = $S['Drivers']
$sections = @(
    ,@('summary',    'This PC',                        (ConvertTo-HtmlList $S['System']))
    ,@('perf',       'Memory and processor right now', $(if ($pf) { (ConvertTo-HtmlList $pf.Summary) + '<h3>Using the most memory</h3>' + (ConvertTo-HtmlTable $pf.TopMem) + '<h3>Using the most processor (over 3 seconds)</h3>' + (ConvertTo-HtmlTable $pf.TopCpu) + '<p class="muted">Programs that run several copies, such as web browsers, are added together.</p>' }))
    ,@('startup',    'Programs that start with Windows', $(if ($null -ne $st) { '<p>Impact is estimated from how much memory each program is using right now. Disabling a program here only stops it starting automatically; it still works when you open it.</p>' + (ConvertTo-HtmlTable $st @('Name', 'Publisher', 'Status', 'Impact', 'Memory now', 'For', 'Where', 'Command')) }))
    ,@('defender',   'Antivirus and Windows Security', (ConvertTo-HtmlList $S['Defender']))
    ,@('updates',    'Windows updates',                $(if ($up) { (ConvertTo-HtmlList $up.Summary) + '<p class="muted">Based on Windows'' own most recent check. The audit does not contact Microsoft itself.</p>' + (ConvertTo-HtmlTable $up.List) }))
    ,@('disks',      'Drive health (SMART)',           (ConvertTo-HtmlTable $S['Disks']))
    ,@('usage',      'Disk space',                     $(if ($us) { (ConvertTo-HtmlTable $us.Volumes) + '<h3>Biggest folders at the top of each drive</h3>' + (ConvertTo-HtmlTable $us.Top) + '<h3>Biggest folders in your user folder</h3><p class="muted">Sizes only. No file names or contents are read or listed.</p>' + (ConvertTo-HtmlTable $us.Profile) + '<p class="muted">The Windows folder looks bigger than it really is, because Windows stores some files once but lists them in several places.</p>' }))
    ,@('programs',   'Installed programs',             $(if ($null -ne $S['Programs']) { "<p>$(@($S['Programs']).Count) programs, biggest first. Store apps are not included.</p>" + (ConvertTo-HtmlTable $S['Programs']) }))
    ,@('temp',       'Temporary files and caches',     (ConvertTo-HtmlTable $S['Temp'] @('What', 'Size', 'Files', 'Cleared by this script', 'Notes')))
    ,@('extensions', 'Browser extensions (Chrome, Edge and Brave)', $(if ($null -ne $S['Extensions']) { '<p>Includes extensions that are installed but switched off.</p>' + (ConvertTo-HtmlTable $S['Extensions']) }))
    ,@('drivers',    'Drivers older than 2 years',     $(if ($dr) { "<p>$($dr.List.Count) drivers from hardware makers are over 2 years old. A further $($dr.MicrosoftOld) old drivers are built into Windows by Microsoft and are not listed, as their dates are normal. Old drivers are only worth updating if a device is causing problems or the maker has a security fix.</p>" + (ConvertTo-HtmlTable $dr.List) }))
)
$nav = ($sections | ForEach-Object { "<a href=""#$($_[0])"">$(Enc $_[1])</a>" }) -join ' '
$body = ($sections | ForEach-Object { "<section id=""$($_[0])""><h2>$(Enc $_[1])</h2>$(if ($_[2]) { $_[2] } else { '<p class="muted">This check could not run. See the note at the top.</p>' })</section>" }) -join "`n"
$bannerHtml = if ($Banner) { "<div class=""banner"">$(Enc $Banner)</div>" } else { '' }

@"
<!DOCTYPE html>
<html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PC audit report $($Created.ToString('d MMM yyyy'))</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:0;color:#1d1d1f;background:#f5f6f8;line-height:1.45}
header{background:#1f3a5f;color:#fff;padding:24px 32px}header h1{margin:0 0 4px;font-size:26px}header p{margin:2px 0;opacity:.9}
nav{background:#fff;padding:10px 32px;border-bottom:1px solid #ddd;position:sticky;top:0}nav a{margin-right:14px;color:#1f3a5f;font-size:14px;text-decoration:none;white-space:nowrap}
main{max-width:1200px;margin:0 auto;padding:16px 32px 48px}
section{background:#fff;border:1px solid #e1e4e8;border-radius:8px;padding:16px 20px;margin:16px 0;overflow-x:auto;scroll-margin-top:96px}
h2{margin:0 0 12px;font-size:20px;color:#1f3a5f}h3{font-size:16px;margin:18px 0 8px}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eee;vertical-align:top}thead th{background:#f0f3f7}
table.kv th{width:280px;font-weight:600;background:none}td.warn{color:#b3261e;font-weight:600}
.muted{color:#666;font-size:13px}.box{padding:12px 16px;border-radius:6px;margin:12px 0}.warnbox{background:#fff4e5;border:1px solid #f0c36d}
ol.recs{padding-left:22px}ol.recs li{margin:0 0 12px}.tag{display:inline-block;font-size:12px;font-weight:700;padding:1px 8px;border-radius:10px;color:#fff}
.p1 .tag{background:#b3261e}.p2 .tag{background:#e8710a}.p3 .tag{background:#c99a00}.p4 .tag{background:#5f6368}
.banner{background:#fff4c2;color:#1d1d1f;border-bottom:2px solid #c99a00;padding:12px 32px;font-size:18px;font-weight:700;text-align:center}
@media print{nav{display:none}section{break-inside:avoid}}
</style></head><body>
$bannerHtml
<header><h1>PC audit report</h1>
<p>Created $($Created.ToString('dddd d MMMM yyyy, HH:mm')) in $Duration seconds. Mode: $(if ($Fix) { 'fix (changes were offered one at a time; see audit.log)' } else { 'read only (nothing was changed)' }).</p>
<p>This report was made on this PC and has not been sent anywhere. It lists program names, folder sizes and settings, never the contents of your files.</p></header>
<nav><a href="#recs">Recommended actions</a> $nav</nav>
<main>
$errHtml
<section id="recs"><h2>Recommended actions, most important first</h2>$recHtml</section>
$body
</main></body></html>
"@
}

$html = New-ReportHtml -Created $Started -Duration ([int]((Get-Date) - $Started).TotalSeconds)
[IO.File]::WriteAllText($ReportPath, $html, (New-Object System.Text.UTF8Encoding($true)))
Write-Log "Report written: $ReportPath ($($Recs.Count) recommendations, $($Errors.Count) errors)"
Write-Host ''
Write-Host "Report saved: $ReportPath" -ForegroundColor Green

# Started by right click, Run with PowerShell: open the report, and offer fix mode only if asked for.
$Interactive = -not [Console]::IsInputRedirected
if ($Interactive) {
    Start-Process $ReportPath
    if (-not $Fix) {
        Write-Host ''
        Write-Host 'Your report is open in your web browser. Send report.html back to your technician.' -ForegroundColor Cyan
        try { $a = Read-Host 'Press Enter to close. (Only if your technician asked you to: type FIX and press Enter for the cleanup steps.)' } catch { $a = '' }
        if ($a -match '^\s*fix\s*$') { $Fix = $true; Write-Log 'Fix mode chosen at the end of the audit' }
    }
}

# ---------------------------------------------------------------- -Fix

function Confirm-Step([string]$Question) {
    $a = Read-Host "$Question  Type Y and press Enter for yes, or just press Enter to skip"
    $ok = $a -match '^\s*(y|yes)\s*$'
    Write-Log ("Asked: {0} Answer: {1}" -f $Question, $(if ($ok) { 'YES' } else { 'no' }))
    $ok
}

function Test-SafeTempRoot([string]$Path) {
    if (-not $Path) { return $false }
    try { $full = [IO.Path]::GetFullPath($Path).TrimEnd('\') } catch { return $false }
    $leaf = Split-Path $full -Leaf
    return ($leaf -in 'Temp', 'Tmp') -and ($full.Split('\').Count -ge 3) -and (Test-Path -LiteralPath $full -PathType Container) -and -not ((Get-Item -LiteralPath $full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)
}

if ($Fix) {
    Write-Host ''
    Write-Host 'Fix mode. You will be asked about each change. Pressing Enter on its own always means no.' -ForegroundColor Cyan
    Write-Log 'Fix mode started'

    # Startup items: marks them disabled exactly as Task Manager does (reversible there). Does not delete the entry.
    foreach ($i in @($S['Startup'] | Where-Object Enabled)) {
        if ($i.ApprovedRoot -eq $Hklm -and -not $IsAdmin) { Write-Host "Skipping $($i.Name): it applies to all users and needs administrator rights."; Write-Log "Skipped startup item (needs admin): $($i.Name)"; continue }
        if (-not (Confirm-Step "Stop '$($i.Name)' starting automatically with Windows? (impact: $($i.Impact))")) { continue }
        try {
            $bytes = [byte[]](@(3, 0, 0, 0) + [BitConverter]::GetBytes((Get-Date).ToFileTime()))   # 03 = disabled, then a timestamp, as Task Manager writes it
            $k = $i.ApprovedRoot.CreateSubKey($i.ApprovedKey)
            $old = $k.GetValue($i.Name)
            $k.SetValue($i.Name, $bytes, [Microsoft.Win32.RegistryValueKind]::Binary); $k.Close()
            Write-Log ("Disabled startup item '{0}' via {1}\{2} (previous value: {3}). Re-enable in Task Manager, Startup apps." -f $i.Name, $(if ($i.ApprovedRoot -eq $Hklm) { 'HKLM' } else { 'HKCU' }), $i.ApprovedKey, $(if ($old) { ($old | ForEach-Object { '{0:X2}' -f $_ }) -join ' ' } else { 'none' }))
            Write-Host "  Done. You can turn it back on in Task Manager, Startup apps." -ForegroundColor Green
        } catch { Write-Log "Failed to disable startup item '$($i.Name)': $($_.Exception.Message)" 'ERROR'; Write-Host "  Could not change it: $($_.Exception.Message)" -ForegroundColor Yellow }
    }

    # Temp folders: only files older than a day, never following links, never this script's own folder.
    $cutoff = (Get-Date).AddDays(-1)
    foreach ($t in @(@{ Name = 'your temporary files'; Path = [IO.Path]::GetTempPath() }, @{ Name = 'Windows temporary files'; Path = "$env:SystemRoot\Temp" })) {
        if (-not (Test-SafeTempRoot $t.Path)) { Write-Host "Skipping $($t.Name): the folder $($t.Path) does not look like a normal temp folder."; Write-Log "Skipped temp clean, failed safety check: $($t.Path)" 'WARN'; continue }
        $sz = [AuditFs]::Measure($t.Path)
        if (-not (Confirm-Step ("Delete {0} older than one day in {1}? (up to {2})" -f $t.Name, $t.Path, (Format-Size $sz[0])))) { continue }
        $r = [AuditFs]::CleanOld($t.Path, $cutoff, $Here)
        $msg = "Cleared {0}: {1} files deleted, {2} freed, {3} skipped because they were in use or protected" -f $t.Path, $r[1], (Format-Size $r[0]), $r[2]
        Write-Log $msg; Write-Host "  $msg" -ForegroundColor Green
    }

    # Recycle bin.
    $binRow = @($S['Temp'] | Where-Object { $_.Key -eq 'Recycle bin' })[0]
    if ($binRow -and $binRow.Bytes -gt 0) {
        if (Confirm-Step "Empty the recycle bin ($($binRow.Size))? Files in it will be gone for good.") {
            $hr = [AuditFs]::SHEmptyRecycleBin([IntPtr]::Zero, $null, 7)   # 7 = no Windows prompt, no progress, no sound
            if ($hr -eq 0) { Write-Log "Emptied recycle bin ($($binRow.Size))"; Write-Host '  Recycle bin emptied.' -ForegroundColor Green }
            else { Write-Log ('Failed to empty recycle bin, Windows returned 0x{0:X8}' -f $hr) 'ERROR'; Write-Host '  Windows could not empty the recycle bin.' -ForegroundColor Yellow }
        }
    } else { Write-Log 'Recycle bin already empty, nothing to do' }

    Write-Log 'Fix mode finished'
    Write-Host ''
    Write-Host 'Fixes finished. Run the audit again for an updated report.' -ForegroundColor Cyan
    if ($Interactive) { try { [void](Read-Host 'Press Enter to close') } catch { } }
}

Write-Log ('==== Audit finished in {0} seconds' -f [int]((Get-Date) - $Started).TotalSeconds)
