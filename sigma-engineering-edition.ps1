#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sigma Engineer Toolkit - engineering workstation diagnostic + software installer.
.DESCRIPTION
    Discipline-driven diagnostic that scans the apps you care about, compares the
    PC against every requirement the vendor lists (hardware + software), verifies
    against online sources (PassMark, vendor feeds, winget), and reports a verdict
    per requirement per application.
#>
[CmdletBinding()]
param(
    [string[]]$Disciplines = @(),
    [string]$Preflight,
    [string]$ProjectGuardian,
    [switch]$DeepScan,
    [switch]$WhySlow,
    [switch]$LiveGpuSample,
    [switch]$NonInteractive,
    [switch]$Offline,
    [switch]$Install,
    [string[]]$InstallList = @()
)

Write-Host "`n========== SIGMA ENGINEER TOOLKIT ==========" -ForegroundColor Green
Write-Host ""
Write-Host "[INFO] Discipline-driven requirement scanner." -ForegroundColor Cyan
Write-Host "[INFO] Picks apps in the selected disciplines, compares each requirement." -ForegroundColor Cyan
Write-Host "[INFO] Online: PassMark, vendor feeds, winget, Windows/BIOS/SMART." -ForegroundColor Cyan
Write-Host "[WARNING] A full scan can take 2-5 minutes on a loaded machine." -ForegroundColor Yellow
Write-Host "[WARNING] This scanning tool isn't 100% accurate." -ForegroundColor Yellow
if ($Offline) { Write-Host "[INFO] Offline mode: online enrichment disabled." -ForegroundColor Cyan }
if ($Disciplines.Count -gt 0) { Write-Host "[INFO] Discipline filter: $($Disciplines -join ', ')" -ForegroundColor Cyan }
Write-Host ""

if (-not $NonInteractive -and -not $Preflight -and -not $WhySlow -and -not $Install) {
    $confirm = Read-Host "Proceed with the engineering diagnostic scan? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "Exiting. No scan performed." -ForegroundColor Cyan
        exit 0
    }
}

Write-Host ""
Write-Host "[INFO] Starting Sigma Engineer Toolkit..." -ForegroundColor Cyan

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
$errorLog   = "$env:TEMP\sigma_engineer_toolkit_errors.log"
$exportPath = Join-Path $env:USERPROFILE 'Documents\SigmaEngineerToolkit'
$stamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportBase = Join-Path $exportPath "SigmaEngineer_$stamp"

if (Test-Path $errorLog) { Remove-Item $errorLog -Force }

function Write-Stage { param([string]$T) Write-Host "  > $T" -NoNewline }
function Write-Ok    { Write-Host " Done." -ForegroundColor Green }
function Write-Head  { param([string]$T)
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host "  $T" -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
}
function Add-Diagnostic {
    param([string]$Category, [string]$Message)
    "[$(Get-Date -Format 'HH:mm:ss')]  $Category  ::  $Message" | Out-File $errorLog -Append
}
function Ensure-Folder { param([string]$P)
    if (-not (Test-Path $P)) { New-Item -ItemType Directory -Path $P -Force | Out-Null }
}
function Expand-Env { param([string]$S) [Environment]::ExpandEnvironmentVariables($S) }

function Get-FolderSizeGB {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path)) { return 0 }
        $bytes = (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
                  Measure-Object -Property Length -Sum).Sum
        if (-not $bytes) { return 0 }
        [math]::Round($bytes / 1GB, 2)
    } catch {
        Add-Diagnostic 'Cache' "Failed to size $Path : $_"
        0
    }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-TcpPort {
    param([string]$ComputerName = 'localhost', [int]$Port, [int]$TimeoutMs = 1500)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($iar)
        return $true
    } catch { return $false }
    finally { try { $client.Close() } catch { } }
}

function Get-GpuKind {
    param([string]$Name)
    if (-not $Name) { return 'Unknown' }
    $n = $Name.ToLower()
    if ($n -match 'microsoft basic')                { return 'Basic' }
    if ($n -match 'intel')                          { return 'Integrated' }
    if ($n -match 'nvidia|geforce|rtx|quadro')      { return 'Discrete' }
    if ($n -match 'radeon pro|radeon rx|firepro')   { return 'Discrete' }
    if ($n -match 'radeon|amd')                     { return 'Integrated' }
    return 'Unknown'
}

function Get-GpuVramMap {
    $map = @{}
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
    try {
        Get-ChildItem -Path $base -ErrorAction Stop | ForEach-Object {
            try {
                $p = Get-ItemProperty -Path $_.PSPath -ErrorAction Stop
                $desc = $p.DriverDesc
                $sz   = $p.'HardwareInformation.qwMemorySize'
                if (-not $sz) { $sz = $p.'HardwareInformation.MemorySize' }
                if ($desc -and $sz) {
                    try { $bytes = [uint64]$sz } catch { $bytes = 0 }
                    if ($bytes -gt 0) {
                        $gb = [math]::Round($bytes / 1GB, 2)
                        if (-not $map.ContainsKey($desc) -or $map[$desc] -lt $gb) {
                            $map[$desc] = $gb
                        }
                    }
                }
            } catch { }
        }
    } catch { Add-Diagnostic 'GPU' "VRAM registry read failed: $_" }
    return $map
}

function Resolve-GpuVram {
    param([string]$GpuName, [hashtable]$Map)
    if (-not $GpuName -or -not $Map) { return $null }
    if ($Map.ContainsKey($GpuName)) { return $Map[$GpuName] }
    foreach ($k in $Map.Keys) {
        if ($k -and ($GpuName -like "*$k*" -or $k -like "*$GpuName*")) {
            return $Map[$k]
        }
    }
    return $null
}

function Get-PowerState {
    try {
        $b = Get-CimInstance Win32_Battery -ErrorAction Stop
        if (-not $b) {
            return [pscustomobject]@{
                HasBattery = $false; OnAC = $true; Percent = $null
                StatusCode = $null; StatusText = 'Desktop / no battery'
            }
        }
        $b = $b | Select-Object -First 1
        $acCodes = @(2, 3, 6, 7, 8, 9, 11)
        $onAc = $acCodes -contains [int]$b.BatteryStatus
        $text = switch ([int]$b.BatteryStatus) {
            1  { 'Discharging' }
            2  { 'On AC' }
            3  { 'Fully charged' }
            4  { 'Low' }
            5  { 'Critical' }
            6  { 'Charging' }
            7  { 'Charging (High)' }
            8  { 'Charging (Low)' }
            9  { 'Charging (Critical)' }
            11 { 'Partially charged' }
            default { "Unknown ($($b.BatteryStatus))" }
        }
        return [pscustomobject]@{
            HasBattery = $true; OnAC = $onAc; Percent = $b.EstimatedChargeRemaining
            StatusCode = $b.BatteryStatus; StatusText = $text
        }
    } catch {
        return [pscustomobject]@{
            HasBattery = $false; OnAC = $true; Percent = $null
            StatusCode = $null; StatusText = 'Unknown'
        }
    }
}

function Get-BatteryHealth {
    $r = [ordered]@{
        DesignCapacity = $null; FullCharge = $null; HealthPercent = $null
        CycleCount = $null; Manufacture = $null; Chemistry = $null
    }
    try {
        $static = Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryStaticData -ErrorAction SilentlyContinue | Select-Object -First 1
        $full   = Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryFullChargedCapacity -ErrorAction SilentlyContinue | Select-Object -First 1
        $cycle  = Get-CimInstance -Namespace 'root\wmi' -ClassName BatteryCycleCount -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($static) { $r.DesignCapacity = $static.DesignedCapacity; $r.Manufacture = $static.ManufactureName; $r.Chemistry = $static.Chemistry }
        if ($full)   { $r.FullCharge = $full.FullChargedCapacity }
        if ($cycle)  { $r.CycleCount = $cycle.CycleCount }
        if ($r.DesignCapacity -and $r.FullCharge -and $r.DesignCapacity -gt 0) {
            $r.HealthPercent = [math]::Round(($r.FullCharge / $r.DesignCapacity) * 100, 1)
        }
    } catch { }
    return [pscustomobject]$r
}

function Get-EventLogIssues {
    $since = (Get-Date).AddDays(-7)
    $r = [ordered]@{
        WheaCount = 0; DiskErrors = 0; DiskErrorDevices = @()
        ThermalEvents = 0; UnexpectedShutdown = 0; AppCrashes = 0; Samples = @()
    }
    try {
        $whea = @(Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; StartTime=$since } -ErrorAction SilentlyContinue)
        $r.WheaCount = $whea.Count
        foreach ($e in ($whea | Select-Object -First 3)) {
            $r.Samples += [pscustomobject]@{ Type='WHEA'; Id=$e.Id; Time=$e.TimeCreated.ToString('s'); Msg=$e.Message.Split("`n")[0] }
        }
    } catch { }
    try {
        $disk = @(Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName=@('disk','Ntfs','storahci','stornvme','volmgr'); StartTime=$since; Level=@(1,2,3) } -ErrorAction SilentlyContinue)
        $r.DiskErrors = $disk.Count
        $devSet = @{}
        foreach ($e in $disk) { if ($e.Message -match 'Harddisk(\d+)') { $devSet[$matches[1]] = $true } }
        $r.DiskErrorDevices = @($devSet.Keys)
        foreach ($e in ($disk | Select-Object -First 3)) {
            $r.Samples += [pscustomobject]@{ Type='Disk'; Id=$e.Id; Time=$e.TimeCreated.ToString('s'); Msg=$e.Message.Split("`n")[0] }
        }
    } catch { }
    try {
        $th = @(Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-Kernel-Processor-Power'; StartTime=$since; Id=@(86,87,88) } -ErrorAction SilentlyContinue)
        $r.ThermalEvents = $th.Count
    } catch { }
    try {
        $shut = @(Get-WinEvent -FilterHashtable @{ LogName='System'; Id=41; ProviderName='Microsoft-Windows-Kernel-Power'; StartTime=$since } -ErrorAction SilentlyContinue)
        $r.UnexpectedShutdown = $shut.Count
    } catch { }
    try {
        $app = @(Get-WinEvent -FilterHashtable @{ LogName='Application'; Id=1000; StartTime=$since } -ErrorAction SilentlyContinue)
        $r.AppCrashes = $app.Count
    } catch { }
    return [pscustomobject]$r
}

function Get-DefenderExclusions {
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        return [pscustomobject]@{
            Paths      = @($pref.ExclusionPath      | Where-Object { $_ -and $_.Trim() })
            Extensions = @($pref.ExclusionExtension | Where-Object { $_ -and $_.Trim() })
            Processes  = @($pref.ExclusionProcess   | Where-Object { $_ -and $_.Trim() })
        }
    } catch { return [pscustomobject]@{ Paths = @(); Extensions = @(); Processes = @() } }
}

function Get-WifiDetails {
    $r = [ordered]@{ Interfaces = @() }
    try {
        $svc = Get-Service wlansvc -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Running') { Start-Service wlansvc -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 500 }
    } catch { }
    try {
        $raw = netsh wlan show interfaces 2>$null | Out-String
        $block = @{}
        foreach ($line in ($raw -split "`r?`n")) {
            if ($line -match '^\s*Name\s*:\s*(.+)$') {
                if ($block.Count -gt 0) { $r.Interfaces += [pscustomobject]$block; $block = @{} }
                $block['Name'] = $matches[1].Trim()
            }
            elseif ($line -match '^\s*Description\s*:\s*(.+)$')   { $block['Description'] = $matches[1].Trim() }
            elseif ($line -match '^\s*State\s*:\s*(.+)$')         { $block['State']       = $matches[1].Trim() }
            elseif ($line -match '^\s*SSID\s*:\s*(.+)$')          { $block['SSID']        = $matches[1].Trim() }
            elseif ($line -match '^\s*BSSID\s*:\s*(.+)$')         { $block['BSSID']       = $matches[1].Trim() }
            elseif ($line -match '^\s*Radio type\s*:\s*(.+)$')    { $block['RadioType']   = $matches[1].Trim() }
            elseif ($line -match '^\s*Band\s*:\s*(.+)$')          { $block['Band']        = $matches[1].Trim() }
            elseif ($line -match '^\s*Channel\s*:\s*(.+)$')       { $block['Channel']     = $matches[1].Trim() }
            elseif ($line -match '^\s*Signal\s*:\s*(.+)$')        { $block['Signal']      = $matches[1].Trim() }
            elseif ($line -match '^\s*Receive rate.*:\s*(.+)$')   { $block['ReceiveRate'] = $matches[1].Trim() }
            elseif ($line -match '^\s*Transmit rate.*:\s*(.+)$')  { $block['TransmitRate']= $matches[1].Trim() }
        }
        if ($block.Count -gt 0) { $r.Interfaces += [pscustomobject]$block }
    } catch { }
    if ($r.Interfaces.Count -eq 0) {
        try {
            $cp = Get-NetConnectionProfile -InterfaceAlias 'Wi-Fi' -ErrorAction Stop
            $r.Interfaces += [pscustomobject]@{ Name='Wi-Fi'; SSID=$cp.Name; State='Connected'; Band=''; Channel=''; RadioType=''; Signal=''; NetworkCategory=$cp.NetworkCategory }
        } catch { }
    }
    return [pscustomobject]$r
}

function Get-DiskReliability {
    $out = @()
    $smartctl = Get-Command smartctl -ErrorAction SilentlyContinue
    foreach ($d in (Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
        $rc = $null
        try { $rc = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch { }

        $entry = [ordered]@{
            FriendlyName = $d.FriendlyName; MediaType = $d.MediaType; BusType = $d.BusType
            SizeGB = [math]::Round($d.Size / 1GB, 1); HealthStatus = $d.HealthStatus
            Wear = if ($rc) { $rc.Wear } else { $null }
            Temperature = if ($rc) { $rc.Temperature } else { $null }
            PowerOnHours = if ($rc) { $rc.PowerOnHours } else { $null }
            ReadErrors = if ($rc) { $rc.ReadErrorsTotal } else { $null }
            WriteErrors = if ($rc) { $rc.WriteErrorsTotal } else { $null }
            Firmware = $null; Serial = $null; Source = 'Win32'
        }

        if ($smartctl -and -not $entry.PowerOnHours) {
            try {
                $devPath = "\\.\PHYSICALDRIVE$($d.DeviceId)"
                $json = & smartctl -a -j $devPath 2>$null | Out-String
                if ($json) {
                    $sd = $json | ConvertFrom-Json -ErrorAction Stop
                    if ($sd.power_on_time -and $sd.power_on_time.hours) { $entry.PowerOnHours = $sd.power_on_time.hours }
                    if ($sd.temperature -and $sd.temperature.current)   { $entry.Temperature  = $sd.temperature.current }
                    if ($sd.nvme_smart_health_information_log) {
                        $log = $sd.nvme_smart_health_information_log
                        if ($log.percentage_used -ne $null)     { $entry.Wear         = $log.percentage_used }
                        if ($log.media_errors   -ne $null)      { $entry.ReadErrors   = $log.media_errors }
                        if ($log.num_err_log_entries -ne $null) { $entry.WriteErrors  = $log.num_err_log_entries }
                    }
                    if ($sd.serial_number)    { $entry.Serial   = $sd.serial_number }
                    if ($sd.firmware_version) { $entry.Firmware = $sd.firmware_version }
                    $entry.Source = 'smartctl'
                }
            } catch { }
        }
        $out += [pscustomobject]$entry
    }
    return $out
}

function Get-InstalledSoftware {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $out = foreach ($p in $paths) {
        try {
            Get-ItemProperty -Path $p -ErrorAction Stop |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
        } catch { }
    }
    $out | Sort-Object DisplayName -Unique
}

function Get-DotNetFrameworkVersion {
    try {
        $rel = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction Stop).Release
        switch ($rel) {
            {$_ -ge 533320} { return '4.8.1+' }
            {$_ -ge 528040} { return '4.8'    }
            {$_ -ge 461808} { return '4.7.2'  }
            {$_ -ge 460798} { return '4.7'    }
            {$_ -ge 394802} { return '4.6.2'  }
            {$_ -ge 393295} { return '4.6'    }
            {$_ -ge 379893} { return '4.5.2'  }
            {$_ -ge 378758} { return '4.5.1'  }
            {$_ -ge 378389} { return '4.5'    }
            default         { return "Unknown ($rel)" }
        }
    } catch { return 'Not found' }
}

function Compare-NetVersion {
    param([string]$Have, [string]$Need)
    if (-not $Need) { return $true }
    $h = $Have -replace '[^0-9\.]',''
    $n = $Need -replace '[^0-9\.]',''
    if (-not $h) { return $false }
    try { return ([version]$h -ge [version]$n) } catch { return $false }
}

function Get-VCRedist {
    Get-InstalledSoftware | Where-Object { $_.DisplayName -match 'Microsoft Visual C\+\+.*Redistributable' } |
        Select-Object DisplayName, DisplayVersion
}

function New-Finding {
    param(
        [string]$Id, [string]$Software, [string]$Problem, [string]$Detected,
        [string]$WhyItMatters, [string]$Recommendation, [string]$Optional = '',
        [string]$Severity = 'warn', [double]$RecoverableGB = 0
    )
    [pscustomobject]@{
        Id = $Id; Software = $Software; Problem = $Problem; Detected = $Detected
        WhyItMatters = $WhyItMatters; Recommendation = $Recommendation
        Optional = $Optional; Severity = $Severity; RecoverableGB = $RecoverableGB
    }
}

function Get-LiveGpuSample {
    param([int]$DurationSeconds = 2)
    try {
        $samples = Get-Counter '\GPU Engine(*)\Utilization Percentage' -SampleInterval 1 -MaxSamples $DurationSeconds -ErrorAction Stop
        $perInstance = @{}
        foreach ($s in $samples.CounterSamples) {
            $key = $s.InstanceName
            if (-not $perInstance.ContainsKey($key)) { $perInstance[$key] = @() }
            $perInstance[$key] += $s.CookedValue
        }
        $perProc = @{}
        foreach ($k in $perInstance.Keys) {
            if ($k -match 'pid_(\d+)') {
                $pid2 = [int]$Matches[1]
                $avg = ($perInstance[$k] | Measure-Object -Average).Average
                if (-not $perProc.ContainsKey($pid2)) { $perProc[$pid2] = 0 }
                if ($avg -gt $perProc[$pid2]) { $perProc[$pid2] = $avg }
            }
        }
        $top = $perProc.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
        $out = foreach ($t in $top) {
            $pname = try { (Get-Process -Id $t.Key -ErrorAction Stop).ProcessName } catch { "pid $($t.Key)" }
            [pscustomobject]@{ Pid = $t.Key; Process = $pname; GPU = [math]::Round($t.Value, 1) }
        }
        return @($out)
    } catch {
        Add-Diagnostic 'GPU' "Live GPU sample failed: $_"
        return @()
    }
}

# =============================================================================
# REQUIREMENT DETECTORS
# =============================================================================
function New-RequirementResult {
    param(
        [string]$Type, [string]$Component,
        [string]$Required, [string]$Actual,
        [string]$Status,   [string]$Note
    )
    [pscustomobject]@{
        Type = $Type; Component = $Component; Required = $Required
        Actual = $Actual; Status = $Status; Note = $Note
    }
}

function Get-CpuInstructionSets {
    $out = @{}
    try { if ([System.Runtime.Intrinsics.X86.Sse42]::IsSupported)   { $out['SSE4.2']  = $true } } catch { }
    try { if ([System.Runtime.Intrinsics.X86.Avx]::IsSupported)     { $out['AVX']     = $true } } catch { }
    try { if ([System.Runtime.Intrinsics.X86.Avx2]::IsSupported)    { $out['AVX2']    = $true } } catch { }
    try { if ([System.Runtime.Intrinsics.X86.Avx512F]::IsSupported) { $out['AVX-512'] = $true } } catch { }
    return $out
}

function Get-DirectXVersion {
    try {
        $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\DirectX' -ErrorAction Stop).Version
        if ($v -match '4\.09\.00\.09(\d\d)') { return [int]$matches[1] }
    } catch { }
    return $null
}

function Test-ReqOS {
    param([hashtable]$Spec, [pscustomobject]$System)
    $os = Get-CimInstance Win32_OperatingSystem
    $actualVersion = "$($os.Version)"
    $actualArch    = $os.OSArchitecture
    $edition       = $os.Caption
    $requiredParts = @(); $fail = $false; $warn = $false
    if ($Spec.MinVersion) {
        $requiredParts += "≥ $($Spec.MinVersion)"
        try { if ([version]$actualVersion -lt [version]$Spec.MinVersion) { $fail = $true } } catch { $fail = $true }
    }
    if ($Spec.Arch) {
        $requiredParts += $Spec.Arch
        $archMap = @{ 'x64'='64-bit'; 'x86'='32-bit'; 'ARM64'='ARM 64-bit' }
        $want = $archMap[$Spec.Arch]
        if ($want -and $actualArch -ne $want) { $fail = $true }
    }
    if ($Spec.Edition) {
        $requiredParts += "edition: $($Spec.Edition -join '/')"
        $hit = $false
        foreach ($e in $Spec.Edition) { if ($edition -match $e) { $hit = $true } }
        if (-not $hit) { $warn = $true }
    }
    $status = if ($fail) { 'FAIL' } elseif ($warn) { 'WARN' } else { 'PASS' }
    $note = if ($fail) { 'OS below minimum' } elseif ($warn) { 'Edition differs from vendor recommendation' } else { 'Meets OS requirement' }
    New-RequirementResult 'OS' 'Operating System' ($requiredParts -join ', ') "$edition ($actualVersion, $actualArch)" $status $note
}

function Test-ReqCPU {
    param([hashtable]$Spec, [pscustomobject]$System, [pscustomobject]$Enrichment)
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $parts = @(); $fail = $false; $warn = $false; $unknown = $false
    if ($Spec.MinCores) {
        $parts += "$($Spec.MinCores)+ cores"
        if ($cpu.NumberOfCores -lt $Spec.MinCores) { $fail = $true }
    }
    if ($Spec.MinClockMHz) {
        $parts += "$($Spec.MinClockMHz)+ MHz"
        if ($cpu.MaxClockSpeed -lt $Spec.MinClockMHz) { $warn = $true }
    }
    if ($Spec.MinPassMark) {
        $parts += "$($Spec.MinPassMark)+ PassMark"
        if ($Enrichment -and $Enrichment.CpuScore) {
            if ($Enrichment.CpuScore -lt $Spec.MinPassMark) { $fail = $true }
        } else { $unknown = $true }
    }
    if ($Spec.InstructionSets) {
        $have = Get-CpuInstructionSets
        $missing = @()
        foreach ($set in $Spec.InstructionSets) { if (-not $have.ContainsKey($set)) { $missing += $set } }
        $parts += "ISA: $($Spec.InstructionSets -join ',')"
        if ($missing.Count -gt 0) {
            if ($have.Count -eq 0) { $unknown = $true } else { $fail = $true }
        }
    }
    $actualParts = @("$($cpu.NumberOfCores)C/$($cpu.NumberOfLogicalProcessors)T")
    if ($Enrichment -and $Enrichment.CpuScore) { $actualParts += "PassMark $($Enrichment.CpuScore)" }
    $actualParts += "$($cpu.MaxClockSpeed) MHz"
    $status = if ($fail) { 'FAIL' } elseif ($unknown) { 'UNKNOWN' } elseif ($warn) { 'WARN' } else { 'PASS' }
    $note = if ($fail) { 'CPU below minimum' }
            elseif ($unknown) { 'Cannot verify (PassMark or ISA unavailable)' }
            elseif ($warn) { 'Meets minimum clock only' }
            else { 'Meets CPU requirement' }
    New-RequirementResult 'CPU' 'Processor' ($parts -join ', ') ($actualParts -join ', ') $status $note
}

function Test-ReqRAM {
    param([hashtable]$Spec, [pscustomobject]$System, [pscustomobject]$Enrichment)
    $have = $System.RAM_GB
    $min = [int]$Spec.Min
    $rec = if ($Spec.Rec) { [int]$Spec.Rec } else { $min }
    $status = if ($have -ge $rec) { 'PASS' } elseif ($have -ge $min) { 'WARN' } else { 'FAIL' }
    $note = switch ($status) { 'PASS' { 'Meets recommended' } 'WARN' { 'Meets minimum only' } 'FAIL' { 'Below minimum' } }
    $reqText = if ($rec -ne $min) { "$min GB min / $rec GB rec" } else { "$min GB" }
    New-RequirementResult 'RAM' 'Memory' $reqText "$have GB" $status $note
}

function Test-ReqDisk {
    param([hashtable]$Spec, [pscustomobject]$System, [pscustomobject]$Enrichment)
    $sysd = $System.Disks | Where-Object Drive -eq "$($env:SystemDrive)" | Select-Object -First 1
    if (-not $sysd) { return New-RequirementResult 'Disk' 'System drive' "$($Spec.Min) GB" 'unknown' 'UNKNOWN' 'Cannot read system drive' }
    $have = $sysd.FreeGB
    $min = [int]$Spec.Min
    $rec = if ($Spec.Rec) { [int]$Spec.Rec } else { $min }
    $status = if ($have -ge $rec) { 'PASS' } elseif ($have -ge $min) { 'WARN' } else { 'FAIL' }
    $note = switch ($status) { 'PASS' { 'Meets recommended' } 'WARN' { 'Meets minimum only' } 'FAIL' { 'Insufficient free space' } }
    if ($Spec.SSD -and $Enrichment -and $Enrichment.DiskMediaTypes) {
        $hasSSD = @($Enrichment.DiskMediaTypes | Where-Object { $_.MediaType -in @('SSD','NVMe') -or $_.BusType -eq 'NVMe' }).Count -gt 0
        if (-not $hasSSD) {
            if ($status -eq 'PASS') { $status = 'WARN' }
            $note += ' · SSD required but not detected'
        }
    }
    $reqText = if ($rec -ne $min) { "$min GB min / $rec GB rec" } else { "$min GB" }
    if ($Spec.SSD) { $reqText += ' (SSD)' }
    New-RequirementResult 'Disk' 'Free disk space' $reqText "$have GB" $status $note
}

function Test-ReqGPU {
    param([hashtable]$Spec, [pscustomobject]$System, [pscustomobject]$Enrichment)
    $bestVRAM = 0; $bestGPU = $null
    foreach ($g in $System.GPUs) {
        if ($g.VRAM_GB -and $g.VRAM_GB -gt $bestVRAM) { $bestVRAM = $g.VRAM_GB; $bestGPU = $g }
    }
    $parts = @(); $fail = $false; $warn = $false; $unknown = $false
    if ($Spec.MinVRAM) {
        $parts += "$($Spec.MinVRAM) GB VRAM min"
        $rec = if ($Spec.RecVRAM) { [int]$Spec.RecVRAM } else { [int]$Spec.MinVRAM }
        if ($bestVRAM -ge $rec) { }
        elseif ($bestVRAM -ge $Spec.MinVRAM) { $warn = $true }
        else { $fail = $true }
    }
    if ($Spec.Vendor) {
        $parts += "vendor: $($Spec.Vendor)"
        $hit = $false
        foreach ($g in $System.GPUs) { if ($g.Name -match $Spec.Vendor) { $hit = $true } }
        if (-not $hit) { $fail = $true }
    }
    if ($Spec.MinDirectX) {
        $parts += "DirectX $($Spec.MinDirectX)+"
        $dx = Get-DirectXVersion
        if ($dx) { if ([int]$dx -lt [int]$Spec.MinDirectX) { $fail = $true } } else { $unknown = $true }
    }
    if ($Spec.MinPassMark) {
        $parts += "G3D $($Spec.MinPassMark)+"
        if ($Enrichment -and $Enrichment.GpuScores) {
            $top = ($Enrichment.GpuScores | Where-Object Score | Sort-Object Score -Descending | Select-Object -First 1)
            if ($top) { if ($top.Score -lt $Spec.MinPassMark) { $fail = $true } } else { $unknown = $true }
        } else { $unknown = $true }
    }
    if ($Spec.RequiresCUDA) {
        $parts += 'CUDA'
        if (-not (Test-Path "$env:SystemRoot\System32\nvcuda.dll")) { $fail = $true }
    }
    if ($Spec.MinOpenGL) {
        $parts += "OpenGL $($Spec.MinOpenGL)+"
        $unknown = $true
    }
    if ($Spec.RequiresVulkan) {
        $parts += 'Vulkan'
        if (-not (Test-Path "$env:SystemRoot\System32\vulkan-1.dll")) { $fail = $true }
    }
    $status = if ($fail) { 'FAIL' } elseif ($unknown) { 'UNKNOWN' } elseif ($warn) { 'WARN' } else { 'PASS' }
    $actual = if ($bestGPU) { "$($bestGPU.Name) · $bestVRAM GB" } else { 'no GPU detected' }
    $note = switch ($status) {
        'PASS' { 'Meets GPU requirement' }
        'WARN' { 'Meets minimum VRAM only' }
        'FAIL' { 'GPU below requirement' }
        'UNKNOWN' { 'Cannot verify API version locally' }
    }
    New-RequirementResult 'GPU' 'Graphics' ($parts -join ', ') $actual $status $note
}

function Test-ReqDisplay {
    param([hashtable]$Spec, [pscustomobject]$System)
    $g = $System.GPUs | Where-Object { $_.Resolution } | Select-Object -First 1
    if (-not $g -or $g.Resolution -notmatch '(\d+)x(\d+)') {
        return New-RequirementResult 'Display' 'Display resolution' "$($Spec.MinWidth)x$($Spec.MinHeight)" 'unknown' 'UNKNOWN' 'No display detected'
    }
    $w = [int]$matches[1]; $h = [int]$matches[2]
    $ok = ($w -ge $Spec.MinWidth) -and ($h -ge $Spec.MinHeight)
    New-RequirementResult 'Display' 'Display resolution' "$($Spec.MinWidth)x$($Spec.MinHeight)" "$w x $h" $(if ($ok) { 'PASS' } else { 'FAIL' }) $(if ($ok) { 'Meets minimum' } else { 'Resolution too low' })
}

function Test-ReqNetFx {
    param([hashtable]$Spec)
    $have = Get-DotNetFrameworkVersion
    $ok = Compare-NetVersion -Have $have -Need $Spec.Min
    New-RequirementResult 'NetFx' '.NET Framework' ".NET $($Spec.Min)+" $have $(if ($ok) { 'PASS' } else { 'FAIL' }) $(if ($ok) { 'Installed' } else { 'Must be installed' })
}

function Test-ReqNetDesktop {
    param([hashtable]$Spec)
    $have = $null
    try {
        $out = & dotnet --list-runtimes 2>$null
        $desktop = $out | Where-Object { $_ -match 'Microsoft\.WindowsDesktop\.App' } |
                   ForEach-Object { if ($_ -match '(\d+\.\d+\.\d+)') { [version]$matches[1] } } |
                   Sort-Object -Descending | Select-Object -First 1
        if ($desktop) { $have = $desktop.ToString() }
    } catch { }
    if (-not $have) {
        $hit = Get-InstalledSoftware | Where-Object { $_.DisplayName -match 'Microsoft Windows Desktop Runtime' } | Select-Object -First 1
        if ($hit) { $have = $hit.DisplayVersion }
    }
    $ok = $false
    if ($have) { try { $ok = ([version]($have -replace '[^0-9\.]','') -ge [version]$Spec.Min) } catch { } }
    New-RequirementResult 'NetDesktop' '.NET Desktop Runtime' ".NET $($Spec.Min)+ Desktop" $(if ($have) { $have } else { 'not found' }) $(if ($ok) { 'PASS' } else { 'FAIL' }) $(if ($ok) { 'Installed' } else { 'Must be installed' })
}

function Test-ReqVCRedist {
    param([hashtable]$Spec)
    $vc = @(Get-VCRedist)
    if ($vc.Count -eq 0) {
        return New-RequirementResult 'VCRedist' 'VC++ Redistributable' "$($Spec.Min)+" 'not found' 'FAIL' 'Must be installed'
    }
    $best = $vc | ForEach-Object { if ($_.DisplayVersion -match '(\d+\.\d+\.\d+)') { [version]$matches[1] } } | Sort-Object -Descending | Select-Object -First 1
    $ok = if ($best) { $best -ge [version]$Spec.Min } else { $false }
    New-RequirementResult 'VCRedist' 'VC++ Redistributable' "$($Spec.Min)+" $(if ($best) { $best.ToString() } else { $vc[0].DisplayVersion }) $(if ($ok) { 'PASS' } else { 'FAIL' }) $(if ($ok) { 'Installed' } else { 'Version too old' })
}

function Test-ReqJava {
    param([hashtable]$Spec)
    $have = $null
    try {
        $out = & java -version 2>&1 | Out-String
        if ($out -match 'version "(\d+)(?:\.(\d+))?') {
            $have = if ($matches[2]) { "$($matches[1]).$($matches[2])" } else { $matches[1] }
        }
    } catch { }
    if (-not $have) {
        $pat = if ($Spec.Kind -eq 'JDK') { 'Java.*Development Kit|JDK' } else { 'Java.*Runtime|JRE|Java \d' }
        $hit = Get-InstalledSoftware | Where-Object { $_.DisplayName -match $pat } | Select-Object -First 1
        if ($hit) { $have = $hit.DisplayVersion }
    }
    $ok = $false
    if ($have) { try { $ok = [double]($have -replace '[^0-9\.]','') -ge [double]$Spec.Min } catch { } }
    $label = if ($Spec.Kind) { "Java $($Spec.Kind)" } else { 'Java' }
    New-RequirementResult 'Java' $label "$($Spec.Min)+" $(if ($have) { $have } else { 'not found' }) $(if ($ok) { 'PASS' } else { 'FAIL' }) $(if ($ok) { 'Installed' } else { 'Must be installed' })
}

function Test-ReqPython {
    param([hashtable]$Spec)
    $have = $null
    try {
        $out = & python --version 2>&1 | Out-String
        if ($out -match 'Python (\d+\.\d+\.\d+)') { $have = $matches[1] }
    } catch { }
    if (-not $have) {
        $hit = Get-InstalledSoftware | Where-Object { $_.DisplayName -match '^Python 3' } | Select-Object -First 1
        if ($hit) { $have = $hit.DisplayVersion }
    }
    $ok = $false
    if ($have) { try { $ok = [version]$have -ge [version]$Spec.Min } catch { } }
    New-RequirementResult 'Python' 'Python' "$($Spec.Min)+" $(if ($have) { $have } else { 'not found' }) $(if ($ok) { 'PASS' } else { 'FAIL' }) $(if ($ok) { 'Installed' } else { 'Must be installed' })
}

function Test-ReqDirectX {
    param([hashtable]$Spec)
    $have = Get-DirectXVersion
    if (-not $have) { return New-RequirementResult 'DirectX' 'DirectX' "$($Spec.Min)+" 'unknown' 'UNKNOWN' 'Cannot read DirectX version' }
    $ok = [int]$have -ge [int]$Spec.Min
    New-RequirementResult 'DirectX' 'DirectX' "$($Spec.Min)+" "$have" $(if ($ok) { 'PASS' } else { 'FAIL' }) $(if ($ok) { 'Installed' } else { 'Version too old' })
}

function Test-ReqWebView2 {
    $hit = Get-InstalledSoftware | Where-Object { $_.DisplayName -match 'WebView2 Runtime' } | Select-Object -First 1
    New-RequirementResult 'WebView2' 'WebView2 Runtime' 'Evergreen' $(if ($hit) { $hit.DisplayVersion } else { 'not found' }) $(if ($hit) { 'PASS' } else { 'FAIL' }) $(if ($hit) { 'Installed' } else { 'Must be installed' })
}

function Test-ReqBrowser {
    param([hashtable]$Spec)
    $name = if ($Spec.Name) { $Spec.Name } else { 'Edge' }
    $hit = Get-InstalledSoftware | Where-Object { $_.DisplayName -match 'Microsoft Edge|Google Chrome|Mozilla Firefox' } | Select-Object -First 1
    New-RequirementResult 'Browser' "$name / browser" 'Edge or Chrome' $(if ($hit) { $hit.DisplayName } else { 'not found' }) $(if ($hit) { 'PASS' } else { 'FAIL' }) $(if ($hit) { 'Installed' } else { 'Must be installed' })
}

function Test-ReqWinFeature {
    param([hashtable]$Spec)
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName $Spec.Name -ErrorAction Stop
        $ok = $f.State -eq 'Enabled'
        New-RequirementResult 'WinFeature' "Windows feature: $($Spec.Name)" 'Enabled' $f.State $(if ($ok) { 'PASS' } else { 'FAIL' }) $(if ($ok) { 'Enabled' } else { 'Feature not enabled' })
    } catch {
        New-RequirementResult 'WinFeature' "Windows feature: $($Spec.Name)" 'Enabled' 'unknown' 'UNKNOWN' 'Cannot query feature'
    }
}

function Test-ReqKB {
    param([hashtable]$Spec)
    $hit = Get-HotFix -Id $Spec.Id -ErrorAction SilentlyContinue
    New-RequirementResult 'KB' "Update $($Spec.Id)" 'Installed' $(if ($hit) { 'present' } else { 'missing' }) $(if ($hit) { 'PASS' } else { 'FAIL' }) $(if ($hit) { 'Installed' } else { 'Update missing' })
}

function Test-ReqTPM {
    param([hashtable]$Spec)
    try {
        $tpm = Get-CimInstance -Namespace 'root/cimv2/security/microsofttpm' -ClassName Win32_Tpm -ErrorAction Stop
        if (-not $tpm) { return New-RequirementResult 'TPM' 'TPM' "v$($Spec.MinVersion)+" 'not present' 'FAIL' 'TPM not present' }
        $have = "$($tpm.SpecVersion -split ',' | Select-Object -First 1)".Trim()
        $ok = $false
        try { $ok = [double]$have -ge [double]$Spec.MinVersion } catch { }
        New-RequirementResult 'TPM' 'TPM' "v$($Spec.MinVersion)+" "v$have" $(if ($ok) { 'PASS' } else { 'FAIL' }) $(if ($ok) { 'Meets TPM requirement' } else { 'TPM too old' })
    } catch {
        New-RequirementResult 'TPM' 'TPM' "v$($Spec.MinVersion)+" 'unknown' 'UNKNOWN' 'Cannot query TPM'
    }
}

function Test-ReqSecureBoot {
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        New-RequirementResult 'SecureBoot' 'Secure Boot' 'Enabled' $(if ($sb) { 'Enabled' } else { 'Disabled' }) $(if ($sb) { 'PASS' } else { 'FAIL' }) $(if ($sb) { 'Enabled' } else { 'Must be enabled in BIOS' })
    } catch {
        New-RequirementResult 'SecureBoot' 'Secure Boot' 'Enabled' 'unknown' 'UNKNOWN' 'Cannot query Secure Boot'
    }
}

function Test-ReqLicenseSvc {
    param([hashtable]$Spec)
    $svc = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { ($_.Name + ' ' + $_.DisplayName) -like $Spec.Pattern })
    $running = @($svc | Where-Object Status -eq 'Running').Count
    $portOpen = $false
    foreach ($p in @($Spec.Ports)) { if (Test-TcpPort -Port $p -TimeoutMs 800) { $portOpen = $true; break } }
    $ok = ($running -gt 0) -or $portOpen
    $actual = "$($svc.Count) service(s), $running running"
    if ($Spec.Ports -and $Spec.Ports.Count -gt 0) { $actual += " · ports $($Spec.Ports -join ',') $(if($portOpen){'open'}else{'closed'})" }
    New-RequirementResult 'LicenseSvc' "License service ($($Spec.Pattern))" 'Service running OR port reachable' $actual $(if ($ok) { 'PASS' } else { 'FAIL' }) $(if ($ok) { 'License path available' } else { 'Cannot acquire license' })
}

function Test-ReqAdmin {
    param([hashtable]$Spec)
    $isAdmin = Test-IsAdmin
    $ok = (-not $Spec.Required) -or $isAdmin
    New-RequirementResult 'Admin' 'Admin rights' $(if ($Spec.Required) { 'Required' } else { 'Optional' }) $(if ($isAdmin) { 'Yes' } else { 'No' }) $(if ($ok) { 'PASS' } else { 'FAIL' }) $(if ($ok) { 'Admin present' } else { 'Run elevated' })
}

function Test-ReqInternet {
    param([hashtable]$Spec)
    $ok = $true; $actual = 'Unknown'
    try { $null = Resolve-DnsName 'microsoft.com' -QuickTimeout -ErrorAction Stop; $actual = 'Online' }
    catch { $actual = 'Offline'; $ok = -not $Spec.Required }
    New-RequirementResult 'Internet' 'Internet connection' $(if ($Spec.Required) { 'Required' } else { 'Optional' }) $actual $(if ($ok) { 'PASS' } else { 'FAIL' }) $(if ($ok) { 'Connectivity OK' } else { 'Internet required' })
}

function Test-ReqLocale {
    param([hashtable]$Spec)
    $have = (Get-WinSystemLocale).Name
    $ok = $have -in @($Spec.Allowed)
    New-RequirementResult 'Locale' 'System locale' ($Spec.Allowed -join ', ') $have $(if ($ok) { 'PASS' } else { 'WARN' }) $(if ($ok) { 'Compatible locale' } else { 'Locale may need changing' })
}

function Test-ReqFont {
    param([hashtable]$Spec)
    $hit = Test-Path "$env:SystemRoot\Fonts\$($Spec.File)"
    New-RequirementResult 'Font' "Font: $($Spec.File)" 'Installed' $(if ($hit) { 'present' } else { 'missing' }) $(if ($hit) { 'PASS' } else { 'WARN' }) $(if ($hit) { 'Font present' } else { 'Install font before use' })
}

function Test-ReqDirectStorage {
    $hit = (Test-Path "$env:SystemRoot\System32\dstorage.dll") -and (Test-Path "$env:SystemRoot\System32\dstoragecore.dll")
    New-RequirementResult 'DirectStorage' 'DirectStorage' 'Present' $(if ($hit) { 'present' } else { 'missing' }) $(if ($hit) { 'PASS' } else { 'FAIL' }) $(if ($hit) { 'Available' } else { 'Requires Windows 11 21H2+' })
}

function Test-Requirement {
    param([hashtable]$Spec, [pscustomobject]$System, [pscustomobject]$Enrichment)
    switch ($Spec.Type) {
        'OS'           { Test-ReqOS          -Spec $Spec -System $System }
        'CPU'          { Test-ReqCPU         -Spec $Spec -System $System -Enrichment $Enrichment }
        'RAM'          { Test-ReqRAM         -Spec $Spec -System $System -Enrichment $Enrichment }
        'Disk'         { Test-ReqDisk        -Spec $Spec -System $System -Enrichment $Enrichment }
        'GPU'          { Test-ReqGPU         -Spec $Spec -System $System -Enrichment $Enrichment }
        'Display'      { Test-ReqDisplay     -Spec $Spec -System $System }
        'NetFx'        { Test-ReqNetFx       -Spec $Spec }
        'NetDesktop'   { Test-ReqNetDesktop  -Spec $Spec }
        'VCRedist'     { Test-ReqVCRedist    -Spec $Spec }
        'Java'         { Test-ReqJava        -Spec $Spec }
        'Python'       { Test-ReqPython      -Spec $Spec }
        'DirectX'      { Test-ReqDirectX     -Spec $Spec }
        'WebView2'     { Test-ReqWebView2 }
        'Browser'      { Test-ReqBrowser     -Spec $Spec }
        'WinFeature'   { Test-ReqWinFeature  -Spec $Spec }
        'KB'           { Test-ReqKB          -Spec $Spec }
        'TPM'          { Test-ReqTPM         -Spec $Spec }
        'SecureBoot'   { Test-ReqSecureBoot }
        'LicenseSvc'   { Test-ReqLicenseSvc  -Spec $Spec }
        'Admin'        { Test-ReqAdmin       -Spec $Spec }
        'Internet'     { Test-ReqInternet    -Spec $Spec }
        'Locale'       { Test-ReqLocale      -Spec $Spec }
        'Font'         { Test-ReqFont        -Spec $Spec }
        'DirectStorage'{ Test-ReqDirectStorage }
        default        { New-RequirementResult $Spec.Type $Spec.Type 'unknown' 'unknown' 'UNKNOWN' 'No detector for this requirement type' }
    }
}

# =============================================================================
# BASELINE
# =============================================================================
$baseline = [pscustomobject]@{
    When       = Get-Date
    Computer   = $env:COMPUTERNAME
    User       = "$env:USERDOMAIN\$env:USERNAME"
    IsAdmin    = (Test-IsAdmin)
    PSVersion  = $PSVersionTable.PSVersion.ToString()
    ReportPath = $reportBase
}
Write-Host "[INFO] Baseline: $($baseline.When) on $($baseline.Computer) as $($baseline.User)" -ForegroundColor DarkGray

# =============================================================================
# MASTER CATALOG
# =============================================================================
Write-Stage "Loading master catalog..."
$Script:RawCatalog = @(
    @{N='AutoCAD';              D=@('Civil','BIM','AEC','Mechanical');  P=@('AutoCAD 20*','AutoCAD LT 20*','Autodesk AutoCAD*'); K='CAD';         RAM=8;  Disk=20;  GPU=$true;  Net='4.8'; VCPP=$true; DX='11'; Lic='Node';     Cache=@('%LOCALAPPDATA%\Autodesk','%APPDATA%\Autodesk')}
    @{N='Civil 3D';             D=@('Civil');                            P=@('Autodesk Civil 3D*');                                 K='Civil';      RAM=16; Disk=30;  GPU=$true;  Net='4.8'; VCPP=$true; DX='11'; Lic='Node';     Cache=@('%LOCALAPPDATA%\Autodesk')}
    @{N='Revit';                D=@('BIM','AEC','Structural','MEP');     P=@('Autodesk Revit*');                                    K='BIM';        RAM=16; Disk=30;  GPU=$true;  Net='4.8'; VCPP=$true; DX='11'; Lic='Node';     Cache=@('%LOCALAPPDATA%\Autodesk\Revit')}
    @{N='Navisworks';           D=@('BIM','AEC');                        P=@('Autodesk Navisworks*');                               K='BIM';        RAM=16; Disk=20;  GPU=$true;  Net='4.8'; VCPP=$true; DX='11'; Lic='Node';     Cache=@('%LOCALAPPDATA%\Autodesk\Navisworks')}
    @{N='Archicad';             D=@('BIM','AEC');                        P=@('Archicad*','GRAPHISOFT Archicad*');                   K='BIM';        RAM=16; Disk=25;  GPU=$true;  Net='4.8'; VCPP=$true; Lic='Node';     Cache=@('%APPDATA%\GRAPHISOFT')}
    @{N='BricsCAD';             D=@('Civil','AEC');                      P=@('BricsCAD*');                                          K='CAD';        RAM=8;  Disk=15;  GPU=$true;  Net='4.8'; Lic='Node'}
    @{N='Rhino';                D=@('AEC','Marine','Industrial');        P=@('Rhinoceros*','Rhino 7*','Rhino 8*');                  K='CAD';        RAM=8;  Disk=10;  GPU=$true;  Net='4.8'; Lic='Node'}
    @{N='Grasshopper';          D=@('AEC','Computational Design');       P=@('Grasshopper*');                                       K='Plugin';     RAM=8;  Disk=5}
    @{N='Dynamo';               D=@('BIM','AEC');                        P=@('Dynamo*');                                            K='Plugin';     RAM=8;  Disk=5}
    @{N='Bluebeam Revu';        D=@('AEC','Project Mgmt');               P=@('Bluebeam Revu*');                                     K='Docs';       RAM=4;  Disk=5;   Net='4.8'; Lic='Node'}
    @{N='SAP2000';              D=@('Structural');                       P=@('SAP2000*','CSI SAP2000*');                            K='FEA';        RAM=8;  Disk=20;  Net='4.8'; VCPP=$true; Lic='Sentinel'; Lsvc=@('Sentinel*','*hasplm*'); Lport=@(1947); Cache=@('%LOCALAPPDATA%\Computers and Structures')}
    @{N='ETABS';                D=@('Structural');                       P=@('ETABS*','CSI ETABS*');                                K='FEA';        RAM=8;  Disk=20;  Net='4.8'; VCPP=$true; Lic='Sentinel'; Lsvc=@('Sentinel*','*hasplm*'); Lport=@(1947)}
    @{N='SAFE';                 D=@('Structural');                       P=@('SAFE 20*','SAFE 21*','SAFE 22*','CSI SAFE*');         K='FEA';        RAM=8;  Disk=20;  Net='4.8'; VCPP=$true; Lic='Sentinel'}
    @{N='CSiBridge';            D=@('Structural','Bridges');             P=@('CSiBridge*');                                         K='Bridge';     RAM=8;  Disk=20;  Net='4.8'; Lic='Sentinel'}
    @{N='STAAD.Pro';            D=@('Structural');                       P=@('STAAD.Pro*');                                         K='FEA';        RAM=8;  Disk=20;  Net='4.8'; VCPP=$true; Lic='Bentley'; Lsvc=@('*Bentley*','*SelLic*'); Cache=@('%LOCALAPPDATA%\Bentley')}
    @{N='Tekla Structures';     D=@('Structural','Steel','BIM');         P=@('Tekla Structures*');                                  K='BIM/FEA';    RAM=16; Disk=30;  GPU=$true;  Net='4.8'; Lic='FlexLM'; Lsvc=@('*Tekla*'); Lport=@(27000); Cache=@('%LOCALAPPDATA%\Tekla Structures')}
    @{N='Tekla Tedds';          D=@('Structural');                       P=@('Tekla Tedds*');                                       K='Design';     RAM=8;  Disk=10;  Net='4.8'; Lic='FlexLM'}
    @{N='RFEM';                 D=@('Structural');                       P=@('RFEM*','Dlubal RFEM*');                               K='FEA';        RAM=8;  Disk=20;  Net='4.8'; Lic='FlexLM'; Lsvc=@('*Dlubal*'); Lport=@(27000)}
    @{N='RISA-3D';              D=@('Structural');                       P=@('RISA-3D*');                                           K='FEA';        RAM=8;  Disk=15;  Net='4.8'; Lic='Node'}
    @{N='MIDAS Civil';          D=@('Structural','Bridges');             P=@('midas Civil*','MIDAS Civil*');                        K='FEA';        RAM=8;  Disk=20;  Lic='Sentinel'}
    @{N='MIDAS Gen';            D=@('Structural');                       P=@('midas Gen*','MIDAS Gen*');                            K='FEA';        RAM=8;  Disk=20;  Lic='Sentinel'}
    @{N='Robot Structural';     D=@('Structural');                       P=@('Autodesk Robot Structural*');                         K='FEA';        RAM=8;  Disk=20;  Net='4.8'; Lic='Node'}
    @{N='IDEA StatiCa';         D=@('Structural','Steel','Concrete');    P=@('IDEA StatiCa*');                                      K='Design';     RAM=8;  Disk=15;  Net='4.8'; Lic='FlexLM'}
    @{N='SCIA Engineer';        D=@('Structural');                       P=@('SCIA Engineer*');                                     K='FEA';        RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='Advance Steel';        D=@('Steel','Structural');               P=@('Advance Steel*');                                     K='Detailing';  RAM=16; Disk=25;  GPU=$true;  Net='4.8'; Lic='Node'}
    @{N='SOLIDWORKS';           D=@('Mechanical','Aerospace','Automotive','Industrial'); P=@('SOLIDWORKS 20*'); K='CAD'; RAM=16; Disk=30; GPU=$true; Net='4.8'; VCPP=$true; DX='11'; Lic='FlexLM'; Lsvc=@('*SolidWorks*','*SW_D*'); Lport=@(25734); Cache=@('%LOCALAPPDATA%\SolidWorks','%APPDATA%\SolidWorks')}
    @{N='Autodesk Inventor';    D=@('Mechanical','Industrial');          P=@('Autodesk Inventor*');                                 K='CAD';        RAM=16; Disk=30;  GPU=$true;  Net='4.8'; VCPP=$true; Lic='Node';     Cache=@('%LOCALAPPDATA%\Autodesk\Inventor')}
    @{N='CATIA';                D=@('Mechanical','Aerospace','Automotive','Marine'); P=@('CATIA*','Dassault Systemes CATIA*'); K='CAD'; RAM=16; Disk=30; GPU=$true; VCPP=$true; Lic='FlexLM'; Lsvc=@('*DS*','*Flex*'); Lport=@(4085)}
    @{N='Siemens NX';           D=@('Mechanical','Aerospace','Automotive','Manufacturing'); P=@('Siemens NX*','NX 20*'); K='CAD'; RAM=16; Disk=30; GPU=$true; VCPP=$true; Lic='FlexLM'; Lsvc=@('*Siemens*','*lmgrd*'); Lport=@(28000)}
    @{N='PTC Creo';             D=@('Mechanical','Aerospace');           P=@('PTC Creo*','Creo Parametric*');                       K='CAD';        RAM=16; Disk=30;  GPU=$true;  VCPP=$true; Lic='FlexLM'; Lsvc=@('*Creo*','*PTC*'); Lport=@(7788)}
    @{N='Solid Edge';           D=@('Mechanical','Industrial');          P=@('Solid Edge*');                                        K='CAD';        RAM=16; Disk=25;  GPU=$true;  Net='4.8'; Lic='FlexLM'}
    @{N='Fusion 360';           D=@('Mechanical','Industrial','CAM');    P=@('Autodesk Fusion*');                                   K='CAD/CAM';    RAM=8;  Disk=15;  GPU=$true;  Net='4.8'; Lic='Cloud'; Cache=@('%LOCALAPPDATA%\Autodesk\Fusion360')}
    @{N='Siemens Teamcenter';   D=@('PLM','Mechanical');                 P=@('Teamcenter*');                                        K='PLM';        RAM=16; Disk=30;  VCPP=$true; Lic='FlexLM'}
    @{N='ANSYS';                D=@('Simulation','Mechanical','Aerospace','Nuclear'); P=@('ANSYS*','Ansys*'); K='FEA/CFD'; RAM=32; Disk=60; GPU=$true; VCPP=$true; Lic='FlexLM'; Lsvc=@('*ansys*','*lmgrd*'); Lport=@(1055,2325); Cache=@('%APPDATA%\Ansys','%TEMP%\Ansys')}
    @{N='Abaqus';               D=@('Simulation','Materials','Aerospace','Biomedical'); P=@('Abaqus*','SIMULIA Abaqus*'); K='FEA'; RAM=32; Disk=50; VCPP=$true; Lic='FlexLM'; Lsvc=@('*SIMULIA*','*lmgrd*'); Lport=@(27000)}
    @{N='COMSOL Multiphysics';  D=@('Simulation','Multiphysics','Bio','Materials'); P=@('COMSOL*'); K='Multiphysics'; RAM=16; Disk=30; VCPP=$true; Lic='FlexLM'; Lsvc=@('*COMSOL*'); Lport=@(1718,1719); Cache=@('%USERPROFILE%\.comsol')}
    @{N='MSC Nastran';          D=@('Simulation','Aerospace');           P=@('MSC Nastran*','Nastran*');                            K='FEA';        RAM=32; Disk=40;  VCPP=$true; Lic='FlexLM'}
    @{N='Patran';               D=@('Simulation','Aerospace');           P=@('Patran*');                                            K='Pre/Post';   RAM=16; Disk=25;  VCPP=$true}
    @{N='LS-DYNA';              D=@('Simulation','Automotive','Aerospace'); P=@('LS-DYNA*');                                        K='Explicit';   RAM=32; Disk=40;  VCPP=$true; Lic='FlexLM'}
    @{N='Altair HyperWorks';    D=@('Simulation','Automotive');          P=@('Altair HyperWorks*','HyperWorks*');                   K='FEA';        RAM=16; Disk=30;  VCPP=$true; Lic='FlexLM'; Lsvc=@('*Altair*','*lmgrd*')}
    @{N='HyperMesh';            D=@('Simulation','Automotive','Aerospace'); P=@('HyperMesh*');                                      K='Meshing';    RAM=16; Disk=20;  VCPP=$true}
    @{N='Simcenter STAR-CCM+';  D=@('Simulation','CFD','Aerospace','Marine'); P=@('STAR-CCM*','Simcenter STAR-CCM*');               K='CFD';        RAM=32; Disk=60;  VCPP=$true; Lic='FlexLM'; Lsvc=@('*CDLMD*','*lmgrd*')}
    @{N='OpenFOAM';             D=@('Simulation','CFD');                 P=@('OpenFOAM*');                                          K='CFD';        RAM=32; Disk=40;  Lic='None'}
    @{N='ANSYS Fluent';         D=@('Simulation','CFD','Chemical');      P=@('ANSYS Fluent*');                                      K='CFD';        RAM=32; Disk=40;  VCPP=$true}
    @{N='MSC Adams';            D=@('Simulation','Automotive','Robotics'); P=@('MSC Adams*','Adams Car*');                          K='Motion';     RAM=16; Disk=25;  VCPP=$true; Lic='FlexLM'}
    @{N='Simulink';             D=@('Simulation','Control','Automotive','Aerospace','Robotics'); P=@('Simulink*','MATLAB*'); K='MBD'; RAM=8; Disk=20; Net='4.8'; Lic='FlexLM'; Lsvc=@('*MATLAB*','*lmgrd*'); Lport=@(27000); Cache=@('%LOCALAPPDATA%\MathWorks','%APPDATA%\MathWorks')}
    @{N='MATLAB';               D=@('Simulation','Math','Robotics','Control','Bio','Materials'); P=@('MATLAB R20*','MATLAB*'); K='Math'; RAM=8; Disk=20; Net='4.8'; Lic='FlexLM'; Lsvc=@('*MATLAB*'); Lport=@(27000); Cache=@('%LOCALAPPDATA%\MathWorks')}
    @{N='Wolfram Mathematica';  D=@('Math','Materials');                 P=@('Wolfram Mathematica*','Mathematica*');                K='Math';       RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Maple';                D=@('Math');                             P=@('Maple 20*','Maple*');                                 K='Math';       RAM=8;  Disk=10;  Lic='FlexLM'}
    @{N='Mathcad Prime';        D=@('Math','Structural');                P=@('Mathcad Prime*','PTC Mathcad*');                      K='Math';       RAM=8;  Disk=10;  Net='4.8'; Lic='FlexLM'}
    @{N='Python';               D=@('Math','Data','Engineering');        P=@('Python 3*','Python 3.*');                             K='Lang';       RAM=2;  Disk=2;   Lic='None'}
    @{N='Anaconda';             D=@('Math','Data');                      P=@('Anaconda*','Miniconda*');                             K='Distro';     RAM=2;  Disk=5;   Lic='None'}
    @{N='Jupyter';              D=@('Math','Data');                      P=@('Jupyter*');                                           K='Notebook';   RAM=2;  Disk=2}
    @{N='R';                    D=@('Math','Data');                      P=@('R for Windows*','R 4.*');                             K='Stats';      RAM=4;  Disk=3}
    @{N='OriginPro';            D=@('Math','Data','Materials');          P=@('OriginPro*','OriginLab*');                            K='Plot';       RAM=4;  Disk=5;   Lic='Node'}
    @{N='Altium Designer';      D=@('Electronics','PCB','Electrical');   P=@('Altium Designer*');                                   K='PCB';        RAM=16; Disk=25;  GPU=$true;  Net='4.8'; Lic='FlexLM/Cloud'; Lsvc=@('*Altium*'); Lport=@(27000); Cache=@('%LOCALAPPDATA%\Altium','%APPDATA%\Altium')}
    @{N='KiCad';                D=@('Electronics','PCB');                P=@('KiCad*');                                             K='PCB';        RAM=8;  Disk=10;  Lic='None'}
    @{N='Cadence Allegro';      D=@('Electronics','PCB');                P=@('Cadence Allegro*','Allegro*');                        K='PCB';        RAM=16; Disk=30;  Lic='FlexLM'; Lsvc=@('*Cadence*','*lmgrd*'); Lport=@(5280)}
    @{N='OrCAD';                D=@('Electronics','PCB');                P=@('OrCAD*');                                             K='PCB';        RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Siemens Xpedition';    D=@('Electronics','PCB');                P=@('Xpedition*');                                         K='PCB';        RAM=16; Disk=25;  Lic='FlexLM'}
    @{N='PADS Professional';    D=@('Electronics','PCB');                P=@('PADS Professional*','Mentor PADS*');                  K='PCB';        RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='LTspice';              D=@('Electronics','Electrical');         P=@('LTspice*','ADI LTspice*');                            K='Circuit';    RAM=4;  Disk=2;   Lic='None'}
    @{N='PSpice';               D=@('Electronics');                      P=@('PSpice*','OrCAD PSpice*');                            K='Circuit';    RAM=8;  Disk=10;  Lic='FlexLM'}
    @{N='NI Multisim';          D=@('Electronics');                      P=@('NI Multisim*','Multisim*');                           K='Circuit';    RAM=8;  Disk=10;  Net='4.8'; Lic='FlexLM'}
    @{N='Proteus';              D=@('Electronics','Embedded');           P=@('Proteus*');                                           K='Circuit+MCU';RAM=8;  Disk=10;  Lic='Node'}
    @{N='EasyEDA';              D=@('Electronics','PCB');                P=@('EasyEDA*');                                           K='PCB';        RAM=4;  Disk=3}
    @{N='DipTrace';             D=@('Electronics','PCB');                P=@('DipTrace*');                                          K='PCB';        RAM=4;  Disk=3}
    @{N='DesignSpark PCB';      D=@('Electronics','PCB');                P=@('DesignSpark*');                                       K='PCB';        RAM=4;  Disk=3}
    @{N='ETAP';                 D=@('Electrical Power');                 P=@('ETAP*');                                              K='Power';      RAM=16; Disk=25;  Net='4.8'; Lic='Sentinel'; Lsvc=@('*ETAP*','Sentinel*'); Lport=@(1947); Cache=@('%LOCALAPPDATA%\ETAP')}
    @{N='SKM PowerTools';       D=@('Electrical Power');                 P=@('SKM Power*','PowerTools*');                           K='Power';      RAM=8;  Disk=15;  Lic='Sentinel'}
    @{N='EasyPower';            D=@('Electrical Power');                 P=@('EasyPower*');                                         K='Power';      RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='DIgSILENT PowerFactory';D=@('Electrical Power');                P=@('PowerFactory*','DIgSILENT*');                         K='Power';      RAM=16; Disk=20;  Lic='FlexLM'; Lsvc=@('*DIgSILENT*')}
    @{N='PSS/E';                D=@('Electrical Power');                 P=@('PSS*E*','PSSE*');                                     K='Power';      RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='PSCAD';                D=@('Electrical Power');                 P=@('PSCAD*');                                             K='Power';      RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='EPLAN Electric P8';    D=@('Electrical','Automation');          P=@('EPLAN*');                                             K='ECAD';       RAM=16; Disk=25;  Net='4.8'; Lic='FlexLM'; Lsvc=@('*EPLAN*','*lmgrd*'); Cache=@('%APPDATA%\EPLAN')}
    @{N='AutoCAD Electrical';   D=@('Electrical','Automation');          P=@('AutoCAD Electrical*');                                K='ECAD';       RAM=8;  Disk=20;  GPU=$true;  Net='4.8'; Lic='Node'}
    @{N='SOLIDWORKS Electrical';D=@('Electrical','Mechanical');          P=@('SOLIDWORKS Electrical*');                             K='ECAD';       RAM=16; Disk=25;  Net='4.8'; Lic='FlexLM'}
    @{N='Siemens TIA Portal';   D=@('Automation','Industrial','Electrical'); P=@('TIA Portal*','SIMATIC*TIA*'); K='PLC'; RAM=16; Disk=40; Net='4.8'; Lic='FlexLM'; Lsvc=@('*Automation License*','*Siemens*','*lmgrd*'); Lport=@(27000); Cache=@('%APPDATA%\Siemens\Automation')}
    @{N='STEP 7';               D=@('Automation');                       P=@('STEP 7*','SIMATIC STEP 7*');                          K='PLC';        RAM=8;  Disk=25;  Lic='FlexLM'}
    @{N='WinCC';                D=@('Automation','SCADA');               P=@('SIMATIC WinCC*','WinCC*');                            K='SCADA';      RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Rockwell Studio 5000'; D=@('Automation','Industrial');          P=@('Studio 5000*','RSLogix*');                            K='PLC';        RAM=16; Disk=30;  Net='4.8'; Lic='Rockwell'; Lsvc=@('*Rockwell*','*FactoryTalk*'); Cache=@('%LOCALAPPDATA%\Rockwell')}
    @{N='FactoryTalk View';     D=@('Automation','SCADA');               P=@('FactoryTalk*');                                       K='SCADA';      RAM=8;  Disk=20;  Lic='Rockwell'}
    @{N='CODESYS';              D=@('Automation');                       P=@('CODESYS*');                                           K='PLC';        RAM=8;  Disk=15;  Lic='None'}
    @{N='Beckhoff TwinCAT 3';   D=@('Automation');                       P=@('TwinCAT*');                                           K='PLC';        RAM=8;  Disk=20;  Lic='Node'}
    @{N='Schneider EcoStruxure';D=@('Automation');                       P=@('EcoStruxure*','Schneider*');                          K='PLC';        RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='Mitsubishi GX Works';  D=@('Automation');                       P=@('GX Works*');                                          K='PLC';        RAM=8;  Disk=15;  Lic='Node'}
    @{N='Omron Sysmac Studio';  D=@('Automation');                       P=@('Sysmac Studio*');                                     K='PLC';        RAM=8;  Disk=15;  Lic='Node'}
    @{N='AVEVA System Platform';D=@('Automation','SCADA');               P=@('AVEVA*','Wonderware*');                               K='SCADA';      RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Ignition';             D=@('Automation','SCADA');               P=@('Ignition*','Inductive Automation*');                  K='SCADA';      RAM=8;  Disk=10;  Lic='Cloud/Node'}
    @{N='NI LabVIEW';           D=@('Automation','Instrumentation','Electrical','Telecom','Bio'); P=@('LabVIEW*','NI LabVIEW*'); K='Instrument'; RAM=8; Disk=20; Net='4.8'; Lic='FlexLM'; Lsvc=@('*NI*','*National Instruments*'); Cache=@('%LOCALAPPDATA%\National Instruments')}
    @{N='Factory I/O';          D=@('Automation');                       P=@('Factory IO*','Factory I/O*');                         K='Sim';        RAM=8;  Disk=5;   GPU=$true}
    @{N='Xilinx Vivado';        D=@('Embedded','Electronics','Computer'); P=@('Xilinx Vivado*','Vivado*');                          K='FPGA';       RAM=16; Disk=60;  Lic='FlexLM'; Cache=@('%APPDATA%\Xilinx')}
    @{N='Intel Quartus Prime';  D=@('Embedded','Electronics','Computer'); P=@('Quartus*');                                          K='FPGA';       RAM=16; Disk=50;  Lic='FlexLM'; Cache=@('%APPDATA%\Altera','%APPDATA%\Intel\Quartus')}
    @{N='ModelSim';             D=@('Embedded','Computer');              P=@('ModelSim*','Questa*');                                K='HDL Sim';    RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='STM32CubeIDE';         D=@('Embedded','Robotics');              P=@('STM32CubeIDE*','STM32Cube*');                         K='Embedded';   RAM=8;  Disk=15;  Lic='None'}
    @{N='MPLAB X';              D=@('Embedded');                         P=@('MPLAB X*');                                           K='Embedded';   RAM=4;  Disk=10;  Lic='None'}
    @{N='Keil uVision';         D=@('Embedded');                         P=@('Keil*','uVision*');                                   K='Embedded';   RAM=4;  Disk=10;  Lic='Node'}
    @{N='IAR Embedded Workbench';D=@('Embedded');                        P=@('IAR Embedded*');                                      K='Embedded';   RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Arduino IDE';          D=@('Embedded','Robotics');              P=@('Arduino IDE*','Arduino*');                            K='Embedded';   RAM=2;  Disk=5;   Lic='None'}
    @{N='PlatformIO';           D=@('Embedded');                         P=@('PlatformIO*');                                        K='Embedded';   RAM=4;  Disk=5;   Lic='None'}
    @{N='Visual Studio';        D=@('Computer','Data');                  P=@('Microsoft Visual Studio*20*');                        K='IDE';        RAM=8;  Disk=30;  Net='4.8'; Lic='Node'; Cache=@('%LOCALAPPDATA%\Microsoft\VisualStudio')}
    @{N='Visual Studio Code';   D=@('Computer','Data');                  P=@('Microsoft Visual Studio Code*');                      K='IDE';        RAM=4;  Disk=5;   Lic='None'}
    @{N='Docker Desktop';       D=@('Computer');                         P=@('Docker Desktop*');                                    K='Containers'; RAM=8;  Disk=20;  Lic='Node'}
    @{N='Git';                  D=@('Computer','Data');                  P=@('Git version*');                                       K='VCS';        RAM=1;  Disk=2;   Lic='None'}
    @{N='Wireshark';            D=@('Computer','Telecom');               P=@('Wireshark*');                                         K='Net tool';   RAM=4;  Disk=5;   Lic='None'}
    @{N='Keysight ADS';         D=@('RF','Telecom','Electronics');       P=@('Keysight ADS*','ADS 20*','Advanced Design System*');  K='RF Sim';     RAM=16; Disk=40;  Lic='FlexLM'; Lsvc=@('*Keysight*','*Agilent*','*lmgrd*'); Lport=@(27000); Cache=@('%USERPROFILE%\hpeesof')}
    @{N='ANSYS HFSS';           D=@('RF','Telecom','Aerospace');         P=@('ANSYS HFSS*','HFSS*');                                K='EM';         RAM=32; Disk=50;  Lic='FlexLM'}
    @{N='CST Studio Suite';     D=@('RF','Telecom');                     P=@('CST Studio*','CST*');                                 K='EM';         RAM=32; Disk=40;  Lic='FlexLM'}
    @{N='AWR Microwave Office'; D=@('RF');                               P=@('AWR*','Microwave Office*');                           K='RF Sim';     RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='FEKO';                 D=@('RF','Aerospace');                   P=@('FEKO*','Altair FEKO*');                               K='EM';         RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Sonnet Suites';        D=@('RF');                               P=@('Sonnet*');                                            K='EM';         RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='GNU Radio';            D=@('Telecom','RF');                     P=@('GNU Radio*');                                         K='SDR';        RAM=4;  Disk=5;   Lic='None'}
    @{N='Cisco Packet Tracer';  D=@('Telecom','Computer');               P=@('Cisco Packet Tracer*');                               K='Net sim';    RAM=4;  Disk=5;   Lic='Node'}
    @{N='Atoll';                D=@('Telecom');                          P=@('Atoll*');                                             K='RAN';        RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='NS-3';                 D=@('Telecom','Computer');               P=@('ns-3*');                                              K='Net sim';    RAM=4;  Disk=5;   Lic='None'}
    @{N='Aspen Plus';           D=@('Chemical','Process');               P=@('Aspen Plus*');                                        K='Process';    RAM=16; Disk=30;  Net='4.8'; Lic='FlexLM'; Lsvc=@('*Aspen*','*lmgrd*','*SLM*'); Lport=@(27000); Cache=@('%LOCALAPPDATA%\AspenTech')}
    @{N='Aspen HYSYS';          D=@('Chemical','Petroleum');             P=@('Aspen HYSYS*');                                       K='Process';    RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='CHEMCAD';              D=@('Chemical');                         P=@('CHEMCAD*');                                           K='Process';    RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='ProMax';               D=@('Chemical','Petroleum');             P=@('ProMax*','BR&E ProMax*');                             K='Process';    RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='DWSIM';                D=@('Chemical');                         P=@('DWSIM*');                                             K='Process';    RAM=4;  Disk=5;   Lic='None'}
    @{N='gPROMS';               D=@('Chemical','Process');               P=@('gPROMS*');                                            K='Process';    RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='OLGA';                 D=@('Petroleum','Chemical');             P=@('OLGA*');                                              K='Flow';       RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='Pipesim';              D=@('Petroleum','Chemical');             P=@('Pipesim*','PIPESIM*');                                K='Flow';       RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='HTRI Xchanger Suite';  D=@('Chemical','Process');               P=@('HTRI*');                                              K='HX design';  RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Petrel';               D=@('Petroleum','Geology');              P=@('Petrel*','Schlumberger Petrel*');                     K='Reservoir';  RAM=32; Disk=50;  GPU=$true;  Lic='FlexLM'; Lsvc=@('*SLB*','*Schlumberger*','*lmgrd*'); Cache=@('%LOCALAPPDATA%\Schlumberger')}
    @{N='Eclipse';              D=@('Petroleum');                        P=@('Eclipse*','Schlumberger Eclipse*');                   K='Reservoir';  RAM=16; Disk=40;  Lic='FlexLM'}
    @{N='CMG GEM';              D=@('Petroleum');                        P=@('CMG*','GEM*');                                        K='Reservoir';  RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Techlog';              D=@('Petroleum','Geology');              P=@('Techlog*');                                           K='Well log';   RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Kingdom';              D=@('Petroleum','Geology');              P=@('Kingdom*','SMT Kingdom*');                            K='Seismic';    RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Deswik';               D=@('Mining');                           P=@('Deswik*');                                            K='Mine plan';  RAM=16; Disk=30;  Lic='FlexLM'; Cache=@('%APPDATA%\Deswik')}
    @{N='Maptek Vulcan';        D=@('Mining','Geology');                 P=@('Maptek Vulcan*','Vulcan*');                           K='Mine';       RAM=16; Disk=30;  Lic='FlexLM'; Lsvc=@('*Maptek*')}
    @{N='Surpac';               D=@('Mining','Geology');                 P=@('Surpac*','Geovia Surpac*');                           K='Mine';       RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Datamine Studio';      D=@('Mining');                           P=@('Datamine*');                                          K='Mine';       RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Micromine';            D=@('Mining','Geology');                 P=@('Micromine*');                                         K='Mine';       RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Leapfrog Geo';         D=@('Mining','Geology','Geotech');       P=@('Leapfrog*');                                          K='Geo model';  RAM=16; Disk=30;  GPU=$true;  Lic='FlexLM'}
    @{N='PLAXIS 2D';            D=@('Geotech','Civil');                  P=@('PLAXIS 2D*');                                         K='Geo FEA';    RAM=8;  Disk=20;  Lic='FlexLM'; Lsvc=@('*Bentley*','*PLAXIS*')}
    @{N='PLAXIS 3D';            D=@('Geotech','Civil');                  P=@('PLAXIS 3D*');                                         K='Geo FEA';    RAM=16; Disk=25;  Lic='FlexLM'}
    @{N='GeoStudio';            D=@('Geotech','Civil','Mining');         P=@('GeoStudio*','GEO-SLOPE*');                            K='Geo';        RAM=8;  Disk=15;  Lic='FlexLM'; Cache=@('%LOCALAPPDATA%\GEO-SLOPE')}
    @{N='Rocscience RS2';       D=@('Geotech','Mining');                 P=@('RS2*','Rocscience RS2*');                             K='Geo FEA';    RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Rocscience RS3';       D=@('Geotech','Mining');                 P=@('RS3*','Rocscience RS3*');                             K='Geo FEA';    RAM=16; Disk=20;  Lic='FlexLM'}
    @{N='Slide2';               D=@('Geotech','Mining');                 P=@('Slide2*','Slide 2*');                                 K='Slope';      RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='FLAC3D';               D=@('Geotech','Mining');                 P=@('FLAC3D*');                                            K='Geo FEA';    RAM=16; Disk=25;  Lic='FlexLM'}
    @{N='GEO5';                 D=@('Geotech','Civil');                  P=@('GEO5*');                                              K='Geo';        RAM=4;  Disk=10;  Lic='Node'}
    @{N='gINT';                 D=@('Geotech');                          P=@('gINT*');                                              K='Boring log'; RAM=4;  Disk=10;  Lic='FlexLM'}
    @{N='HEC-RAS';              D=@('Water','Civil','Environmental');    P=@('HEC-RAS*');                                           K='Hydraulics'; RAM=8;  Disk=15;  Lic='None'; Cache=@('%USERPROFILE%\Documents\HEC-RAS')}
    @{N='HEC-HMS';              D=@('Water','Civil','Environmental');    P=@('HEC-HMS*');                                           K='Hydrology';  RAM=8;  Disk=10;  Lic='None'}
    @{N='EPA SWMM';             D=@('Water','Environmental');            P=@('EPA SWMM*','SWMM*');                                  K='Stormwater'; RAM=4;  Disk=5;   Lic='None'}
    @{N='EPANET';               D=@('Water','Environmental');            P=@('EPANET*');                                            K='Water net';  RAM=4;  Disk=5;   Lic='None'}
    @{N='WaterGEMS';            D=@('Water','Civil');                    P=@('WaterGEMS*');                                         K='Water net';  RAM=8;  Disk=20;  Lic='Bentley'; Lsvc=@('*Bentley*','*SelectServer*'); Cache=@('%LOCALAPPDATA%\Bentley')}
    @{N='SewerGEMS';            D=@('Water','Civil');                    P=@('SewerGEMS*');                                         K='Sewer';      RAM=8;  Disk=20;  Lic='Bentley'}
    @{N='InfoWorks ICM';        D=@('Water','Civil');                    P=@('InfoWorks*');                                         K='Hydraulic';  RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='MIKE+';                D=@('Water','Civil');                    P=@('MIKE+*','DHI MIKE*');                                 K='Hydraulic';  RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='MODFLOW';              D=@('Water','Geology');                  P=@('MODFLOW*','Visual MODFLOW*');                         K='GW';         RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='AERMOD';               D=@('Environmental');                    P=@('AERMOD*','AERMOD View*');                             K='Air';        RAM=4;  Disk=10;  Lic='None'}
    @{N='CALPUFF';              D=@('Environmental');                    P=@('CALPUFF*');                                           K='Air';        RAM=4;  Disk=10;  Lic='None'}
    @{N='ArcGIS Pro';           D=@('GIS','Geomatics','Environmental','Civil'); P=@('ArcGIS Pro*');                                 K='GIS';        RAM=16; Disk=30;  GPU=$true;  Net='4.8'; Lic='FlexLM/Cloud'; Lsvc=@('*ArcGIS*','*ESRI*','*lmgrd*'); Lport=@(27000); Cache=@('%LOCALAPPDATA%\ESRI')}
    @{N='ArcGIS Desktop';       D=@('GIS');                              P=@('ArcGIS Desktop*','ArcMap*','ArcGIS 10*');             K='GIS';        RAM=8;  Disk=25;  Net='4.8'; Lic='FlexLM'}
    @{N='QGIS';                 D=@('GIS','Geomatics','Environmental');  P=@('QGIS*');                                              K='GIS';        RAM=8;  Disk=10;  Lic='None'; Cache=@('%APPDATA%\QGIS')}
    @{N='Global Mapper';        D=@('GIS','Geomatics');                  P=@('Global Mapper*');                                     K='GIS';        RAM=8;  Disk=15;  Lic='Node'}
    @{N='ENVI';                 D=@('GIS','Remote Sensing');             P=@('ENVI*','NV5 ENVI*');                                  K='RS';         RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='ERDAS Imagine';        D=@('GIS','Remote Sensing');             P=@('ERDAS*','Hexagon ERDAS*');                            K='RS';         RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='Pix4Dmapper';          D=@('Geomatics','Survey','GIS');         P=@('Pix4D*');                                             K='Photogram';  RAM=16; Disk=25;  GPU=$true;  Lic='FlexLM'; Lsvc=@('*Pix4D*')}
    @{N='Agisoft Metashape';    D=@('Geomatics','Survey');               P=@('Agisoft Metashape*','Agisoft PhotoScan*');            K='Photogram';  RAM=16; Disk=25;  GPU=$true;  Lic='Node'}
    @{N='Trimble Business Center';D=@('Geomatics','Survey');             P=@('Trimble Business Center*');                           K='Survey';     RAM=8;  Disk=20;  Lic='FlexLM'; Lsvc=@('*Trimble*')}
    @{N='Leica Infinity';       D=@('Geomatics','Survey');               P=@('Leica Infinity*');                                    K='Survey';     RAM=8;  Disk=20;  Lic='Node'}
    @{N='Leica Cyclone';        D=@('Geomatics','Survey');               P=@('Leica Cyclone*');                                     K='PointCloud'; RAM=16; Disk=30;  GPU=$true;  Lic='FlexLM'}
    @{N='CloudCompare';         D=@('Geomatics','Survey');               P=@('CloudCompare*');                                      K='PointCloud'; RAM=8;  Disk=10;  Lic='None'}
    @{N='Autodesk ReCap';       D=@('Geomatics','AEC');                  P=@('Autodesk ReCap*');                                    K='PointCloud'; RAM=8;  Disk=15;  Lic='Node'}
    @{N='Carlson Survey';       D=@('Survey','Civil');                   P=@('Carlson Survey*');                                    K='Survey';     RAM=8;  Disk=15;  Lic='Node'}
    @{N='AVEVA Marine';         D=@('Marine','Naval');                   P=@('AVEVA Marine*','AVEVA*');                             K='Ship CAD';   RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='ShipConstructor';      D=@('Marine','Naval');                   P=@('ShipConstructor*');                                   K='Ship CAD';   RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Maxsurf';              D=@('Marine','Naval');                   P=@('Maxsurf*');                                           K='Naval arch'; RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='NAPA';                 D=@('Marine','Naval');                   P=@('NAPA*');                                              K='Naval arch'; RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='ANSYS AQWA';           D=@('Marine','Naval','Offshore');        P=@('ANSYS AQWA*','AQWA*');                                K='Hydro';      RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='MOSES';                D=@('Marine','Offshore');                P=@('MOSES*','Bentley MOSES*');                            K='Hydro';      RAM=8;  Disk=20;  Lic='Bentley'}
    @{N='Bentley OpenRail';     D=@('Railway','Civil');                  P=@('OpenRail*');                                          K='Rail CAD';   RAM=16; Disk=30;  GPU=$true;  Lic='Bentley'; Lsvc=@('*Bentley*','*SelectServer*')}
    @{N='OpenTrack';            D=@('Railway');                          P=@('OpenTrack*');                                         K='Rail sim';   RAM=8;  Disk=15;  Lic='None'}
    @{N='RailSys';              D=@('Railway');                          P=@('RailSys*');                                           K='Rail sim';   RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='AutoSPRINK';           D=@('Fire','MEP');                       P=@('AutoSPRINK*');                                        K='Fire';       RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='HydraCALC';            D=@('Fire','MEP');                       P=@('HydraCALC*');                                         K='Fire';       RAM=4;  Disk=10;  Lic='Node'}
    @{N='PyroSim';              D=@('Fire');                             P=@('PyroSim*');                                           K='Fire sim';   RAM=16; Disk=20;  GPU=$true;  Lic='Node'}
    @{N='FDS';                  D=@('Fire');                             P=@('FDS*','NIST FDS*');                                   K='Fire sim';   RAM=16; Disk=20;  Lic='None'}
    @{N='Pathfinder';           D=@('Fire');                             P=@('Pathfinder*');                                        K='Egress';     RAM=8;  Disk=15;  Lic='Node'}
    @{N='CONTAM';               D=@('Fire','HVAC');                      P=@('CONTAM*','NIST CONTAM*');                             K='Airflow';    RAM=4;  Disk=10;  Lic='None'}
    @{N='Revit MEP';            D=@('MEP','HVAC','Fire');                P=@('Autodesk Revit*');                                    K='MEP';        RAM=16; Disk=30;  GPU=$true;  Net='4.8'; Lic='Node'}
    @{N='AutoCAD MEP';          D=@('MEP','HVAC');                       P=@('AutoCAD MEP*','AutoCAD Architecture*');               K='MEP';        RAM=8;  Disk=20;  GPU=$true;  Net='4.8'; Lic='Node'}
    @{N='Carrier HAP';          D=@('HVAC');                             P=@('Carrier HAP*','HAP*');                                K='HVAC load';  RAM=4;  Disk=10;  Lic='Node'}
    @{N='TRACE 3D Plus';        D=@('HVAC');                             P=@('TRACE 700*','TRACE 3D*','Trane TRACE*');              K='HVAC load';  RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='EnergyPlus';           D=@('HVAC','Building');                  P=@('EnergyPlus*');                                        K='BEM';        RAM=8;  Disk=15;  Lic='None'}
    @{N='OpenStudio';           D=@('HVAC','Building');                  P=@('OpenStudio*');                                        K='BEM';        RAM=8;  Disk=15;  Lic='None'}
    @{N='IES VE';               D=@('HVAC','Building');                  P=@('IES*','IESVE*');                                      K='BEM';        RAM=16; Disk=25;  Lic='FlexLM'}
    @{N='DesignBuilder';        D=@('HVAC','Building');                  P=@('DesignBuilder*');                                     K='BEM';        RAM=8;  Disk=20;  GPU=$true;  Lic='FlexLM'}
    @{N='eQUEST';               D=@('HVAC','Building');                  P=@('eQUEST*');                                            K='BEM';        RAM=4;  Disk=10;  Lic='None'}
    @{N='DIALux evo';           D=@('Lighting','MEP');                   P=@('DIALux*');                                            K='Lighting';   RAM=8;  Disk=15;  GPU=$true;  Lic='None'}
    @{N='AGi32';                D=@('Lighting','MEP');                   P=@('AGi32*');                                             K='Lighting';   RAM=8;  Disk=15;  Lic='Node'}
    @{N='MCNP';                 D=@('Nuclear');                          P=@('MCNP*');                                              K='Neutronics'; RAM=8;  Disk=20;  Lic='Node'}
    @{N='SCALE';                D=@('Nuclear');                          P=@('SCALE*','ORNL SCALE*');                               K='Neutronics'; RAM=8;  Disk=20;  Lic='Node'}
    @{N='SERPENT';              D=@('Nuclear');                          P=@('Serpent*','SERPENT*');                                K='Neutronics'; RAM=8;  Disk=20;  Lic='None'}
    @{N='RELAP5';               D=@('Nuclear');                          P=@('RELAP5*');                                            K='Thermal';    RAM=8;  Disk=20;  Lic='Node'}
    @{N='TRACE';                D=@('Nuclear');                          P=@('TRACE*','NRC TRACE*');                                K='Thermal';    RAM=8;  Disk=20;  Lic='None'}
    @{N='OpenMC';               D=@('Nuclear');                          P=@('OpenMC*');                                            K='Neutronics'; RAM=8;  Disk=20;  Lic='None'}
    @{N='Mimics Innovation Suite';D=@('Biomedical');                     P=@('Mimics*','Materialise Mimics*');                      K='Bio model';  RAM=16; Disk=25;  GPU=$true;  Lic='FlexLM'}
    @{N='Simpleware';           D=@('Biomedical');                       P=@('Simpleware*','Synopsys Simpleware*');                 K='Bio model';  RAM=16; Disk=25;  Lic='FlexLM'}
    @{N='ImageJ';               D=@('Biomedical','Materials');           P=@('ImageJ*','Fiji*');                                    K='Imaging';    RAM=4;  Disk=5;   Lic='None'}
    @{N='3D Slicer';            D=@('Biomedical');                       P=@('3D Slicer*');                                         K='Imaging';    RAM=8;  Disk=10;  Lic='None'}
    @{N='Thermo-Calc';          D=@('Materials');                        P=@('Thermo-Calc*');                                       K='Thermo';     RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='JMatPro';              D=@('Materials');                        P=@('JMatPro*');                                           K='Materials';  RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='FactSage';             D=@('Materials');                        P=@('FactSage*');                                          K='Thermo';     RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Materials Studio';     D=@('Materials');                        P=@('Materials Studio*','BIOVIA*');                        K='MD';         RAM=16; Disk=25;  Lic='FlexLM'}
    @{N='PVsyst';               D=@('Renewable','Solar');                P=@('PVsyst*');                                            K='Solar';      RAM=4;  Disk=10;  Lic='Node'}
    @{N='HOMER Pro';            D=@('Renewable');                        P=@('HOMER*');                                             K='Microgrid';  RAM=4;  Disk=10;  Lic='Node'}
    @{N='SAM';                  D=@('Renewable');                        P=@('SAM 20*','System Advisor Model*');                    K='Renewable';  RAM=4;  Disk=10;  Lic='None'}
    @{N='RETScreen Expert';     D=@('Renewable');                        P=@('RETScreen*');                                         K='Feasibility';RAM=4;  Disk=5;   Lic='Node'}
    @{N='HelioScope';           D=@('Renewable','Solar');                P=@('HelioScope*');                                        K='Solar';      RAM=4;  Disk=5;   Lic='Cloud'}
    @{N='WindPRO';              D=@('Renewable','Wind');                 P=@('WindPRO*');                                           K='Wind';       RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='WAsP';                 D=@('Renewable','Wind');                 P=@('WAsP*');                                              K='Wind';       RAM=4;  Disk=10;  Lic='FlexLM'}
    @{N='GT-AutoLion';          D=@('Battery');                          P=@('GT-AutoLion*','AutoLion*');                           K='Battery';    RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Battery Design Studio';D=@('Battery');                          P=@('Battery Design Studio*','CD-adapco BDS*');            K='Battery';    RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Microsoft Project';    D=@('Project Mgmt');                     P=@('Microsoft Project*','Microsoft 365*Project*');        K='PM';         RAM=4;  Disk=10;  Net='4.8'; Lic='Node'}
    @{N='Primavera P6';         D=@('Project Mgmt');                     P=@('Primavera P6*','Oracle Primavera*');                  K='PM';         RAM=8;  Disk=20;  Net='4.8'; Lic='FlexLM/Cloud'; Lsvc=@('*Primavera*','*Oracle*')}
    @{N='Procore';              D=@('Project Mgmt','Construction');      P=@('Procore*');                                           K='PM';         RAM=4;  Disk=5;   Lic='Cloud'}
    @{N='Autodesk Construction Cloud'; D=@('Project Mgmt','Construction'); P=@('Autodesk Construction Cloud*','BIM 360*','ACC*');   K='PM';         RAM=4;  Disk=5;   Lic='Cloud'}
    @{N='Oracle Aconex';        D=@('Project Mgmt');                     P=@('Aconex*');                                            K='PM';         RAM=4;  Disk=5;   Lic='Cloud'}
    @{N='CostX';                D=@('Project Mgmt','Estimation');        P=@('CostX*');                                             K='Estimation'; RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='PlanSwift';            D=@('Estimation');                       P=@('PlanSwift*');                                         K='Estimation'; RAM=4;  Disk=10;  Lic='Node'}
    @{N='Mastercam';            D=@('Manufacturing','CAM');              P=@('Mastercam*');                                         K='CAM';        RAM=16; Disk=25;  GPU=$true;  Net='4.8'; Lic='FlexLM/Node'; Lsvc=@('*Mastercam*','*Sentinel*'); Cache=@('%USERPROFILE%\Documents\My MCAM*')}
    @{N='SolidCAM';             D=@('Manufacturing','CAM');              P=@('SolidCAM*');                                          K='CAM';        RAM=8;  Disk=20;  Net='4.8'; Lic='FlexLM'}
    @{N='PowerMill';            D=@('Manufacturing','CAM');              P=@('PowerMill*','Autodesk PowerMill*');                   K='CAM';        RAM=16; Disk=20;  Net='4.8'; Lic='Node'}
    @{N='VERICUT';              D=@('Manufacturing','CAM');              P=@('VERICUT*');                                           K='CAM verify'; RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='ESPRIT';               D=@('Manufacturing','CAM');              P=@('ESPRIT*');                                            K='CAM';        RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='PC-DMIS';              D=@('Metrology','Manufacturing');        P=@('PC-DMIS*');                                           K='Metrology';  RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='PolyWorks';            D=@('Metrology','Manufacturing');        P=@('PolyWorks*');                                         K='Metrology';  RAM=16; Disk=20;  GPU=$true;  Lic='FlexLM'}
    @{N='IBM Engineering DOORS';D=@('Systems');                          P=@('DOORS*','IBM Engineering Requirements*');             K='Req mgmt';   RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='Cameo Systems Modeler';D=@('Systems');                          P=@('Cameo*','No Magic*');                                 K='MBSE';       RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='Capella';              D=@('Systems');                          P=@('Capella*');                                           K='MBSE';       RAM=8;  Disk=15;  Lic='None'}
    @{N='Enterprise Architect'; D=@('Systems','Computer');               P=@('Enterprise Architect*','Sparx*');                     K='MBSE';       RAM=8;  Disk=15;  Lic='Node'}
)
$Script:RawCatalog = @($Script:RawCatalog | ForEach-Object { [pscustomobject]$_ })
$Script:CatalogCount = $Script:RawCatalog.Count
Write-Ok

# =============================================================================
# DISCIPLINE PROFILES
# =============================================================================
Write-Stage "Loading discipline profiles..."
$Script:Profiles = @{
    'Civil'           = @('AutoCAD','Civil 3D','BricsCAD','Revit','Navisworks','HEC-RAS','HEC-HMS','WaterGEMS','SewerGEMS','InfoWorks ICM','Bentley OpenRail','Carlson Survey','Trimble Business Center')
    'Structural'      = @('SAP2000','ETABS','SAFE','CSiBridge','STAAD.Pro','Tekla Structures','Tekla Tedds','RFEM','RISA-3D','MIDAS Civil','MIDAS Gen','Robot Structural','IDEA StatiCa','SCIA Engineer','Advance Steel')
    'Geotech'         = @('PLAXIS 2D','PLAXIS 3D','GeoStudio','Rocscience RS2','Rocscience RS3','Slide2','FLAC3D','GEO5','gINT','Leapfrog Geo')
    'Mining'          = @('Deswik','Maptek Vulcan','Surpac','Datamine Studio','Micromine','Leapfrog Geo','Rocscience RS2','Rocscience RS3','Slide2','FLAC3D')
    'BIM'             = @('Revit','Archicad','Navisworks','Tekla Structures','Grasshopper','Dynamo','Autodesk Construction Cloud','Bluebeam Revu')
    'Mechanical'      = @('SOLIDWORKS','Autodesk Inventor','CATIA','Siemens NX','PTC Creo','Solid Edge','Fusion 360','ANSYS','Abaqus','COMSOL Multiphysics')
    'Aerospace'       = @('CATIA','Siemens NX','PTC Creo','ANSYS','Abaqus','MSC Nastran','Patran','HyperMesh','LS-DYNA','Simcenter STAR-CCM+','MATLAB','Simulink','ANSYS HFSS')
    'Automotive'      = @('CATIA','Siemens NX','Altair HyperWorks','HyperMesh','LS-DYNA','Simcenter STAR-CCM+','MATLAB','Simulink','MSC Adams','GT-AutoLion')
    'Marine'          = @('AVEVA Marine','ShipConstructor','Maxsurf','NAPA','ANSYS AQWA','MOSES','Rhino','Simcenter STAR-CCM+','OpenFOAM')
    'Railway'         = @('Bentley OpenRail','OpenTrack','RailSys','Civil 3D','Revit','AutoCAD','MATLAB','Simulink','PLAXIS 2D','PLAXIS 3D')
    'Electrical'      = @('AutoCAD Electrical','EPLAN Electric P8','SOLIDWORKS Electrical','ETAP','SKM PowerTools','EasyPower','DIgSILENT PowerFactory','PSS/E','PSCAD','NI LabVIEW')
    'Electronics'     = @('Altium Designer','KiCad','Cadence Allegro','OrCAD','Siemens Xpedition','PADS Professional','LTspice','PSpice','NI Multisim','Proteus','Xilinx Vivado','Intel Quartus Prime','ModelSim')
    'Automation'      = @('Siemens TIA Portal','STEP 7','WinCC','Rockwell Studio 5000','FactoryTalk View','CODESYS','Beckhoff TwinCAT 3','Schneider EcoStruxure','Mitsubishi GX Works','Omron Sysmac Studio','AVEVA System Platform','Ignition','NI LabVIEW','Factory I/O','EPLAN Electric P8')
    'Robotics'        = @('MATLAB','Simulink','SOLIDWORKS','Fusion 360','ANSYS','Python','STM32CubeIDE','Arduino IDE')
    'Embedded'        = @('Xilinx Vivado','Intel Quartus Prime','ModelSim','STM32CubeIDE','MPLAB X','Keil uVision','IAR Embedded Workbench','Arduino IDE','PlatformIO','Proteus','Visual Studio Code')
    'Chemical'        = @('Aspen Plus','Aspen HYSYS','CHEMCAD','ProMax','DWSIM','gPROMS','OLGA','Pipesim','HTRI Xchanger Suite','ANSYS Fluent','COMSOL Multiphysics','MATLAB','Simulink')
    'Petroleum'       = @('Petrel','Eclipse','CMG GEM','Techlog','Kingdom','OLGA','Pipesim','Aspen HYSYS','MATLAB')
    'Geology'         = @('Leapfrog Geo','Petrel','Kingdom','Techlog','Maptek Vulcan','Surpac','Micromine','ArcGIS Pro','QGIS')
    'Water'           = @('HEC-RAS','HEC-HMS','EPA SWMM','EPANET','WaterGEMS','SewerGEMS','InfoWorks ICM','MIKE+','MODFLOW')
    'Environmental'   = @('AERMOD','CALPUFF','HEC-RAS','EPA SWMM','EPANET','MODFLOW','ArcGIS Pro','QGIS','MATLAB')
    'GIS'             = @('ArcGIS Pro','ArcGIS Desktop','QGIS','Global Mapper','ENVI','ERDAS Imagine','Autodesk ReCap','Pix4Dmapper','Agisoft Metashape','CloudCompare','Leica Cyclone')
    'Survey'          = @('Trimble Business Center','Leica Infinity','Carlson Survey','Civil 3D','Pix4Dmapper','Agisoft Metashape','ArcGIS Pro','QGIS','Autodesk ReCap','CloudCompare','Leica Cyclone')
    'Fire'            = @('AutoSPRINK','HydraCALC','PyroSim','FDS','Pathfinder','CONTAM','Revit MEP','AutoCAD MEP')
    'MEP'             = @('Revit MEP','AutoCAD MEP','Carrier HAP','TRACE 3D Plus','EnergyPlus','OpenStudio','IES VE','DesignBuilder','eQUEST','DIALux evo','AGi32')
    'HVAC'            = @('Carrier HAP','TRACE 3D Plus','EnergyPlus','OpenStudio','IES VE','DesignBuilder','eQUEST','Revit MEP','AutoCAD MEP','CONTAM','DIALux evo','AGi32')
    'Nuclear'         = @('MCNP','SCALE','SERPENT','RELAP5','TRACE','OpenMC','ANSYS','Abaqus','COMSOL Multiphysics','MATLAB')
    'Biomedical'      = @('MATLAB','Simulink','NI LabVIEW','COMSOL Multiphysics','ANSYS','Abaqus','Mimics Innovation Suite','Simpleware','ImageJ','3D Slicer','SOLIDWORKS','Python')
    'Materials'       = @('ANSYS','Abaqus','COMSOL Multiphysics','Thermo-Calc','JMatPro','FactSage','Materials Studio','ImageJ','MATLAB','OriginPro')
    'Simulation'      = @('ANSYS','Abaqus','COMSOL Multiphysics','MSC Nastran','LS-DYNA','Altair HyperWorks','HyperMesh','Simcenter STAR-CCM+','OpenFOAM','ANSYS Fluent','MSC Adams','Simulink','MATLAB')
    'Math'            = @('MATLAB','Simulink','Wolfram Mathematica','Maple','Mathcad Prime','Python','Anaconda','Jupyter','R','OriginPro')
    'Computer'        = @('Visual Studio','Visual Studio Code','Git','Docker Desktop','Wireshark','Xilinx Vivado','Intel Quartus Prime','ModelSim','Python','MATLAB','Simulink')
    'Telecom'         = @('MATLAB','Simulink','Keysight ADS','ANSYS HFSS','CST Studio Suite','NI LabVIEW','GNU Radio','Atoll','NS-3','Wireshark','Cisco Packet Tracer')
    'RF'              = @('Keysight ADS','ANSYS HFSS','CST Studio Suite','AWR Microwave Office','FEKO','Sonnet Suites','COMSOL Multiphysics','MATLAB')
    'Renewable'       = @('PVsyst','HOMER Pro','SAM','RETScreen Expert','HelioScope','WindPRO','WAsP','ETAP','DIgSILENT PowerFactory','MATLAB','Simulink')
    'Battery'         = @('GT-AutoLion','Battery Design Studio','ANSYS','COMSOL Multiphysics','MATLAB','Simulink')
    'Project Mgmt'    = @('Microsoft Project','Primavera P6','Procore','Autodesk Construction Cloud','Oracle Aconex','Bluebeam Revu','CostX','PlanSwift','Navisworks')
    'Manufacturing'   = @('Mastercam','SolidCAM','PowerMill','VERICUT','ESPRIT','PC-DMIS','PolyWorks','Fusion 360','Siemens NX','Autodesk Inventor')
    'Metrology'       = @('PC-DMIS','PolyWorks','ImageJ')
    'Systems'         = @('IBM Engineering DOORS','Cameo Systems Modeler','Capella','Enterprise Architect','MATLAB','Simulink','Siemens Teamcenter')
    'PLM'             = @('Siemens Teamcenter','SOLIDWORKS','CATIA','Siemens NX','PTC Creo')
    'CFD'             = @('ANSYS Fluent','Simcenter STAR-CCM+','OpenFOAM','COMSOL Multiphysics','ANSYS')
    'FEA'             = @('ANSYS','Abaqus','MSC Nastran','LS-DYNA','Altair HyperWorks','COMSOL Multiphysics')
    'CAD'             = @('AutoCAD','SOLIDWORKS','Autodesk Inventor','CATIA','Siemens NX','PTC Creo','Solid Edge','BricsCAD','Fusion 360','Rhino')
}
Write-Ok

# =============================================================================
# SOFTWARE REQUIREMENTS TABLE
# =============================================================================
Write-Stage "Loading requirement grids..."

$Script:SoftwareRequirements = @{
    'AutoCAD' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';     MinCores=4;  MinPassMark=4000;  InstructionSets=@('SSE4.2') }
        @{ Type='RAM';     Min=8;  Rec=16 }
        @{ Type='Disk';    Min=10; Rec=20 }
        @{ Type='GPU';     MinVRAM=1; RecVRAM=2; MinDirectX='11' }
        @{ Type='Display'; MinWidth=1920; MinHeight=1080 }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='VCRedist';Min='14.30' }
    )
    'Revit' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';     MinCores=4;  MinPassMark=6000; InstructionSets=@('SSE4.2') }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=20; Rec=40; SSD=$true }
        @{ Type='GPU';     MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='Display'; MinWidth=1920; MinHeight=1080 }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='VCRedist';Min='14.30' }
    )
    'Civil 3D' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';     MinCores=4;  MinPassMark=5000 }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=20; Rec=40; SSD=$true }
        @{ Type='GPU';     MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='VCRedist';Min='14.30' }
    )
    'SOLIDWORKS' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';     MinCores=4;  MinPassMark=6000; InstructionSets=@('SSE4.2') }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=20; Rec=60; SSD=$true }
        @{ Type='GPU';     MinVRAM=2; RecVRAM=4; MinOpenGL='4.5'; MinDirectX='11' }
        @{ Type='Display'; MinWidth=1920; MinHeight=1080 }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*SolidWorks*'; Ports=@(25734) }
    )
    'Autodesk Inventor' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';     MinCores=4;  MinPassMark=6000 }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=20; Rec=40; SSD=$true }
        @{ Type='GPU';     MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='VCRedist';Min='14.30' }
    )
    'CATIA' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='CPU';     MinCores=4;  MinPassMark=6000 }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=20; Rec=60 }
        @{ Type='GPU';     MinVRAM=2; RecVRAM=4; MinOpenGL='4.5' }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*DS*'; Ports=@(4085) }
    )
    'Siemens NX' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='CPU';     MinCores=4;  MinPassMark=6000 }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=20; Rec=60 }
        @{ Type='GPU';     MinVRAM=2; RecVRAM=4; MinOpenGL='4.5' }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='Java';    Min='8'; Kind='JRE' }
        @{ Type='LicenseSvc'; Pattern='*Siemens*'; Ports=@(28000) }
    )
    'PTC Creo' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='CPU';     MinCores=4;  MinPassMark=6000 }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=20; Rec=40 }
        @{ Type='GPU';     MinVRAM=2; RecVRAM=4; MinOpenGL='4.5' }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*Creo*'; Ports=@(7788) }
    )
    'ANSYS' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='CPU';     MinCores=4;  MinPassMark=12000; InstructionSets=@('AVX2') }
        @{ Type='RAM';     Min=16; Rec=64 }
        @{ Type='Disk';    Min=60; Rec=200; SSD=$true }
        @{ Type='GPU';     MinVRAM=4; RecVRAM=12; MinDirectX='11'; MinPassMark=3000 }
        @{ Type='Display'; MinWidth=1920; MinHeight=1080 }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*ansys*'; Ports=@(1055,2325) }
    )
    'Abaqus' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='CPU';     MinCores=4;  MinPassMark=12000; InstructionSets=@('AVX2') }
        @{ Type='RAM';     Min=16; Rec=64 }
        @{ Type='Disk';    Min=50; Rec=150; SSD=$true }
        @{ Type='GPU';     MinVRAM=4; RecVRAM=11 }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*SIMULIA*'; Ports=@(27000) }
    )
    'COMSOL Multiphysics' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='CPU';     MinCores=4;  MinPassMark=10000 }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=30; Rec=80 }
        @{ Type='GPU';     MinVRAM=2; RecVRAM=8 }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*COMSOL*'; Ports=@(1718,1719) }
    )
    'Simcenter STAR-CCM+' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=32; Rec=64 }
        @{ Type='Disk';    Min=60; Rec=200; SSD=$true }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='Java';    Min='11'; Kind='JRE' }
        @{ Type='LicenseSvc'; Pattern='*CDLMD*'; Ports=@() }
    )
    'MATLAB' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';     MinCores=4;  MinPassMark=4000 }
        @{ Type='RAM';     Min=4;  Rec=16 }
        @{ Type='Disk';    Min=5;  Rec=20; SSD=$true }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='Java';    Min='8'; Kind='JRE' }
        @{ Type='LicenseSvc'; Pattern='*MATLAB*'; Ports=@(27000) }
    )
    'SAP2000' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='CPU';     MinCores=4;  MinPassMark=3000 }
        @{ Type='RAM';     Min=8;  Rec=16 }
        @{ Type='Disk';    Min=10; Rec=30 }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='Sentinel*'; Ports=@(1947) }
    )
    'ETABS' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='CPU';     MinCores=4;  MinPassMark=3000 }
        @{ Type='RAM';     Min=8;  Rec=16 }
        @{ Type='Disk';    Min=10; Rec=30 }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='Sentinel*'; Ports=@(1947) }
    )
    'STAAD.Pro' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=8;  Rec=16 }
        @{ Type='Disk';    Min=10; Rec=30 }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*Bentley*'; Ports=@() }
    )
    'Tekla Structures' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=20; Rec=50 }
        @{ Type='GPU';     MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='LicenseSvc'; Pattern='*Tekla*'; Ports=@(27000) }
    )
    'ArcGIS Pro' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';     MinCores=4;  MinPassMark=6000 }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=20; Rec=40; SSD=$true }
        @{ Type='GPU';     MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='WebView2' }
        @{ Type='LicenseSvc'; Pattern='*ArcGIS*'; Ports=@(27000) }
    )
    'QGIS' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=4;  Rec=8 }
        @{ Type='Disk';    Min=5;  Rec=10 }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='Python';  Min='3.9' }
    )
    'Altium Designer' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=15; Rec=30 }
        @{ Type='GPU';     MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*Altium*'; Ports=@(27000) }
    )
    'KiCad' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=4;  Rec=8 }
        @{ Type='Disk';    Min=5;  Rec=10 }
        @{ Type='VCRedist';Min='14.30' }
    )
    'Xilinx Vivado' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=60; Rec=150 }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='Java';    Min='8';  Kind='JRE' }
        @{ Type='Python';  Min='3.8' }
        @{ Type='LicenseSvc'; Pattern='*Xilinx*'; Ports=@() }
    )
    'Intel Quartus Prime' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=50; Rec=120 }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*Quartus*'; Ports=@() }
    )
    'Siemens TIA Portal' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=40; Rec=80 }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='LicenseSvc'; Pattern='*Automation License*'; Ports=@(27000) }
    )
    'Rockwell Studio 5000' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=30; Rec=60 }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='LicenseSvc'; Pattern='*Rockwell*'; Ports=@() }
    )
    'NI LabVIEW' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=8;  Rec=16 }
        @{ Type='Disk';    Min=20; Rec=40 }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='LicenseSvc'; Pattern='*National Instruments*'; Ports=@() }
    )
    'Aspen Plus' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=8;  Rec=16 }
        @{ Type='Disk';    Min=20; Rec=40 }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='LicenseSvc'; Pattern='*Aspen*'; Ports=@(27000) }
    )
    'Petrel' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=30; Rec=80; SSD=$true }
        @{ Type='GPU';     MinVRAM=4; RecVRAM=8; MinDirectX='11' }
        @{ Type='LicenseSvc'; Pattern='*Schlumberger*'; Ports=@() }
    )
    'Keysight ADS' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=40; Rec=80 }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*Keysight*'; Ports=@(27000) }
    )
    'ANSYS HFSS' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=32; Rec=64 }
        @{ Type='Disk';    Min=50; Rec=120 }
        @{ Type='VCRedist';Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*ansys*'; Ports=@(1055) }
    )
    'Mastercam' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=20; Rec=50; SSD=$true }
        @{ Type='GPU';     MinVRAM=2; RecVRAM=4; MinOpenGL='3.3' }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='LicenseSvc'; Pattern='*Mastercam*'; Ports=@() }
    )
    'Primavera P6' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=8;  Rec=16 }
        @{ Type='Disk';    Min=15; Rec=30 }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='Java';    Min='8'; Kind='JRE' }
        @{ Type='LicenseSvc'; Pattern='*Primavera*'; Ports=@() }
    )
    'Microsoft Project' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=4;  Rec=8 }
        @{ Type='Disk';    Min=5;  Rec=10 }
        @{ Type='NetFx';   Min='4.8' }
    )
    'Fusion 360' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=8;  Rec=16 }
        @{ Type='Disk';    Min=10; Rec=20 }
        @{ Type='GPU';     MinVRAM=1; RecVRAM=2; MinDirectX='11' }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='VCRedist';Min='14.30' }
    )
    'Visual Studio' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=8;  Rec=16 }
        @{ Type='Disk';    Min=30; Rec=60; SSD=$true }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='VCRedist';Min='14.30' }
    )
    'Visual Studio Code' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=4;  Rec=8 }
        @{ Type='Disk';    Min=5;  Rec=10 }
        @{ Type='NetFx';   Min='4.8' }
    )
    'Docker Desktop' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=8;  Rec=16 }
        @{ Type='Disk';    Min=20; Rec=40; SSD=$true }
        @{ Type='WinFeature'; Name='Microsoft-Hyper-V-All' }
        @{ Type='WinFeature'; Name='Containers' }
        @{ Type='WinFeature'; Name='VirtualMachinePlatform' }
    )
    'Git' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=2;  Rec=4 }
        @{ Type='Disk';    Min=2;  Rec=5 }
    )
    'Wireshark' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=4;  Rec=8 }
        @{ Type='Disk';    Min=5;  Rec=10 }
    )
    'Python' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=2;  Rec=4 }
        @{ Type='Disk';    Min=1;  Rec=2 }
    )
    'Anaconda' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=4;  Rec=8 }
        @{ Type='Disk';    Min=4;  Rec=10 }
    )
    'Wolfram Mathematica' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=4;  Rec=16 }
        @{ Type='Disk';    Min=8;  Rec=20 }
        @{ Type='VCRedist';Min='14.30' }
    )
    'SolidCAM' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=8;  Rec=16 }
        @{ Type='Disk';    Min=20; Rec=40 }
        @{ Type='NetFx';   Min='4.8' }
        @{ Type='LicenseSvc'; Pattern='*SolidCAM*'; Ports=@() }
    )
    'OpenFOAM' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=16; Rec=64 }
        @{ Type='Disk';    Min=40; Rec=150; SSD=$true }
    )
    'HEC-RAS' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=4;  Rec=8 }
        @{ Type='Disk';    Min=10; Rec=20 }
        @{ Type='NetFx';   Min='4.8' }
    )
    'EPA SWMM' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=4;  Rec=8 }
        @{ Type='Disk';    Min=2;  Rec=5 }
    )
    'LTspice' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=2;  Rec=4 }
        @{ Type='Disk';    Min=1;  Rec=2 }
        @{ Type='NetFx';   Min='4.8' }
    )
    'Arduino IDE' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=2;  Rec=4 }
        @{ Type='Disk';    Min=1;  Rec=5 }
        @{ Type='Java';    Min='8'; Kind='JRE' }
    )
    'STM32CubeIDE' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=8;  Rec=16 }
        @{ Type='Disk';    Min=15; Rec=30 }
        @{ Type='Java';    Min='11'; Kind='JRE' }
    )
    'ImageJ' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=2;  Rec=4 }
        @{ Type='Disk';    Min=2;  Rec=5 }
        @{ Type='Java';    Min='8'; Kind='JRE' }
    )
    'Blender' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=8;  Rec=16 }
        @{ Type='Disk';    Min=5;  Rec=10 }
        @{ Type='GPU';     MinVRAM=2; RecVRAM=4; MinOpenGL='4.3' }
    )
    'FreeCAD' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=4;  Rec=8 }
        @{ Type='Disk';    Min=2;  Rec=5 }
    )
    'CloudCompare' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=8;  Rec=16 }
        @{ Type='Disk';    Min=5;  Rec=10 }
        @{ Type='GPU';     MinVRAM=2; RecVRAM=4; MinOpenGL='3.3' }
    )
    'Pix4Dmapper' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=20; Rec=50; SSD=$true }
        @{ Type='GPU';     MinVRAM=4; RecVRAM=6; MinOpenGL='3.3' }
        @{ Type='LicenseSvc'; Pattern='*Pix4D*'; Ports=@() }
    )
    'Agisoft Metashape' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=20; Rec=50; SSD=$true }
        @{ Type='GPU';     MinVRAM=4; RecVRAM=6; MinOpenCL='1.2' }
    )
    'PyroSim' = @(
        @{ Type='OS';      MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';     Min=16; Rec=32 }
        @{ Type='Disk';    Min=10; Rec=30; SSD=$true }
        @{ Type='GPU';     MinVRAM=2; RecVRAM=4; MinOpenGL='3.3' }
    )
    'EnergyPlus' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=4;  Rec=16 }
        @{ Type='Disk';    Min=5;  Rec=15 }
    )
    'PVsyst' = @(
        @{ Type='OS';      MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';     Min=4;  Rec=8 }
        @{ Type='Disk';    Min=5;  Rec=10 }
        @{ Type='NetFx';   Min='4.8' }
    )
}
Write-Ok

# =============================================================================
# INSTALLED SOFTWARE + SYSTEM INVENTORY
# =============================================================================
Write-Stage "Scanning installed software..."
$installed = Get-InstalledSoftware
Write-Host " $($installed.Count) entries." -ForegroundColor Green

Write-Stage "Capturing system inventory..."
$sys = & {
    $os   = Get-CimInstance Win32_OperatingSystem
    $cs   = Get-CimInstance Win32_ComputerSystem
    $cpu  = Get-CimInstance Win32_Processor | Select-Object -First 1
    $gpus = @(Get-CimInstance Win32_VideoController)
    $vramMap = Get-GpuVramMap

    $gpuInfo = foreach ($g in $gpus) {
        $regVram = Resolve-GpuVram -GpuName $g.Name -Map $vramMap
        $wmiVram = if ($g.AdapterRAM -and $g.AdapterRAM -gt 0) { [math]::Round($g.AdapterRAM / 1GB, 2) } else { $null }
        $finalVram = if ($regVram) { $regVram } else { $wmiVram }
        $res = if ($g.CurrentHorizontalResolution -and $g.CurrentVerticalResolution -and
                   $g.CurrentHorizontalResolution -gt 0 -and $g.CurrentVerticalResolution -gt 0) {
            "$($g.CurrentHorizontalResolution)x$($g.CurrentVerticalResolution)"
        } else { '' }
        $refresh = $null
        try { if ($g.CurrentRefreshRate -and $g.CurrentRefreshRate -gt 0) { $refresh = [int]$g.CurrentRefreshRate } } catch { }
        [pscustomobject]@{
            Name = $g.Name; Kind = Get-GpuKind -Name $g.Name
            DriverVersion = $g.DriverVersion
            DriverDate = if ($g.DriverDate) { ([datetime]$g.DriverDate).ToString('yyyy-MM-dd') } else { '' }
            VRAM_GB = $finalVram
            VRAM_Source = if ($regVram) { 'registry' } else { 'wmi' }
            Resolution = $res; RefreshHz = $refresh; VideoProcessor = $g.VideoProcessor
        }
    }

    $disks = @()
    try {
        $vols = Get-Volume -ErrorAction Stop | Where-Object DriveLetter
        foreach ($v in $vols) {
            $disks += [pscustomobject]@{
                Drive = "$($v.DriveLetter):"; Label = $v.FileSystemLabel; FS = $v.FileSystem
                SizeGB = [math]::Round($v.Size / 1GB, 1); FreeGB = [math]::Round($v.SizeRemaining / 1GB, 1)
                FreePct = if ($v.Size -gt 0) { [math]::Round(($v.SizeRemaining / $v.Size) * 100, 1) } else { 0 }
            }
        }
    } catch {
        foreach ($d in Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue) {
            if ($d.Used -ne $null) {
                $size = $d.Used + $d.Free
                $disks += [pscustomobject]@{
                    Drive = "$($d.Name):"; Label = ''; FS = ''
                    SizeGB = [math]::Round($size / 1GB, 1); FreeGB = [math]::Round($d.Free / 1GB, 1)
                    FreePct = if ($size -gt 0) { [math]::Round(($d.Free / $size) * 100, 1) } else { 0 }
                }
            }
        }
    }

    $pf = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue
    $hasDedicated  = @($gpuInfo | Where-Object Kind -eq 'Discrete').Count -gt 0
    $hasIntegrated = @($gpuInfo | Where-Object Kind -eq 'Integrated').Count -gt 0

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        User = "$env:USERDOMAIN\$env:USERNAME"
        OS = "$($os.Caption) ($($os.Version), Build $($os.BuildNumber))"
        OSBuild = "$($os.Version).$($os.BuildNumber)"
        OSVersion = $os.Version
        OSBuildNumber = $os.BuildNumber
        OSDisplayVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).DisplayVersion
        Arch = $os.OSArchitecture
        LastBoot = $os.LastBootUpTime
        InstallDate = $os.InstallDate
        CPU = $cpu.Name
        Cores = $cpu.NumberOfCores
        LogicalCPUs = $cpu.NumberOfLogicalProcessors
        ClockMHz = $cpu.MaxClockSpeed
        RAM_GB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        FreeRAM_GB = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
        GPUs = $gpuInfo
        HasDiscreteGPU = $hasDedicated
        HasIntegrated = $hasIntegrated
        Disks = $disks
        PageFile = $pf
        Power = Get-PowerState
        Battery = Get-BatteryHealth
        IsAdmin = (Test-IsAdmin)
    }
}
Write-Ok

# =============================================================================
# PREREQUISITES
# =============================================================================
Write-Stage "Checking prerequisites..."
$netFx = Get-DotNetFrameworkVersion
$vc    = @(Get-VCRedist)
Write-Ok

# =============================================================================
# WINDOWS HEALTH / NETWORK HEALTH
# =============================================================================
function Get-WindowsHealth {
    param([pscustomobject]$System)
    $r = [ordered]@{
        PendingReboot = $false; RebootReason = ''
        UpdateService = 'Unknown'; UpdateStartMode = ''
        Defender = 'Unknown'; DefenderSig = 'Unknown'; DefenderSigDate = ''
        Firewall = 'Unknown'; Activation = 'Unknown'
        BuildAgeDays = 0; Score = 100
    }
    $rebootKeys = @(
        @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'; Reason='CBS RebootPending'},
        @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'; Reason='Windows Update RebootRequired'},
        @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending'; Reason='CBS PackagesPending'}
    )
    foreach ($k in $rebootKeys) {
        if (Test-Path $k.Path) { $r.PendingReboot = $true; $r.RebootReason = $k.Reason; break }
    }
    try {
        $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop).PendingFileRenameOperations
        if ($pfro) { $r.PendingReboot = $true; if (-not $r.RebootReason) { $r.RebootReason = 'PendingFileRenameOperations' } }
    } catch { }
    try {
        $wu = Get-Service wuauserv -ErrorAction Stop
        $wuStart = (Get-CimInstance Win32_Service -Filter "Name='wuauserv'" -ErrorAction SilentlyContinue).StartMode
        $r.UpdateStartMode = $wuStart
        if ($wuStart -eq 'Disabled') { $r.UpdateService = 'Disabled' }
        elseif ($wu.Status -eq 'Running') { $r.UpdateService = 'Running' }
        else { $r.UpdateService = "Stopped ($wuStart)" }
    } catch { }
    try {
        $def = Get-MpComputerStatus -ErrorAction Stop
        $r.Defender = if ($def.AntivirusEnabled) { 'Active' } else { 'Off' }
        if ($def.AntivirusSignatureVersion) { $r.DefenderSig = $def.AntivirusSignatureVersion }
        if ($def.AntivirusSignatureLastUpdated) { $r.DefenderSigDate = ([datetime]$def.AntivirusSignatureLastUpdated).ToString('yyyy-MM-dd') }
    } catch {
        try {
            $sc = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
            $r.Defender = if ($sc) { 'Active' } else { 'Unknown' }
        } catch { }
    }
    try {
        $fw = Get-NetFirewallProfile -ErrorAction Stop
        $enabled = @($fw | Where-Object Enabled -eq $true).Count
        $r.Firewall = if ($enabled -eq $fw.Count) { 'On' } elseif ($enabled -eq 0) { 'Off' } else { "Partial ($enabled/$($fw.Count))" }
    } catch { }
    try {
        $lic = Get-CimInstance SoftwareLicensingProduct -ErrorAction SilentlyContinue |
               Where-Object { $_.PartialProductKey -and $_.ApplicationID -eq '55c92734-d682-4d71-983e-d6ec3f16059f' } |
               Select-Object -First 1
        if ($lic) {
            $r.Activation = switch ([int]$lic.LicenseStatus) {
                0 { 'Unlicensed' } 1 { 'Licensed' } 2 { 'OOB Grace' } 3 { 'OOT Grace' }
                4 { 'Non-Genuine Grace' } 5 { 'Notification' } 6 { 'Extended Grace' }
                default { "Unknown ($($lic.LicenseStatus))" }
            }
        }
    } catch { }
    if ($System.InstallDate) {
        try { $r.BuildAgeDays = (New-TimeSpan -Start $System.InstallDate -End (Get-Date)).Days } catch { }
    }
    $s = 100
    if ($r.PendingReboot) { $s -= 20 }
    if ($r.UpdateService -eq 'Disabled') { $s -= 15 }
    if ($r.Defender -eq 'Off') { $s -= 15 }
    if ($r.Firewall -eq 'Off') { $s -= 10 }
    if ($r.Activation -in @('Unlicensed','Notification','Non-Genuine Grace')) { $s -= 25 }
    if ($r.BuildAgeDays -gt 3 * 365) { $s -= 10 } elseif ($r.BuildAgeDays -gt 2 * 365) { $s -= 5 }
    $r.Score = [math]::Max(0, $s)
    [pscustomobject]$r
}

function Get-NetworkHealth {
    param([pscustomobject]$System, [array]$Catalog, [array]$Installed)
    $r = [ordered]@{
        Adapters = @(); WifiDetails = @()
        LinkSpeedMbps = 0; LinkSpeedText = ''
        DNS = 'Unknown'; DNSms = $null
        DefaultGW = ''; License = @(); Score = 100; Confidence = 'High'
    }
    try {
        $nics = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object Status -eq 'Up')
        $maxMbps = 0
        foreach ($n in $nics) {
            $mbps = 0
            if ($n.LinkSpeed -match '([\d\.]+)\s*Gbps') { $mbps = [double]$Matches[1] * 1000 }
            elseif ($n.LinkSpeed -match '([\d\.]+)\s*Mbps') { $mbps = [double]$Matches[1] }
            if ($mbps -gt $maxMbps) { $maxMbps = $mbps }
            $r.Adapters += [pscustomobject]@{
                Name = $n.Name; LinkSpeed = $n.LinkSpeed; Mac = $n.MacAddress
                MediaType = $n.MediaType; Description = $n.InterfaceDescription
            }
        }
        $r.LinkSpeedMbps = [int]$maxMbps
        $r.LinkSpeedText = if ($maxMbps -ge 1000) { "$([math]::Round($maxMbps/1000,1)) Gbps" }
                           elseif ($maxMbps -gt 0) { "$maxMbps Mbps" } else { '' }
    } catch { }
    try { $wifi = Get-WifiDetails; if ($wifi.Interfaces.Count -gt 0) { $r.WifiDetails = @($wifi.Interfaces) } } catch { }
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $null = Resolve-DnsName 'microsoft.com' -ErrorAction Stop -QuickTimeout
        $sw.Stop()
        $r.DNSms = [int]$sw.ElapsedMilliseconds
        $r.DNS = 'OK'
    } catch { $r.DNS = 'Failed' }
    try {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Select-Object -First 1
        if ($route) { $r.DefaultGW = $route.NextHop }
    } catch { }
    foreach ($entry in $Catalog) {
        if (-not $entry.Lport) { continue }
        $hit = $false
        foreach ($pat in @($entry.P)) { if ($Installed | Where-Object { $_.DisplayName -like $pat }) { $hit = $true; break } }
        if (-not $hit) { continue }
        $anyOpen = $false
        foreach ($p in $entry.Lport) { if (Test-TcpPort -Port $p -TimeoutMs 800) { $anyOpen = $true; break } }
        $r.License += [pscustomobject]@{ Product = $entry.N; Ports = ($entry.Lport -join ', '); Local = $anyOpen }
    }
    $s = 100
    if ($r.Adapters.Count -eq 0) { $s -= 20 }
    elseif ($r.LinkSpeedMbps -gt 0 -and $r.LinkSpeedMbps -lt 100) { $s -= 15 }
    elseif ($r.LinkSpeedMbps -gt 0 -and $r.LinkSpeedMbps -lt 1000) { $s -= 5 }
    if ($r.DNS -ne 'OK') { $s -= 10 }
    if (-not $r.DefaultGW) { $s -= 10 }
    $r.Score = [math]::Max(0, $s)
    [pscustomobject]$r
}

# =============================================================================
# PREFLIGHT / WHY-SLOW / DISPATCH
# =============================================================================
function Invoke-Preflight {
    param([string]$ProductName, [array]$Catalog, [pscustomobject]$System,
          [string]$NetFx, [array]$VC, [array]$Installed)
    Write-Head "PREFLIGHT: $ProductName"
    $entry = $Catalog | Where-Object { $_.N -eq $ProductName } | Select-Object -First 1
    if (-not $entry) { $entry = $Catalog | Where-Object { $_.N -like "*$ProductName*" } | Select-Object -First 1 }
    if (-not $entry) {
        Write-Host "[ERROR] Product not found: $ProductName" -ForegroundColor Red
        return
    }
    $script:pass = 0; $script:warn = 0; $script:fail = 0
    function Report {
        param([string]$State, [string]$Label, [string]$Detail = '')
        switch ($State) {
            'OK'   { Write-Host "  [ OK ]  " -ForegroundColor Green -NoNewline; $script:pass++ }
            'WARN' { Write-Host "  [WARN]  " -ForegroundColor Yellow -NoNewline; $script:warn++ }
            'FAIL' { Write-Host "  [FAIL]  " -ForegroundColor Red -NoNewline; $script:fail++ }
        }
        Write-Host $Label -NoNewline
        if ($Detail) { Write-Host "  ($Detail)" -ForegroundColor DarkGray } else { Write-Host "" }
    }
    if ($entry.RAM) {
        if ($System.RAM_GB -ge $entry.RAM) { Report 'OK' "RAM" "$($System.RAM_GB) GB >= $($entry.RAM) GB" }
        else { Report 'WARN' "RAM below" "$($System.RAM_GB) GB / $($entry.RAM) GB" }
    }
    if ($entry.Disk) {
        $sysd = $System.Disks | Where-Object Drive -eq "$($env:SystemDrive)"
        if ($sysd -and $sysd.FreeGB -ge $entry.Disk) { Report 'OK' "Disk" "$($sysd.FreeGB) GB free" }
        elseif ($sysd) { Report 'WARN' "Disk tight" "$($sysd.FreeGB) GB / $($entry.Disk) GB" }
    }
    if ($entry.Net) {
        if (Compare-NetVersion -Have $NetFx -Need $entry.Net) { Report 'OK' ".NET" "$NetFx >= $($entry.Net)" }
        else { Report 'FAIL' ".NET" "have $NetFx, need $($entry.Net)" }
    }
    if ($entry.VCPP) {
        if ($VC -and $VC.Count -gt 0) { Report 'OK' "VC++ Runtime" "$($VC.Count) redistributable(s)" }
        else { Report 'FAIL' "VC++ Runtime" "not detected" }
    }
    Write-Host ""
    $verdict = if ($fail -gt 0) { 'NOT READY' } elseif ($warn -gt 2) { 'CAUTION' } else { 'READY' }
    $col = if ($fail -gt 0) { 'Red' } elseif ($warn -gt 2) { 'Yellow' } else { 'Green' }
    Write-Host ("  $script:pass OK   $script:warn WARN   $script:fail FAIL   ->  $verdict") -ForegroundColor $col
    Write-Host ""
}

function Invoke-WhySlow {
    param([pscustomobject]$System)
    Write-Head "WHY IS MY PC SLOW?"
    $ramPctFree = [math]::Round(($System.FreeRAM_GB / $System.RAM_GB) * 100, 1)
    $critDisk = $System.Disks | Sort-Object FreePct | Select-Object -First 1
    $topMem = @()
    try {
        $topMem = Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending |
                  Select-Object -First 8 | ForEach-Object {
                      [pscustomobject]@{ Name = $_.ProcessName; GB = [math]::Round($_.WorkingSet64 / 1GB, 2) }
                  }
    } catch { }
    $topCpu = @()
    try {
        $s1 = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $s1[$_.Id] = $_.TotalProcessorTime.TotalMilliseconds }
        Start-Sleep -Milliseconds 800
        $cores = [math]::Max(1, $System.LogicalCPUs)
        $topCpu = Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            $prev = if ($s1.ContainsKey($_.Id)) { $s1[$_.Id] } else { 0 }
            $delta = $_.TotalProcessorTime.TotalMilliseconds - $prev
            $pct = [math]::Round(($delta / 800) * 100 / $cores, 1)
            [pscustomobject]@{ Name = $_.ProcessName; CPU = $pct }
        } | Sort-Object CPU -Descending | Select-Object -First 8
    } catch { }
    $verdicts = [ordered]@{
        RAM   = if ($ramPctFree -lt 15) { 'CRITICAL' } elseif ($ramPctFree -lt 30) { 'ELEVATED' } else { 'OK' }
        Disk  = if ($critDisk -and $critDisk.FreePct -lt 5) { 'CRITICAL' } elseif ($critDisk -and $critDisk.FreePct -lt 15) { 'ELEVATED' } else { 'OK' }
        CPU   = if (($topCpu | Select-Object -First 1).CPU -gt 60) { 'ELEVATED' } else { 'OK' }
        GPU   = if ($System.HasDiscreteGPU) { 'OK' } else { 'ELEVATED' }
        Power = if ($System.Power.HasBattery -and -not $System.Power.OnAC) { 'ELEVATED' } else { 'OK' }
    }
    $primary = 'None detected'
    foreach ($k in @('RAM','Disk','Power','CPU','GPU')) { if ($verdicts[$k] -eq 'CRITICAL') { $primary = $k; break } }
    if ($primary -eq 'None detected') {
        foreach ($k in @('RAM','Disk','Power','CPU','GPU')) { if ($verdicts[$k] -eq 'ELEVATED') { $primary = $k; break } }
    }
    Write-Host "  Current snapshot" -ForegroundColor Cyan
    Write-Host ("    RAM free            {0} GB / {1} GB ({2}%)" -f $System.FreeRAM_GB, $System.RAM_GB, $ramPctFree)
    Write-Host ("    Worst disk free     {0} GB ({1}% on {2})" -f $critDisk.FreeGB, $critDisk.FreePct, $critDisk.Drive)
    Write-Host ("    Power               {0}" -f $System.Power.StatusText)
    Write-Host ""
    Write-Host "  Verdicts" -ForegroundColor Cyan
    foreach ($k in $verdicts.Keys) {
        $col = switch ($verdicts[$k]) { 'CRITICAL' { 'Red' } 'ELEVATED' { 'Yellow' } default { 'Green' } }
        Write-Host ("    {0,-8} {1}" -f $k, $verdicts[$k]) -ForegroundColor $col
    }
    Write-Host ""
    Write-Host ("  PRIMARY BOTTLENECK: {0}" -f $primary) -ForegroundColor Yellow
    Write-Host ""
    if ($topMem.Count -gt 0) {
        Write-Host "  Top memory consumers" -ForegroundColor Cyan
        foreach ($p in $topMem) { Write-Host ("    {0,-22} {1,6} GB" -f $p.Name, $p.GB) }
        Write-Host ""
    }
    Write-Host ""
}

if ($Preflight) {
    Invoke-Preflight -ProductName $Preflight -Catalog $Script:RawCatalog -System $sys -NetFx $netFx -VC $vc -Installed $installed
    exit 0
}
if ($WhySlow) {
    Invoke-WhySlow -System $sys
    exit 0
}

# =============================================================================
# ONLINE CACHE / FETCH
# =============================================================================
$Script:OnlineCache     = @{}
$Script:OnlineCachePath = Join-Path $env:TEMP 'sigma_online_cache.json'
$Script:OnlineEnabled   = -not $Offline

try {
    if (Test-Path $Script:OnlineCachePath) {
        $cached = Get-Content $Script:OnlineCachePath -Raw | ConvertFrom-Json
        foreach ($p in $cached.PSObject.Properties) { $Script:OnlineCache[$p.Name] = $p.Value }
    }
} catch { }

function Save-OnlineCache {
    try { $Script:OnlineCache | ConvertTo-Json -Depth 6 | Set-Content $Script:OnlineCachePath -Encoding UTF8 } catch { }
}

function Get-Cached {
    param([string]$Key, [scriptblock]$Fetch, [int]$TtlHours = 24)
    if (-not $Script:OnlineEnabled) { return $null }
    if ($Script:OnlineCache.ContainsKey($Key)) {
        $e = $Script:OnlineCache[$Key]
        try {
            $age = (New-TimeSpan -Start ([datetime]$e.Fetched) -End (Get-Date)).TotalHours
            if ($age -lt $TtlHours) { return $e.Value }
        } catch { }
    }
    $val = $null
    try { $val = & $Fetch } catch { Add-Diagnostic 'Online' "Fetch failed for ${Key}: $_" }
    $Script:OnlineCache[$Key] = @{ Value = $val; Fetched = (Get-Date).ToString('s') }
    Save-OnlineCache
    return $val
}

function Invoke-SafeWebRequest {
    param([string]$Url, [int]$TimeoutSec = 8, [hashtable]$Headers = @{})
    if (-not $Headers.ContainsKey('User-Agent')) {
        $Headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SigmaEngineerToolkit/1.7'
    }
    try { return Invoke-WebRequest -Uri $Url -TimeoutSec $TimeoutSec -UseBasicParsing -Headers $Headers -ErrorAction Stop }
    catch { Add-Diagnostic 'Online' "GET $Url failed: $_"; return $null }
}

function Get-CpuPassMarkScore {
    param([string]$CpuName)
    if (-not $CpuName) { return $null }
    $clean = $CpuName -replace '\(R\)','' -replace '\(TM\)','' -replace '\s+CPU\s+@.*$','' `
                      -replace '\s+Processor.*$','' -replace '\s+\d+-Core.*$','' -replace '\s+@.*$','' -replace '\s+',' '
    $clean = $clean.Trim()
    $key = "cpu_passmark_v2_$clean"
    Get-Cached -Key $key -TtlHours 168 -Fetch {
        $q = [uri]::EscapeDataString($clean)
        $r = Invoke-SafeWebRequest -Url "https://www.cpubenchmark.net/cpu.php?cpu=$q"
        if ($r) {
            $html = $r.Content
            if ($html -match 'id="mark-neww"[^>]*>\s*([\d,]+)')              { return [int]($matches[1] -replace ',','') }
            if ($html -match 'class="[^"]*mark-neww[^"]*"[^>]*>\s*([\d,]+)') { return [int]($matches[1] -replace ',','') }
            if ($html -match 'CPU Mark[^<]*<[^>]*>\s*([\d,]+)')               { return [int]($matches[1] -replace ',','') }
        }
        return $null
    }
}

function Get-GpuPassMarkScore {
    param([string]$GpuName)
    if (-not $GpuName) { return $null }
    $clean = ($GpuName -replace '^NVIDIA\s+','' -replace '^AMD\s+','' -replace '^Intel\s+','').Trim()
    $key = "gpu_passmark_v2_$clean"
    Get-Cached -Key $key -TtlHours 168 -Fetch {
        $q = [uri]::EscapeDataString($clean)
        $r = Invoke-SafeWebRequest -Url "https://www.videocardbenchmark.net/gpu.php?gpu=$q"
        if ($r) {
            $html = $r.Content
            if ($html -match 'id="mark-neww"[^>]*>\s*([\d,]+)')              { return [int]($matches[1] -replace ',','') }
            if ($html -match 'G3D Mark[^<]*<[^>]*>\s*([\d,]+)')               { return [int]($matches[1] -replace ',','') }
        }
        return $null
    }
}

function Get-LatestComponentVersion {
    param([string]$Component)
    $key = "latest_comp_v1_$Component"
    Get-Cached -Key $key -TtlHours 168 -Fetch {
        switch ($Component) {
            '.NET Framework' {
                $r = Invoke-SafeWebRequest -Url 'https://dotnet.microsoft.com/en-us/download/dotnet-framework'
                if ($r -and $r.Content -match '\.NET Framework (\d+\.\d+(?:\.\d+)?)') { return $matches[1] }
            }
            '.NET Desktop Runtime' {
                $r = Invoke-SafeWebRequest -Url 'https://dotnet.microsoft.com/en-us/download/dotnet'
                if ($r -and $r.Content -match '\.NET (\d+\.\d+)') { return $matches[1] }
            }
            'VC++ Redistributable' {
                $r = Invoke-SafeWebRequest -Url 'https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist'
                if ($r) {
                    $all = [regex]::Matches($r.Content, 'v14\.(\d+)\.(\d+)\.(\d+)') |
                           ForEach-Object { "14.$($_.Groups[1].Value).$($_.Groups[2].Value).$($_.Groups[3].Value)" }
                    if ($all) { return ($all | Sort-Object { [version]$_ } | Select-Object -Last 1) }
                }
            }
            'Java JRE' {
                $r = Invoke-SafeWebRequest -Url 'https://www.oracle.com/java/technologies/downloads/'
                if ($r -and $r.Content -match 'Java (\d+)') { return $matches[1] }
            }
            'Java JDK' {
                $r = Invoke-SafeWebRequest -Url 'https://www.oracle.com/java/technologies/downloads/'
                if ($r -and $r.Content -match 'Java (\d+)') { return $matches[1] }
            }
            'Python' {
                $r = Invoke-SafeWebRequest -Url 'https://www.python.org/downloads/'
                if ($r -and $r.Content -match 'Python (\d+\.\d+\.\d+)') { return $matches[1] }
            }
            'NVIDIA Driver' {
                try {
                    $r = Invoke-SafeWebRequest -Url 'https://www.nvidia.com/en-us/geforce/drivers/' -TimeoutSec 10
                    if ($r -and $r.Content -match '\b(5[0-9]{2}\.\d{2})\b') { return $matches[1] }
                } catch { }
            }
            'AMD Driver' {
                try {
                    $r = Invoke-SafeWebRequest -Url 'https://www.amd.com/en/support/rss' -TimeoutSec 8
                    if ($r -and $r.Content -match 'Adrenalin[^\d]*(\d+\.\d+\.\d+)') { return $matches[1] }
                } catch { }
            }
        }
        return $null
    }
}

function Get-WingetUpgradeable {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { return @() }
    $key = 'winget_upgradeable_v2'
    Get-Cached -Key $key -TtlHours 6 -Fetch {
        try {
            $raw = & winget upgrade --include-unknown --accept-source-agreements --disable-interactivity 2>$null | Out-String
            $list = @()
            $lines = $raw -split "`r?`n"
            $headerIdx = -1
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^\s*Name\s+Id\s+Version\s+Available\s+Source\s*$') { $headerIdx = $i; break }
            }
            if ($headerIdx -lt 0) { return @() }
            $dataLines = @()
            for ($i = $headerIdx + 1; $i -lt $lines.Count; $i++) {
                $line = $lines[$i]
                if ($line -match '^-{5,}') { continue }
                if ($line -match '^\s*\d+\s+upgrades?\s+available') { break }
                if (-not $line.Trim()) { continue }
                $dataLines += $line
            }
            $headerLine = $lines[$headerIdx]
            $colStarts = @()
            foreach ($m in [regex]::Matches($headerLine, '\S+')) { $colStarts += $m.Index }
            if ($colStarts.Count -lt 5) { return @() }
            foreach ($dl in $dataLines) {
                if ($dl.Length -lt $colStarts[-1] + 1) { $dl = $dl.PadRight($colStarts[-1] + 40) }
                $name      = $dl.Substring($colStarts[0], $colStarts[1] - $colStarts[0]).Trim()
                $id        = $dl.Substring($colStarts[1], $colStarts[2] - $colStarts[1]).Trim()
                $installed = $dl.Substring($colStarts[2], $colStarts[3] - $colStarts[2]).Trim()
                $available = $dl.Substring($colStarts[3], $colStarts[4] - $colStarts[3]).Trim()
                $source    = $dl.Substring($colStarts[4]).Trim()
                if ($name -and $id) {
                    $list += [pscustomobject]@{ Name = $name; Id = $id; Installed = $installed; Available = $available; Source = $source }
                }
            }
            return $list
        } catch { return @() }
    }
}

function Get-DiskMediaTypes {
    try {
        $out = @()
        Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
            $out += [pscustomobject]@{
                FriendlyName = $_.FriendlyName; MediaType = $_.MediaType
                BusType = $_.BusType; SizeGB = [math]::Round($_.Size / 1GB, 1)
            }
        }
        return $out
    } catch { return @() }
}

function Get-RamDetail {
    try {
        $mods = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop)
        if ($mods.Count -eq 0) { return $null }
        $speedMhz = ($mods | Measure-Object -Property Speed -Average).Average
        $typeCode = ($mods | Select-Object -First 1).SMBIOSMemoryType
        $type = switch ($typeCode) { 26 { 'DDR4' } 34 { 'DDR5' } 24 { 'DDR3' } 21 { 'DDR2' } default { "Unknown ($typeCode)" } }
        return [pscustomobject]@{
            Modules = $mods.Count; SpeedMHz = [int]$speedMhz; Type = $type
            TotalGB = [math]::Round((($mods | Measure-Object -Property Capacity -Sum).Sum) / 1GB, 1)
        }
    } catch { return $null }
}

function Get-MotherboardInfo {
    try {
        $bb   = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
        $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
        return [pscustomobject]@{
            Manufacturer = $bb.Manufacturer; Product = $bb.Product; Version = $bb.Version
            SerialNumber = $bb.SerialNumber; BiosVendor = $bios.Manufacturer
            BiosVersion = $bios.SMBIOSBIOSVersion
            BiosReleaseDate = if ($bios.ReleaseDate) { ([datetime]$bios.ReleaseDate).ToString('yyyy-MM-dd') } else { '' }
        }
    } catch { return $null }
}

function Get-RamPartNumbers {
    try {
        $mods = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop)
        $out = @()
        foreach ($m in $mods) {
            $out += [pscustomobject]@{
                Manufacturer = $m.Manufacturer; PartNumber = $m.PartNumber
                CapacityGB = [math]::Round($m.Capacity / 1GB, 0)
                SpeedMHz = $m.Speed; ConfiguredMHz = $m.ConfiguredClockSpeed
                TypeCode = $m.SMBIOSMemoryType; FormFactor = $m.FormFactor
            }
        }
        return $out
    } catch { return @() }
}

function Get-AdapterCapabilities {
    try {
        $out = @()
        foreach ($n in Get-NetAdapter -Physical -ErrorAction SilentlyContinue) {
            $maxSpeed = $null
            if ($n.InterfaceDescription -match '2\.5G') { $maxSpeed = '2.5 Gb' }
            elseif ($n.InterfaceDescription -match '10G') { $maxSpeed = '10 Gb' }
            elseif ($n.InterfaceDescription -match '(\d+)\s*Gb') { $maxSpeed = "$($matches[1]) Gb" }
            elseif ($n.InterfaceDescription -match '(\d+)\s*Mb') { $maxSpeed = "$($matches[1]) Mb" }
            $drv = try { (Get-NetAdapter -Name $n.Name -ErrorAction Stop).DriverVersion } catch { '' }
            $out += [pscustomobject]@{
                Name = $n.Name; Description = $n.InterfaceDescription
                LinkSpeed = $n.LinkSpeed; MaxSpeed = $maxSpeed; Status = $n.Status
                DriverVersion = $drv
            }
        }
        return $out
    } catch { return @() }
}

function Invoke-OnlineEnrichment {
    param([pscustomobject]$System)
    $enrich = [ordered]@{
        CpuScore = $null; GpuScores = @()
        LatestNvidia = $null; LatestAmd = $null; LatestIntelGpu = $null
        Upgradeable = @(); DiskMediaTypes = @(); Ram = $null
        EnrichedAt = (Get-Date).ToString('s'); OnlineAvailable = $true
    }
    $enrich.DiskMediaTypes = @(Get-DiskMediaTypes)
    $enrich.Ram = Get-RamDetail
    if (-not $Script:OnlineEnabled) { $enrich.OnlineAvailable = $false; return [pscustomobject]$enrich }
    Write-Stage "Fetching live online data (PassMark, winget, vendor feeds)..."
    $enrich.CpuScore = Get-CpuPassMarkScore -CpuName $System.CPU
    foreach ($g in $System.GPUs) {
        if ($g.Kind -eq 'Integrated') { continue }
        $score = Get-GpuPassMarkScore -GpuName $g.Name
        $enrich.GpuScores += [pscustomobject]@{ Name = $g.Name; Score = $score }
    }
    $hasNvidia = @($System.GPUs | Where-Object { $_.Name -match 'NVIDIA|GeForce|RTX|Quadro' }).Count -gt 0
    $hasAmd    = @($System.GPUs | Where-Object { $_.Name -match 'Radeon|AMD' }).Count -gt 0
    $hasIntel  = @($System.GPUs | Where-Object { $_.Name -match 'Intel' }).Count -gt 0
    if ($hasNvidia) { $enrich.LatestNvidia = Get-LatestComponentVersion -Component 'NVIDIA Driver' }
    if ($hasAmd)    { $enrich.LatestAmd = Get-LatestComponentVersion -Component 'AMD Driver' }
    $enrich.Upgradeable = @(Get-WingetUpgradeable)
    if (-not $enrich.CpuScore -and $enrich.GpuScores.Count -eq 0 -and $enrich.Upgradeable.Count -eq 0) {
        $enrich.OnlineAvailable = $false
    }
    Write-Ok
    return [pscustomobject]$enrich
}

$windowsHealth = Get-WindowsHealth -System $sys
$networkHealth = Get-NetworkHealth -System $sys -Catalog $Script:RawCatalog -Installed $installed
$motherboard   = Get-MotherboardInfo
$enrichment    = Invoke-OnlineEnrichment -System $sys

Write-Stage "Scanning event logs (last 7 days)..."
$eventLogs = Get-EventLogIssues
Write-Ok
$defenderExcl = Get-DefenderExclusions

# =============================================================================
# DISCIPLINE-DRIVEN REQUIREMENT SCAN
# =============================================================================
$requirementResults = @()

if ($Disciplines.Count -gt 0) {
    Write-Head "Discipline Requirement Scan - $($Disciplines -join ', ')"
    Write-Host "  For each selected app, every vendor requirement is checked against this PC." -ForegroundColor DarkGray
    Write-Host ""

    $seen = @{}
    foreach ($entry in $Script:RawCatalog) {
        $overlap = $false
        foreach ($d in $entry.D) { if ($Disciplines -contains $d) { $overlap = $true; break } }
        if (-not $overlap -or $seen.ContainsKey($entry.N)) { continue }
        $seen[$entry.N] = $true

        $specs = @()
        if ($Script:SoftwareRequirements.ContainsKey($entry.N)) {
            $specs = @($Script:SoftwareRequirements[$entry.N])
        } else {
            if ($entry.RAM)  { $specs += @{ Type='RAM';  Min=[int][math]::Ceiling($entry.RAM*0.5); Rec=[int]$entry.RAM } }
            if ($entry.Disk) { $specs += @{ Type='Disk'; Min=[int][math]::Ceiling($entry.Disk*0.5); Rec=[int]$entry.Disk } }
            if ($entry.GPU)  { $specs += @{ Type='GPU';  MinVRAM=1; RecVRAM=2; MinDirectX='11' } }
            if ($entry.Net)  { $specs += @{ Type='NetFx'; Min=$entry.Net } }
            if ($entry.VCPP) { $specs += @{ Type='VCRedist'; Min='14.30' } }
            if ($entry.Lsvc) {
                foreach ($pat in $entry.Lsvc) { $specs += @{ Type='LicenseSvc'; Pattern=$pat; Ports=@($entry.Lport) } }
            }
        }

        $checks = New-Object System.Collections.Generic.List[object]
        foreach ($spec in $specs) {
            $checks.Add((Test-Requirement -Spec $spec -System $sys -Enrichment $enrichment))
        }

        # annotate latest published version for software-version types
        foreach ($c in $checks) {
            if ($c.Type -in @('NetFx','NetDesktop','VCRedist','Java','Python','WebView2')) {
                $latest = Get-LatestComponentVersion -Component $c.Component
                $c | Add-Member -NotePropertyName LatestOnline -NotePropertyValue $latest -Force
            }
        }

        $fail = @($checks | Where-Object Status -eq 'FAIL').Count
        $warn = @($checks | Where-Object Status -eq 'WARN').Count
        $unk  = @($checks | Where-Object Status -eq 'UNKNOWN').Count

        $verdict =
            if     ($fail -gt 0) { 'DOES NOT MEET' }
            elseif ($warn -gt 0) { 'PARTIALLY MEETS' }
            elseif ($unk  -gt 0) { 'MEETS (unverified)' }
            else                 { 'MEETS' }

        $requirementResults += [pscustomobject]@{
            Product     = $entry.N
            Disciplines = ($entry.D -join ', ')
            Kind        = $entry.K
            Verdict     = $verdict
            Failures    = $fail
            Warnings    = $warn
            Unverified  = $unk
            Checks      = $checks
        }
    }

    $requirementResults = @($requirementResults | Sort-Object Failures, Warnings, Product)
    Write-Host ("  {0} product(s) evaluated." -f $requirementResults.Count) -ForegroundColor Green
    Write-Host ""

    foreach ($rr in $requirementResults) {
        $col = switch ($rr.Verdict) {
            'MEETS'             { 'Green' }
            'MEETS (unverified)'{ 'Green' }
            'PARTIALLY MEETS'   { 'Yellow' }
            'DOES NOT MEET'     { 'Red' }
            default             { 'Gray' }
        }
        Write-Host ("  {0,-30} {1}" -f $rr.Product, $rr.Verdict) -ForegroundColor $col
        foreach ($c in $rr.Checks) {
            $flag = switch ($c.Status) {
                'PASS'    { 'OK  ' }
                'WARN'    { 'WARN' }
                'FAIL'    { 'FAIL' }
                'UNKNOWN' { 'n/a ' }
            }
            $mark = switch ($c.Status) {
                'PASS'    { '  +' }
                'WARN'    { '  ~' }
                'FAIL'    { '  !' }
                'UNKNOWN' { '  ?' }
            }
            $line = "{0} [{1,-4}] {2,-12} need: {3,-34} have: {4}" -f $mark, $flag, $c.Component, $c.Required, $c.Actual
            if ($c.LatestOnline) { $line += "  (latest: $($c.LatestOnline))" }
            $lineCol = switch ($c.Status) {
                'PASS' { 'DarkGray' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'DarkGray' }
            }
            Write-Host $line -ForegroundColor $lineCol
        }
        Write-Host ""
    }
}

# =============================================================================
# DISCIPLINE ROLLUP (only when no disciplines chosen)
# =============================================================================
if ($Disciplines.Count -eq 0) {
    Write-Head "Full system scan - no discipline filter"
    Write-Host "  Tip: add -Disciplines Civil,FEA,... to focus the scan on specific apps." -ForegroundColor DarkGray
    Write-Host ""
}

# =============================================================================
# PROJECT GUARDIAN
# =============================================================================
function Get-DwgReferences {
    param([string]$FilePath)
    $refs = New-Object System.Collections.Generic.List[object]
    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
    try {
        if ($ext -eq '.dxf') {
            if ((Get-Item -LiteralPath $FilePath).Length -gt 200MB) { return $refs }
            $text = Get-Content -LiteralPath $FilePath -Raw -ErrorAction Stop
            foreach ($m in [regex]::Matches($text, '\(0\s*\.\s*"BLOCK"\)[\s\S]{0,4000}?\(2\s*\.\s*"\*X[^"]*"\)[\s\S]{0,4000}?\(1\s*\.\s*"([^"]+)"\)')) {
                $refs.Add([pscustomobject]@{ Type = 'XREF'; Path = $m.Groups[1].Value })
            }
            foreach ($m in [regex]::Matches($text, '\(0\s*\.\s*"IMAGEDEF"\)[\s\S]{0,3000}?\(1\s*\.\s*"([^"]+)"\)')) {
                $refs.Add([pscustomobject]@{ Type = 'IMAGE'; Path = $m.Groups[1].Value })
            }
        } elseif ($ext -eq '.dwg') {
            $fi = Get-Item -LiteralPath $FilePath
            if ($fi.Length -gt 250MB) { return $refs }
            $bytes = [System.IO.File]::ReadAllBytes($FilePath)
            $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
            $extPat = '(dwg|dxf|pdf|jpg|jpeg|png|tif|tiff|shx|ttf|shp|dgn|dwf|dwfx)'
            foreach ($m in [regex]::Matches($ascii, "[A-Za-z]:\\\\[^\x00-\x1F`"<>|]{0,250}\.$extPat", 'IgnoreCase')) {
                $refs.Add([pscustomobject]@{ Type = 'REF'; Path = $m.Value })
            }
        }
    } catch {
        Add-Diagnostic 'XREF' "Failed to parse ${FilePath}: $_"
    }
    return $refs
}

function Invoke-ProjectGuardian {
    param([string]$Root)
    if (-not (Test-Path $Root)) { Write-Host "[ERROR] Path not found: $Root" -ForegroundColor Red; return $null }
    Write-Head "Project Guardian: $Root"
    $engExt = @('.dwg','.dxf','.rvt','.rfa','.nwd','.nwc','.ifc','.sldprt','.sldasm','.slddrw',
                '.step','.stp','.iges','.igs','.stl','.inp','.cdb','.mph','.mat','.m','.slx',
                '.kicad_pcb','.kicad_sch','.sch','.brd','.shp','.shx','.dbf','.las','.laz',
                '.tif','.tiff','.catpart','.catproduct','.prt','.asm','.3dxml','.model','.exp','.cgr')
    $backupExt = @('.bak','.tmp','.sv$','.dwl','.dwl2','.ac$','.err','.log')
    $scan = @(Get-ChildItem -LiteralPath $Root -Recurse -Force -File -ErrorAction SilentlyContinue)
    $byExt = @{}; $totalBytes = 0; $longPaths = 0; $backupFiles = 0
    $largeFiles = 0; $largeBytes = 0; $oldBackups = 0
    $cutoff = (Get-Date).AddDays(-180)
    foreach ($f in $scan) {
        $ext = $f.Extension.ToLower()
        if (-not $byExt.ContainsKey($ext)) { $byExt[$ext] = 0 }
        $byExt[$ext]++
        $totalBytes += $f.Length
        if ($f.FullName.Length -gt 240) { $longPaths++ }
        if ($backupExt -contains $ext) { $backupFiles++; if ($f.LastWriteTime -lt $cutoff) { $oldBackups++ } }
        if ($f.Length -gt 500MB) { $largeFiles++; $largeBytes += $f.Length }
    }
    $engFiles = 0
    foreach ($k in $byExt.Keys) { if ($engExt -contains $k) { $engFiles += $byExt[$k] } }
    Write-Host ""
    Write-Host ("  Total files:          {0}" -f $scan.Count)
    Write-Host ("  Total size:           {0} GB" -f [math]::Round($totalBytes/1GB, 2))
    Write-Host ("  Engineering files:    {0}" -f $engFiles)
    Write-Host ("  Long paths (>240):    {0}" -f $longPaths)
    Write-Host ("  Backup/temp files:    {0} (older than 180 days: {1})" -f $backupFiles, $oldBackups)
    $penalty = 0
    if ($longPaths -gt 0)  { $penalty += [math]::Min(25, $longPaths) }
    if ($oldBackups -gt 5) { $penalty += [math]::Min(15, [int]($oldBackups / 5)) }
    $health = [math]::Max(0, 100 - $penalty)
    Write-Host ("  Project Health: {0}%" -f $health) -ForegroundColor Cyan
    Write-Host ""
    return [pscustomobject]@{
        Root = $Root; TotalFiles = $scan.Count; TotalGB = [math]::Round($totalBytes/1GB, 2)
        EngineeringFiles = $engFiles; LongPaths = $longPaths; BackupFiles = $backupFiles
        OldBackups = $oldBackups; LargeFiles = $largeFiles
        LargeGB = [math]::Round($largeBytes/1GB, 2); ByExtension = $byExt; Health = $health
    }
}

$guardian = $null
if ($ProjectGuardian) { $guardian = Invoke-ProjectGuardian -Root $ProjectGuardian }

# =============================================================================
# WRITE REPORT
# =============================================================================
Write-Stage "Writing report (HTML / JSON / CSV)..."
Ensure-Folder $exportPath

# JSON
[pscustomobject]@{
    GeneratedAt         = (Get-Date).ToString('s')
    SelectedDisciplines = $Disciplines
    System              = $sys
    Motherboard         = $motherboard
    NetFx               = $netFx
    VCRedist            = $vc
    WindowsHealth       = $windowsHealth
    NetworkHealth       = $networkHealth
    Enrichment          = $enrichment
    EventLogs           = $eventLogs
    DefenderExclusions  = $defenderExcl
    Guardian            = $guardian
    RequirementResults  = $requirementResults
    InstalledSoftware   = $installed
} | ConvertTo-Json -Depth 12 | Set-Content "$reportBase.json" -Encoding UTF8

# CSV - requirement grid
if ($requirementResults.Count -gt 0) {
    $rows = foreach ($rr in $requirementResults) {
        foreach ($c in $rr.Checks) {
            [pscustomobject]@{
                Product     = $rr.Product
                Disciplines = $rr.Disciplines
                Verdict     = $rr.Verdict
                Component   = $c.Component
                Type        = $c.Type
                Required    = $c.Required
                Actual      = $c.Actual
                Status      = $c.Status
                Note        = $c.Note
                LatestOnline = if ($c.PSObject.Properties.Match('LatestOnline').Count) { $c.LatestOnline } else { '' }
            }
        }
    }
    $rows | Export-Csv "$reportBase.csv" -NoTypeInformation -Encoding UTF8
}

# HTML
$style = @'
<style>
 body{font-family:'Segoe UI',Arial,sans-serif;margin:24px;color:#1a1a1a;background:#f7f8fa}
 h1{color:#0b5394;margin-bottom:4px}
 h2{color:#0b5394;margin-top:32px;border-bottom:2px solid #dde3ec;padding-bottom:4px}
 h3{color:#222;margin-top:20px}
 .sub{color:#555;font-size:12px;margin-top:0}
 .card{background:#fff;border:1px solid #e0e4ea;border-radius:8px;padding:14px 18px;margin:10px 0;box-shadow:0 1px 2px rgba(0,0,0,.03)}
 table{border-collapse:collapse;width:100%;margin:8px 0 16px 0;font-size:13px;background:#fff}
 th,td{border:1px solid #e0e4ea;padding:6px 8px;text-align:left;vertical-align:top}
 th{background:#eef2f8}
 tr:nth-child(even) td{background:#fafbfd}
 .chip{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff}
 .chip.green{background:#1c9b4b}.chip.yellow{background:#d18b00}.chip.red{background:#c23636}
 .chip.gray{background:#8b95a5}.chip.darkgray{background:#4a5568}.chip.blue{background:#2b6cb0}
 .small{font-size:12px;color:#666}
 .hero{background:linear-gradient(135deg,#0b5394,#0a3d6e);color:#fff;border-radius:12px;padding:28px 24px;margin:10px 0 20px 0;text-align:center}
 .hero-num{font-size:52px;font-weight:800;line-height:1}
 .hero-cats{display:flex;flex-wrap:wrap;justify-content:center;gap:12px;margin-top:18px}
 .hero-cats > div{background:rgba(255,255,255,.12);padding:8px 12px;border-radius:8px;min-width:110px}
 .hero-cats b{display:block;font-size:18px;font-weight:700}
 .hero-cats span{font-size:10px;text-transform:uppercase;letter-spacing:1px;opacity:.85}
 .product-block{margin:20px 0;padding:14px 18px;background:#fff;border-left:5px solid #8b95a5;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,.05)}
 .product-block.meets{border-left-color:#1c9b4b}
 .product-block.partial{border-left-color:#d18b00}
 .product-block.fails{border-left-color:#c23636}
 .product-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
 .product-name{font-size:15px;font-weight:700}
 .product-disc{font-size:11px;color:#8b95a5}
</style>
'@

$chipForVerdict = @{
    'MEETS'              = 'green'
    'MEETS (unverified)' = 'green'
    'PARTIALLY MEETS'    = 'yellow'
    'DOES NOT MEET'      = 'red'
}
$chipForStatus = @{ 'PASS'='green'; 'WARN'='yellow'; 'FAIL'='red'; 'UNKNOWN'='gray' }

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("<!doctype html><html><head><meta charset='utf-8'><title>Sigma Engineer Toolkit</title>$style</head><body>")
[void]$sb.AppendLine("<h1>Sigma Engineer Toolkit</h1>")
[void]$sb.AppendLine("<p class='sub'>Generated $(Get-Date) on $($sys.ComputerName) by $($sys.User)</p>")

# Hero
[void]$sb.AppendLine("<div class='hero'>")
if ($Disciplines.Count -gt 0) {
    [void]$sb.AppendLine("<div class='hero-num'>$($requirementResults.Count)</div>")
    [void]$sb.AppendLine("<div>apps scanned in $($Disciplines -join ', ')</div>")
} else {
    [void]$sb.AppendLine("<div class='hero-num'>$($Script:CatalogCount)</div>")
    [void]$sb.AppendLine("<div>catalog products available</div>")
}
[void]$sb.AppendLine("<div class='hero-cats'>")
$meets = @($requirementResults | Where-Object Verdict -eq 'MEETS').Count
$partial = @($requirementResults | Where-Object Verdict -eq 'PARTIALLY MEETS').Count
$fails = @($requirementResults | Where-Object Verdict -eq 'DOES NOT MEET').Count
if ($Disciplines.Count -gt 0) {
    [void]$sb.AppendLine("<div><b>$meets</b><span>Meets</span></div>")
    [void]$sb.AppendLine("<div><b>$partial</b><span>Partial</span></div>")
    [void]$sb.AppendLine("<div><b>$fails</b><span>Fails</span></div>")
} else {
    [void]$sb.AppendLine("<div><b>$($sys.RAM_GB) GB</b><span>RAM</span></div>")
    [void]$sb.AppendLine("<div><b>$($sys.Cores)C/$($sys.LogicalCPUs)T</b><span>CPU</span></div>")
    [void]$sb.AppendLine("<div><b>$(if($sys.HasDiscreteGPU){'Yes'}else{'No'})</b><span>Discrete GPU</span></div>")
}
[void]$sb.AppendLine("</div></div>")

# Machine
$cpuMarkText = if ($enrichment.CpuScore) { [string]$enrichment.CpuScore } else { 'unavailable' }
[void]$sb.AppendLine("<h2>Machine</h2><div class='card'><table>")
foreach ($kv in @(
    @('OS', $sys.OS), @('Display version', $sys.OSDisplayVersion),
    @('Architecture', $sys.Arch),
    @('CPU', "$($sys.CPU) ($($sys.Cores)C/$($sys.LogicalCPUs)T @ $($sys.ClockMHz) MHz)"),
    @('RAM', "$($sys.RAM_GB) GB (free $($sys.FreeRAM_GB) GB)"),
    @('.NET Framework', $netFx),
    @('VC++ Redistributables', "$($vc.Count) installed"),
    @('PowerShell', $PSVersionTable.PSVersion.ToString()),
    @('Admin', $sys.IsAdmin),
    @('Power', $sys.Power.StatusText),
    @('PassMark CPU Mark', $cpuMarkText)
)) {
    [void]$sb.AppendLine("<tr><th style='width:220px'>$($kv[0])</th><td>$($kv[1])</td></tr>")
}
[void]$sb.AppendLine("</table></div>")

# GPUs
[void]$sb.AppendLine("<h2>Graphics</h2><div class='card'><table><tr><th>GPU</th><th>Kind</th><th>Driver</th><th>Date</th><th>VRAM (GB)</th><th>Resolution</th><th>G3D Mark</th></tr>")
foreach ($g in $sys.GPUs) {
    $score = ($enrichment.GpuScores | Where-Object { $_.Name -eq $g.Name } | Select-Object -First 1).Score
    [void]$sb.AppendLine("<tr><td>$($g.Name)</td><td>$($g.Kind)</td><td>$($g.DriverVersion)</td><td>$($g.DriverDate)</td><td><b>$($g.VRAM_GB)</b></td><td>$($g.Resolution)</td><td>$(if($score){$score}else{'-'})</td></tr>")
}
[void]$sb.AppendLine("</table></div>")

# Disks
[void]$sb.AppendLine("<h2>Disks</h2><div class='card'><table><tr><th>Drive</th><th>Label</th><th>FS</th><th>Size GB</th><th>Free GB</th><th>Free %</th></tr>")
foreach ($d in $sys.Disks) {
    $cls = if ($d.FreePct -lt 10) { 'red' } elseif ($d.FreePct -lt 20) { 'yellow' } else { 'green' }
    [void]$sb.AppendLine("<tr><td>$($d.Drive)</td><td>$($d.Label)</td><td>$($d.FS)</td><td>$($d.SizeGB)</td><td>$($d.FreeGB)</td><td><span class='chip $cls'>$($d.FreePct)%</span></td></tr>")
}
[void]$sb.AppendLine("</table></div>")

# Requirement scan section
if ($requirementResults.Count -gt 0) {
    [void]$sb.AppendLine("<h2>Discipline Requirement Scan - $($Disciplines -join ', ')</h2>")
    [void]$sb.AppendLine("<p class='small'>For each app, every vendor requirement is checked against this PC. Online sources verify hardware scores and latest published software versions where available.</p>")

    foreach ($rr in $requirementResults) {
        $cls = if ($rr.Verdict -eq 'MEETS' -or $rr.Verdict -eq 'MEETS (unverified)') { 'meets' }
               elseif ($rr.Verdict -eq 'PARTIALLY MEETS') { 'partial' } else { 'fails' }
        $chipCls = if ($chipForVerdict.ContainsKey($rr.Verdict)) { $chipForVerdict[$rr.Verdict] } else { 'gray' }

        [void]$sb.AppendLine("<div class='product-block $cls'>")
        [void]$sb.AppendLine("<div class='product-head'>")
        [void]$sb.AppendLine("<div><div class='product-name'>$($rr.Product)</div><div class='product-disc'>$($rr.Disciplines) · $($rr.Kind)</div></div>")
        [void]$sb.AppendLine("<div><span class='chip $chipCls'>$($rr.Verdict)</span></div>")
        [void]$sb.AppendLine("</div>")
        [void]$sb.AppendLine("<table>")
        [void]$sb.AppendLine("<tr><th style='width:160px'>Component</th><th style='width:220px'>Required</th><th style='width:220px'>Actual</th><th style='width:80px'>Status</th><th>Note</th></tr>")
        foreach ($c in $rr.Checks) {
            $sc = if ($chipForStatus.ContainsKey($c.Status)) { $chipForStatus[$c.Status] } else { 'gray' }
            $latest = if ($c.PSObject.Properties.Match('LatestOnline').Count -and $c.LatestOnline) { " <span class='small'>(latest online: $($c.LatestOnline))</span>" } else { '' }
            [void]$sb.AppendLine("<tr><td><b>$($c.Component)</b></td><td>$($c.Required)$latest</td><td>$($c.Actual)</td><td><span class='chip $sc'>$($c.Status)</span></td><td class='small'>$($c.Note)</td></tr>")
        }
        [void]$sb.AppendLine("</table></div>")
    }
}

# Windows Health
[void]$sb.AppendLine("<h2>Windows Health</h2><div class='card'><table>")
$rb = if ($windowsHealth.PendingReboot) { "<span class='chip red'>YES</span> $($windowsHealth.RebootReason)" } else { "<span class='chip green'>No</span>" }
[void]$sb.AppendLine("<tr><th style='width:220px'>Pending reboot</th><td>$rb</td></tr>")
[void]$sb.AppendLine("<tr><th>Windows Update service</th><td>$($windowsHealth.UpdateService)</td></tr>")
[void]$sb.AppendLine("<tr><th>Defender</th><td>$($windowsHealth.Defender)</td></tr>")
[void]$sb.AppendLine("<tr><th>Defender signature</th><td>$($windowsHealth.DefenderSig) ($($windowsHealth.DefenderSigDate))</td></tr>")
[void]$sb.AppendLine("<tr><th>Firewall</th><td>$($windowsHealth.Firewall)</td></tr>")
[void]$sb.AppendLine("<tr><th>Activation</th><td>$($windowsHealth.Activation)</td></tr>")
[void]$sb.AppendLine("<tr><th>Build age</th><td>$($windowsHealth.BuildAgeDays) days</td></tr>")
[void]$sb.AppendLine("</table></div>")

# Event logs
[void]$sb.AppendLine("<h2>Event Logs (last 7 days)</h2><div class='card'><table>")
[void]$sb.AppendLine("<tr><th style='width:220px'>WHEA errors</th><td>$($eventLogs.WheaCount)</td></tr>")
[void]$sb.AppendLine("<tr><th>Disk / controller errors</th><td>$($eventLogs.DiskErrors)</td></tr>")
[void]$sb.AppendLine("<tr><th>Thermal events</th><td>$($eventLogs.ThermalEvents)</td></tr>")
[void]$sb.AppendLine("<tr><th>Unexpected shutdowns</th><td>$($eventLogs.UnexpectedShutdown)</td></tr>")
[void]$sb.AppendLine("<tr><th>Application crashes</th><td>$($eventLogs.AppCrashes)</td></tr>")
[void]$sb.AppendLine("</table></div>")

# Installed software
[void]$sb.AppendLine("<h2>Installed Software ($($installed.Count))</h2><div class='card'><table>")
[void]$sb.AppendLine("<tr><th>Name</th><th>Version</th><th>Publisher</th></tr>")
foreach ($s in ($installed | Sort-Object DisplayName | Select-Object -First 200)) {
    [void]$sb.AppendLine("<tr><td>$($s.DisplayName)</td><td>$($s.DisplayVersion)</td><td>$($s.Publisher)</td></tr>")
}
[void]$sb.AppendLine("</table></div>")

if ($guardian) {
    [void]$sb.AppendLine("<h2>Project Guardian</h2><div class='card'><table>")
    [void]$sb.AppendLine("<tr><th style='width:220px'>Root</th><td>$($guardian.Root)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Total files</th><td>$($guardian.TotalFiles)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Total size</th><td>$($guardian.TotalGB) GB</td></tr>")
    [void]$sb.AppendLine("<tr><th>Engineering files</th><td>$($guardian.EngineeringFiles)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Long paths</th><td>$($guardian.LongPaths)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Backup/temp files</th><td>$($guardian.BackupFiles) (old: $($guardian.OldBackups))</td></tr>")
    [void]$sb.AppendLine("<tr><th>Project health</th><td><b>$($guardian.Health)%</b></td></tr>")
    [void]$sb.AppendLine("</table></div>")
}

[void]$sb.AppendLine("<p class='small'>End of report. Requirements are checked against curated vendor specifications; verify against vendor documentation before critical deployments.</p>")
[void]$sb.AppendLine("</body></html>")

$sb.ToString() | Set-Content "$reportBase.html" -Encoding UTF8
Write-Ok

# =============================================================================
# FINAL
# =============================================================================
if (Test-Path $errorLog) { Remove-Item $errorLog -Force -ErrorAction SilentlyContinue }

Write-Host "[SUCCESS] Engineering diagnostic complete." -ForegroundColor Green
Write-Host "[INFO] HTML : $reportBase.html" -ForegroundColor Cyan
Write-Host "[INFO] JSON : $reportBase.json" -ForegroundColor Cyan
Write-Host "[INFO] CSV  : $reportBase.csv"  -ForegroundColor Cyan
Write-Host ""
Write-Host "Have a good day!" -ForegroundColor Cyan
Write-Host ""

if ($NonInteractive) { exit 0 }

$finalChoice = Read-Host "Press R to open report folder, or Q to quit"
switch -Regex ($finalChoice) {
    '^[Rr]$' { Start-Process $exportPath }
    default  { exit 0 }
}
