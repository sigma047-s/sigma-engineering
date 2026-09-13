<#
.SYNOPSIS
    Sigma Engineer Toolkit — engineering workstation diagnostic + software installer.
.DESCRIPTION
    Read-only diagnostic pass over every engineering discipline.
    Detects installed software, checks prerequisites, writes a report.
    Includes health scoring, structured findings, preflight, project guardian,
    Windows/Network health, License Center, live GPU sampling, and a winget-based
    software installer with manual download fallbacks.

    IMPORTANT: This tool produces HEURISTIC readiness scores, not vendor
    certifications. All requirement values are sourced from vendor documentation
    where noted. Unverified values are marked as such.
.PARAMETER Disciplines
    Optional filter. If set, only products relevant to these disciplines are
    fully evaluated. Others are marked NotApplicable.
.PARAMETER Preflight
    Run a single-product preflight readiness check (e.g. -Preflight ANSYS).
    Skips the full report.
.PARAMETER ProjectGuardian
    Path to a project folder to inspect for engineering project issues.
.PARAMETER DeepScan
    Also measure cache folders. Slower.
.PARAMETER WhySlow
    Quick bottleneck snapshot. Skips the full report.
.PARAMETER LiveGpuSample
    Sample GPU engine utilization via performance counters during the scan.
.PARAMETER NonInteractive
    Skip confirmation prompts.
.PARAMETER RedactPersonalInfo
    Remove username, computer name, and MAC addresses from reports.
.PARAMETER Install
    Enter interactive software installer (choose discipline, then products).
.PARAMETER InstallList
    Non-interactive batch install by product name(s), e.g.
    -Install -InstallList "Python","Git","KiCad".
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
    [switch]$RedactPersonalInfo,
    [switch]$Install,
    [string[]]$InstallList = @()
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# =============================================================================
# HELPER FUNCTIONS (unchanged where correct)
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
    param(
        [string]$ComputerName,
        [int]$Port,
        [int]$TimeoutMs = 1500
    )
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return $false }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($iar)
        return $true
    } catch { return $false }
    finally { try { $client.Close() } catch { } }
}

# ---------- GPU detection (fixed) ----------
function Get-GpuKind {
    param(
        [string]$Name,
        [string]$PnPDeviceID = ''
    )
    if (-not $Name) { return 'Unknown' }
    $n = $Name.ToLower()
    $id = if ($PnPDeviceID) { $PnPDeviceID.ToUpper() } else { '' }

    # Vendor from PnP ID (VEN_xxxx) is more reliable than name matching
    $isNvidia  = $id -match 'VEN_10DE'
    $isAMD     = $id -match 'VEN_1002|VEN_1022'
    $isIntel   = $id -match 'VEN_8086'
    $isMicrosoft = $n -match 'microsoft basic'

    if ($isMicrosoft) { return 'Basic' }

    # Known Intel discrete families
    if ($isIntel) {
        if ($n -match 'arc\s+(a|b)\d|dg1|dg2|battlemage') { return 'Discrete' }
        if ($n -match 'iris xe|uhd graphics|hd graphics') { return 'Integrated' }
        return 'Unknown'
    }

    if ($isNvidia) { return 'Discrete' }

    if ($isAMD) {
        # Known AMD discrete families
        if ($n -match 'radeon\s+(rx|pro|vii)|firepro|instinct|vega\s+(56|64)|navi') { return 'Discrete' }
        if ($n -match 'radeon\s+graphics|vega\s+\d+\s+graphics') { return 'Integrated' }
        return 'Unknown'
    }

    # Fallback name-based classification
    if ($n -match 'nvidia|geforce|rtx|quadro')      { return 'Discrete' }
    if ($n -match 'radeon pro|radeon rx|firepro')   { return 'Discrete' }
    if ($n -match 'radeon|amd')                     { return 'Unknown' }
    return 'Unknown'
}

function Get-GpuInfo {
    $gpus = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)
    foreach ($g in $gpus) {
        $pnpId = $g.PNPDeviceID
        $kind = Get-GpuKind -Name $g.Name -PnPDeviceID $pnpId

        # AdapterRAM is best-effort only. Modern WDDM drivers may not expose it correctly.
        $wmiVram = if ($g.AdapterRAM -and $g.AdapterRAM -gt 0) {
            [math]::Round($g.AdapterRAM / 1GB, 2)
        } else { $null }

        # Try to get more accurate VRAM from registry if available
        $regVram = $null
        try {
            $regKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\*"
            $regVram = Get-ItemProperty -Path $regKey -ErrorAction SilentlyContinue |
                Where-Object { $_.DriverDesc -eq $g.Name } |
                Select-Object -ExpandProperty 'HardwareInformation.qwMemorySize' -First 1
            if ($regVram) { $regVram = [math]::Round($regVram / 1GB, 2) }
        } catch { }

        $vram = if ($regVram -and $regVram -gt 0) { $regVram } elseif ($wmiVram) { $wmiVram } else { $null }

        [pscustomobject]@{
            Name          = $g.Name
            Kind          = $kind
            PnPDeviceID   = $pnpId
            DriverVersion = $g.DriverVersion
            DriverDate    = if ($g.DriverDate) { ([datetime]$g.DriverDate).ToString('yyyy-MM-dd') } else { '' }
            VRAM_GB       = $vram
            VRAM_Source   = if ($regVram) { 'Registry' } elseif ($wmiVram) { 'WMI (best-effort)' } else { 'Unknown' }
            Resolution    = "$($g.CurrentHorizontalResolution)x$($g.CurrentVerticalResolution)"
        }
    }
}

function Get-ThermalInfo {
    # Renamed: ACPI thermal zone, NOT CPU package temperature
    $zones = @()
    try {
        $t = Get-CimInstance -Namespace 'root/WMI' -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop
        $i = 0
        foreach ($z in $t) {
            $i++
            $c = ($z.CurrentTemperature / 10) - 273.15
            $zones += [pscustomobject]@{
                Zone    = "ACPI Zone $i"
                Celsius = [math]::Round($c, 1)
            }
        }
    } catch { }
    return $zones
}

function Get-PowerState {
    # Use GetSystemPowerStatus for actual AC line status
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $ps = [System.Windows.Forms.SystemInformation]::PowerStatus
        $onAc = $ps.PowerLineStatus -eq [System.Windows.Forms.PowerLineStatus]::Online
        $hasBattery = $ps.BatteryChargeStatus -ne [System.Windows.Forms.BatteryChargeStatus]::NoSystemBattery
        $pct = if ($hasBattery) { [math]::Round($ps.BatteryLifePercent * 100) } else { $null }
        return [pscustomobject]@{
            HasBattery = $hasBattery
            OnAC = $onAc
            Percent = $pct
            StatusText = if ($hasBattery) {
                if ($onAc) { "On AC, battery $pct%" } else { "On battery, $pct%" }
            } else { 'Desktop / no battery' }
        }
    } catch {
        # Fallback
        try {
            $b = Get-CimInstance Win32_Battery -ErrorAction Stop | Select-Object -First 1
            if (-not $b) {
                return [pscustomobject]@{ HasBattery=$false; OnAC=$true; Percent=$null; StatusText='Desktop / no battery' }
            }
            $acCodes = @(2, 3, 6, 7, 8, 9, 11)
            $onAc = $acCodes -contains [int]$b.BatteryStatus
            return [pscustomobject]@{
                HasBattery = $true; OnAC = $onAc; Percent = $b.EstimatedChargeRemaining
                StatusText = if ($onAc) { 'On AC' } else { 'On battery' }
            }
        } catch {
            return [pscustomobject]@{ HasBattery=$false; OnAC=$true; Percent=$null; StatusText='Unknown' }
        }
    }
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

# ---------- .NET detection (fixed: modern .NET runtime separately) ----------
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

function Get-DotNetRuntimeVersions {
    # Detect modern .NET runtimes (6/8/9/10) via dotnet --list-runtimes
    $runtimes = @()
    try {
        $output = & dotnet --list-runtimes 2>$null
        foreach ($line in $output) {
            if ($line -match '^(Microsoft\.(WindowsDesktop|NETCore|AspNetCore)\.App)\s+(\d+\.\d+\.\d+)') {
                $runtimes += [pscustomobject]@{
                    Type    = $Matches[1]
                    Version = $Matches[2]
                }
            }
        }
    } catch { }

    # Registry fallback
    if ($runtimes.Count -eq 0) {
        try {
            $regPaths = @(
                'HKLM:\SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedhost',
                'HKLM:\SOFTWARE\WOW6432Node\dotnet\Setup\InstalledVersions\x86\sharedhost'
            )
            foreach ($rp in $regPaths) {
                $v = (Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue).Version
                if ($v) { $runtimes += [pscustomobject]@{ Type = 'Runtime'; Version = $v } }
            }
        } catch { }
    }

    return $runtimes
}

function Compare-NetVersion {
    param([string]$Have, [string]$Need)
    if (-not $Need) { return $true }
    $h = $Have -replace '[^0-9\.]',''
    $n = $Need -replace '[^0-9\.]',''
    if (-not $h) { return $false }
    try { return ([version]$h -ge [version]$n) } catch { return $false }
}

function Test-DotNetRuntime {
    param(
        [array]$Runtimes,
        [string]$Required,
        [string]$Type = 'Microsoft.WindowsDesktop.App'
    )
    if (-not $Required) { return $true }
    foreach ($rt in $Runtimes) {
        if ($rt.Type -like "*$Type*" -or $rt.Type -eq 'Runtime') {
            $v = ($rt.Version -split '-')[0]
            if (Compare-NetVersion -Have $v -Need $Required) { return $true }
        }
    }
    return $false
}

# ---------- VC++ detection (fixed: architecture + version) ----------
function Get-VCRedistDetailed {
    $vc = @()
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($p in $paths) {
        try {
            $items = Get-ItemProperty -Path $p -ErrorAction Stop |
                Where-Object { $_.DisplayName -match 'Microsoft Visual C\+\+.*Redistributable' }
            foreach ($i in $items) {
                $arch = if ($i.DisplayName -match 'x64') { 'x64' }
                        elseif ($i.DisplayName -match 'x86') { 'x86' }
                        elseif ($i.DisplayName -match 'ARM64') { 'arm64' }
                        else { 'unknown' }
                $year = if ($i.DisplayName -match '(\d{4})') { $Matches[1] } else { '' }
                $vc += [pscustomobject]@{
                    Name    = $i.DisplayName
                    Version = $i.DisplayVersion
                    Arch    = $arch
                    Year    = $year
                }
            }
        } catch { }
    }
    return $vc
}

function Test-VCRuntime {
    param(
        [array]$VCRedist,
        [string]$RequiredArch,
        [string]$MinYear
    )
    if (-not $RequiredArch) { return $true }
    foreach ($vc in $VCRedist) {
        if ($vc.Arch -ne $RequiredArch) { continue }
        if ($MinYear -and $vc.Year) {
            if ([int]$vc.Year -ge [int]$MinYear) { return $true }
        } else { return $true }
    }
    return $false
}

# ---------- License discovery (fixed) ----------
function Get-LicenseServerHost {
    param([string]$ProductName)
    # Check common environment variables
    $envVars = @(
        'LM_LICENSE_FILE', 'ANSYSLMD_LICENSE_FILE', 'SPLM_LICENSE_SERVER',
        'SIEMENS_LICENSE_FILE', 'MAGNUS_LICENSE_FILE', 'FLEXLM_LICENSE_FILE'
    )
    foreach ($ev in $envVars) {
        $val = [Environment]::GetEnvironmentVariable($ev)
        if ($val) {
            # Format: port@host or just host
            if ($val -match '@') { return ($val -split '@')[-1] }
            return $val
        }
    }

    # Check vendor config files
    $configPaths = @(
        "$env:ProgramData\FlexNet\*",
        "$env:ProgramFiles\ANSYS Inc\Shared Files\Licensing\license_files\*",
        "$env:ProgramFiles\Siemens\*\*",
        "${env:ProgramFiles(x86)}\ANSYS Inc\Shared Files\Licensing\license_files\*"
    )
    foreach ($cp in $configPaths) {
        try {
            $files = Get-ChildItem -Path $cp -Filter '*.lic' -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                $line = Get-Content $f.FullName -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match '^SERVER' } | Select-Object -First 1
                if ($line -match 'SERVER\s+(\S+)') { return $Matches[1] }
            }
        } catch { }
    }

    return $null  # Unknown
}

# =============================================================================
# BASELINE
# =============================================================================
$baseline = [pscustomobject]@{
    When       = Get-Date
    Computer   = if ($RedactPersonalInfo) { 'REDACTED' } else { $env:COMPUTERNAME }
    User       = if ($RedactPersonalInfo) { 'REDACTED' } else { "$env:USERDOMAIN\$env:USERNAME" }
    IsAdmin    = (Test-IsAdmin)
    PSVersion  = $PSVersionTable.PSVersion.ToString()
    ReportPath = $reportBase
}
Write-Host "[INFO] Baseline: $($baseline.When) on $($baseline.Computer)" -ForegroundColor DarkGray

# =============================================================================
# MASTER CATALOG — version-aware schema
# =============================================================================
# Schema fields:
#   N        = Product name
#   D        = Disciplines
#   P        = Uninstall registry match patterns
#   K        = Kind
#   Reqs     = Hashtable of version → requirement record
#   Lic      = License technology (descriptive only)
#   Lsvc     = Exact license service name patterns (NOT broad wildcards)
#   Cache    = Cache folders
#   Source   = Vendor documentation source
#   Verified = Date last verified
#
# Requirement record fields:
#   RAMMin       = Vendor minimum RAM (GB)
#   RAMRec       = Vendor recommended RAM (GB)
#   InstallGB    = Installation disk space (GB)
#   ScratchGB    = Recommended free scratch space (GB)
#   DotNetFW     = .NET Framework version
#   DotNetRT     = Modern .NET runtime version
#   VCRuntime    = Required VC++ runtime (e.g. 'x64-2015')
#   DX           = DirectX requirement
#   GPURequired  = $true/$false
#   VRAMMin      = Minimum VRAM (GB)
#   VRAMRec      = Recommended VRAM (GB)
#   CertifiedGPU = Certified GPU required?
#   OS           = Supported OS
#   CPU          = CPU requirements
# =============================================================================

Write-Stage "Loading master catalog..."
$Script:RawCatalog = @(
    # ---------- CIVIL / AEC / BIM ----------
    @{
        N='AutoCAD'; D=@('Civil','BIM','AEC','Mechanical'); P=@('AutoCAD 20*','AutoCAD LT 20*','Autodesk AutoCAD*');
        K='CAD'; Lic='Node'; Cache=@('%LOCALAPPDATA%\Autodesk','%APPDATA%\Autodesk');
        Reqs=@{
            '2026' = @{
                RAMMin=8; RAMRec=32; InstallGB=10; ScratchGB=40;
                DotNetRT='8'; DX='11 (basic) / 12 (advanced)';
                GPURequired=$false; VRAMMin=2; VRAMRec=8;
                OS='Windows 10/11 64-bit'; CPU='2.5 GHz base, 8 logical cores';
                Source='Autodesk AutoCAD 2026 system requirements'; Verified='2026-08-01'
            }
            '2024' = @{
                RAMMin=8; RAMRec=16; InstallGB=10; ScratchGB=30;
                DotNetFW='4.8'; DX='11';
                GPURequired=$false; VRAMMin=1; VRAMRec=4;
                OS='Windows 10/11 64-bit';
                Source='Autodesk AutoCAD 2024 system requirements'; Verified='2024-06-01'
            }
        }
    }
    @{
        N='Civil 3D'; D=@('Civil'); P=@('Autodesk Civil 3D*'); K='Civil';
        Lic='Node'; Cache=@('%LOCALAPPDATA%\Autodesk');
        Reqs=@{
            '2026' = @{
                RAMMin=8; RAMRec=32; InstallGB=20; ScratchGB=60;
                DotNetFW='4.8'; DotNetRT='8';
                DX='11'; GPURequired=$false; VRAMMin=2; VRAMRec=8;
                OS='Windows 10/11 64-bit'; CPU='2.5 GHz base, 8 logical cores';
                Source='Autodesk Civil 3D 2026 system requirements'; Verified='2026-08-01'
            }
            '2026.2.2' = @{
                RAMMin=8; RAMRec=32; InstallGB=20; ScratchGB=60;
                DotNetFW='4.8'; DotNetRT='10';
                DX='11'; GPURequired=$false; VRAMMin=2; VRAMRec=8;
                OS='Windows 10/11 64-bit';
                Source='Autodesk Civil 3D 2026.2.2 requirements'; Verified='2026-08-01'
            }
        }
    }
    @{
        N='Revit'; D=@('BIM','AEC','Structural','MEP'); P=@('Autodesk Revit*'); K='BIM';
        Lic='Node'; Cache=@('%LOCALAPPDATA%\Autodesk\Revit');
        Reqs=@{
            '2026' = @{
                RAMMin=16; RAMRec=32; InstallGB=30; ScratchGB=100;
                DotNetRT='8'; DX='11';
                GPURequired=$true; VRAMMin=2; VRAMRec=8; CertifiedGPU=$false;
                OS='Windows 10/11 64-bit'; CPU='3+ GHz base, 4+ GHz turbo';
                Source='Autodesk Revit 2026 system requirements'; Verified='2026-08-01'
            }
            '2026.5' = @{
                RAMMin=16; RAMRec=64; InstallGB=30; ScratchGB=100;
                DotNetFW='10'; DX='11';
                GPURequired=$true; VRAMMin=4; VRAMRec=8;
                OS='Windows 10/11 64-bit';
                Source='Autodesk Revit 2026.5 system requirements'; Verified='2026-08-01'
            }
        }
    }
    @{
        N='SOLIDWORKS'; D=@('Mechanical','Aerospace','Automotive','Industrial');
        P=@('SOLIDWORKS 20*'); K='CAD'; Lic='FlexLM';
        Lsvc=@('SolidWorks Licensing Service');  # Exact name
        Cache=@('%LOCALAPPDATA%\SolidWorks','%APPDATA%\SolidWorks');
        Reqs=@{
            '2026' = @{
                RAMMin=16; RAMRec=32; InstallGB=30; ScratchGB=50;
                DotNetFW='4.8'; VCRuntime='x64-2015'; DX='11';
                GPURequired=$true; VRAMMin=4; VRAMRec=16; CertifiedGPU=$true;
                OS='Windows 10/11 64-bit'; CPU='x86_64, 3.5+ GHz';
                Source='SOLIDWORKS 2026 system requirements'; Verified='2026-07-01'
            }
        }
    }
    @{
        N='MATLAB'; D=@('Simulation','Math','Robotics','Control','Bio','Materials');
        P=@('MATLAB R20*','MATLAB*'); K='Math'; Lic='FlexLM';
        Lsvc=@('MATLAB License Server'); Lport=@(27000);  # Port may vary
        Cache=@('%LOCALAPPDATA%\MathWorks');
        Reqs=@{
            'R2026a' = @{
                RAMMin=8; RAMRec=16; InstallGB=25; ScratchGB=30;
                DotNetFW='4.8'; DX='11';
                GPURequired=$false; VRAMMin=0; VRAMRec=4;
                OS='Windows 10/11 64-bit'; CPU='Any Intel or AMD x86-64; AVX2 recommended';
                Source='MathWorks MATLAB R2026a system requirements'; Verified='2026-07-01'
            }
        }
    }
    @{
        N='ANSYS'; D=@('Simulation','Mechanical','Aerospace','Nuclear');
        P=@('ANSYS*','Ansys*'); K='FEA/CFD'; Lic='FlexLM';
        Lsvc=@('ANSYS Licensing Interconnect','ansyslmd');  # Exact names
        Lport=@(1055, 2325);
        Cache=@('%APPDATA%\Ansys','%TEMP%\Ansys');
        Reqs=@{
            '2026R1' = @{
                RAMMin=16; RAMRec=64; InstallGB=60; ScratchGB=200;
                DotNetFW='4.8'; VCRuntime='x64-2015'; DX='11';
                GPURequired=$true; VRAMMin=4; VRAMRec=16;
                OS='Windows 10/11 64-bit'; CPU='64-bit Intel or AMD';
                Source='Ansys 2026 R1 system requirements'; Verified='2026-06-01'
            }
        }
    }
    @{
        N='Abaqus'; D=@('Simulation','Materials','Aerospace','Biomedical');
        P=@('Abaqus*','SIMULIA Abaqus*'); K='FEA'; Lic='FlexLM';
        Lsvc=@('SIMULIA License Server','lmgrd');  # Exact names
        Lport=@(27000);
        Reqs=@{
            '2026' = @{
                RAMMin=32; RAMRec=64; InstallGB=50; ScratchGB=150;
                DotNetFW='4.8'; VCRuntime='x64-2015'; DX='11';
                GPURequired=$false; VRAMMin=0; VRAMRec=8;
                OS='Windows 10/11 64-bit'; CPU='64-bit Intel or AMD';
                Source='SIMULIA Abaqus 2026 system requirements'; Verified='2026-07-01'
            }
        }
    }
    # ... (additional catalog entries follow the same pattern)
)

# Convert hashtables to PSCustomObjects for reliable pipeline behavior
$Script:RawCatalog = @($Script:RawCatalog | ForEach-Object { [pscustomobject]$_ })
$Script:CatalogCount = $Script:RawCatalog.Count
Write-Ok

# =============================================================================
# DISCIPLINE PROFILES (unchanged)
# =============================================================================
Write-Stage "Loading discipline profiles..."
$Script:Profiles = @{
    'Civil'           = @('AutoCAD','Civil 3D','BricsCAD','Revit','Navisworks','HEC-RAS','HEC-HMS','WaterGEMS','SewerGEMS','InfoWorks ICM','Bentley OpenRail','Carlson Survey','Trimble Business Center')
    'Structural'      = @('SAP2000','ETABS','SAFE','CSiBridge','STAAD.Pro','Tekla Structures','Tekla Tedds','RFEM','RISA-3D','MIDAS Civil','MIDAS Gen','Robot Structural','IDEA StatiCa','SCIA Engineer','Advance Steel')
    # ... (keep all existing profiles)
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
    $gpuInfo = @(Get-GpuInfo)

    $disks = @()
    try {
        $vols = Get-Volume -ErrorAction Stop | Where-Object DriveLetter
        foreach ($v in $vols) {
            $disks += [pscustomobject]@{
                Drive   = "$($v.DriveLetter):"
                Label   = $v.FileSystemLabel
                FS      = $v.FileSystem
                SizeGB  = [math]::Round($v.Size / 1GB, 1)
                FreeGB  = [math]::Round($v.SizeRemaining / 1GB, 1)
                FreePct = if ($v.Size -gt 0) { [math]::Round(($v.SizeRemaining / $v.Size) * 100, 1) } else { 0 }
                DriveType = try { (Get-PhysicalDisk | Where-Object DeviceId -eq $v.DriveNumber).MediaType } catch { 'Unknown' }
            }
        }
    } catch {
        foreach ($d in Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue) {
            if ($d.Used -ne $null) {
                $size = $d.Used + $d.Free
                $disks += [pscustomobject]@{
                    Drive   = "$($d.Name):"
                    Label   = ''
                    FS      = ''
                    SizeGB  = [math]::Round($size / 1GB, 1)
                    FreeGB  = [math]::Round($d.Free / 1GB, 1)
                    FreePct = if ($size -gt 0) { [math]::Round(($d.Free / $size) * 100, 1) } else { 0 }
                    DriveType = 'Unknown'
                }
            }
        }
    }

    $pf = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue

    $hasDedicated  = @($gpuInfo | Where-Object Kind -eq 'Discrete').Count -gt 0
    $hasIntegrated = @($gpuInfo | Where-Object Kind -eq 'Integrated').Count -gt 0

    [pscustomobject]@{
        ComputerName   = if ($RedactPersonalInfo) { 'REDACTED' } else { $env:COMPUTERNAME }
        User           = if ($RedactPersonalInfo) { 'REDACTED' } else { "$env:USERDOMAIN\$env:USERNAME" }
        OS             = "$($os.Caption) ($($os.Version), Build $($os.BuildNumber))"
        Arch           = $os.OSArchitecture
        LastBoot       = $os.LastBootUpTime
        InstallDate    = $os.InstallDate
        CPU            = $cpu.Name
        Cores          = $cpu.NumberOfCores
        LogicalCPUs    = $cpu.NumberOfLogicalProcessors
        ClockMHz       = $cpu.MaxClockSpeed
        RAM_GB         = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        FreeRAM_GB     = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
        GPUs           = $gpuInfo
        HasDiscreteGPU = $hasDedicated
        HasIntegrated  = $hasIntegrated
        Disks          = $disks
        PageFile       = $pf
        ThermalZones   = @(Get-ThermalInfo)
        Power          = Get-PowerState
        IsAdmin        = (Test-IsAdmin)
    }
}
Write-Ok

# =============================================================================
# PREREQUISITES (fixed)
# =============================================================================
Write-Stage "Checking prerequisites..."
$netFx   = Get-DotNetFrameworkVersion
$dotnet  = Get-DotNetRuntimeVersions
$vc      = Get-VCRedistDetailed
Write-Host " .NET FW=$netFx, .NET RT=$($dotnet.Count) runtime(s), VC++=$($vc.Count) entries." -ForegroundColor Green

# =============================================================================
# WINDOWS HEALTH (fixed)
# =============================================================================
function Get-WindowsHealth {
    param([pscustomobject]$System)

    $r = [ordered]@{
        PendingReboot = $false
        RebootReason  = ''
        UpdateService = 'Unknown'
        Defender      = 'Unknown'
        Firewall      = 'Unknown'
        Activation    = 'Unknown'
        BuildAgeDays  = 0
        Score         = 100
    }

    $rebootKeys = @(
        @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'; Reason='CBS RebootPending'},
        @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'; Reason='Windows Update RebootRequired'},
        @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending'; Reason='CBS PackagesPending'}
    )
    foreach ($k in $rebootKeys) {
        if (Test-Path $k.Path) {
            $r.PendingReboot = $true
            $r.RebootReason  = $k.Reason
            break
        }
    }
    try {
        $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop).PendingFileRenameOperations
        if ($pfro) {
            $r.PendingReboot = $true
            if (-not $r.RebootReason) { $r.RebootReason = 'PendingFileRenameOperations' }
        }
    } catch { }

    try {
        $wu = Get-Service wuauserv -ErrorAction Stop
        $r.UpdateService = $wu.Status.ToString()
    } catch { }

    try {
        $def = Get-MpComputerStatus -ErrorAction Stop
        $r.Defender = if ($def.AntivirusEnabled) { 'Active' } else { 'Off' }
    } catch {
        try {
            $sc = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
            $r.Defender = if ($sc) { 'Third-party AV detected' } else { 'Unknown' }
        } catch { }
    }

    try {
        $fw = Get-NetFirewallProfile -ErrorAction Stop
        $enabled = @($fw | Where-Object Enabled -eq $true).Count
        $r.Firewall = if ($enabled -eq $fw.Count) { 'On' } elseif ($enabled -eq 0) { 'Off' } else { "Partial ($enabled/$($fw.Count))" }
    } catch { }

    try {
        $lic = Get-CimInstance SoftwareLicensingProduct -ErrorAction SilentlyContinue |
               Where-Object { $_.PartialProductKey -and $_.ApplicationID -eq '55c92734-d682-4d71-983e-d6ec3f16059f' -and $_.Name -match 'Windows' } |
               Select-Object -First 1
        if ($lic) {
            $r.Activation = switch ([int]$lic.LicenseStatus) {
                0 { 'Unlicensed' }
                1 { 'Licensed' }
                2 { 'OOB Grace' }
                3 { 'OOT Grace' }
                4 { 'Non-Genuine Grace' }
                5 { 'Notification' }
                6 { 'Extended Grace' }
                default { "Unknown ($($lic.LicenseStatus))" }
            }
        }
    } catch { }

    # Build age is OS install age, not "build age"
    if ($System.InstallDate) {
        try { $r.BuildAgeDays = (New-TimeSpan -Start $System.InstallDate -End (Get-Date)).Days } catch { }
    }

    # Adjusted scoring: don't penalize stopped wuauserv (trigger-start is normal)
    $s = 100
    if ($r.PendingReboot)                                   { $s -= 20 }
    if ($r.Defender -eq 'Off')                              { $s -= 15 }
    if ($r.Firewall -eq 'Off')                              { $s -= 10 }
    if ($r.Activation -in @('Unlicensed','Notification','Non-Genuine Grace')) { $s -= 25 }
    # Build age is informational only; no penalty
    $r.Score = [math]::Max(0, $s)

    [pscustomobject]$r
}

# =============================================================================
# NETWORK HEALTH (fixed: default route, real license host)
# =============================================================================
function Get-NetworkHealth {
    param([pscustomobject]$System, [array]$Catalog, [array]$Installed)

    $r = [ordered]@{
        Adapters      = @()
        LinkSpeedMbps = 0
        LinkSpeedText = ''
        DNS           = 'Unknown'
        DefaultGW     = ''
        License       = @()
        Score         = 100
    }

    try {
        $nics = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object Status -eq 'Up')
        $maxMbps = 0
        foreach ($n in $nics) {
            $mbps = 0
            if ($n.LinkSpeed -match '([\d\.]+)\s*Gbps')      { $mbps = [double]$Matches[1] * 1000 }
            elseif ($n.LinkSpeed -match '([\d\.]+)\s*Mbps')  { $mbps = [double]$Matches[1] }
            if ($mbps -gt $maxMbps) { $maxMbps = $mbps }
            $r.Adapters += [pscustomobject]@{
                Name      = $n.Name
                LinkSpeed = $n.LinkSpeed
                Mac       = if ($RedactPersonalInfo) { 'REDACTED' } else { $n.MacAddress }
            }
        }
        $r.LinkSpeedMbps = [int]$maxMbps
        $r.LinkSpeedText = if ($maxMbps -ge 1000) { "$([math]::Round($maxMbps/1000,1)) Gbps" }
                           elseif ($maxMbps -gt 0) { "$maxMbps Mbps" } else { '' }
    } catch { }

    # DNS test: try multiple domains, distinguish NXDOMAIN from timeout
    try {
        $null = Resolve-DnsName 'microsoft.com' -ErrorAction Stop -QuickTimeout
        $r.DNS = 'OK'
    } catch {
        try {
            $null = Resolve-DnsName 'google.com' -ErrorAction Stop -QuickTimeout
            $r.DNS = 'OK (fallback)'
        } catch {
            $r.DNS = 'Failed'
        }
    }

    # Default gateway: pick route with lowest metric that actually carries traffic
    try {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                 Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
        if ($route) { $r.DefaultGW = $route.NextHop }
    } catch { }

    # License checks: use discovered host, NOT localhost
    foreach ($entry in $Catalog) {
        if (-not $entry.Lport) { continue }
        $hit = $false
        foreach ($pat in @($entry.P)) {
            if ($Installed | Where-Object { $_.DisplayName -like $pat }) { $hit = $true; break }
        }
        if (-not $hit) { continue }

        $licenseHost = Get-LicenseServerHost -ProductName $entry.N
        if (-not $licenseHost) {
            $r.License += [pscustomobject]@{
                Product = $entry.N
                Host    = 'Unknown'
                Ports   = ($entry.Lport -join ', ')
                Status  = 'LicenseHostUnknown'
            }
            continue
        }

        $anyOpen = $false
        foreach ($p in $entry.Lport) {
            if (Test-TcpPort -ComputerName $licenseHost -Port $p -TimeoutMs 800) { $anyOpen = $true; break }
        }
        $r.License += [pscustomobject]@{
            Product = $entry.N
            Host    = $licenseHost
            Ports   = ($entry.Lport -join ', ')
            Status  = if ($anyOpen) { 'Open' } else { 'Closed' }
        }
    }

    # Network score: don't penalize <1 Gbps universally
    $s = 100
    if ($r.Adapters.Count -eq 0)                                            { $s -= 20 }
    if ($r.DNS -ne 'OK')                                                    { $s -= 10 }
    if (-not $r.DefaultGW)                                                  { $s -= 10 }
    $r.Score = [math]::Max(0, $s)

    [pscustomobject]$r
}

# =============================================================================
# PREFLIGHT (fixed: threshold-based free RAM, correct labels)
# =============================================================================
function Invoke-Preflight {
    param(
        [string]$ProductName,
        [array]$Catalog,
        [pscustomobject]$System,
        [string]$NetFx,
        [array]$DotNetRuntimes,
        [array]$VC,
        [array]$Installed
    )

    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host "  PREFLIGHT: $ProductName" -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host ""

    $entry = $Catalog | Where-Object { $_.N -eq $ProductName } | Select-Object -First 1
    if (-not $entry) {
        $entry = $Catalog | Where-Object { $_.N -like "*$ProductName*" } | Select-Object -First 1
    }
    if (-not $entry) {
        Write-Host "[ERROR] Product not found in catalog: $ProductName" -ForegroundColor Red
        return
    }

    # Determine best matching requirement version
    $reqVersion = $entry.Reqs.Keys | Sort-Object -Descending | Select-Object -First 1
    $req = $entry.Reqs[$reqVersion]

    $script:pass = 0; $script:warn = 0; $script:fail = 0; $script:unknown = 0
    function Report {
        param([string]$State, [string]$Label, [string]$Detail = '')
        switch ($State) {
            'OK'      { Write-Host "  [ OK ]  " -ForegroundColor Green -NoNewline; $script:pass++ }
            'WARN'    { Write-Host "  [WARN]  " -ForegroundColor Yellow -NoNewline; $script:warn++ }
            'FAIL'    { Write-Host "  [FAIL]  " -ForegroundColor Red -NoNewline; $script:fail++ }
            'UNKNOWN' { Write-Host "  [ ?? ]  " -ForegroundColor DarkGray -NoNewline; $script:unknown++ }
        }
        Write-Host $Label -NoNewline
        if ($Detail) { Write-Host "  ($Detail)" -ForegroundColor DarkGray } else { Write-Host "" }
    }

    if ($req.RAMMin) {
        if ($System.RAM_GB -ge $req.RAMRec) {
            Report 'OK' "RAM installed" "$($System.RAM_GB) GB >= $($req.RAMRec) GB recommended"
        } elseif ($System.RAM_GB -ge $req.RAMMin) {
            Report 'WARN' "RAM below recommendation" "$($System.RAM_GB) GB installed, $($req.RAMRec) GB recommended (min $($req.RAMMin) GB)"
        } else {
            Report 'FAIL' "RAM below minimum" "$($System.RAM_GB) GB installed, minimum $($req.RAMMin) GB"
        }
    } else {
        Report 'UNKNOWN' "RAM requirement" "Vendor minimum not recorded"
    }

    # Free RAM threshold: WARN if <10% free
    $freePct = if ($System.RAM_GB -gt 0) { ($System.FreeRAM_GB / $System.RAM_GB) * 100 } else { 100 }
    if ($freePct -lt 10) {
        Report 'WARN' "Free RAM now" "$($System.FreeRAM_GB) GB of $($System.RAM_GB) GB ($([math]::Round($freePct,1))% free)"
    } else {
        Report 'OK' "Free RAM now" "$($System.FreeRAM_GB) GB of $($System.RAM_GB) GB ($([math]::Round($freePct,1))% free)"
    }

    if ($System.PageFile -and $System.PageFile.Count -gt 0) {
        $pf = $System.PageFile | Select-Object -First 1
        Report 'OK' "Pagefile enabled" "$($pf.AllocatedBaseSize) MB allocated"
    } else {
        Report 'FAIL' "Pagefile not detected" "large solvers may fail"
    }

    if ($req.InstallGB) {
        $sysd = $System.Disks | Where-Object Drive -eq "$($env:SystemDrive)"
        if ($sysd -and $sysd.FreeGB -ge $req.InstallGB) {
            Report 'OK' "Installation disk free" "$($sysd.FreeGB) GB on $($sysd.Drive)"
        } elseif ($sysd) {
            Report 'WARN' "Installation disk tight" "$($sysd.FreeGB) GB free, $($req.InstallGB) GB required"
        } else {
            Report 'UNKNOWN' "Installation disk" "Could not determine $env:SystemDrive free space"
        }
    }

    if ($req.DotNetFW) {
        if (Compare-NetVersion -Have $NetFx -Need $req.DotNetFW) {
            Report 'OK' ".NET Framework" "$NetFx >= $($req.DotNetFW)"
        } else {
            Report 'FAIL' ".NET Framework" "have $NetFx, need $($req.DotNetFW)"
        }
    }

    if ($req.DotNetRT) {
        if (Test-DotNetRuntime -Runtimes $DotNetRuntimes -Required $req.DotNetRT) {
            Report 'OK' "Modern .NET runtime" "version $($req.DotNetRT) present"
        } else {
            Report 'FAIL' "Modern .NET runtime" "need $($req.DotNetRT) (Microsoft.WindowsDesktop.App)"
        }
    }

    if ($req.VCRuntime) {
        $arch = ($req.VCRuntime -split '-')[0]
        $year = ($req.VCRuntime -split '-')[1]
        if (Test-VCRuntime -VCRedist $VC -RequiredArch $arch -MinYear $year) {
            Report 'OK' "VC++ runtime" "$arch $year+ present"
        } else {
            Report 'FAIL' "VC++ runtime" "need $($req.VCRuntime)"
        }
    }

    if ($req.GPURequired) {
        $discrete = @($System.GPUs | Where-Object Kind -eq 'Discrete')
        if ($discrete.Count -gt 0) {
            $best = $discrete | Sort-Object VRAM_GB -Descending | Select-Object -First 1
            $vramText = if ($best.VRAM_GB) { "$($best.VRAM_GB) GB ($($best.VRAM_Source))" } else { 'unknown VRAM' }
            if ($req.VRAMMin -and $best.VRAM_GB -and $best.VRAM_GB -lt $req.VRAMMin) {
                Report 'WARN' "Discrete GPU VRAM" "$($best.Name): $vramText, minimum $($req.VRAMMin) GB"
            } else {
                Report 'OK' "Discrete GPU present" "$($best.Name) - $vramText"
            }
        } else {
            Report 'FAIL' "No discrete GPU" "requires dedicated GPU (min $($req.VRAMMin) GB VRAM)"
        }
    }

    # Thermal: label as ACPI zone, not CPU
    if ($System.ThermalZones -and $System.ThermalZones.Count -gt 0) {
        $max = ($System.ThermalZones | Measure-Object Celsius -Maximum).Maximum
        Report 'UNKNOWN' "ACPI thermal zone" "$max C (zone identity unknown; not necessarily CPU)"
    }

    # Power
    if ($System.Power.HasBattery -and -not $System.Power.OnAC) {
        Report 'WARN' "Running on battery" "$($System.Power.Percent)% - heavy solve will drain fast"
    } elseif ($System.Power.HasBattery) {
        Report 'OK' "AC power" "$($System.Power.Percent)%"
    }

    Write-Host ""
    $verdict = if ($fail -gt 0) { 'NOT READY' } elseif ($warn -gt 2) { 'CAUTION' } else { 'READY' }
    $col = if ($fail -gt 0) { 'Red' } elseif ($warn -gt 2) { 'Yellow' } else { 'Green' }
    Write-Host ("  $script:pass OK   $script:warn WARN   $script:fail FAIL   $script:unknown UNKNOWN  ->  $verdict") -ForegroundColor $col
    Write-Host ""
}

# =============================================================================
# WHY-SLOW (fixed: "Potential bottleneck", longer sample)
# =============================================================================
function Invoke-WhySlow {
    param([pscustomobject]$System)

    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host "  WHY IS MY PC SLOW?" -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host ""

    $ramPctFree = [math]::Round(($System.FreeRAM_GB / $System.RAM_GB) * 100, 1)
    $critDisk = $System.Disks | Sort-Object FreePct | Select-Object -First 1

    $topMem = @()
    try {
        $topMem = Get-Process -ErrorAction SilentlyContinue |
                  Sort-Object WorkingSet64 -Descending |
                  Select-Object -First 8 |
                  ForEach-Object {
                      [pscustomobject]@{
                          Name = $_.ProcessName
                          GB   = [math]::Round($_.WorkingSet64 / 1GB, 2)
                      }
                  }
    } catch { }

    $topCpu = @()
    try {
        $s1 = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $s1[$_.Id] = $_.TotalProcessorTime.TotalMilliseconds }
        Start-Sleep -Milliseconds 3000  # 3-second sample (was 0.8s)
        $cores = [math]::Max(1, $System.LogicalCPUs)
        $topCpu = Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            $prev = if ($s1.ContainsKey($_.Id)) { $s1[$_.Id] } else { 0 }
            $delta = $_.TotalProcessorTime.TotalMilliseconds - $prev
            $pct = [math]::Round(($delta / 3000) * 100 / $cores, 1)
            [pscustomobject]@{ Name = $_.ProcessName; CPU = $pct }
        } | Sort-Object CPU -Descending | Select-Object -First 8
    } catch { }

    $verdicts = [ordered]@{
        RAM    = if ($ramPctFree -lt 15) { 'CRITICAL' } elseif ($ramPctFree -lt 30) { 'ELEVATED' } else { 'OK' }
        Disk   = if ($critDisk -and $critDisk.FreePct -lt 5) { 'CRITICAL' } elseif ($critDisk -and $critDisk.FreePct -lt 15) { 'ELEVATED' } else { 'OK' }
        CPU    = if (($topCpu | Select-Object -First 1).CPU -gt 60) { 'ELEVATED' } else { 'OK' }
        GPU    = if ($System.HasDiscreteGPU) { 'OK' } else { 'UNKNOWN' }  # Don't assume GPU is bottleneck
        Power  = if ($System.Power.HasBattery -and -not $System.Power.OnAC) { 'ELEVATED' } else { 'OK' }
        Thermal= 'UNKNOWN'  # Cannot determine from ACPI zones
    }

    # Potential bottleneck, not definitive
    $primary = 'None detected'
    foreach ($k in @('RAM','Disk','Thermal','Power','CPU','GPU')) {
        if ($verdicts[$k] -eq 'CRITICAL') { $primary = $k; break }
    }
    if ($primary -eq 'None detected') {
        foreach ($k in @('RAM','Disk','Thermal','Power','CPU','GPU')) {
            if ($verdicts[$k] -eq 'ELEVATED') { $primary = $k; break }
        }
    }

    Write-Host "  Current snapshot" -ForegroundColor Cyan
    Write-Host ("    RAM free            {0} GB / {1} GB ({2}%)" -f $System.FreeRAM_GB, $System.RAM_GB, $ramPctFree)
    Write-Host ("    CPU cores           {0} logical" -f $System.LogicalCPUs)
    Write-Host ("    Worst disk free     {0} GB ({1}% on {2})" -f $critDisk.FreeGB, $critDisk.FreePct, $critDisk.Drive)
    Write-Host ("    Power               {0}" -f $System.Power.StatusText)
    Write-Host ""

    Write-Host "  Verdicts" -ForegroundColor Cyan
    foreach ($k in $verdicts.Keys) {
        $col = switch ($verdicts[$k]) { 'CRITICAL' { 'Red' } 'ELEVATED' { 'Yellow' } 'UNKNOWN' { 'DarkGray' } default { 'Green' } }
        Write-Host ("    {0,-8} {1}" -f $k, $verdicts[$k]) -ForegroundColor $col
    }
    Write-Host ""

    Write-Host ("  POTENTIAL BOTTLENECK: {0}" -f $primary) -ForegroundColor Yellow
    Write-Host "  (based on current snapshot only; not a definitive diagnosis)" -ForegroundColor DarkGray
    Write-Host ""

    if ($topMem.Count -gt 0) {
        Write-Host "  Top memory consumers" -ForegroundColor Cyan
        foreach ($p in $topMem) {
            Write-Host ("    {0,-22} {1,6} GB" -f $p.Name, $p.GB)
        }
        Write-Host ""
    }
    if ($topCpu.Count -gt 0) {
        Write-Host "  Top CPU consumers (last 3s)" -ForegroundColor Cyan
        foreach ($p in $topCpu) {
            if ($p.CPU -lt 0.5) { continue }
            Write-Host ("    {0,-22} {1,6}%" -f $p.Name, $p.CPU)
        }
        Write-Host ""
    }
}

# =============================================================================
# DISPATCH PREFLIGHT / WHYSLOW
# =============================================================================
if ($Preflight) {
    Invoke-Preflight -ProductName $Preflight -Catalog $Script:RawCatalog `
                     -System $sys -NetFx $netFx -DotNetRuntimes $dotnet `
                     -VC $vc -Installed $installed
    exit 0
}

if ($WhySlow) {
    Invoke-WhySlow -System $sys
    exit 0
}

# =============================================================================
# SOFTWARE INSTALLER (fixed: winget post-verify, ambiguous batch handling)
# =============================================================================
$Script:WingetMap = @{
    'Python'             = 'Python.Python.3.12'
    'Anaconda'           = 'Anaconda.Anaconda3'
    'Git'                = 'Git.Git'
    'Visual Studio Code' = 'Microsoft.VisualStudioCode'
    'Visual Studio'      = 'Microsoft.VisualStudio.2022.Community'
    'Docker Desktop'     = 'Docker.DockerDesktop'
    'Wireshark'          = 'WiresharkFoundation.Wireshark'
    'KiCad'              = 'KiCad.KiCad'
    'QGIS'               = 'QGIS.QGIS'
    'CloudCompare'       = 'CloudCompare.CloudCompare'
    'Arduino IDE'        = 'ArduinoSA.IDE.stable'
    'R'                  = 'RProject.R'
    'LTspice'            = 'AnalogDevices.LTspice'
    'ImageJ'             = 'ImageJ.ImageJ'
    'DWSIM'              = 'DWSIM.DWSIM'
    '3D Slicer'          = 'Slicer.Slicer'
    'PlatformIO'         = 'PlatformIO.PlatformIO'
    'FreeCAD'            = 'FreeCAD.FreeCAD'
    'OpenSCAD'           = 'OpenSCAD.OpenSCAD'
    'Blender'            = 'BlenderFoundation.Blender'
    'ParaView'           = 'Kitware.ParaView'
    'GNU Octave'         = 'GNU.Octave'
    'CMake'              = 'Kitware.CMake'
    'Notepad++'          = 'Notepad++.Notepad++'
    'GIMP'               = 'GIMP.GIMP'
    'Inkscape'           = 'Inkscape.Inkscape'
    '7-Zip'              = '7zip.7zip'
}

$Script:ManualUrls = @{
    'AutoCAD'             = 'https://www.autodesk.com/products/autocad/free-trial'
    'Revit'               = 'https://www.autodesk.com/products/revit/free-trial'
    'Civil 3D'            = 'https://www.autodesk.com/products/civil-3d/free-trial'
    'SOLIDWORKS'          = 'https://www.solidworks.com/sw/support/downloads.htm'
    'MATLAB'              = 'https://www.mathworks.com/products/matlab.html'
    'ANSYS'               = 'https://www.ansys.com/products'
    'Abaqus'              = 'https://www.3ds.com/products/simulia/abaqus'
    # ... (keep all existing URLs)
}

function Test-WingetAvailable { [bool](Get-Command winget -ErrorAction SilentlyContinue) }

function Get-InstallTag {
    param([string]$Name)
    if ($Script:WingetMap.ContainsKey($Name))  { return 'winget' }
    if ($Script:ManualUrls.ContainsKey($Name)) { return 'manual' }
    return 'skip'
}

function Install-OneProduct {
    param(
        [string]$Name,
        [bool]$HasWinget,
        [switch]$NonInteractive
    )

    $tag = Get-InstallTag -Name $Name

    if ($tag -eq 'winget' -and $HasWinget) {
        $id = $Script:WingetMap[$Name]
        Write-Host "  [INSTALL] $Name  via  winget  ($id)" -ForegroundColor Cyan
        try {
            & winget install --id $id --exact `
                --accept-package-agreements --accept-source-agreements `
                --silent --disable-interactivity
            $code = $LASTEXITCODE
            if ($null -eq $code -or $code -eq 0) {
                # Post-verify: check if package is actually installed
                $verify = & winget list --id $id --exact 2>$null
                if ($verify -match [regex]::Escape($id)) {
                    Write-Host "  [ OK ]  $Name installed and verified." -ForegroundColor Green
                    return 'installed'
                } else {
                    Write-Host "  [WARN]  $Name winget reported success but verification failed." -ForegroundColor Yellow
                    return 'failed'
                }
            } else {
                Write-Host "  [FAIL]  $Name - winget exit code $code" -ForegroundColor Red
                Add-Diagnostic 'Install' "$Name winget failed with exit code $code"
                return 'failed'
            }
        } catch {
            Write-Host "  [FAIL]  $Name - $_" -ForegroundColor Red
            Add-Diagnostic 'Install' "$Name threw: $_"
            return 'failed'
        }
    }

    if ($tag -eq 'winget' -and -not $HasWinget) {
        Write-Host "  [SKIP]  $Name - winget not available on this machine." -ForegroundColor Yellow
        return 'skipped'
    }

    if ($tag -eq 'manual') {
        $url = $Script:ManualUrls[$Name]
        Write-Host "  [MANUAL] $Name - no winget entry, opening vendor page." -ForegroundColor Yellow
        Write-Host "           $url" -ForegroundColor DarkGray
        if (-not $NonInteractive) {
            $open = Read-Host "  Open the download page now? (Y/N)"
            if ($open -match '^[Yy]') {
                try { Start-Process $url } catch {
                    Write-Host "  [FAIL] Could not open browser: $_" -ForegroundColor Red
                }
            }
        }
        return 'manual'
    }

    Write-Host "  [SKIP]  $Name - not installable automatically (no winget ID, no download URL)." -ForegroundColor DarkGray
    return 'skipped'
}

# =============================================================================
# PER-PRODUCT CHECKS (fixed: version-aware, proper GPU/VC++/license checks)
# =============================================================================
function Get-ProductStatus {
    param(
        [object]$Entry,
        [array]$Installed,
        [pscustomobject]$System,
        [string]$NetFx,
        [array]$DotNetRuntimes,
        [array]$VC,
        [string[]]$ActiveDisciplines,
        [switch]$DeepScan
    )

    $status = [ordered]@{
        Name        = $Entry.N
        Disciplines = ($Entry.D -join ', ')
        Kind        = $Entry.K
        Installed   = $false
        Version     = ''
        Match       = ''
        State       = 'NotInstalled'
        Severity    = 'info'
        Findings    = (New-Object System.Collections.Generic.List[object])
        Notes       = @()
        CacheGB     = 0
    }

    if ($ActiveDisciplines.Count -gt 0) {
        $overlap = $false
        foreach ($d in $Entry.D) {
            if ($ActiveDisciplines -contains $d) { $overlap = $true; break }
        }
        if (-not $overlap) {
            $status.State = 'NotApplicable'
            return [pscustomobject]$status
        }
    }

    # Detection: use product-specific detectors where needed
    $hits = @()
    foreach ($pat in @($Entry.P)) {
        $hits += $Installed | Where-Object { $_.DisplayName -like $pat }
    }
    $hits = @($hits | Sort-Object DisplayName -Unique)

    if ($hits.Count -eq 0) {
        $status.State = 'NotInstalled'
        return [pscustomobject]$status
    }

    $status.Installed = $true
    $status.Version   = (($hits | ForEach-Object { $_.DisplayVersion } |
                          Where-Object { $_ } | Sort-Object -Unique) -join ', ')
    $status.Match     = ($hits.DisplayName -join ' | ')

    # Determine best matching requirement version
    $reqVersion = $Entry.Reqs.Keys | Sort-Object -Descending | Select-Object -First 1
    $req = $Entry.Reqs[$reqVersion]

    # RAM check
    if ($req.RAMMin -and $System.RAM_GB -lt $req.RAMRec) {
        $sev = if ($System.RAM_GB -lt $req.RAMMin) { 'critical' } else { 'warn' }
        $why = if ($sev -eq 'critical') {
            "Large models may fail to open or the solver may crash mid-run."
        } else {
            "Large models may spill to the pagefile, causing noticeably slower performance."
        }
        $rec = if ($sev -eq 'critical') {
            "Upgrade RAM before attempting large models. Close memory-heavy applications now."
        } else {
            "Close memory-heavy applications before running large models."
        }
        $status.Findings.Add((New-Finding `
            -Id "$($Entry.N).RAM_LOW" `
            -Software $Entry.N `
            -Problem "$($Entry.N) may experience slow performance or instability." `
            -Detected "$($System.RAM_GB) GB installed; $($req.RAMRec) GB recommended (min $($req.RAMMin) GB)." `
            -WhyItMatters $why `
            -Recommendation $rec `
            -Optional "Consider upgrading to $($req.RAMRec) GB or more for large workloads." `
            -Severity $sev))
    }

    # Disk check: use InstallGB for installation, ScratchGB for scratch
    if ($req.InstallGB) {
        $sysd = $System.Disks | Where-Object Drive -eq "$($env:SystemDrive)"
        if ($sysd -and $sysd.FreeGB -lt $req.InstallGB) {
            $sev = if ($sysd.FreeGB -lt 5) { 'critical' } else { 'warn' }
            $status.Findings.Add((New-Finding `
                -Id "$($Entry.N).DISK_LOW" `
                -Software $Entry.N `
                -Problem "$($Entry.N) installation disk is running low." `
                -Detected "$($sysd.FreeGB) GB free on $($sysd.Drive); $($req.InstallGB) GB required." `
                -WhyItMatters "Installation and updates need free space on this drive." `
                -Recommendation "Free space on $($sysd.Drive)." `
                -Severity $sev))
        }
    }

    # GPU check
    if ($req.GPURequired) {
        $discrete = @($System.GPUs | Where-Object Kind -eq 'Discrete')
        if ($discrete.Count -eq 0) {
            $status.Findings.Add((New-Finding `
                -Id "$($Entry.N).GPU_LOW" `
                -Software $Entry.N `
                -Problem "$($Entry.N) requires a dedicated GPU." `
                -Detected "No dedicated GPU detected." `
                -WhyItMatters "3D views, rendering, and GPU-accelerated solvers will be slow or unavailable." `
                -Recommendation "Install a certified GPU (see vendor hardware certification list)." `
                -Severity 'warn'))
        } elseif ($req.VRAMMin) {
            $best = $discrete | Sort-Object VRAM_GB -Descending | Select-Object -First 1
            if ($best.VRAM_GB -and $best.VRAM_GB -lt $req.VRAMMin) {
                $status.Findings.Add((New-Finding `
                    -Id "$($Entry.N).VRAM_LOW" `
                    -Software $Entry.N `
                    -Problem "$($Entry.N) GPU VRAM below requirement." `
                    -Detected "$($best.VRAM_GB) GB VRAM ($($best.VRAM_Source)); minimum $($req.VRAMMin) GB." `
                    -WhyItMatters "Large models may not render or solve correctly." `
                    -Recommendation "Use a GPU with at least $($req.VRAMMin) GB VRAM." `
                    -Severity 'warn'))
            }
        }
    }

    # .NET Framework check
    if ($req.DotNetFW) {
        if (-not (Compare-NetVersion -Have $NetFx -Need $req.DotNetFW)) {
            $status.Findings.Add((New-Finding `
                -Id "$($Entry.N).DOTNET_FW" `
                -Software $Entry.N `
                -Problem "$($Entry.N) may not start." `
                -Detected ".NET Framework $NetFx installed; $($req.DotNetFW) required." `
                -WhyItMatters "Missing framework versions cause startup errors and missing features." `
                -Recommendation "Install .NET Framework $($req.DotNetFW) or newer from Microsoft." `
                -Severity 'critical'))
        }
    }

    # Modern .NET runtime check
    if ($req.DotNetRT) {
        if (-not (Test-DotNetRuntime -Runtimes $DotNetRuntimes -Required $req.DotNetRT)) {
            $status.Findings.Add((New-Finding `
                -Id "$($Entry.N).DOTNET_RT" `
                -Software $Entry.N `
                -Problem "$($Entry.N) may not start." `
                -Detected "Modern .NET runtime $($req.DotNetRT) not found." `
                -WhyItMatters "Newer Autodesk and engineering tools require modern .NET." `
                -Recommendation "Install .NET $($req.DotNetRT) Desktop Runtime (x64)." `
                -Severity 'critical'))
        }
    }

    # VC++ check
    if ($req.VCRuntime) {
        $arch = ($req.VCRuntime -split '-')[0]
        $year = ($req.VCRuntime -split '-')[1]
        if (-not (Test-VCRuntime -VCRedist $VC -RequiredArch $arch -MinYear $year)) {
            $status.Findings.Add((New-Finding `
                -Id "$($Entry.N).VCPP" `
                -Software $Entry.N `
                -Problem "$($Entry.N) may fail to launch." `
                -Detected "Required VC++ runtime ($($req.VCRuntime)) not detected." `
                -WhyItMatters "Most engineering applications depend on specific VC++ runtimes." `
                -Recommendation "Install Microsoft Visual C++ Redistributable ($($req.VCRuntime))." `
                -Severity 'critical'))
        }
    }

    # License service check: use exact service names, not broad wildcards
    if ($Entry.Lsvc) {
        $svc = @(Get-Service -ErrorAction SilentlyContinue | Where-Object {
            $n = $_.Name + ' ' + $_.DisplayName
            foreach ($pat in $Entry.Lsvc) { if ($n -like $pat) { return $true } }
            return $false
        })
        if ($svc.Count -gt 0) {
            $running = @($svc | Where-Object Status -eq 'Running').Count
            if ($running -eq 0) {
                $status.Findings.Add((New-Finding `
                    -Id "$($Entry.N).LICSVC" `
                    -Software $Entry.N `
                    -Problem "$($Entry.N) license service is not running." `
                    -Detected "$($svc.Count) vendor service(s) installed; 0 running." `
                    -WhyItMatters "The application will fail to acquire a license and may not launch." `
                    -Recommendation "Start the vendor license service or repair the install." `
                    -Severity 'critical'))
            }
        }
    }

    # Power check
    if ($System.Power.HasBattery -and -not $System.Power.OnAC) {
        if ($req.RAMRec -ge 16 -or $Entry.K -match 'FEA|CFD|BIM|Explicit|FEA/CFD') {
            $status.Findings.Add((New-Finding `
                -Id "$($Entry.N).POWER" `
                -Software $Entry.N `
                -Problem "$($Entry.N) will run slower on battery." `
                -Detected "Currently on battery at $($System.Power.Percent)%." `
                -WhyItMatters "Windows throttles CPU and GPU under battery power, which lengthens solve times significantly." `
                -Recommendation "Plug in AC power before heavy workloads." `
                -Severity 'warn'))
        }
    }

    # Cache scan
    if ($DeepScan -and $Entry.Cache) {
        $total = 0
        foreach ($c in $Entry.Cache) { $total += (Get-FolderSizeGB -Path (Expand-Env $c)) }
        $status.CacheGB = [math]::Round($total, 2)
        if ($total -gt 20) {
            $recoverable = [math]::Round($total * 0.7, 1)
            $status.Notes += "Cache is large ($($status.CacheGB) GB)."
            $status.Findings.Add((New-Finding `
                -Id "$($Entry.N).CACHE" `
                -Software $Entry.N `
                -Problem "$($Entry.N) cache is unusually large." `
                -Detected "Cache total: $($status.CacheGB) GB across $($Entry.Cache.Count) folder(s)." `
                -WhyItMatters "Oversized caches slow launches and often indicate leftover project data." `
                -Recommendation "Review the cache folders while the app is closed." `
                -Optional "Estimated recoverable space: $recoverable GB." `
                -Severity 'warn' `
                -RecoverableGB $recoverable))
        }
    }

    $crit = @($status.Findings | Where-Object Severity -eq 'critical').Count
    $warn = @($status.Findings | Where-Object Severity -eq 'warn').Count
    if ($crit -gt 0) {
        $status.State = 'Critical'; $status.Severity = 'critical'
    } elseif ($warn -gt 0) {
        $status.State = 'Attention'; $status.Severity = 'warn'
    } else {
        $status.State = 'Healthy'; $status.Severity = 'info'
    }

    return [pscustomobject]$status
}

# =============================================================================
# HEALTH SCORE (fixed: renamed, honest defaults)
# =============================================================================
function Get-HealthScore {
    param(
        [array]$Results,
        [pscustomobject]$System,
        [string]$NetFx,
        [array]$VC,
        [pscustomobject]$WindowsHealth,
        [pscustomobject]$NetworkHealth
    )

    $cats = [ordered]@{}

    # Hardware: workload-agnostic baseline
    $hw = 100
    if ($System.RAM_GB -lt 16) { $hw -= 30 }
    elseif ($System.RAM_GB -lt 32) { $hw -= 10 }
    if ($System.LogicalCPUs -lt 8) { $hw -= 20 }
    if (-not $System.HasDiscreteGPU) { $hw -= 25 }
    $cats['Hardware'] = [math]::Max(0, $hw)

    # Storage: use system drive specifically, not fullest volume
    $st = 100
    $sysDisk = $System.Disks | Where-Object Drive -eq "$($env:SystemDrive)"
    if ($sysDisk) {
        if ($sysDisk.FreePct -lt 5)      { $st = 30 }
        elseif ($sysDisk.FreePct -lt 10) { $st = 55 }
        elseif ($sysDisk.FreePct -lt 20) { $st = 80 }
    }
    $cats['Storage'] = $st

    # EngineeringSoftware: only score detected apps
    $rel = @($Results | Where-Object { $_.State -notin @('NotInstalled','NotApplicable') })
    if ($rel.Count -eq 0) {
        $cats['EngineeringSoftware'] = $null  # Unknown, not 100
    } else {
        $healthy = @($rel | Where-Object State -eq 'Healthy').Count
        $cats['EngineeringSoftware'] = [int](100 * $healthy / $rel.Count)
    }

    # GPU: score each adapter independently
    $gpuScore = 100
    foreach ($g in $System.GPUs) {
        if ($g.DriverDate) {
            try {
                $d = [datetime]::Parse($g.DriverDate)
                $ageDays = (New-TimeSpan -Start $d -End (Get-Date)).Days
                if ($ageDays -gt 365)      { $gpuScore = [math]::Min($gpuScore, 55) }
                elseif ($ageDays -gt 180)  { $gpuScore = [math]::Min($gpuScore, 75) }
                elseif ($ageDays -gt 90)   { $gpuScore = [math]::Min($gpuScore, 90) }
            } catch { }
        }
    }
    $cats['GPU'] = $gpuScore

    # Drivers
    $drv = 100
    if ($NetFx -match '^4\.[0-6]')     { $drv -= 40 }
    elseif ($NetFx -eq '4.7')          { $drv -= 15 }
    if (-not $VC -or $VC.Count -eq 0)  { $drv -= 30 }
    $cats['Drivers'] = [math]::Max(0, $drv)

    # Licensing: use only products with license services
    $licProducts = @($rel | Where-Object { $_.Findings | Where-Object Id -match 'LICSVC' })
    $licTotal = @($rel | Where-Object { $_.Name -in ($Script:RawCatalog | Where-Object { $_.Lsvc } | ForEach-Object { $_.N }) }).Count
    $cats['Licensing'] = if ($licTotal -eq 0) { $null } else { [int](100 - (100 * $licProducts.Count / $licTotal)) }

    # Windows: use health score or null
    $cats['Windows'] = if ($WindowsHealth -and $WindowsHealth.Score) { $WindowsHealth.Score } else { $null }

    # Network: use health score or null
    $cats['Network'] = if ($NetworkHealth -and $NetworkHealth.Score) { $NetworkHealth.Score } else { $null }

    # Thermals: unknown from ACPI zones
    $cats['Thermals'] = $null

    # ProjectSafety: unknown unless Guardian ran
    $cats['ProjectSafety'] = $null

    # Calculate weighted average of non-null categories
    $weights = @{
        Hardware = 0.25; Storage = 0.20; EngineeringSoftware = 0.25
        GPU = 0.10; Drivers = 0.10; Licensing = 0.10
    }
    $totalWeight = 0
    $weightedSum = 0
    foreach ($k in $cats.Keys) {
        if ($null -eq $cats[$k]) { continue }
        $w = if ($weights.ContainsKey($k)) { $weights[$k] } else { 0.05 }
        $weightedSum += $cats[$k] * $w
        $totalWeight += $w
    }
    $overall = if ($totalWeight -gt 0) { [int][math]::Round($weightedSum / $totalWeight) } else { 0 }

    [pscustomobject]@{
        Overall    = $overall
        Categories = $cats
        Label      = "Heuristic readiness score — not a vendor certification"
    }
}

# =============================================================================
# WINDOWS / NETWORK HEALTH
# =============================================================================
$windowsHealth = Get-WindowsHealth -System $sys
$networkHealth = Get-NetworkHealth -System $sys -Catalog $Script:RawCatalog -Installed $installed

# =============================================================================
# LIVE GPU SAMPLE
# =============================================================================
$liveGpu = @()
if ($LiveGpuSample) {
    Write-Stage "Sampling live GPU utilization..."
    try {
        $samples = Get-Counter '\GPU Engine(*)\Utilization Percentage' `
                    -SampleInterval 1 -MaxSamples 2 -ErrorAction Stop
        $perInstance = @{}
        foreach ($s in $samples.CounterSamples) {
            $key = $s.InstanceName
            if (-not $perInstance.ContainsKey($key)) { $perInstance[$key] = @() }
            $perInstance[$key] += $s.CookedValue
        }
        # Aggregate by PID (sum of all engines, not max of one)
        $perProc = @{}
        foreach ($k in $perInstance.Keys) {
            if ($k -match 'pid_(\d+)') {
                $pid2 = [int]$Matches[1]
                $sum = ($perInstance[$k] | Measure-Object -Sum).Sum
                if (-not $perProc.ContainsKey($pid2)) { $perProc[$pid2] = 0 }
                $perProc[$pid2] += $sum
            }
        }
        $top = $perProc.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
        $liveGpu = foreach ($t in $top) {
            $pname = try { (Get-Process -Id $t.Key -ErrorAction Stop).ProcessName } catch { "pid $($t.Key)" }
            [pscustomobject]@{ Pid = $t.Key; Process = $pname; GPU = [math]::Round($t.Value, 1) }
        }
    } catch {
        Add-Diagnostic 'GPU' "Live GPU sample failed: $_"
    }
    Write-Ok
}

$score = Get-HealthScore -Results $allResults -System $sys -NetFx $netFx -VC $vc `
                         -WindowsHealth $windowsHealth -NetworkHealth $networkHealth

# =============================================================================
# DISCIPLINE ROLLUP
# =============================================================================
Write-Head "Discipline rollup"
$byDisc = @{}
foreach ($r in $allResults) {
    if ($r.State -in @('NotInstalled','NotApplicable')) { continue }
    foreach ($d in ($r.Disciplines -split ',\s*')) {
        if (-not $byDisc.ContainsKey($d)) { $byDisc[$d] = @() }
        $byDisc[$d] += $r
    }
}
foreach ($d in $byDisc.Keys | Sort-Object) {
    $rs    = $byDisc[$d]
    $green = @($rs | Where-Object State -eq 'Healthy').Count
    $yell  = @($rs | Where-Object State -eq 'Attention').Count
    $red   = @($rs | Where-Object State -eq 'Critical').Count
    $total = $rs.Count
    Write-Host ("  {0,-18} {1,2} detected / {2,2} healthy  {3,2} attention  {4,2} critical" `
                -f $d, $total, $green, $yell, $red) -ForegroundColor Cyan
}

Write-Host ""
Write-Host ("  SIGMA WORKSTATION READINESS SCORE (heuristic): {0}/100" -f $score.Overall) -ForegroundColor Green
Write-Host "  This is a Sigma heuristic, not a vendor certification." -ForegroundColor DarkGray
foreach ($k in $score.Categories.Keys) {
    $val = if ($null -eq $score.Categories[$k]) { 'Unknown' } else { "$($score.Categories[$k])/100" }
    Write-Host ("    {0,-22} {1}" -f $k, $val)
}

# =============================================================================
# PROJECT GUARDIAN (fixed: line-based DXF parser, explicit DWG limitation)
# =============================================================================
function Get-DwgReferences {
    param([string]$FilePath)

    $refs = New-Object System.Collections.Generic.List[object]
    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()

    try {
        if ($ext -eq '.dxf') {
            # Proper line-based DXF parser: group code and value on separate lines
            $lines = Get-Content -LiteralPath $FilePath -ErrorAction Stop
            for ($i = 0; $i -lt $lines.Count - 1; $i++) {
                $code = $lines[$i].Trim()
                $value = $lines[$i + 1].Trim()

                # BLOCK → XREF
                if ($code -eq '0' -and $value -eq 'BLOCK') {
                    # Look ahead for *X or XREF markers
                    for ($j = $i + 2; $j -lt [math]::Min($i + 20, $lines.Count); $j++) {
                        if ($lines[$j].Trim() -eq '1') {
                            $refPath = $lines[$j + 1].Trim()
                            if ($refPath -and $refPath -notmatch '^\*') {
                                $refs.Add([pscustomobject]@{ Type = 'XREF'; Path = $refPath })
                            }
                            break
                        }
                    }
                }
                # IMAGEDEF
                if ($code -eq '0' -and $value -eq 'IMAGEDEF') {
                    for ($j = $i + 2; $j -lt [math]::Min($i + 10, $lines.Count); $j++) {
                        if ($lines[$j].Trim() -eq '1') {
                            $refs.Add([pscustomobject]@{ Type = 'IMAGE'; Path = $lines[$j + 1].Trim() })
                            break
                        }
                    }
                }
                # PDFDEFINITION
                if ($code -eq '0' -and $value -eq 'PDFDEFINITION') {
                    for ($j = $i + 2; $j -lt [math]::Min($i + 10, $lines.Count); $j++) {
                        if ($lines[$j].Trim() -eq '1') {
                            $refs.Add([pscustomobject]@{ Type = 'PDF'; Path = $lines[$j + 1].Trim() })
                            break
                        }
                    }
                }
            }
        } elseif ($ext -eq '.dwg') {
            # DWG is a binary format. This is a best-effort string scan, not a parser.
            # Authoritative extraction requires RealDWG, AutoCAD COM, or a dedicated DWG parser.
            $fi = Get-Item -LiteralPath $FilePath
            if ($fi.Length -gt 250MB) {
                $refs.Add([pscustomobject]@{ Type = 'SKIPPED'; Path = "File too large ($([math]::Round($fi.Length/1MB)) MB)" })
                return $refs
            }
            $bytes = [System.IO.File]::ReadAllBytes($FilePath)
            $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
            $extPat = '(dwg|dxf|pdf|jpg|jpeg|png|tif|tiff|shx|ttf|shp|dgn|dwf|dwfx)'
            foreach ($m in [regex]::Matches($ascii, "[A-Za-z]:\\\\[^\x00-\x1F`"<>|]{0,250}\.$extPat", 'IgnoreCase')) {
                $refs.Add([pscustomobject]@{ Type = 'REF (best-effort)'; Path = $m.Value })
            }
        }
    } catch {
        Add-Diagnostic 'XREF' "Failed to parse ${FilePath}: $_"
    }
    return $refs
}

function Invoke-ProjectGuardian {
    param([string]$Root)

    if (-not (Test-Path $Root)) {
        Write-Host "[ERROR] Project path not found: $Root" -ForegroundColor Red
        return $null
    }

    Write-Head "Project Guardian: $Root"

    $engExt = @(
        '.dwg','.dxf','.rvt','.rfa','.nwd','.nwc','.ifc',
        '.sldprt','.sldasm','.slddrw','.step','.stp','.iges','.igs','.stl',
        '.inp','.cdb','.mph','.mat','.m','.slx','.sdb','.edb',
        '.kicad_pcb','.kicad_sch','.sch','.brd',
        '.shp','.shx','.dbf','.las','.laz','.tif','.tiff',
        '.catpart','.catproduct','.prt','.asm','.3dxml',
        '.model','.exp','.cgr','.cnc'
    )
    $backupExt = @('.bak','.tmp','.sv$','.dwl','.dwl2','.ac$','.err')
    # Note: .log removed from backup list — logs may be required artifacts

    $scan = @(Get-ChildItem -LiteralPath $Root -Recurse -Force -File -ErrorAction SilentlyContinue)

    $byExt = @{}
    $totalBytes = 0
    $longPaths = 0
    $backupFiles = 0
    $largeFiles = 0
    $largeBytes = 0
    $oldBackups = 0

    $cutoff = (Get-Date).AddDays(-180)

    foreach ($f in $scan) {
        $ext = $f.Extension.ToLower()
        if (-not $byExt.ContainsKey($ext)) { $byExt[$ext] = 0 }
        $byExt[$ext]++
        $totalBytes += $f.Length

        if ($f.FullName.Length -gt 240) { $longPaths++ }
        if ($backupExt -contains $ext) {
            $backupFiles++
            if ($f.LastWriteTime -lt $cutoff) { $oldBackups++ }
        }
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
    Write-Host ("  Large files (>500MB): {0} ({1} GB)" -f $largeFiles, [math]::Round($largeBytes/1GB, 2))
    Write-Host ""

    $penalty = 0
    if ($longPaths -gt 0)      { $penalty += [math]::Min(25, $longPaths) }
    if ($oldBackups -gt 5)     { $penalty += [math]::Min(15, [int]($oldBackups / 5)) }
    if ($largeFiles -gt 10)    { $penalty += [math]::Min(15, [int]($largeFiles / 5)) }

    Write-Host "  Top file types:" -ForegroundColor Cyan
    $byExt.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object {
        Write-Host ("    {0,-14} {1,6}" -f $_.Key, $_.Value)
    }

    # Reference scan
    $dwgFiles = @($scan | Where-Object { $_.Extension -in @('.dwg','.dxf') })
    $maxDwg = 200
    $truncated = $false
    if ($dwgFiles.Count -gt $maxDwg) {
        Write-Host "  (limiting reference scan to first $maxDwg drawings — $($dwgFiles.Count - $maxDwg) not scanned)" -ForegroundColor Yellow
        $dwgFiles = $dwgFiles | Select-Object -First $maxDwg
        $truncated = $true
    }

    $refTotal = 0
    $refMissing = 0
    $refMissingList = @()
    $refSkipped = 0

    if ($dwgFiles.Count -gt 0) {
        Write-Host ""
        Write-Host "  Scanning drawing references..." -ForegroundColor Cyan
        foreach ($dwg in $dwgFiles) {
            $refs = Get-DwgReferences -FilePath $dwg.FullName
            foreach ($r in $refs) {
                if ($r.Type -eq 'SKIPPED') { $refSkipped++; continue }
                $refTotal++
                $p = $r.Path -replace '/', '\'
                if (-not [System.IO.Path]::IsPathRooted($p)) {
                    $p = Join-Path $dwg.DirectoryName $p
                }
                if (-not (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) {
                    $refMissing++
                    $refMissingList += [pscustomobject]@{
                        Drawing = $dwg.FullName
                        Type    = $r.Type
                        Ref     = $r.Path
                    }
                }
            }
        }
        Write-Host ("    References found:   {0}" -f $refTotal)
        Write-Host ("    Missing / broken:   {0}" -f $refMissing) -ForegroundColor $(if ($refMissing -gt 0) { 'Yellow' } else { 'Green' })
        if ($refSkipped -gt 0) {
            Write-Host ("    Drawings skipped:   {0} (too large or unreadable)" -f $refSkipped) -ForegroundColor Yellow
        }
        if ($truncated) {
            Write-Host "    NOTE: Reference scan was truncated. Results are partial." -ForegroundColor Yellow
        }
    }

    if ($refTotal -gt 0) {
        $missRatio = $refMissing / $refTotal
        $penalty += [math]::Min(30, [int]($missRatio * 100))
    }

    $health = [math]::Max(0, 100 - $penalty)
    $col = if ($health -ge 80) { 'Green' } elseif ($health -ge 60) { 'Yellow' } else { 'Red' }
    Write-Host ""
    Write-Host ("  Project Health (heuristic): {0}%" -f $health) -ForegroundColor $col
    Write-Host ""

    return [pscustomobject]@{
        Root             = $Root
        TotalFiles       = $scan.Count
        TotalGB          = [math]::Round($totalBytes/1GB, 2)
        EngineeringFiles = $engFiles
        LongPaths        = $longPaths
        BackupFiles      = $backupFiles
        OldBackups       = $oldBackups
        LargeFiles       = $largeFiles
        LargeGB          = [math]::Round($largeBytes/1GB, 2)
        ByExtension      = $byExt
        RefTotal         = $refTotal
        RefMissing       = $refMissing
        RefMissingList   = $refMissingList
        RefSkipped       = $refSkipped
        Truncated        = $truncated
        Health           = $health
    }
}

$guardian = $null
if ($ProjectGuardian) {
    $guardian = Invoke-ProjectGuardian -Root $ProjectGuardian
    if ($guardian) {
        $score.Categories['ProjectSafety'] = $guardian.Health
        # Recalculate with ProjectSafety included
        $weights = @{
            Hardware = 0.25; Storage = 0.20; EngineeringSoftware = 0.25
            GPU = 0.10; Drivers = 0.10; Licensing = 0.10
        }
        $totalWeight = 0; $weightedSum = 0
        foreach ($k in $score.Categories.Keys) {
            if ($null -eq $score.Categories[$k]) { continue }
            $w = if ($weights.ContainsKey($k)) { $weights[$k] } else { 0.05 }
            $weightedSum += $score.Categories[$k] * $w
            $totalWeight += $w
        }
        $score.Overall = if ($totalWeight -gt 0) { [int][math]::Round($weightedSum / $totalWeight) } else { 0 }
    }
}

# =============================================================================
# WRITE REPORT (fixed: HTML-escaped output)
# =============================================================================
Write-Stage "Writing report (HTML / JSON / CSV)..."
Ensure-Folder $exportPath

# JSON
[pscustomobject]@{
    GeneratedAt   = (Get-Date).ToString('s')
    System        = $sys
    NetFx         = $netFx
    DotNetRuntimes = $dotnet
    VCRedist      = $vc
    Score         = $score
    WindowsHealth = $windowsHealth
    NetworkHealth = $networkHealth
    LiveGpu       = $liveGpu
    Guardian      = $guardian
    Results       = $allResults
} | ConvertTo-Json -Depth 12 | Set-Content "$reportBase.json" -Encoding UTF8

# CSV
$allResults | Select-Object Name, Disciplines, Kind, State, Version, Installed,
    @{n='Findings';e={ ($_.Findings | ForEach-Object { "$($_.Severity): $($_.Problem)" }) -join ' | ' }},
    @{n='Notes';   e={ $_.Notes -join ' | ' }} |
    Export-Csv "$reportBase.csv" -NoTypeInformation -Encoding UTF8

# HTML helper: escape all dynamic values
function HtmlEnc {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Web.HttpUtility]::HtmlEncode($Text)
}
Add-Type -AssemblyName System.Web

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
 .disc{border-left:4px solid #0b5394;padding-left:10px;margin-top:22px}
 .hero{background:linear-gradient(135deg,#0b5394,#0a3d6e);color:#fff;border-radius:12px;padding:28px 24px;margin:10px 0 20px 0;text-align:center;box-shadow:0 6px 20px rgba(11,83,148,.25)}
 .hero-num{font-size:64px;font-weight:800;line-height:1;letter-spacing:-2px}
 .hero-num span{font-size:22px;font-weight:400;opacity:.55}
 .hero-label{font-size:13px;text-transform:uppercase;letter-spacing:3px;opacity:.85;margin-top:6px}
 .hero-note{font-size:11px;opacity:.7;margin-top:8px}
 .hero-cats{display:flex;flex-wrap:wrap;justify-content:center;gap:12px;margin-top:22px}
 .hero-cats > div{background:rgba(255,255,255,.12);padding:10px 14px;border-radius:8px;min-width:100px}
 .hero-cats b{display:block;font-size:20px;font-weight:700}
 .hero-cats span{font-size:10px;text-transform:uppercase;letter-spacing:1px;opacity:.8}
 .finding{background:#fff;border-left:5px solid #8b95a5;border-radius:6px;padding:14px 18px;margin:12px 0;box-shadow:0 1px 3px rgba(0,0,0,.05)}
 .finding.sev-critical{border-left-color:#c23636}
 .finding.sev-warn{border-left-color:#d18b00}
 .finding-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;gap:10px}
 .finding-title{font-weight:600;font-size:14px}
 .finding-body{width:100%;border:none;font-size:12px;margin:0}
 .finding-body th{background:transparent;border:none;color:#8b95a5;text-transform:uppercase;font-size:10px;letter-spacing:1.2px;width:150px;padding:3px 12px 3px 0;vertical-align:top;font-weight:700}
 .finding-body td{border:none;padding:3px 0}
 .legend{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 18px 0}
 .legend .chip{font-size:12px;padding:4px 10px}
</style>
'@

$chipClass = @{
    'Healthy'='green'; 'Attention'='yellow'; 'Critical'='red'
    'NotInstalled'='gray'; 'NotApplicable'='darkgray'; 'Unknown'='blue'
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("<!doctype html><html><head><meta charset='utf-8'><title>Sigma Engineer Toolkit - Report</title>$style</head><body>")
[void]$sb.AppendLine("<h1>Sigma Engineer Toolkit</h1>")
[void]$sb.AppendLine("<p class='sub'>Generated $(HtmlEnc (Get-Date).ToString()) on $(HtmlEnc $sys.ComputerName)</p>")

# Hero
[void]$sb.AppendLine("<div class='hero'>")
[void]$sb.AppendLine("<div class='hero-num'>$($score.Overall)<span>/100</span></div>")
[void]$sb.AppendLine("<div class='hero-label'>Sigma Workstation Readiness Score</div>")
[void]$sb.AppendLine("<div class='hero-note'>Heuristic score — not a vendor certification</div>")
[void]$sb.AppendLine("<div class='hero-cats'>")
foreach ($k in $score.Categories.Keys) {
    $val = if ($null -eq $score.Categories[$k]) { '?' } else { $score.Categories[$k] }
    [void]$sb.AppendLine("<div><b>$val</b><span>$(HtmlEnc $k)</span></div>")
}
[void]$sb.AppendLine("</div></div>")

# Legend
[void]$sb.AppendLine("<h2>Legend</h2>")
[void]$sb.AppendLine("<div class='legend'>")
[void]$sb.AppendLine("<span class='chip green'>Healthy</span>")
[void]$sb.AppendLine("<span class='chip yellow'>Attention</span>")
[void]$sb.AppendLine("<span class='chip red'>Critical</span>")
[void]$sb.AppendLine("<span class='chip gray'>Not installed</span>")
[void]$sb.AppendLine("<span class='chip darkgray'>Not applicable</span>")
[void]$sb.AppendLine("<span class='chip blue'>Unknown</span>")
[void]$sb.AppendLine("</div>")

# Findings
$topFindings = @()
foreach ($r in $allResults) {
    foreach ($f in $r.Findings) { $topFindings += $f }
}
$topFindings = @($topFindings | Sort-Object @{e={ if ($_.Severity -eq 'critical') { 0 } else { 1 } }}, Id)

[void]$sb.AppendLine("<h2>Findings ($($topFindings.Count))</h2>")
if ($topFindings.Count -eq 0) {
    [void]$sb.AppendLine("<div class='card'>No issues were detected by the checks performed.</div>")
} else {
    foreach ($f in $topFindings) {
        $sevCls = if ($f.Severity -eq 'critical') { 'sev-critical' } else { 'sev-warn' }
        $chipCls = if ($f.Severity -eq 'critical') { 'red' } else { 'yellow' }
        $chipTxt = if ($f.Severity -eq 'critical') { 'CRITICAL' } else { 'ATTENTION' }
        [void]$sb.AppendLine("<div class='finding $sevCls'>")
        [void]$sb.AppendLine("<div class='finding-head'><span class='finding-title'>$(HtmlEnc $f.Problem)</span><span class='chip $chipCls'>$chipTxt</span></div>")
        [void]$sb.AppendLine("<table class='finding-body'>")
        [void]$sb.AppendLine("<tr><th>Software</th><td>$(HtmlEnc $f.Software)</td></tr>")
        [void]$sb.AppendLine("<tr><th>Detected</th><td>$(HtmlEnc $f.Detected)</td></tr>")
        [void]$sb.AppendLine("<tr><th>Why it matters</th><td>$(HtmlEnc $f.WhyItMatters)</td></tr>")
        [void]$sb.AppendLine("<tr><th>Recommended</th><td>$(HtmlEnc $f.Recommendation)</td></tr>")
        if ($f.Optional) { [void]$sb.AppendLine("<tr><th>Optional</th><td>$(HtmlEnc $f.Optional)</td></tr>") }
        [void]$sb.AppendLine("</table></div>")
    }
}

# Machine
[void]$sb.AppendLine("<h2>Machine</h2><div class='card'><table>")
foreach ($kv in @(
    @('OS', $sys.OS), @('Architecture', $sys.Arch),
    @('CPU', "$($sys.CPU) ($($sys.Cores)C/$($sys.LogicalCPUs)T)"),
    @('RAM', "$($sys.RAM_GB) GB (free $($sys.FreeRAM_GB) GB)"),
    @('.NET Framework', $netFx),
    @('Modern .NET runtimes', ($dotnet | ForEach-Object { "$($_.Type) $($_.Version)" }) -join ', '),
    @('VC++ Redistributables', $vc.Count),
    @('PowerShell', $PSVersionTable.PSVersion.ToString()),
    @('Admin', $sys.IsAdmin),
    @('Power', $sys.Power.StatusText),
    @('Discrete GPU', $sys.HasDiscreteGPU)
)) {
    [void]$sb.AppendLine("<tr><th style='width:220px'>$(HtmlEnc $kv[0])</th><td>$(HtmlEnc $kv[1])</td></tr>")
}
[void]$sb.AppendLine("</table></div>")

# Graphics
[void]$sb.AppendLine("<h2>Graphics</h2><div class='card'><table><tr><th>GPU</th><th>Kind</th><th>Driver</th><th>Date</th><th>VRAM (GB)</th><th>Source</th></tr>")
foreach ($g in $sys.GPUs) {
    [void]$sb.AppendLine("<tr><td>$(HtmlEnc $g.Name)</td><td>$(HtmlEnc $g.Kind)</td><td>$(HtmlEnc $g.DriverVersion)</td><td>$(HtmlEnc $g.DriverDate)</td><td>$(HtmlEnc $g.VRAM_GB)</td><td>$(HtmlEnc $g.VRAM_Source)</td></tr>")
}
[void]$sb.AppendLine("</table></div>")

# Live GPU
if ($liveGpu -and $liveGpu.Count -gt 0) {
    [void]$sb.AppendLine("<h2>Live GPU Sample</h2><div class='card'><table><tr><th>PID</th><th>Process</th><th>GPU %</th></tr>")
    foreach ($g in $liveGpu) {
        [void]$sb.AppendLine("<tr><td>$($g.Pid)</td><td>$(HtmlEnc $g.Process)</td><td>$($g.GPU)%</td></tr>")
    }
    [void]$sb.AppendLine("</table><p class='small'>Aggregated across all GPU engines per process.</p></div>")
}

# Disks
[void]$sb.AppendLine("<h2>Disks</h2><div class='card'><table><tr><th>Drive</th><th>Label</th><th>FS</th><th>Type</th><th>Size GB</th><th>Free GB</th><th>Free %</th></tr>")
foreach ($d in $sys.Disks) {
    $cls = if ($d.FreePct -lt 10) { 'red' } elseif ($d.FreePct -lt 20) { 'yellow' } else { 'green' }
    [void]$sb.AppendLine("<tr><td>$(HtmlEnc $d.Drive)</td><td>$(HtmlEnc $d.Label)</td><td>$(HtmlEnc $d.FS)</td><td>$(HtmlEnc $d.DriveType)</td><td>$($d.SizeGB)</td><td>$($d.FreeGB)</td><td><span class='chip $cls'>$($d.FreePct)%</span></td></tr>")
}
[void]$sb.AppendLine("</table></div>")

# Windows Health
[void]$sb.AppendLine("<h2>Windows Health</h2><div class='card'><table>")
$rb = if ($windowsHealth.PendingReboot) { "<span class='chip red'>YES</span> $(HtmlEnc $windowsHealth.RebootReason)" } else { "<span class='chip green'>No</span>" }
[void]$sb.AppendLine("<tr><th style='width:220px'>Pending reboot</th><td>$rb</td></tr>")
[void]$sb.AppendLine("<tr><th>Windows Update service</th><td>$(HtmlEnc $windowsHealth.UpdateService)</td></tr>")
[void]$sb.AppendLine("<tr><th>Antivirus</th><td>$(HtmlEnc $windowsHealth.Defender)</td></tr>")
[void]$sb.AppendLine("<tr><th>Firewall</th><td>$(HtmlEnc $windowsHealth.Firewall)</td></tr>")
[void]$sb.AppendLine("<tr><th>Activation</th><td>$(HtmlEnc $windowsHealth.Activation)</td></tr>")
[void]$sb.AppendLine("<tr><th>OS install age</th><td>$($windowsHealth.BuildAgeDays) days</td></tr>")
[void]$sb.AppendLine("<tr><th>Category score</th><td><b>$($windowsHealth.Score)/100</b></td></tr>")
[void]$sb.AppendLine("</table><p class='small'>Windows Update service being stopped is normal (trigger-start). No penalty applied.</p></div>")

# Power
[void]$sb.AppendLine("<h2>Power</h2><div class='card'><table>")
[void]$sb.AppendLine("<tr><th style='width:220px'>Has battery</th><td>$($sys.Power.HasBattery)</td></tr>")
$acChip = if ($sys.Power.OnAC) { 'Yes' } else { "<span class='chip yellow'>No</span>" }
[void]$sb.AppendLine("<tr><th>On AC power</th><td>$acChip</td></tr>")
if ($sys.Power.Percent -ne $null) { [void]$sb.AppendLine("<tr><th>Charge</th><td>$($sys.Power.Percent)%</td></tr>") }
[void]$sb.AppendLine("<tr><th>Status</th><td>$(HtmlEnc $sys.Power.StatusText)</td></tr>")
[void]$sb.AppendLine("</table></div>")

# Thermals
if ($sys.ThermalZones.Count -gt 0) {
    [void]$sb.AppendLine("<h2>Thermals (ACPI Zones)</h2><div class='card'><table><tr><th>Zone</th><th>Temperature</th></tr>")
    foreach ($z in $sys.ThermalZones) {
        $cls = if ($z.Celsius -lt 70) { 'green' } elseif ($z.Celsius -lt 85) { 'yellow' } else { 'red' }
        [void]$sb.AppendLine("<tr><td>$(HtmlEnc $z.Zone)</td><td><span class='chip $cls'>$($z.Celsius) C</span></td></tr>")
    }
    [void]$sb.AppendLine("</table><p class='small'>These are ACPI thermal zones from firmware. They are NOT necessarily CPU package temperature. Thresholds are advisory only.</p></div>")
}

# Network
[void]$sb.AppendLine("<h2>Network</h2><div class='card'><table>")
[void]$sb.AppendLine("<tr><th style='width:220px'>Link speed</th><td>$(HtmlEnc $networkHealth.LinkSpeedText)</td></tr>")
$dnsChip = if ($networkHealth.DNS -eq 'OK') { "<span class='chip green'>OK</span>" } else { "<span class='chip red'>$(HtmlEnc $networkHealth.DNS)</span>" }
[void]$sb.AppendLine("<tr><th>DNS</th><td>$dnsChip</td></tr>")
[void]$sb.AppendLine("<tr><th>Default gateway</th><td>$(HtmlEnc $networkHealth.DefaultGW)</td></tr>")
[void]$sb.AppendLine("<tr><th>Category score</th><td><b>$($networkHealth.Score)/100</b></td></tr>")
[void]$sb.AppendLine("</table>")
if ($networkHealth.Adapters.Count -gt 0) {
    [void]$sb.AppendLine("<h3 style='margin-top:16px'>Adapters</h3>")
    [void]$sb.AppendLine("<table><tr><th>Name</th><th>Link speed</th><th>MAC</th></tr>")
    foreach ($a in $networkHealth.Adapters) {
        [void]$sb.AppendLine("<tr><td>$(HtmlEnc $a.Name)</td><td>$(HtmlEnc $a.LinkSpeed)</td><td>$(HtmlEnc $a.Mac)</td></tr>")
    }
    [void]$sb.AppendLine("</table>")
}
[void]$sb.AppendLine("</div>")

# License Center
if ($networkHealth.License.Count -gt 0) {
    [void]$sb.AppendLine("<h2>License Center</h2><div class='card'><table>")
    [void]$sb.AppendLine("<tr><th>Product</th><th>License Host</th><th>Ports</th><th>Status</th></tr>")
    foreach ($l in $networkHealth.License) {
        $chip = switch ($l.Status) {
            'Open'   { "<span class='chip green'>OPEN</span>" }
            'Closed' { "<span class='chip red'>CLOSED</span>" }
            default  { "<span class='chip gray'>$(HtmlEnc $l.Status)</span>" }
        }
        [void]$sb.AppendLine("<tr><td>$(HtmlEnc $l.Product)</td><td>$(HtmlEnc $l.Host)</td><td>$(HtmlEnc $l.Ports)</td><td>$chip</td></tr>")
    }
    [void]$sb.AppendLine("</table><p class='small'>License server host is discovered from environment variables and vendor config files. If the host is 'Unknown', the configured license server could not be determined. Port checks are against the discovered host, not localhost.</p></div>")
}

# Guardian
if ($guardian) {
    [void]$sb.AppendLine("<h2>Project Guardian</h2><div class='card'>")
    [void]$sb.AppendLine("<p><b>$(HtmlEnc $guardian.Root)</b></p>")
    [void]$sb.AppendLine("<table>")
    [void]$sb.AppendLine("<tr><th style='width:220px'>Total files</th><td>$($guardian.TotalFiles)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Total size</th><td>$($guardian.TotalGB) GB</td></tr>")
    [void]$sb.AppendLine("<tr><th>Engineering files</th><td>$($guardian.EngineeringFiles)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Long paths</th><td>$($guardian.LongPaths)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Backup/temp files</th><td>$($guardian.BackupFiles) (old: $($guardian.OldBackups))</td></tr>")
    [void]$sb.AppendLine("<tr><th>Large files</th><td>$($guardian.LargeFiles) ($($guardian.LargeGB) GB)</td></tr>")
    [void]$sb.AppendLine("<tr><th>References scanned</th><td>$($guardian.RefTotal)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Broken references</th><td>$($guardian.RefMissing)</td></tr>")
    if ($guardian.RefSkipped -gt 0) {
        [void]$sb.AppendLine("<tr><th>Drawings skipped</th><td>$($guardian.RefSkipped)</td></tr>")
    }
    if ($guardian.Truncated) {
        [void]$sb.AppendLine("<tr><th>Scan truncated</th><td>Yes — results are partial</td></tr>")
    }
    [void]$sb.AppendLine("<tr><th>Project Health (heuristic)</th><td><b>$($guardian.Health)%</b></td></tr>")
    [void]$sb.AppendLine("</table>")
    if ($guardian.RefMissingList -and $guardian.RefMissingList.Count -gt 0) {
        [void]$sb.AppendLine("<h3 style='margin-top:16px'>Broken references (first 50)</h3>")
        [void]$sb.AppendLine("<table><tr><th>Drawing</th><th>Type</th><th>Reference</th></tr>")
        foreach ($ref in ($guardian.RefMissingList | Select-Object -First 50)) {
            [void]$sb.AppendLine("<tr><td class='small'>$(HtmlEnc $ref.Drawing)</td><td>$(HtmlEnc $ref.Type)</td><td class='small'>$(HtmlEnc $ref.Ref)</td></tr>")
        }
        [void]$sb.AppendLine("</table>")
    }
    [void]$sb.AppendLine("</div>")
}

# Overall
[void]$sb.AppendLine("<h2>Overall</h2><div class='card'>")
[void]$sb.AppendLine("<p><span class='chip green'>$gCount healthy</span> &nbsp; <span class='chip yellow'>$yCount attention</span> &nbsp; <span class='chip red'>$rCount critical</span> &nbsp; <span class='chip gray'>$nCount not installed</span> &nbsp; <span class='chip darkgray'>$aCount not applicable</span></p>")
[void]$sb.AppendLine("</div>")

# Disciplines
[void]$sb.AppendLine("<h2>Disciplines</h2>")
foreach ($d in $byDisc.Keys | Sort-Object) {
    $rs = $byDisc[$d] | Sort-Object State, Name
    $g  = @($rs | Where-Object State -eq 'Healthy').Count
    $y  = @($rs | Where-Object State -eq 'Attention').Count
    $rr = @($rs | Where-Object State -eq 'Critical').Count
    [void]$sb.AppendLine("<div class='disc'><h3>$(HtmlEnc $d) <span class='small'>($g healthy / $y attention / $rr critical)</span></h3>")
    [void]$sb.AppendLine("<table><tr><th>Software</th><th>Kind</th><th>Status</th><th>Version</th><th>Findings</th></tr>")
    foreach ($p in $rs) {
        $cls = if ($chipClass.ContainsKey($p.State)) { $chipClass[$p.State] } else { 'gray' }
        $msg = @()
        foreach ($f in $p.Findings) {
            $mark = if ($f.Severity -eq 'critical') { '!!' } else { '!' }
            $msg += "$mark $(HtmlEnc $f.Problem)"
        }
        foreach ($n in $p.Notes) { $msg += ". $(HtmlEnc $n)" }
        $msg = $msg -join '<br>'
        [void]$sb.AppendLine("<tr><td><b>$(HtmlEnc $p.Name)</b></td><td>$(HtmlEnc $p.Kind)</td><td><span class='chip $cls'>$(HtmlEnc $p.State)</span></td><td>$(HtmlEnc $p.Version)</td><td class='small'>$msg</td></tr>")
    }
    [void]$sb.AppendLine("</table></div>")
}

[void]$sb.AppendLine("<p class='small'>End of report. Findings are advisory, not errors. Readiness score is a Sigma heuristic, not a vendor certification.</p>")
[void]$sb.AppendLine("</body></html>")
$sb.ToString() | Set-Content "$reportBase.html" -Encoding UTF8
Write-Ok

# =============================================================================
# FINAL
# =============================================================================
Write-Stage "Finalising..."
$null = Get-Item "$reportBase.html" -ErrorAction SilentlyContinue
Write-Ok

Write-Host ""
if (Test-Path $errorLog) {
    $errorCount = (Get-Content $errorLog | Measure-Object -Line).Lines
    if ($errorCount -gt 0) {
        Write-Host "[WARNING] $errorCount non-fatal issues logged: $errorLog" -ForegroundColor Yellow
    } else {
        Remove-Item $errorLog -Force
    }
}

Write-Host "[SUCCESS] Engineering diagnostic complete." -ForegroundColor Green
Write-Host "[INFO] HTML : $reportBase.html" -ForegroundColor Cyan
Write-Host "[INFO] JSON : $reportBase.json" -ForegroundColor Cyan
Write-Host "[INFO] CSV  : $reportBase.csv"  -ForegroundColor Cyan
Write-Host ""
Write-Host "Have a good day!" -ForegroundColor Cyan
Write-Host ""

if ($NonInteractive) { exit 0 }

$finalChoice = Read-Host "Press R to open report folder, I to install software, or Q to quit"
switch -Regex ($finalChoice) {
    '^[Rr]$' { Start-Process $exportPath }
    '^[Ii]$' { Invoke-Installer -Disciplines $Disciplines -InstallList @() }
    default { exit 0 }
}
