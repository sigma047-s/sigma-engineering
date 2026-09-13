#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sigma Engineer Toolkit — engineering workstation diagnostic + software installer.
.DESCRIPTION
    Read-only diagnostic pass over every engineering discipline.
    Detects installed software, checks prerequisites, writes a report.
    Includes health scoring, structured findings, preflight, project guardian,
    Windows/Network health, License Center, live GPU sampling, and a winget-based
    software installer with manual download fallbacks.

    NEW: Online enrichment — PassMark CPU/GPU benchmarks, real vendor driver
    version feeds (NVIDIA/AMD), and winget-based outdated-package detection.

    NEW: Full system online verification — Windows build, .NET Framework,
    VC++ Redistributable, Defender signatures, motherboard BIOS, disk SMART,
    RAM module part numbers, and network adapter capability. Every scanned
    fact is cross-checked against an online source when available.
    All online data is cached and degrades gracefully if offline.
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
.PARAMETER Offline
    Skip all online enrichment. Uses local heuristics only.
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
    [switch]$Offline,
    [switch]$Install,
    [string[]]$InstallList = @()
)

Write-Host "`n========== SIGMA ENGINEER TOOLKIT ==========" -ForegroundColor Green
Write-Host ""
Write-Host "[INFO] Scans every engineering discipline on this workstation." -ForegroundColor Cyan
Write-Host "[INFO] Detects installed software, checks prerequisites, writes a report." -ForegroundColor Cyan
Write-Host "[INFO] The tool can install engineering software." -ForegroundColor Cyan
Write-Host "[INFO] Online: PassMark, vendor driver feeds, winget, Windows/BIOS/SMART." -ForegroundColor Cyan
Write-Host "[WARNING] A full scan can take 2-5 minutes on a loaded machine." -ForegroundColor Yellow
Write-Host "[WARNING] Deep cache scan adds 1-3 minutes per large product." -ForegroundColor Yellow
Write-Host "[WARNING] This scaning tool isn't 100% accurate." -ForegroundColor Yellow
if ($Offline) {
    Write-Host "[INFO] Offline mode: online enrichment disabled." -ForegroundColor Cyan
}
if ($Disciplines.Count -gt 0) {
    Write-Host "[INFO] Discipline filter: $($Disciplines -join ', ')" -ForegroundColor Cyan
}
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
    param(
        [string]$ComputerName = 'localhost',
        [int]$Port,
        [int]$TimeoutMs = 1500
    )
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

function Get-ThermalInfo {
    $zones = @()
    try {
        $t = Get-CimInstance -Namespace 'root/WMI' -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop
        $i = 0
        foreach ($z in $t) {
            $i++
            $c = ($z.CurrentTemperature / 10) - 273.15
            $zones += [pscustomobject]@{
                Zone    = "Zone$i"
                Celsius = [math]::Round($c, 1)
            }
        }
    } catch { }
    return $zones
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
    Get-InstalledSoftware | Where-Object {
        $_.DisplayName -match 'Microsoft Visual C\+\+.*Redistributable'
    } | Select-Object DisplayName, DisplayVersion
}

function New-Finding {
    param(
        [string]$Id,
        [string]$Software,
        [string]$Problem,
        [string]$Detected,
        [string]$WhyItMatters,
        [string]$Recommendation,
        [string]$Optional = '',
        [string]$Severity = 'warn',
        [double]$RecoverableGB = 0
    )
    [pscustomobject]@{
        Id             = $Id
        Software       = $Software
        Problem        = $Problem
        Detected       = $Detected
        WhyItMatters   = $WhyItMatters
        Recommendation = $Recommendation
        Optional       = $Optional
        Severity       = $Severity
        RecoverableGB  = $RecoverableGB
    }
}

function Get-LiveGpuSample {
    param([int]$DurationSeconds = 2)
    try {
        $samples = Get-Counter '\GPU Engine(*)\Utilization Percentage' `
                    -SampleInterval 1 -MaxSamples $DurationSeconds -ErrorAction Stop
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
# 1. MASTER CATALOG
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
# 2. DISCIPLINE PROFILES
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
    'Surveying'       = @('Trimble Business Center','Leica Infinity','Carlson Survey','Civil 3D','Autodesk ReCap')
    'PLM'             = @('Siemens Teamcenter','SOLIDWORKS','CATIA','Siemens NX','PTC Creo')
    'CFD'             = @('ANSYS Fluent','Simcenter STAR-CCM+','OpenFOAM','COMSOL Multiphysics','ANSYS')
    'FEA'             = @('ANSYS','Abaqus','MSC Nastran','LS-DYNA','Altair HyperWorks','COMSOL Multiphysics')
    'CAD'             = @('AutoCAD','SOLIDWORKS','Autodesk Inventor','CATIA','Siemens NX','PTC Creo','Solid Edge','BricsCAD','Fusion 360','Rhino')
}
Write-Ok

# =============================================================================
# 3. INSTALLED SOFTWARE
# =============================================================================
Write-Stage "Scanning installed software..."
$installed = Get-InstalledSoftware
Write-Host " $($installed.Count) entries." -ForegroundColor Green

# =============================================================================
# 4. SYSTEM INVENTORY
# =============================================================================
Write-Stage "Capturing system inventory..."
$sys = & {
    $os   = Get-CimInstance Win32_OperatingSystem
    $cs   = Get-CimInstance Win32_ComputerSystem
    $cpu  = Get-CimInstance Win32_Processor | Select-Object -First 1
    $gpus = @(Get-CimInstance Win32_VideoController)

    $gpuInfo = foreach ($g in $gpus) {
        $mem = if ($g.AdapterRAM -and $g.AdapterRAM -gt 0) { [math]::Round($g.AdapterRAM / 1GB, 2) } else { $null }
        [pscustomobject]@{
            Name          = $g.Name
            Kind          = Get-GpuKind -Name $g.Name
            DriverVersion = $g.DriverVersion
            DriverDate    = if ($g.DriverDate) { ([datetime]$g.DriverDate).ToString('yyyy-MM-dd') } else { '' }
            VRAM_GB       = $mem
            Resolution    = "$($g.CurrentHorizontalResolution)x$($g.CurrentVerticalResolution)"
        }
    }

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
                }
            }
        }
    }

    $pf = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue

    $hasDedicated  = @($gpuInfo | Where-Object Kind -eq 'Discrete').Count -gt 0
    $hasIntegrated = @($gpuInfo | Where-Object Kind -eq 'Integrated').Count -gt 0

    [pscustomobject]@{
        ComputerName   = $env:COMPUTERNAME
        User           = "$env:USERDOMAIN\$env:USERNAME"
        OS             = "$($os.Caption) ($($os.Version), Build $($os.BuildNumber))"
        OSBuild        = "$($os.Version).$($os.BuildNumber)"
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
# 5. PREREQUISITES
# =============================================================================
Write-Stage "Checking prerequisites..."
$netFx = Get-DotNetFrameworkVersion
$vc    = @(Get-VCRedist)
Write-Host " .NET=$netFx, VC++=$($vc.Count) entries." -ForegroundColor Green

# =============================================================================
# 5b. WINDOWS HEALTH
# =============================================================================
function Get-WindowsHealth {
    param([pscustomobject]$System)

    $r = [ordered]@{
        PendingReboot = $false
        RebootReason  = ''
        UpdateService = 'Unknown'
        Defender      = 'Unknown'
        DefenderSig   = 'Unknown'
        DefenderSigDate = ''
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
        if ($def.AntivirusSignatureVersion) {
            $r.DefenderSig = $def.AntivirusSignatureVersion
        }
        if ($def.AntivirusSignatureLastUpdated) {
            $r.DefenderSigDate = ([datetime]$def.AntivirusSignatureLastUpdated).ToString('yyyy-MM-dd')
        }
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

    if ($System.InstallDate) {
        try { $r.BuildAgeDays = (New-TimeSpan -Start $System.InstallDate -End (Get-Date)).Days } catch { }
    }

    $s = 100
    if ($r.PendingReboot)                                   { $s -= 20 }
    if ($r.UpdateService -ne 'Running')                     { $s -= 15 }
    if ($r.Defender -eq 'Off')                              { $s -= 15 }
    if ($r.Firewall -eq 'Off')                              { $s -= 10 }
    if ($r.Activation -in @('Unlicensed','Notification','Non-Genuine Grace')) { $s -= 25 }
    if ($r.BuildAgeDays -gt 3 * 365)                        { $s -= 10 }
    elseif ($r.BuildAgeDays -gt 2 * 365)                    { $s -= 5 }
    $r.Score = [math]::Max(0, $s)

    [pscustomobject]$r
}

# =============================================================================
# 5c. NETWORK HEALTH
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
                Mac       = $n.MacAddress
            }
        }
        $r.LinkSpeedMbps = [int]$maxMbps
        $r.LinkSpeedText = if ($maxMbps -ge 1000) { "$([math]::Round($maxMbps/1000,1)) Gbps" }
                           elseif ($maxMbps -gt 0) { "$maxMbps Mbps" } else { '' }
    } catch { }

    try {
        $null = Resolve-DnsName 'microsoft.com' -ErrorAction Stop -QuickTimeout
        $r.DNS = 'OK'
    } catch {
        $r.DNS = 'Failed'
    }

    try {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Select-Object -First 1
        if ($route) { $r.DefaultGW = $route.NextHop }
    } catch { }

    foreach ($entry in $Catalog) {
        if (-not $entry.Lport) { continue }
        $hit = $false
        foreach ($pat in @($entry.P)) {
            if ($Installed | Where-Object { $_.DisplayName -like $pat }) { $hit = $true; break }
        }
        if (-not $hit) { continue }

        $anyOpen = $false
        foreach ($p in $entry.Lport) {
            if (Test-TcpPort -Port $p -TimeoutMs 800) { $anyOpen = $true; break }
        }
        $r.License += [pscustomobject]@{
            Product = $entry.N
            Ports   = ($entry.Lport -join ', ')
            Local   = $anyOpen
        }
    }

    $s = 100
    if ($r.Adapters.Count -eq 0)                                            { $s -= 20 }
    elseif ($r.LinkSpeedMbps -gt 0 -and $r.LinkSpeedMbps -lt 100)           { $s -= 15 }
    elseif ($r.LinkSpeedMbps -gt 0 -and $r.LinkSpeedMbps -lt 1000)          { $s -= 5 }
    if ($r.DNS -ne 'OK')                                                    { $s -= 10 }
    if (-not $r.DefaultGW)                                                  { $s -= 10 }
    $r.Score = [math]::Max(0, $s)

    [pscustomobject]$r
}

# =============================================================================
# 5d. PREFLIGHT
# =============================================================================
function Invoke-Preflight {
    param(
        [string]$ProductName,
        [array]$Catalog,
        [pscustomobject]$System,
        [string]$NetFx,
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
        Write-Host "[INFO]  Try one of the catalog names, e.g. ANSYS, SOLIDWORKS, Revit, MATLAB" -ForegroundColor Yellow
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
        if ($System.RAM_GB -ge $entry.RAM) {
            Report 'OK' "RAM installed" "$($System.RAM_GB) GB >= $($entry.RAM) GB recommended"
        } else {
            Report 'WARN' "RAM below recommendation" "$($System.RAM_GB) GB installed, $($entry.RAM) GB recommended"
        }
    }
    Report 'OK' "Free RAM now" "$($System.FreeRAM_GB) GB of $($System.RAM_GB) GB"

    if ($System.PageFile -and $System.PageFile.Count -gt 0) {
        $pf = $System.PageFile | Select-Object -First 1
        Report 'OK' "Pagefile enabled" "$($pf.AllocatedBaseSize) MB allocated"
    } else {
        Report 'FAIL' "Pagefile not detected" "large solvers may fail"
    }

    if ($entry.Disk) {
        $sysd = $System.Disks | Where-Object Drive -eq "$($env:SystemDrive)"
        if ($sysd -and $sysd.FreeGB -ge $entry.Disk) {
            Report 'OK' "Scratch disk free" "$($sysd.FreeGB) GB on $($sysd.Drive)"
        } elseif ($sysd) {
            Report 'WARN' "Scratch disk tight" "$($sysd.FreeGB) GB free, $($entry.Disk) GB recommended"
        }
    }

    if ($entry.Net) {
        if (Compare-NetVersion -Have $NetFx -Need $entry.Net) {
            Report 'OK' ".NET Framework" "$NetFx >= $($entry.Net)"
        } else {
            Report 'FAIL' ".NET Framework" "have $NetFx, need $($entry.Net)"
        }
    }

    if ($entry.VCPP) {
        if ($VC -and $VC.Count -gt 0) {
            Report 'OK' "VC++ Runtime" "$($VC.Count) redistributable(s) present"
        } else {
            Report 'FAIL' "VC++ Runtime" "not detected"
        }
    }

    if ($entry.GPU) {
        $discrete = @($System.GPUs | Where-Object Kind -eq 'Discrete')
        if ($discrete.Count -gt 0) {
            Report 'OK' "Discrete GPU present" (($discrete | ForEach-Object { $_.Name }) -join ', ')
        } else {
            Report 'WARN' "No discrete GPU" "using integrated graphics"
        }
    }

    if ($entry.Lsvc) {
        $svc = @(Get-Service -ErrorAction SilentlyContinue | Where-Object {
            $n = $_.Name + ' ' + $_.DisplayName
            foreach ($pat in $entry.Lsvc) { if ($n -like $pat) { return $true } }
            return $false
        })
        if ($svc.Count -gt 0 -and (@($svc | Where-Object Status -eq 'Running').Count -gt 0)) {
            Report 'OK' "License service running" (($svc | Where-Object Status -eq 'Running' | Select-Object -First 1).DisplayName)
        } elseif ($svc.Count -gt 0) {
            Report 'FAIL' "License service stopped" (($svc | Select-Object -First 1).DisplayName)
        } else {
            Report 'WARN' "License service not found" "may be remote"
        }
    }

    if ($entry.Lport) {
        $open = @()
        foreach ($p in $entry.Lport) { if (Test-TcpPort -Port $p -TimeoutMs 800) { $open += $p } }
        if ($open.Count -gt 0) {
            Report 'OK' "License port(s) open" ($open -join ', ')
        } else {
            Report 'WARN' "License ports closed locally" "normal for node-locked or remote servers"
        }
    }

    if ($System.ThermalZones -and $System.ThermalZones.Count -gt 0) {
        $max = ($System.ThermalZones | Measure-Object Celsius -Maximum).Maximum
        if ($max -lt 80) {
            Report 'OK' "CPU temperature" "$max C"
        } elseif ($max -lt 95) {
            Report 'WARN' "CPU temperature elevated" "$max C"
        } else {
            Report 'FAIL' "CPU temperature critical" "$max C"
        }
    }

    if ($System.Power.HasBattery) {
        if ($System.Power.OnAC) {
            Report 'OK' "AC power" "battery at $($System.Power.Percent)% ($($System.Power.StatusText))"
        } else {
            Report 'WARN' "Running on battery" "$($System.Power.Percent)% - heavy solve will drain fast"
        }
    }

    $heavyNames = @('chrome','msedge','firefox','teams','slack','discord','zoom',
                    'photoshop','illustrator','premiere','aftereffects',
                    'code','devenv','rider','webstorm','pycharm','idea',
                    'excel','powerpnt','winword','outlook','spotify','obs','blender')
    $heavy = @()
    $recoverGB = 0
    try {
        $procs = Get-Process -ErrorAction SilentlyContinue
        foreach ($p in $procs) {
            if ($heavyNames -contains $p.ProcessName.ToLower()) {
                $gb = [math]::Round($p.WorkingSet64 / 1GB, 2)
                $heavy += [pscustomobject]@{ Name = $p.ProcessName; GB = $gb }
                $recoverGB += $gb
            }
        }
    } catch { }
    if ($heavy.Count -eq 0) {
        Report 'OK' "No heavy background apps detected"
    } else {
        $recoverGB = [math]::Round($recoverGB, 1)
        Report 'WARN' "$($heavy.Count) heavy application(s) open" "closing them recovers ~$recoverGB GB"
        foreach ($h in ($heavy | Sort-Object GB -Descending | Select-Object -First 5)) {
            Write-Host ("           - {0,-14} {1,5} GB" -f $h.Name, $h.GB) -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    $verdict = if ($fail -gt 0) { 'NOT READY' } elseif ($warn -gt 2) { 'CAUTION' } else { 'READY' }
    $col = if ($fail -gt 0) { 'Red' } elseif ($warn -gt 2) { 'Yellow' } else { 'Green' }
    Write-Host ("  $script:pass OK   $script:warn WARN   $script:fail FAIL   ->  $verdict") -ForegroundColor $col
    Write-Host ""
}

# =============================================================================
# 5e. WHY-SLOW
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
        RAM    = if ($ramPctFree -lt 15) { 'CRITICAL' } elseif ($ramPctFree -lt 30) { 'ELEVATED' } else { 'OK' }
        Disk   = if ($critDisk -and $critDisk.FreePct -lt 5) { 'CRITICAL' } elseif ($critDisk -and $critDisk.FreePct -lt 15) { 'ELEVATED' } else { 'OK' }
        CPU    = if (($topCpu | Select-Object -First 1).CPU -gt 60) { 'ELEVATED' } else { 'OK' }
        GPU    = if ($System.HasDiscreteGPU) { 'OK' } else { 'ELEVATED' }
        Power  = if ($System.Power.HasBattery -and -not $System.Power.OnAC) { 'ELEVATED' } else { 'OK' }
        Thermal= if ($System.ThermalZones.Count -gt 0 -and (($System.ThermalZones | Measure-Object Celsius -Maximum).Maximum) -gt 85) { 'ELEVATED' } else { 'OK' }
    }

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
    $thMax = if ($System.ThermalZones.Count -gt 0) { "$((($System.ThermalZones | Measure-Object Celsius -Maximum).Maximum)) C max" } else { 'not exposed' }
    Write-Host ("    Thermals            {0}" -f $thMax)
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
        foreach ($p in $topMem) {
            Write-Host ("    {0,-22} {1,6} GB" -f $p.Name, $p.GB)
        }
        Write-Host ""
    }
    if ($topCpu.Count -gt 0) {
        Write-Host "  Top CPU consumers (last 0.8s)" -ForegroundColor Cyan
        foreach ($p in $topCpu) {
            if ($p.CPU -lt 0.5) { continue }
            Write-Host ("    {0,-22} {1,6}%" -f $p.Name, $p.CPU)
        }
        Write-Host ""
    }

    $rec = switch ($primary) {
        'RAM'    { "Close unused applications or upgrade RAM. Currently $ramPctFree% free." }
        'Disk'   { "Free space on $($critDisk.Drive). Engineering tools need scratch headroom." }
        'Thermal'{ "Check cooling. Consider limiting solver threads until temperatures fall." }
        'Power'  { "Plug in AC power. Laptop battery mode throttles CPU and GPU." }
        'CPU'    { "A background process is consuming CPU. See the list above." }
        'GPU'    { "No discrete GPU detected. Some 3D and solver workloads will be slow." }
        default  { "No obvious local bottleneck. Check license server reachability and project file size." }
    }
    Write-Host "  RECOMMENDATION" -ForegroundColor Cyan
    Write-Host "    $rec"
    Write-Host ""
}

# =============================================================================
# 5f. DISPATCH PREFLIGHT / WHYSLOW
# =============================================================================
if ($Preflight) {
    Invoke-Preflight -ProductName $Preflight -Catalog $Script:RawCatalog `
                     -System $sys -NetFx $netFx -VC $vc -Installed $installed
    exit 0
}

if ($WhySlow) {
    Invoke-WhySlow -System $sys
    exit 0
}

# =============================================================================
# 5g. SOFTWARE INSTALLER
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
    'Autodesk Inventor'   = 'https://www.autodesk.com/products/inventor/free-trial'
    'Fusion 360'          = 'https://www.autodesk.com/products/fusion-360/free-trial'
    'Navisworks'          = 'https://www.autodesk.com/products/navisworks/free-trial'
    'Advance Steel'       = 'https://www.autodesk.com/products/advance-steel/free-trial'
    'AutoCAD Electrical'  = 'https://www.autodesk.com/products/autocad-electrical/free-trial'
    'AutoCAD MEP'         = 'https://www.autodesk.com/products/autocad-mep/free-trial'
    'Revit MEP'           = 'https://www.autodesk.com/products/revit/free-trial'
    'Robot Structural'    = 'https://www.autodesk.com/products/robot-structural-analysis/free-trial'
    'Autodesk ReCap'      = 'https://www.autodesk.com/products/recap/free-trial'
    'PowerMill'           = 'https://www.autodesk.com/products/powermill/overview'
    'InfoWorks ICM'       = 'https://www.autodesk.com/products/infoworks-icm'
    'Autodesk Construction Cloud' = 'https://construction.autodesk.com/'
    'Dynamo'              = 'https://dynamobim.org/download/'
    'BricsCAD'            = 'https://www.bricsys.com/en-intl/bricscad/'
    'Archicad'            = 'https://www.graphisoft.com/archicad/'
    'Bluebeam Revu'       = 'https://www.bluebeam.com/'
    'Rhino'               = 'https://www.rhino3d.com/download/'
    'Grasshopper'         = 'https://www.grasshopper3d.com/'
    'SOLIDWORKS'          = 'https://www.solidworks.com/sw/support/downloads.htm'
    'SOLIDWORKS Electrical' = 'https://www.solidworks.com/sw/support/downloads.htm'
    'CATIA'               = 'https://www.3ds.com/products/catia'
    'Abaqus'              = 'https://www.3ds.com/products/simulia/abaqus'
    'CST Studio Suite'    = 'https://www.3ds.com/products/simulia/cst-studio-suite'
    'Materials Studio'    = 'https://www.3ds.com/products/biovia/materials-studio'
    'Cameo Systems Modeler' = 'https://www.3ds.com/products/catia/no-magic/cameo-systems-modeler'
    'Siemens NX'          = 'https://plm.sw.siemens.com/en-US/nx/'
    'Siemens Teamcenter'  = 'https://plm.sw.siemens.com/en-US/teamcenter/'
    'Simcenter STAR-CCM+' = 'https://plm.sw.siemens.com/en-US/simcenter/fluids-thermal-simulation/star-ccm/'
    'Solid Edge'          = 'https://solidedge.siemens.com/'
    'Siemens Xpedition'   = 'https://eda.sw.siemens.com/en-US/pcb/xpedition/'
    'PADS Professional'   = 'https://eda.sw.siemens.com/en-US/pcb/pads/'
    'ANSYS'               = 'https://www.ansys.com/products'
    'ANSYS HFSS'          = 'https://www.ansys.com/products/electronics/ansys-hfss'
    'ANSYS Fluent'        = 'https://www.ansys.com/products/fluids/ansys-fluent'
    'ANSYS AQWA'          = 'https://www.ansys.com/products/structures/ansys-aqwa'
    'LS-DYNA'             = 'https://www.ansys.com/products/structures/ansys-ls-dyna'
    'COMSOL Multiphysics' = 'https://www.comsol.com/'
    'MATLAB'              = 'https://www.mathworks.com/products/matlab.html'
    'Simulink'            = 'https://www.mathworks.com/products/simulink.html'
    'MSC Nastran'         = 'https://www.mscsoftware.com/product/msc-nastran'
    'MSC Adams'           = 'https://www.mscsoftware.com/product/adams'
    'Altair HyperWorks'   = 'https://altair.com/hyperworks'
    'Altair HyperMesh'    = 'https://altair.com/hypermesh'
    'HyperMesh'           = 'https://altair.com/hypermesh'
    'OpenFOAM'            = 'https://openfoam.org/download/'
    'FactSage'            = 'https://www.factsage.com/'
    'Thermo-Calc'         = 'https://thermocalc.com/'
    'JMatPro'             = 'https://www.sentesoftware.co.uk/jmatpro'
    'Altium Designer'     = 'https://www.altium.com/'
    'ETAP'                = 'https://etap.com/'
    'EPLAN Electric P8'   = 'https://www.eplan-software.com/'
    'Cadence Allegro'     = 'https://www.cadence.com/en_US/home/tools/pcb-design-and-analysis/allegro.html'
    'OrCAD'               = 'https://www.orcad.com/'
    'PSpice'              = 'https://www.orcad.com/products/orcad-pspice-designer/overview'
    'Proteus'             = 'https://www.labcenter.com/'
    'EasyEDA'             = 'https://easyeda.com/'
    'DipTrace'            = 'https://diptrace.com/'
    'DesignSpark PCB'     = 'https://www.rs-online.com/designspark/pcb-software'
    'SKM PowerTools'      = 'https://www.skm.com/'
    'EasyPower'           = 'https://www.easypower.com/'
    'PSS/E'               = 'https://www.siemens.com/global/en/products/energy/services/transmission-distribution-smart-grid/consulting-and-planning/pss-software/pss-e.html'
    'PSCAD'               = 'https://www.pscad.com/'
    'DIgSILENT PowerFactory' = 'https://www.digsilent.de/en/downloads.html'
    'Keysight ADS'        = 'https://www.keysight.com/us/en/products/software/pathwave-design-software/pathwave-advanced-design-system.html'
    'NI LabVIEW'          = 'https://www.ni.com/en-us/support/downloads/software-products/download.labview.html'
    'NI Multisim'         = 'https://www.ni.com/en-us/support/downloads/software-products/download.multisim.html'
    'Siemens TIA Portal'  = 'https://support.industry.siemens.com/cs/products?dtp=Download&mfn=ps&lc=en-WW'
    'STEP 7'              = 'https://support.industry.siemens.com/cs/products?dtp=Download&mfn=ps&lc=en-WW'
    'WinCC'               = 'https://support.industry.siemens.com/cs/products?dtp=Download&mfn=ps&lc=en-WW'
    'Rockwell Studio 5000'= 'https://www.rockwellautomation.com/en-us/products/software/factorytalk/designsuite/studio-5000.html'
    'FactoryTalk View'    = 'https://www.rockwellautomation.com/en-us/products/software/factorytalk/operationsuite/view.html'
    'Beckhoff TwinCAT 3'  = 'https://www.beckhoff.com/en-en/products/automation/twincat/'
    'Schneider EcoStruxure' = 'https://www.se.com/ww/en/product-range/65878856-ecostruxure-control-expert/'
    'Mitsubishi GX Works' = 'https://www.mitsubishielectric.com/fa/products/cnt/plceng/smerit/gx_works3/index.html'
    'Omron Sysmac Studio' = 'https://automation.omron.com/en/us/products/family/sysmac-studio'
    'AVEVA System Platform' = 'https://www.aveva.com/en/products/system-platform/'
    'AVEVA Marine'        = 'https://www.aveva.com/en/products/'
    'CODESYS'             = 'https://www.codesys.com/download.html'
    'Ignition'            = 'https://inductiveautomation.com/downloads/'
    'Factory I/O'         = 'https://factoryio.com/downloads/'
    'Xilinx Vivado'       = 'https://www.xilinx.com/support/download.html'
    'Intel Quartus Prime' = 'https://www.intel.com/content/www/us/en/software-kit/'
    'ModelSim'            = 'https://www.intel.com/content/www/us/en/software/programmable/quartus-prime/model-sim.html'
    'MPLAB X'             = 'https://www.microchip.com/en-us/development-tools-tools-and-software/mplab-x-ide'
    'STM32CubeIDE'        = 'https://www.st.com/en/development-tools/stm32cubeide.html'
    'IAR Embedded Workbench' = 'https://www.iar.com/products/architectures/arm/iar-embedded-workbench-for-arm/'
    'Keil uVision'        = 'https://www.keil.com/demo/eval/arm.htm'
    'STAAD.Pro'           = 'https://www.bentley.com/software/staad-pro/'
    'Tekla Structures'    = 'https://www.tekla.com/products/tekla-structures'
    'Tekla Tedds'         = 'https://www.tekla.com/products/tekla-tedds'
    'SAP2000'             = 'https://www.csiamerica.com/products/sap2000'
    'ETABS'               = 'https://www.csiamerica.com/products/etabs'
    'SAFE'                = 'https://www.csiamerica.com/products/safe'
    'CSiBridge'           = 'https://www.csiamerica.com/products/csibridge'
    'MIDAS Civil'         = 'https://www.midasuser.com/'
    'MIDAS Gen'           = 'https://www.midasuser.com/'
    'SCIA Engineer'       = 'https://www.scia.net/en'
    'RISA-3D'             = 'https://risa.com/products/risa-3d'
    'IDEA StatiCa'        = 'https://www.ideastatica.com/'
    'RFEM'                = 'https://www.dlubal.com/en'
    'PLAXIS 2D'           = 'https://www.bentley.com/software/plaxis-2d/'
    'PLAXIS 3D'           = 'https://www.bentley.com/software/plaxis-3d/'
    'GeoStudio'           = 'https://www.geoslope.com/'
    'Slide2'              = 'https://www.rocscience.com/software/slide2'
    'Rocscience RS2'      = 'https://www.rocscience.com/software/rs2'
    'Rocscience RS3'      = 'https://www.rocscience.com/software/rs3'
    'FLAC3D'              = 'https://www.itascacg.com/software/flac3d'
    'GEO5'                = 'https://www.finesoftware.eu/geotechnical-software/'
    'gINT'                = 'https://www.bentley.com/software/gint/'
    'Deswik'              = 'https://www.deswik.com/'
    'Maptek Vulcan'       = 'https://www.maptek.com/products/vulcan/'
    'Datamine Studio'     = 'https://www.dataminesoftware.com/'
    'Micromine'           = 'https://www.micromine.com/'
    'Leapfrog Geo'        = 'https://www.seequent.com/products-solutions/leapfrog-geo/'
    'Bentley OpenRail'    = 'https://www.bentley.com/software/openrail-designer/'
    'RailSys'             = 'https://www.rmcon.de/en/'
    'HEC-RAS'             = 'https://www.hec.usace.army.mil/software/hec-ras/downloads.aspx'
    'HEC-HMS'             = 'https://www.hec.usace.army.mil/software/hec-hms/downloads.aspx'
    'EPA SWMM'            = 'https://www.epa.gov/water-research/storm-water-management-model-swmm'
    'EPANET'              = 'https://www.epa.gov/water-research/epanet'
    'WaterGEMS'           = 'https://www.bentley.com/software/watergems/'
    'SewerGEMS'           = 'https://www.bentley.com/software/sewergems/'
    'MIKE+'               = 'https://www.dhigroup.com/technologies/mikepoweredbydhi'
    'MODFLOW'             = 'https://www.usgs.gov/software/modflow-6-usgs-modular-hydrologic-model'
    'AERMOD'              = 'https://www.epa.gov/scram/air-quality-dispersion-modeling-preferred-and-recommended-models#aermod'
    'CALPUFF'             = 'https://www.epa.gov/scram/air-quality-dispersion-modeling-preferred-and-recommended-models#calpuff'
    'ArcGIS Pro'          = 'https://www.esri.com/en-us/arcgis/products/arcgis-pro/overview'
    'ArcGIS Desktop'      = 'https://www.esri.com/en-us/arcgis/products/arcgis-desktop/overview'
    'Global Mapper'       = 'https://www.bluemarblegeo.com/global-mapper/'
    'ENVI'                = 'https://www.nv5geospatialsoftware.com/Products/ENVI'
    'ERDAS Imagine'       = 'https://www.hexagongeospatial.com/products/power-portfolio/erdas-imagine'
    'Agisoft Metashape'   = 'https://www.agisoft.com/downloads/installer/'
    'Pix4Dmapper'         = 'https://www.pix4d.com/product/pix4dmapper-photogrammetry-software'
    'Trimble Business Center' = 'https://geospatial.trimble.com/products-and-solutions/trimble-business-center'
    'Leica Infinity'      = 'https://leica-geosystems.com/products/software/leica-infinity'
    'Leica Cyclone'       = 'https://leica-geosystems.com/products/laser-scanners/software/leica-cyclone'
    'Carlson Survey'      = 'https://www.carlsonsw.com/'
    'Aspen Plus'          = 'https://www.aspentech.com/en/products/engineering/aspen-plus'
    'Aspen HYSYS'         = 'https://www.aspentech.com/en/products/engineering/aspen-hysys'
    'Petrel'              = 'https://www.software.slb.com/products/petrel'
    'ShipConstructor'     = 'https://www.ssi-corporate.com/'
    'Maxsurf'             = 'https://www.bentley.com/software/maxsurf/'
    'NAPA'                = 'https://www.napa.fi/'
    'MOSES'               = 'https://www.bentley.com/software/moses/'
    'AutoSPRINK'          = 'https://www.autosprink.com/'
    'HydraCALC'           = 'https://www.hydratec.com/'
    'PyroSim'             = 'https://www.thunderheadeng.com/pyrosim/'
    'Pathfinder'          = 'https://www.thunderheadeng.com/pathfinder/'
    'FDS'                 = 'https://pages.nist.gov/fds-smv/downloads.html'
    'CONTAM'              = 'https://www.nist.gov/services-resources/software/contam'
    'Carrier HAP'         = 'https://www.carrier.com/commercial/en/us/software/hvac-system-design/'
    'TRACE 3D Plus'       = 'https://www.trane.com/commercial/north-america/us/en/products-systems/design-and-analysis-tools/trace-3d-plus.html'
    'EnergyPlus'          = 'https://energyplus.net/downloads'
    'OpenStudio'          = 'https://openstudio.net/downloads'
    'IES VE'              = 'https://www.iesve.com/'
    'DesignBuilder'       = 'https://designbuilder.co.uk/'
    'DIALux evo'          = 'https://www.dialux.com/en-GB/download'
    'AGi32'               = 'https://lightinganalysts.com/software-products/agi32/'
    'MCNP'                = 'https://mcnp.lanl.gov/'
    'SCALE'               = 'https://www.ornl.gov/scale'
    'RELAP5'              = 'https://www.nrc.gov/about-nrc/regulatory/research/safetycodes.html'
    'OpenMC'              = 'https://docs.openmc.org/'
    'Mimics Innovation Suite' = 'https://www.materialise.com/en/medical/mimics-innovation-suite'
    'Simpleware'          = 'https://www.synopsys.com/simpleware.html'
    'PVsyst'              = 'https://www.pvsyst.com/'
    'HOMER Pro'           = 'https://www.homerenergy.com/products/pro/'
    'SAM'                 = 'https://sam.nrel.gov/download'
    'RETScreen Expert'    = 'https://www.nrcan.gc.ca/maps-tools-and-publications/tools/modelling-tools/retscreen/7465'
    'WindPRO'             = 'https://www.emdt.co.uk/product/windpro'
    'WAsP'                = 'https://www.wasp.dk/'
    'Wolfram Mathematica' = 'https://www.wolfram.com/mathematica/'
    'Maple'               = 'https://www.maplesoft.com/products/Maple/'
    'Mathcad Prime'       = 'https://www.ptc.com/en/products/mathcad'
    'OriginPro'           = 'https://www.originlab.com/'
    'GNU Radio'           = 'https://wiki.gnuradio.org/index.php/InstallingGR'
    'Mastercam'           = 'https://www.mastercam.com/'
    'SolidCAM'            = 'https://www.solidcam.com/'
    'VERICUT'             = 'https://www.cgtech.com/'
    'ESPRIT'              = 'https://www.espritcam.com/'
    'PC-DMIS'             = 'https://www.hexagonmi.com/products/software/pc-dmis'
    'PolyWorks'           = 'https://www.innovmetric.com/'
    'Microsoft Project'   = 'https://www.microsoft.com/en-us/microsoft-365/project/project-management-software'
    'Primavera P6'        = 'https://www.oracle.com/industries/construction-engineering/primavera-p6/'
    'Procore'             = 'https://www.procore.com/'
    'Oracle Aconex'       = 'https://www.oracle.com/construction-engineering/aconex/'
    'CostX'               = 'https://www.exactal.com/'
    'PlanSwift'           = 'https://www.planswift.com/'
    'IBM Engineering DOORS' = 'https://www.ibm.com/products/requirements-management-doors'
    'Capella'             = 'https://www.eclipse.org/capella/'
    'Enterprise Architect'= 'https://sparxsystems.com/products/ea/'
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
                Write-Host "  [ OK ]  $Name installed." -ForegroundColor Green
                return 'installed'
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

function Show-DisciplineInstaller {
    param([bool]$HasWinget)

    $byDisc = @{}
    foreach ($e in $Script:RawCatalog) {
        foreach ($d in $e.D) {
            if (-not $byDisc.ContainsKey($d)) { $byDisc[$d] = @() }
            $byDisc[$d] += $e
        }
    }

    $disc = @($byDisc.Keys | Sort-Object)
    if ($disc.Count -eq 0) {
        Write-Host "  No disciplines available." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "  Choose a discipline:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $disc.Count; $i++) {
        $d = $disc[$i]
        $products = @($byDisc[$d] | Sort-Object N -Unique)
        $auto = @($products | Where-Object { (Get-InstallTag -Name $_.N) -eq 'winget' }).Count
        $man  = @($products | Where-Object { (Get-InstallTag -Name $_.N) -eq 'manual' }).Count
        Write-Host ("    {0,2}. {1,-22}  {2} product(s)  ({3} winget, {4} manual)" -f `
                    ($i+1), $d, $products.Count, $auto, $man)
    }
    Write-Host "     0. Cancel"

    $sel = Read-Host "`n  Number"
    if (-not $sel -or $sel -eq '0') { return }
    $idx = 0
    if (-not [int]::TryParse($sel, [ref]$idx) -or $idx -lt 1 -or $idx -gt $disc.Count) {
        Write-Host "  Invalid selection." -ForegroundColor Red
        return
    }

    $pickedDisc = $disc[$idx-1]
    $products   = @($byDisc[$pickedDisc] | Sort-Object N -Unique)

    Write-Host ""
    Write-Host "  Products in $pickedDisc  ($($products.Count) total):" -ForegroundColor Cyan
    Write-Host "    Tags: [winget] = auto-install  [manual] = opens download page  [skip] = not installable" -ForegroundColor DarkGray
    Write-Host ""
    for ($i = 0; $i -lt $products.Count; $i++) {
        $p   = $products[$i]
        $tag = Get-InstallTag -Name $p.N
        $tagStr = "[$tag]".PadRight(9)
        $col = switch ($tag) {
            'winget' { 'Green' }
            'manual' { 'Yellow' }
            default  { 'DarkGray' }
        }
        Write-Host ("    {0,2}. " -f ($i+1)) -NoNewline
        Write-Host $tagStr -ForegroundColor $col -NoNewline
        Write-Host $p.N
    }

    Write-Host ""
    Write-Host "  Enter numbers separated by commas (e.g. 1,3,5) or 'all':"
    $pick = Read-Host "  Selection"

    $indices = @()
    if ($pick -match '^all$') {
        $indices = 1..$products.Count
    } else {
        foreach ($tok in ($pick -split ',')) {
            $n = 0
            if ([int]::TryParse($tok.Trim(), [ref]$n) -and $n -ge 1 -and $n -le $products.Count) {
                $indices += $n
            }
        }
    }
    if ($indices.Count -eq 0) { Write-Host "  Nothing selected." -ForegroundColor Yellow; return }

    Write-Host ""
    Write-Host "  Install plan:" -ForegroundColor Cyan
    foreach ($i in $indices) {
        $p = $products[$i-1]
        $tag = Get-InstallTag -Name $p.N
        Write-Host ("    - {0,-32} [{1}]" -f $p.N, $tag)
    }
    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -notmatch '^[Yy]') { Write-Host "  Cancelled." -ForegroundColor Yellow; return }

    $ok = 0; $fail = 0; $manual = 0; $skipped = 0
    foreach ($i in $indices) {
        $p = $products[$i-1]
        $res = Install-OneProduct -Name $p.N -HasWinget $HasWinget
        switch ($res) {
            'installed' { $ok++ }
            'failed'    { $fail++ }
            'manual'    { $manual++ }
            'skipped'   { $skipped++ }
        }
    }

    Write-Host ""
    Write-Host ("  Summary: {0} installed, {1} failed, {2} manual download, {3} skipped." -f `
                $ok, $fail, $manual, $skipped) -ForegroundColor Cyan
}

function Invoke-Installer {
    param(
        [string[]]$Disciplines = @(),
        [string[]]$InstallList = @()
    )

    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host "  SIGMA SOFTWARE INSTALLER" -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host ("  Catalog products: {0}" -f $Script:CatalogCount) -ForegroundColor DarkGray

    $hasWinget = Test-WingetAvailable
    Write-Host ("  winget          : {0}" -f $(if ($hasWinget) { 'available' } else { 'not found' })) `
        -ForegroundColor $(if ($hasWinget) { 'Green' } else { 'Yellow' })

    if (-not $hasWinget) {
        Write-Host ""
        Write-Host "  [WARN] winget is not available." -ForegroundColor Yellow
        Write-Host "  [INFO] Install 'App Installer' from the Microsoft Store to enable silent installs." -ForegroundColor Yellow
        Write-Host "  [INFO] Manual download pages will still be offered." -ForegroundColor Yellow
    }

    if ($InstallList.Count -gt 0) {
        Write-Host ""
        Write-Host "  Batch mode: $($InstallList -join ', ')" -ForegroundColor Cyan
        $ok = 0; $fail = 0; $manual = 0; $skipped = 0
        foreach ($name in $InstallList) {
            $entry = $Script:RawCatalog | Where-Object {
                $_.N -eq $name -or $_.N -like "*$name*"
            } | Select-Object -First 1

            if (-not $entry) {
                Write-Host "  [SKIP] Unknown product: $name" -ForegroundColor Yellow
                $skipped++
                continue
            }
            $res = Install-OneProduct -Name $entry.N -HasWinget $hasWinget -NonInteractive
            switch ($res) {
                'installed' { $ok++ }
                'failed'    { $fail++ }
                'manual'    { $manual++ }
                'skipped'   { $skipped++ }
            }
        }
        Write-Host ""
        Write-Host ("  Batch summary: {0} installed, {1} failed, {2} manual, {3} skipped." -f `
                    $ok, $fail, $manual, $skipped) -ForegroundColor Cyan
        return
    }

    while ($true) {
        Show-DisciplineInstaller -HasWinget $hasWinget
        Write-Host ""
        $again = Read-Host "  Install something else? (Y/N)"
        if ($again -notmatch '^[Yy]') { break }
    }
}

# =============================================================================
# 5h. SOFTWARE INSTALLER DISPATCH
# =============================================================================
if ($Install) {
    Invoke-Installer -Disciplines $Disciplines -InstallList $InstallList
    exit 0
}

# =============================================================================
# 6. PER-PRODUCT CHECKS
# =============================================================================
function Get-ProductStatus {
    param(
        [object]$Entry,
        [array]$Installed,
        [pscustomobject]$System,
        [string]$NetFx,
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

    $minRam = 0
    if ($Entry.MinRAM) { $minRam = [int]$Entry.MinRAM }
    elseif ($Entry.RAM) { $minRam = [int][math]::Ceiling($Entry.RAM * 0.5) }

    if ($Entry.RAM -and $System.RAM_GB -lt $Entry.RAM) {
        $sev = if ($minRam -gt 0 -and $System.RAM_GB -lt $minRam) { 'critical' } else { 'warn' }
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
            -Detected "$($System.RAM_GB) GB installed; $($Entry.RAM) GB recommended (min $minRam GB)." `
            -WhyItMatters $why `
            -Recommendation $rec `
            -Optional "Consider upgrading to $($Entry.RAM) GB or more for large workloads." `
            -Severity $sev))
    }

    if ($Entry.Disk) {
        $sysd = $System.Disks | Where-Object Drive -eq "$($env:SystemDrive)"
        if ($sysd -and $sysd.FreeGB -lt $Entry.Disk) {
            $sev = if ($sysd.FreeGB -lt 5) { 'critical' } else { 'warn' }
            $status.Findings.Add((New-Finding `
                -Id "$($Entry.N).DISK_LOW" `
                -Software $Entry.N `
                -Problem "$($Entry.N) scratch disk is running low." `
                -Detected "$($sysd.FreeGB) GB free on $($sysd.Drive); $($Entry.Disk) GB recommended." `
                -WhyItMatters "Solvers, caches, and autosaves write to this disk. Running out can abort jobs." `
                -Recommendation "Free space on $($sysd.Drive) or redirect scratch to another volume." `
                -Severity $sev))
        }
    }

    if ($Entry.GPU) {
        $hasDedicated = $false
        foreach ($g in $System.GPUs) {
            if ($g.VRAM_GB -and $g.VRAM_GB -ge 2) { $hasDedicated = $true }
        }
        if (-not $hasDedicated) {
            $status.Findings.Add((New-Finding `
                -Id "$($Entry.N).GPU_LOW" `
                -Software $Entry.N `
                -Problem "$($Entry.N) prefers a dedicated GPU." `
                -Detected "No dedicated GPU with 2 GB or more VRAM detected." `
                -WhyItMatters "3D views, rendering, and GPU-accelerated solvers will be slow." `
                -Recommendation "Install a dedicated GPU (NVIDIA RTX / AMD Radeon Pro class)." `
                -Severity 'warn'))
        }
    }

    if ($Entry.Net) {
        if (-not (Compare-NetVersion -Have $NetFx -Need $Entry.Net)) {
            $status.Findings.Add((New-Finding `
                -Id "$($Entry.N).DOTNET" `
                -Software $Entry.N `
                -Problem "$($Entry.N) may not start." `
                -Detected ".NET Framework $NetFx installed; $($Entry.Net) required." `
                -WhyItMatters "Missing framework versions cause startup errors and missing features." `
                -Recommendation "Install .NET Framework $($Entry.Net) or newer from Microsoft." `
                -Severity 'critical'))
        }
    }

    if ($Entry.VCPP -and (-not $VC -or $VC.Count -eq 0)) {
        $status.Findings.Add((New-Finding `
            -Id "$($Entry.N).VCPP" `
            -Software $Entry.N `
            -Problem "$($Entry.N) may fail to launch." `
            -Detected "No Microsoft Visual C++ Redistributable detected." `
            -WhyItMatters "Most engineering applications depend on the VC++ runtime." `
            -Recommendation "Install the Microsoft Visual C++ Redistributable (2015-2022, x64)." `
            -Severity 'critical'))
    }

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

    if ($Entry.Lport) {
        $openAny = $false
        foreach ($p in $Entry.Lport) {
            if (Test-TcpPort -Port $p -TimeoutMs 800) { $openAny = $true; break }
        }
        if (-not $openAny) {
            $status.Notes += "License ports not open locally ($($Entry.Lport -join ', ')) - normal for node-locked or remote license servers."
        }
    }

    if ($System.Power.HasBattery -and -not $System.Power.OnAC) {
        if ($Entry.RAM -ge 16 -or $Entry.K -match 'FEA|CFD|BIM|Explicit|FEA/CFD') {
            $status.Findings.Add((New-Finding `
                -Id "$($Entry.N).POWER" `
                -Software $Entry.N `
                -Problem "$($Entry.N) will run slower on battery." `
                -Detected "Currently on battery at $($System.Power.Percent)% ($($System.Power.StatusText))." `
                -WhyItMatters "Windows throttles CPU and GPU under battery power, which lengthens solve times significantly." `
                -Recommendation "Plug in AC power before heavy workloads." `
                -Severity 'warn'))
        }
    }

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

Write-Stage "Checking every product in the catalog..."
$allResults = New-Object System.Collections.Generic.List[object]
foreach ($entry in $Script:RawCatalog) {
    $allResults.Add((Get-ProductStatus -Entry $entry -Installed $installed -System $sys `
                                        -NetFx $netFx -VC $vc -ActiveDisciplines $Disciplines `
                                        -DeepScan:$DeepScan))
}

$gCount = @($allResults | Where-Object State -eq 'Healthy').Count
$yCount = @($allResults | Where-Object State -eq 'Attention').Count
$rCount = @($allResults | Where-Object State -eq 'Critical').Count
$nCount = @($allResults | Where-Object State -eq 'NotInstalled').Count
$aCount = @($allResults | Where-Object State -eq 'NotApplicable').Count
Write-Host " $gCount healthy / $yCount attention / $rCount critical / $nCount not installed / $aCount not applicable." -ForegroundColor Green

# =============================================================================
# 6b. ONLINE ENRICHMENT — fetches live data to make the score truthful
# =============================================================================
$Script:OnlineCache     = @{}
$Script:OnlineCachePath = Join-Path $env:TEMP 'sigma_online_cache.json'
$Script:OnlineEnabled   = -not $Offline

try {
    if (Test-Path $Script:OnlineCachePath) {
        $cached = Get-Content $Script:OnlineCachePath -Raw | ConvertFrom-Json
        foreach ($p in $cached.PSObject.Properties) {
            $Script:OnlineCache[$p.Name] = $p.Value
        }
    }
} catch { }

function Save-OnlineCache {
    try {
        $Script:OnlineCache | ConvertTo-Json -Depth 6 |
            Set-Content $Script:OnlineCachePath -Encoding UTF8
    } catch { }
}

function Get-Cached {
    param(
        [string]$Key,
        [scriptblock]$Fetch,
        [int]$TtlHours = 24
    )
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
        $Headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SigmaEngineerToolkit/1.0'
    }
    try {
        return Invoke-WebRequest -Uri $Url -TimeoutSec $TimeoutSec -UseBasicParsing `
                                 -Headers $Headers -ErrorAction Stop
    } catch {
        Add-Diagnostic 'Online' "GET $Url failed: $_"
        return $null
    }
}

function Get-CpuPassMarkScore {
    param([string]$CpuName)
    if (-not $CpuName) { return $null }

    $clean = $CpuName -replace '\(R\)','' -replace '\(TM\)','' `
                      -replace '\s+CPU\s+@.*$','' `
                      -replace '\s+Processor.*$','' `
                      -replace '\s+\d+-Core.*$','' `
                      -replace '\s+@.*$','' `
                      -replace '\s+',' '
    $clean = $clean.Trim()
    $key   = "cpu_passmark_$clean"

    Get-Cached -Key $key -TtlHours 168 -Fetch {
        $q = [uri]::EscapeDataString($clean)
        $r = Invoke-SafeWebRequest -Url "https://www.cpubenchmark.net/cpu.php?cpu=$q"
        if (-not $r) { return $null }
        $html = $r.Content
        if ($html -match 'mark-neww[^>]*>\s*([\d,]+)\s*<') {
            return [int]($matches[1] -replace ',','')
        }
        if ($html -match 'CPU Mark[^<]*<[^>]*>\s*([\d,]+)') {
            return [int]($matches[1] -replace ',','')
        }
        return $null
    }
}

function Get-GpuPassMarkScore {
    param([string]$GpuName)
    if (-not $GpuName) { return $null }

    $clean = $GpuName -replace '^NVIDIA\s+','' -replace '^AMD\s+','' -replace '^Intel\s+',''
    $clean = $clean.Trim()
    $key   = "gpu_passmark_$clean"

    Get-Cached -Key $key -TtlHours 168 -Fetch {
        $q = [uri]::EscapeDataString($clean)
        $r = Invoke-SafeWebRequest -Url "https://www.videocardbenchmark.net/gpu.php?gpu=$q"
        if (-not $r) { return $null }
        $html = $r.Content
        if ($html -match 'mark-neww[^>]*>\s*([\d,]+)\s*<') {
            return [int]($matches[1] -replace ',','')
        }
        if ($html -match 'G3D Mark[^<]*<[^>]*>\s*([\d,]+)') {
            return [int]($matches[1] -replace ',','')
        }
        return $null
    }
}

function Get-NvidiaLatestDriver {
    param([string]$GpuName)
    $series = switch -Regex ($GpuName) {
        'RTX\s*50'  { 'rtx50' }
        'RTX\s*40'  { 'rtx40' }
        'RTX\s*30'  { 'rtx30' }
        'RTX\s*20'  { 'rtx20' }
        'GTX\s*16'  { 'gtx16' }
        'GTX\s*10'  { 'gtx10' }
        default     { 'unknown' }
    }
    if ($series -eq 'unknown') { return $null }

    $key = "nvidia_driver_$series"
    Get-Cached -Key $key -TtlHours 24 -Fetch {
        $psid = switch ($series) {
            'rtx50' { 129 }
            'rtx40' { 127 }
            'rtx30' { 124 }
            'rtx20' { 120 }
            'gtx16' { 118 }
            'gtx10' { 101 }
        }
        try {
            $body = @{
                func = 'DriverManualLookup'
                psid = $psid
                pfid = 0
                osID = 135
                lid  = 1
                whql = 1
                dch  = 1
                sort1 = 0
                numberOfResults = 1
            }
            $r = Invoke-RestMethod -Uri 'https://gfwsl.geforce.com/services_toolkit/services/com/nvidia/services/AjaxDriverService.php' `
                                   -Method Get -Body $body -TimeoutSec 8 -ErrorAction Stop
            if ($r -and $r.IDS -and $r.IDS.Count -gt 0) {
                return $r.IDS[0].downloadInfo.Version
            }
        } catch { }
        return $null
    }
}

function Get-AmdLatestDriver {
    param([string]$GpuName)
    if ($GpuName -notmatch 'Radeon|AMD') { return $null }

    $key = 'amd_latest_driver'
    Get-Cached -Key $key -TtlHours 24 -Fetch {
        try {
            $r = Invoke-SafeWebRequest -Url 'https://www.amd.com/en/support/rss' -TimeoutSec 8
            if ($r -and $r.Content -match 'Adrenalin[^\d]*(\d+\.\d+\.\d+)') {
                return $matches[1]
            }
        } catch { }
        return $null
    }
}

function Get-IntelLatestGraphicsDriver {
    param([string]$GpuName)
    if ($GpuName -notmatch 'Intel') { return $null }

    $key = 'intel_latest_graphics'
    Get-Cached -Key $key -TtlHours 24 -Fetch {
        try {
            # Intel's Arc & Iris Xe driver download page
            $r = Invoke-SafeWebRequest -Url 'https://www.intel.com/content/www/us/en/download/785597/intel-arc-iris-xe-graphics-windows.html' -TimeoutSec 10
            if ($r -and $r.Content -match '(\d+\.\d+\.\d+\.\d+)') {
                return $matches[1]
            }
        } catch { }
        return $null
    }
}

function Get-WingetUpgradeable {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { return @() }

    $key = 'winget_upgradeable'
    Get-Cached -Key $key -TtlHours 6 -Fetch {
        try {
            $raw = winget upgrade --include-unknown --accept-source-agreements 2>$null | Out-String
            $list = @()
            $lines = $raw -split "`r?`n"
            $inTable = $false

            foreach ($line in $lines) {
                if ($line -match '^-{5,}') { $inTable = $true; continue }
                if (-not $inTable) { continue }
                if ($line -match '^\s*\d+\s+upgrades?\s+available') { break }

                if ($line -match '^(.+?)\s{2,}(\S+)\s{2,}(\S+)\s{2,}(\S+)\s{2,}(\S+)\s*$') {
                    $list += [pscustomobject]@{
                        Name      = $matches[1].Trim()
                        Id        = $matches[2].Trim()
                        Installed = $matches[3].Trim()
                        Available = $matches[4].Trim()
                        Source    = $matches[5].Trim()
                    }
                }
            }
            return $list
        } catch {
            Add-Diagnostic 'winget' "upgrade query failed: $_"
            return @()
        }
    }
}

function Get-DiskMediaTypes {
    try {
        $out = @()
        Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
            $out += [pscustomobject]@{
                FriendlyName = $_.FriendlyName
                MediaType    = $_.MediaType
                BusType      = $_.BusType
                SizeGB       = [math]::Round($_.Size / 1GB, 1)
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
        $type = switch ($typeCode) {
            26 { 'DDR4' }
            34 { 'DDR5' }
            24 { 'DDR3' }
            21 { 'DDR2' }
            default { "Unknown ($typeCode)" }
        }
        return [pscustomobject]@{
            Modules  = $mods.Count
            SpeedMHz = [int]$speedMhz
            Type     = $type
            TotalGB  = [math]::Round((($mods | Measure-Object -Property Capacity -Sum).Sum) / 1GB, 1)
        }
    } catch { return $null }
}

function Invoke-OnlineEnrichment {
    param([pscustomobject]$System)

    $enrich = [ordered]@{
        CpuScore        = $null
        GpuScores       = @()
        LatestNvidia    = $null
        LatestAmd       = $null
        LatestIntelGpu  = $null
        Upgradeable     = @()
        DiskMediaTypes  = @()
        Ram             = $null
        EnrichedAt      = (Get-Date).ToString('s')
        OnlineAvailable = $true
    }

    if (-not $Script:OnlineEnabled) {
        $enrich.OnlineAvailable = $false
        $enrich.DiskMediaTypes = @(Get-DiskMediaTypes)
        $enrich.Ram            = Get-RamDetail
        return [pscustomobject]$enrich
    }

    Write-Stage "Fetching live online data (PassMark, winget, vendor feeds)..."

    $enrich.DiskMediaTypes = @(Get-DiskMediaTypes)
    $enrich.Ram            = Get-RamDetail

    $enrich.CpuScore = Get-CpuPassMarkScore -CpuName $System.CPU

    foreach ($g in $System.GPUs) {
        if ($g.Kind -eq 'Integrated') { continue }
        $score = Get-GpuPassMarkScore -GpuName $g.Name
        $enrich.GpuScores += [pscustomobject]@{
            Name  = $g.Name
            Score = $score
        }
    }

    $hasNvidia = @($System.GPUs | Where-Object { $_.Name -match 'NVIDIA|GeForce|RTX|Quadro' }).Count -gt 0
    $hasAmd    = @($System.GPUs | Where-Object { $_.Name -match 'Radeon|AMD' }).Count -gt 0
    $hasIntel  = @($System.GPUs | Where-Object { $_.Name -match 'Intel' }).Count -gt 0
    if ($hasNvidia) {
        $nvName = ($System.GPUs | Where-Object { $_.Name -match 'NVIDIA|GeForce|RTX|Quadro' } | Select-Object -First 1).Name
        $enrich.LatestNvidia = Get-NvidiaLatestDriver -GpuName $nvName
    }
    if ($hasAmd) {
        $amdName = ($System.GPUs | Where-Object { $_.Name -match 'Radeon|AMD' } | Select-Object -First 1).Name
        $enrich.LatestAmd = Get-AmdLatestDriver -GpuName $amdName
    }
    if ($hasIntel) {
        $intelName = ($System.GPUs | Where-Object { $_.Name -match 'Intel' } | Select-Object -First 1).Name
        $enrich.LatestIntelGpu = Get-IntelLatestGraphicsDriver -GpuName $intelName
    }

    $enrich.Upgradeable = @(Get-WingetUpgradeable)

    if (-not $enrich.CpuScore -and $enrich.GpuScores.Count -eq 0 -and $enrich.Upgradeable.Count -eq 0) {
        $enrich.OnlineAvailable = $false
    }

    Write-Ok
    return [pscustomobject]$enrich
}

# =============================================================================
# 6c. SYSTEM ONLINE VERIFICATION — cross-check every scanned fact
# =============================================================================
#   * Windows build     -> latest from Microsoft release info
#   * .NET Framework    -> latest from Microsoft downloads
#   * VC++ Redist       -> latest supported version from Microsoft Learn
#   * Defender          -> latest signature version from Microsoft WDSI
#   * Motherboard BIOS  -> latest from vendor (Dell supported, others best-effort)
#   * Disk SMART        -> local reliability counters (wear, temp, errors)
#   * RAM modules       -> part numbers + configured vs rated speed
#   * Network adapters  -> running vs max supported speed
# =============================================================================

function Get-LatestWindowsBuild {
    $key = 'ms_latest_windows'
    Get-Cached -Key $key -TtlHours 168 -Fetch {
        try {
            $r = Invoke-SafeWebRequest -Url 'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information' -TimeoutSec 10
            if (-not $r) { return $null }
            # The page lists "OS build" values like 26100.2314
            $matches2 = [regex]::Matches($r.Content, '\b(2[0-9]{4}\.\d{3,5})\b')
            if ($matches2.Count -gt 0) {
                $versions = $matches2 | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
                return ($versions | Sort-Object { [version]$_ } | Select-Object -Last 1)
            }
        } catch { }
        return $null
    }
}

function Get-LatestDotNetFrameworkVersion {
    $key = 'ms_latest_dotnet_fx'
    Get-Cached -Key $key -TtlHours 168 -Fetch {
        try {
            $r = Invoke-SafeWebRequest -Url 'https://dotnet.microsoft.com/en-us/download/dotnet-framework' -TimeoutSec 10
            if ($r -and $r.Content -match '\.NET Framework (\d+\.\d+(?:\.\d+)?)') {
                return $matches[1]
            }
        } catch { }
        return $null
    }
}

function Get-LatestVCRedistVersion {
    $key = 'ms_latest_vcredist'
    Get-Cached -Key $key -TtlHours 168 -Fetch {
        try {
            $r = Invoke-SafeWebRequest -Url 'https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist' -TimeoutSec 10
            if ($r -and $r.Content -match 'v14\.(\d+)\.(\d+)\.(\d+)') {
                return "14.$($matches[1]).$($matches[2]).$($matches[3])"
            }
        } catch { }
        return $null
    }
}

function Get-LatestDefenderSignature {
    $key = 'ms_latest_defender'
    Get-Cached -Key $key -TtlHours 12 -Fetch {
        try {
            $r = Invoke-SafeWebRequest -Url 'https://www.microsoft.com/en-us/wdsi/defenderupdates' -TimeoutSec 10
            if ($r -and $r.Content -match '(\d+\.\d+\.\d+\.\d+)') {
                return $matches[1]
            }
        } catch { }
        return $null
    }
}

function Get-MotherboardInfo {
    try {
        $bb   = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
        $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
        return [pscustomobject]@{
            Manufacturer    = $bb.Manufacturer
            Product         = $bb.Product
            Version         = $bb.Version
            SerialNumber    = $bb.SerialNumber
            BiosVendor      = $bios.Manufacturer
            BiosVersion     = $bios.SMBIOSBIOSVersion
            BiosReleaseDate = if ($bios.ReleaseDate) { ([datetime]$bios.ReleaseDate).ToString('yyyy-MM-dd') } else { '' }
        }
    } catch { return $null }
}

function Get-LatestBiosVersion {
    param([pscustomobject]$Board)
    if (-not $Board -or -not $Board.Manufacturer) { return $null }

    $mfg = $Board.Manufacturer.ToLower()
    $key = "bios_$($Board.Manufacturer)_$($Board.Product)_$($Board.BiosVersion)"

    Get-Cached -Key $key -TtlHours 168 -Fetch {
        try {
            # Dell: query driver catalog for the BIOS
            if ($mfg -match 'dell') {
                $svcTag = (Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue).SerialNumber
                if ($svcTag) {
                    $r = Invoke-SafeWebRequest -Url "https://www.dell.com/support/home/en-us/product-support/servicetag/$svcTag/drivers" -TimeoutSec 12
                    if ($r -and $r.Content -match 'BIOS[^<]{0,200}?(\d+\.\d+\.\d+)') {
                        return $matches[1]
                    }
                }
            }
            # HP: web lookup is JS-heavy, skip
            # Lenovo: requires API key, skip
            # ASUS / MSI / Gigabyte: JS-heavy, skip
            # Return null when we can't reliably fetch
            return $null
        } catch { return $null }
    }
}

function Get-DiskReliability {
    try {
        $out = @()
        foreach ($d in Get-PhysicalDisk -ErrorAction Stop) {
            $rc = $null
            try { $rc = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch { }
            $out += [pscustomobject]@{
                FriendlyName  = $d.FriendlyName
                MediaType     = $d.MediaType
                BusType       = $d.BusType
                SizeGB        = [math]::Round($d.Size / 1GB, 1)
                HealthStatus  = $d.HealthStatus
                Wear          = if ($rc) { $rc.Wear } else { $null }
                Temperature   = if ($rc) { $rc.Temperature } else { $null }
                PowerOnHours  = if ($rc) { $rc.PowerOnHours } else { $null }
                ReadErrors    = if ($rc) { $rc.ReadErrorsTotal } else { $null }
                WriteErrors   = if ($rc) { $rc.WriteErrorsTotal } else { $null }
            }
        }
        return $out
    } catch { return @() }
}

function Get-RamPartNumbers {
    try {
        $mods = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop)
        $out = @()
        foreach ($m in $mods) {
            $out += [pscustomobject]@{
                Manufacturer  = $m.Manufacturer
                PartNumber    = $m.PartNumber
                CapacityGB    = [math]::Round($m.Capacity / 1GB, 0)
                SpeedMHz      = $m.Speed
                ConfiguredMHz = $m.ConfiguredClockSpeed
                TypeCode      = $m.SMBIOSMemoryType
                FormFactor    = $m.FormFactor
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
            if ($n.InterfaceDescription -match '(\d+)\s*Gb') { $maxSpeed = "$($matches[1]) Gb" }
            elseif ($n.InterfaceDescription -match '(\d+)\s*Mb') { $maxSpeed = "$($matches[1]) Mb" }
            if ($n.InterfaceDescription -match '2\.5G') { $maxSpeed = '2.5 Gb' }
            if ($n.InterfaceDescription -match '10G')   { $maxSpeed = '10 Gb' }

            $drv = try { (Get-NetAdapter -Name $n.Name -ErrorAction Stop).DriverVersion } catch { '' }

            $out += [pscustomobject]@{
                Name          = $n.Name
                Description   = $n.InterfaceDescription
                LinkSpeed     = $n.LinkSpeed
                MaxSpeed      = $maxSpeed
                Status        = $n.Status
                DriverVersion = $drv
            }
        }
        return $out
    } catch { return @() }
}

function Invoke-SystemOnlineVerification {
    param([pscustomobject]$System, [pscustomobject]$Motherboard)

    $v = [ordered]@{
        LatestWindowsBuild   = $null
        LatestDotNetFx       = $null
        LatestVCRedist       = $null
        LatestDefenderSig    = $null
        LatestBios           = $null
        DiskReliability      = @()
        RamModules           = @()
        AdapterCapabilities  = @()
        VerifiedAt           = (Get-Date).ToString('s')
        Available            = $true
    }

    if (-not $Script:OnlineEnabled) {
        $v.DiskReliability     = @(Get-DiskReliability)
        $v.RamModules          = @(Get-RamPartNumbers)
        $v.AdapterCapabilities = @(Get-AdapterCapabilities)
        $v.Available           = $false
        return [pscustomobject]$v
    }

    Write-Stage "Verifying hardware & OS against online sources..."

    $v.LatestWindowsBuild = Get-LatestWindowsBuild
    $v.LatestDotNetFx     = Get-LatestDotNetFrameworkVersion
    $v.LatestVCRedist     = Get-LatestVCRedistVersion
    $v.LatestDefenderSig  = Get-LatestDefenderSignature
    if ($Motherboard) {
        $v.LatestBios = Get-LatestBiosVersion -Board $Motherboard
    }

    $v.DiskReliability     = @(Get-DiskReliability)
    $v.RamModules          = @(Get-RamPartNumbers)
    $v.AdapterCapabilities = @(Get-AdapterCapabilities)

    if (-not $v.LatestWindowsBuild -and -not $v.LatestDotNetFx -and -not $v.LatestVCRedist -and -not $v.LatestDefenderSig) {
        $v.Available = $false
    }

    Write-Ok
    return [pscustomobject]$v
}

# =============================================================================
# 7. HEALTH SCORE
# =============================================================================
function Get-HealthScore {
    param(
        [array]$Results,
        [pscustomobject]$System,
        [string]$NetFx,
        [array]$VC,
        [pscustomobject]$WindowsHealth,
        [pscustomobject]$NetworkHealth,
        [pscustomobject]$Enrichment,
        [pscustomobject]$SystemVerification
    )

    $cats = [ordered]@{}

    # -----------------------------------------------------------------
    # HARDWARE — PassMark CPU + RAM type/speed
    # -----------------------------------------------------------------
    $ramScore = 100
    if ($System.RAM_GB -lt 16)                        { $ramScore -= 30 }
    elseif ($System.RAM_GB -lt 32)                    { $ramScore -= 10 }
    if ($Enrichment -and $Enrichment.Ram) {
        if ($Enrichment.Ram.Type -eq 'DDR3')          { $ramScore -= 15 }
        elseif ($Enrichment.Ram.SpeedMHz -lt 2400)    { $ramScore -= 10 }
        elseif ($Enrichment.Ram.SpeedMHz -lt 3200 -and $Enrichment.Ram.Type -eq 'DDR4') { $ramScore -= 5 }
    }

    $cpuScore = 100
    if ($Enrichment -and $Enrichment.CpuScore) {
        $mark = $Enrichment.CpuScore
        $cpuScore = if     ($mark -ge 35000) { 100 }
                    elseif ($mark -ge 20000) { 95 }
                    elseif ($mark -ge 12000) { 85 }
                    elseif ($mark -ge 7000)  { 70 }
                    elseif ($mark -ge 3500)  { 55 }
                    else                     { 30 }
    } else {
        if ($System.LogicalCPUs -lt 8)      { $cpuScore = 60 }
        elseif ($System.LogicalCPUs -ge 16) { $cpuScore = 95 }
    }

    $hw = [int](($ramScore * 0.4) + ($cpuScore * 0.6))
    $cats['Hardware'] = [math]::Max(0, $hw)

    # -----------------------------------------------------------------
    # STORAGE — free space + media type + SMART health
    # -----------------------------------------------------------------
    $st = 100
    if ($System.Disks.Count -gt 0) {
        $worst = ($System.Disks | Sort-Object FreePct | Select-Object -First 1).FreePct
        if ($worst -lt 5)      { $st = 30 }
        elseif ($worst -lt 10) { $st = 55 }
        elseif ($worst -lt 20) { $st = 80 }
    }
    if ($Enrichment -and $Enrichment.DiskMediaTypes.Count -gt 0) {
        $hasNvme = @($Enrichment.DiskMediaTypes | Where-Object BusType -eq 'NVMe').Count -gt 0
        $hasSsd  = @($Enrichment.DiskMediaTypes | Where-Object MediaType -eq 'SSD').Count -gt 0
        if (-not $hasNvme -and -not $hasSsd) { $st = [math]::Max(0, $st - 25) }
        elseif (-not $hasNvme -and $hasSsd)  { $st = [math]::Max(0, $st - 10) }
    }

    # SMART penalties
    if ($SystemVerification -and $SystemVerification.DiskReliability.Count -gt 0) {
        foreach ($disk in $SystemVerification.DiskReliability) {
            if ($disk.HealthStatus -and $disk.HealthStatus -ne 'Healthy') {
                $st = [math]::Max(0, $st - 25)
            }
            if ($disk.Wear -and $disk.Wear -ge 80) { $st = [math]::Max(0, $st - 20) }
            elseif ($disk.Wear -and $disk.Wear -ge 50) { $st = [math]::Max(0, $st - 8) }
            if ($disk.Temperature -and $disk.Temperature -ge 65) { $st = [math]::Max(0, $st - 5) }
            if ($disk.ReadErrors -and $disk.ReadErrors -gt 100)  { $st = [math]::Max(0, $st - 5) }
            if ($disk.WriteErrors -and $disk.WriteErrors -gt 100) { $st = [math]::Max(0, $st - 5) }
        }
    }
    $cats['Storage'] = $st

    # -----------------------------------------------------------------
    # ENGINEERING SOFTWARE
    # -----------------------------------------------------------------
    $rel = @($Results | Where-Object { $_.State -notin @('NotInstalled','NotApplicable') })
    if ($rel.Count -eq 0) {
        $cats['EngineeringSoftware'] = 100
    } else {
        $healthy = @($rel | Where-Object State -eq 'Healthy').Count
        $baseScore = [int](100 * $healthy / $rel.Count)

        if ($Enrichment -and $Enrichment.Upgradeable.Count -gt 0) {
            $outdatedEng = 0
            foreach ($up in $Enrichment.Upgradeable) {
                foreach ($r in $rel) {
                    if ($r.Name -and $up.Name -and ($up.Name -like "*$($r.Name)*" -or $r.Name -like "*$($up.Name)*")) {
                        $outdatedEng++
                        break
                    }
                }
            }
            if ($outdatedEng -gt 0) {
                $penalty = [math]::Min(30, $outdatedEng * 3)
                $baseScore = [math]::Max(0, $baseScore - $penalty)
            }
        }
        $cats['EngineeringSoftware'] = $baseScore
    }

    # -----------------------------------------------------------------
    # GPU — PassMark + real driver version comparison (NVIDIA/AMD/Intel)
    # -----------------------------------------------------------------
    $gpuScore = 100
    if ($Enrichment -and $Enrichment.GpuScores.Count -gt 0) {
        $best = ($Enrichment.GpuScores | Where-Object Score | Sort-Object Score -Descending | Select-Object -First 1)
        if ($best -and $best.Score) {
            $g = $best.Score
            $gpuScore = if     ($g -ge 25000) { 100 }
                        elseif ($g -ge 15000) { 95 }
                        elseif ($g -ge 8000)  { 85 }
                        elseif ($g -ge 3000)  { 70 }
                        elseif ($g -ge 1000)  { 50 }
                        else                  { 25 }
        }
    } elseif (-not $System.HasDiscreteGPU) {
        $gpuScore = 40
    }

    $driverPenalty = 0
    $installedNv  = ($System.GPUs | Where-Object { $_.Name -match 'NVIDIA|GeForce|RTX|Quadro' } | Select-Object -First 1).DriverVersion
    $installedAmd = ($System.GPUs | Where-Object { $_.Name -match 'Radeon' } | Select-Object -First 1).DriverVersion

    if ($Enrichment -and $Enrichment.LatestNvidia -and $installedNv) {
        $nvLatest = $Enrichment.LatestNvidia -replace '\.',''
        $nvInst   = $installedNv -replace '\.',''
        if ($nvInst.Length -gt 5) { $nvInst = $nvInst.Substring($nvInst.Length - 5) }
        try {
            if ([int]$nvLatest -gt [int]$nvInst) { $driverPenalty = 15 }
        } catch { }
    }

    if ($driverPenalty -eq 0 -and $installedAmd -and $Enrichment.LatestAmd) {
        # AMD version strings vary; use winget as a secondary signal
        try {
            $amdLatest = [version]($Enrichment.LatestAmd)
            $amdInst   = [version]($installedAmd -replace '[^0-9\.]','')
            if ($amdLatest -gt $amdInst) { $driverPenalty = 15 }
        } catch { }
    }

    if ($driverPenalty -eq 0 -and $Enrichment -and $Enrichment.Upgradeable.Count -gt 0) {
        $gpuUp = @($Enrichment.Upgradeable | Where-Object {
            $_.Name -match 'NVIDIA|GeForce|Radeon|AMD|Intel.*Graphics'
        }).Count
        if ($gpuUp -gt 0) { $driverPenalty = 10 }
    }

    $cats['GPU'] = [math]::Max(0, $gpuScore - $driverPenalty)

    # -----------------------------------------------------------------
    # DRIVERS — .NET, VC++, GPU driver, BIOS, Defender signatures
    # -----------------------------------------------------------------
    $drv = 100
    if ($NetFx -match '^4\.[0-6]')    { $drv -= 40 }
    elseif ($NetFx -eq '4.7')         { $drv -= 15 }
    if (-not $VC -or $VC.Count -eq 0) { $drv -= 30 }
    if ($driverPenalty -gt 0)         { $drv -= $driverPenalty }

    # Additional penalties from online verification
    if ($SystemVerification) {
        # Defender signature staleness
        if ($SystemVerification.LatestDefenderSig -and $WindowsHealth.DefenderSig) {
            try {
                $haveSig = [version]($WindowsHealth.DefenderSig)
                $wantSig = [version]($SystemVerification.LatestDefenderSig)
                if ($wantSig -gt $haveSig) { $drv -= 5 }
            } catch { }
        }
        # BIOS age — if release date > 3 years, mild penalty
        if ($Motherboard -and $Motherboard.BiosReleaseDate) {
            try {
                $biosAge = (New-TimeSpan -Start ([datetime]$Motherboard.BiosReleaseDate) -End (Get-Date)).TotalDays
                if ($biosAge -gt 3 * 365) { $drv -= 5 }
            } catch { }
        }
    }
    $cats['Drivers'] = [math]::Max(0, $drv)

    # -----------------------------------------------------------------
    # LICENSING
    # -----------------------------------------------------------------
    $licIssues = @($rel | Where-Object { @($_.Findings | Where-Object Id -match 'LICSVC').Count -gt 0 }).Count
    $cats['Licensing'] = if ($rel.Count -eq 0) { 100 } else { [int](100 - (100 * $licIssues / $rel.Count)) }

    # -----------------------------------------------------------------
    # WINDOWS — pending reboot, updates, activation, build freshness
    # -----------------------------------------------------------------
    $winScore = if ($WindowsHealth) { $WindowsHealth.Score } else { 85 }
    if ($SystemVerification -and $SystemVerification.LatestWindowsBuild -and $System.OSBuild) {
        try {
            $haveBuild = [version]($System.OSBuild -replace '^.*?(\d+\.\d+)$','$1')
            $wantBuild = [version]$SystemVerification.LatestWindowsBuild
            # If the current build is more than a few revisions behind, deduct
            $buildGap = $wantBuild.Build - $haveBuild.Build
            if ($buildGap -gt 0 -and $wantBuild.Major -eq $haveBuild.Major) {
                $winScore = [math]::Max(0, $winScore - [math]::Min(15, $buildGap * 2))
            }
        } catch { }
    }
    $cats['Windows'] = $winScore

    $cats['Network'] = if ($NetworkHealth) { $NetworkHealth.Score } else { 90 }

    # Network adapter capability check
    if ($SystemVerification -and $SystemVerification.AdapterCapabilities.Count -gt 0) {
        foreach ($a in $SystemVerification.AdapterCapabilities) {
            if ($a.MaxSpeed -and $a.LinkSpeed -and $a.MaxSpeed -ne $a.LinkSpeed) {
                # Running well below capability (e.g. 100 Mb on a 1 Gb NIC)
                if ($a.LinkSpeed -match '100\s*Mbps' -and $a.MaxSpeed -match 'Gb') {
                    $cats['Network'] = [math]::Max(0, $cats['Network'] - 10)
                }
            }
        }
    }

    # -----------------------------------------------------------------
    # THERMALS
    # -----------------------------------------------------------------
    $th = 85
    if ($System.ThermalZones -and $System.ThermalZones.Count -gt 0) {
        $max = ($System.ThermalZones | Measure-Object Celsius -Maximum).Maximum
        if ($max -lt 60)      { $th = 100 }
        elseif ($max -lt 80)  { $th = 88 }
        elseif ($max -lt 95)  { $th = 60 }
        else                  { $th = 30 }
    }
    $cats['Thermals'] = $th

    $cats['ProjectSafety'] = 100

    $weights = @{
        Hardware = 0.20; Storage = 0.15; EngineeringSoftware = 0.20
        GPU = 0.08; Drivers = 0.10; Licensing = 0.07
        Windows = 0.05; Thermals = 0.05; Network = 0.05; ProjectSafety = 0.05
    }
    $overall = 0
    foreach ($k in $cats.Keys) {
        $w = if ($weights.ContainsKey($k)) { $weights[$k] } else { 0 }
        $overall += $cats[$k] * $w
    }

    [pscustomobject]@{
        Overall    = [int][math]::Round($overall)
        Categories = $cats
    }
}

# ---------------------------------------------------------------------------
# Windows / Network health
# ---------------------------------------------------------------------------
$windowsHealth = Get-WindowsHealth -System $sys
$networkHealth = Get-NetworkHealth -System $sys -Catalog $Script:RawCatalog -Installed $installed

# ---------------------------------------------------------------------------
# Online enrichment + hardware / OS verification
# ---------------------------------------------------------------------------
$motherboard    = Get-MotherboardInfo
$enrichment     = Invoke-OnlineEnrichment -System $sys
$systemVerify   = Invoke-SystemOnlineVerification -System $sys -Motherboard $motherboard

# ---------------------------------------------------------------------------
# Live GPU sample (optional)
# ---------------------------------------------------------------------------
$liveGpu = @()
if ($LiveGpuSample) {
    Write-Stage "Sampling live GPU utilization..."
    $liveGpu = Get-LiveGpuSample -DurationSeconds 2
    Write-Ok
}

$score = Get-HealthScore -Results $allResults -System $sys -NetFx $netFx -VC $vc `
                         -WindowsHealth $windowsHealth -NetworkHealth $networkHealth `
                         -Enrichment $enrichment -SystemVerification $systemVerify

# =============================================================================
# 8. DISCIPLINE ROLLUP
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
    $bar   = ('#' * $green) + ('=' * $yell) + ('.' * $red)
    Write-Host ("  {0,-18} {1,2}/{2,2} healthy  {3,2} attention  {4,2} critical   [{5}]" `
                -f $d, $green, $total, $yell, $red, $bar) -ForegroundColor Cyan
}

Write-Host ""
Write-Host ("  SIGMA ENGINEERING SCORE: {0}/100" -f $score.Overall) -ForegroundColor Green
foreach ($k in $score.Categories.Keys) {
    Write-Host ("    {0,-22} {1,3}/100" -f $k, $score.Categories[$k])
}

# =============================================================================
# 9. PROJECT GUARDIAN
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
            foreach ($m in [regex]::Matches($text, '\(0\s*\.\s*"PDFDEFINITION"\)[\s\S]{0,3000}?\(1\s*\.\s*"([^"]+)"\)')) {
                $refs.Add([pscustomobject]@{ Type = 'PDF'; Path = $m.Groups[1].Value })
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
            foreach ($m in [regex]::Matches($ascii, "\\\\\\\\[^\x00-\x1F`"<>|]{0,250}\.$extPat", 'IgnoreCase')) {
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
    $backupExt = @('.bak','.tmp','.sv$','.dwl','.dwl2','.ac$','.err','.log')

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

    $dwgFiles = @($scan | Where-Object { $_.Extension -in @('.dwg','.dxf') })
    $maxDwg = 200
    if ($dwgFiles.Count -gt $maxDwg) {
        Write-Host "  (limiting reference scan to first $maxDwg drawings)" -ForegroundColor Yellow
        $dwgFiles = $dwgFiles | Select-Object -First $maxDwg
    }

    $refTotal = 0
    $refMissing = 0
    $refMissingList = @()

    if ($dwgFiles.Count -gt 0) {
        Write-Host ""
        Write-Host "  Scanning drawing references..." -ForegroundColor Cyan
        foreach ($dwg in $dwgFiles) {
            $refs = Get-DwgReferences -FilePath $dwg.FullName
            foreach ($r in $refs) {
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
    }

    if ($refTotal -gt 0) {
        $missRatio = $refMissing / $refTotal
        $penalty += [math]::Min(30, [int]($missRatio * 100))
    }

    $health = [math]::Max(0, 100 - $penalty)
    $col = if ($health -ge 80) { 'Green' } elseif ($health -ge 60) { 'Yellow' } else { 'Red' }
    Write-Host ""
    Write-Host ("  Project Health: {0}%" -f $health) -ForegroundColor $col
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
        Health           = $health
    }
}

$guardian = $null
if ($ProjectGuardian) {
    $guardian = Invoke-ProjectGuardian -Root $ProjectGuardian
    if ($guardian) {
        $score.Categories['ProjectSafety'] = $guardian.Health
        $weights = @{
            Hardware = 0.20; Storage = 0.15; EngineeringSoftware = 0.20
            GPU = 0.08; Drivers = 0.10; Licensing = 0.07
            Windows = 0.05; Thermals = 0.05; Network = 0.05; ProjectSafety = 0.05
        }
        $recalc = 0
        foreach ($k in $score.Categories.Keys) {
            $w = if ($weights.ContainsKey($k)) { $weights[$k] } else { 0 }
            $recalc += $score.Categories[$k] * $w
        }
        $score.Overall = [int][math]::Round($recalc)
    }
}

# =============================================================================
# 10. WRITE REPORT
# =============================================================================
Write-Stage "Writing report (HTML / JSON / CSV)..."
Ensure-Folder $exportPath

[pscustomobject]@{
    GeneratedAt        = (Get-Date).ToString('s')
    System             = $sys
    Motherboard        = $motherboard
    NetFx              = $netFx
    VCRedist           = $vc
    Score              = $score
    WindowsHealth      = $windowsHealth
    NetworkHealth      = $networkHealth
    Enrichment         = $enrichment
    SystemVerification = $systemVerify
    LiveGpu            = $liveGpu
    Guardian           = $guardian
    Results            = $allResults
} | ConvertTo-Json -Depth 12 | Set-Content "$reportBase.json" -Encoding UTF8

$allResults | Select-Object Name, Disciplines, Kind, State, Version, Installed,
    @{n='Findings';e={ ($_.Findings | ForEach-Object { "$($_.Severity): $($_.Problem)" }) -join ' | ' }},
    @{n='Notes';   e={ $_.Notes -join ' | ' }} |
    Export-Csv "$reportBase.csv" -NoTypeInformation -Encoding UTF8

# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
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

 .enrich{background:#eef6ff;border-left:5px solid #2b6cb0;border-radius:6px;padding:12px 16px;margin:10px 0;font-size:13px}
 .enrich b{color:#0b5394}
 .verify{background:#f0fbf1;border-left:5px solid #1c9b4b;border-radius:6px;padding:12px 16px;margin:10px 0;font-size:13px}
 .verify b{color:#0f7233}
 .match{background:#1c9b4b;color:#fff;padding:1px 6px;border-radius:8px;font-size:11px;font-weight:700}
 .mismatch{background:#d18b00;color:#fff;padding:1px 6px;border-radius:8px;font-size:11px;font-weight:700}
 .unknown{background:#8b95a5;color:#fff;padding:1px 6px;border-radius:8px;font-size:11px;font-weight:700}
</style>
'@

$chipClass = @{
    'Healthy'       = 'green'
    'Attention'     = 'yellow'
    'Critical'      = 'red'
    'NotInstalled'  = 'gray'
    'NotApplicable' = 'darkgray'
    'Unknown'       = 'blue'
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("<!doctype html><html><head><meta charset='utf-8'><title>Sigma Engineer Toolkit - Report</title>$style</head><body>")
[void]$sb.AppendLine("<h1>Sigma Engineer Toolkit</h1>")
[void]$sb.AppendLine("<p class='sub'>Generated $(Get-Date) on $($sys.ComputerName) by $($sys.User)</p>")

# Hero
[void]$sb.AppendLine("<div class='hero'>")
[void]$sb.AppendLine("<div class='hero-num'>$($score.Overall)<span>/100</span></div>")
[void]$sb.AppendLine("<div class='hero-label'>Sigma Engineering Score</div>")
[void]$sb.AppendLine("<div class='hero-cats'>")
foreach ($k in $score.Categories.Keys) {
    [void]$sb.AppendLine("<div><b>$($score.Categories[$k])</b><span>$k</span></div>")
}
[void]$sb.AppendLine("</div></div>")

# ---------------------------------------------------------------------------
# NEW: Verified Components — shows online-verified facts side by side
# ---------------------------------------------------------------------------
[void]$sb.AppendLine("<h2>Verified Components (Local vs Online)</h2>")
[void]$sb.AppendLine("<div class='verify'>")
if (-not $systemVerify.Available) {
    [void]$sb.AppendLine("<b>Online verification unavailable</b> — using local data only. Values below are from WMI/SMART.")
} else {
    [void]$sb.AppendLine("<b>Every checked component has been cross-referenced with an online source where possible.</b>")
}
[void]$sb.AppendLine("</div>")

[void]$sb.AppendLine("<div class='card'><table>")
[void]$sb.AppendLine("<tr><th>Component</th><th>Local Value</th><th>Online / Expected</th><th>Status</th></tr>")

# Windows build
$winLocal = if ($sys.OSBuild) { $sys.OSBuild } else { 'n/a' }
$winOnline = if ($systemVerify.LatestWindowsBuild) { $systemVerify.LatestWindowsBuild } else { 'unknown' }
$winStatus = if (-not $systemVerify.LatestWindowsBuild) { 'unknown' }
             else {
                 try {
                     $lb = [version]($sys.OSBuild -replace '^.*?(\d+\.\d+)$','$1')
                     $lo = [version]$systemVerify.LatestWindowsBuild
                     if ($lb.Build -ge $lo.Build) { 'match' } else { 'mismatch' }
                 } catch { 'unknown' }
             }
[void]$sb.AppendLine("<tr><td><b>Windows Build</b></td><td>$winLocal</td><td>$winOnline</td><td><span class='$winStatus'>$($winStatus.ToUpper())</span></td></tr>")

# .NET
$netStatus = if (-not $systemVerify.LatestDotNetFx) { 'unknown' }
             elseif ($netFx -match 'Not found') { 'mismatch' }
             else { 'match' }
[void]$sb.AppendLine("<tr><td><b>.NET Framework</b></td><td>$netFx</td><td>$($systemVerify.LatestDotNetFx)</td><td><span class='$netStatus'>$($netStatus.ToUpper())</span></td></tr>")

# VC++ Redist
$vcLocal = if ($vc.Count -gt 0) { ($vc | ForEach-Object { $_.DisplayVersion } | Sort-Object -Unique) -join ', ' } else { 'none' }
$vcOnline = if ($systemVerify.LatestVCRedist) { $systemVerify.LatestVCRedist } else { 'unknown' }
$vcStatus = if (-not $systemVerify.LatestVCRedist) { 'unknown' }
            elseif ($vc.Count -eq 0) { 'mismatch' }
            else { 'match' }
[void]$sb.AppendLine("<tr><td><b>VC++ Redistributable</b></td><td>$vcLocal</td><td>$vcOnline</td><td><span class='$vcStatus'>$($vcStatus.ToUpper())</span></td></tr>")

# Defender Signature
$defLocal = if ($windowsHealth.DefenderSig) { $windowsHealth.DefenderSig } else { 'unknown' }
$defOnline = if ($systemVerify.LatestDefenderSig) { $systemVerify.LatestDefenderSig } else { 'unknown' }
$defStatus = if (-not $systemVerify.LatestDefenderSig) { 'unknown' }
             elseif ($windowsHealth.DefenderSig) {
                 try {
                     $hl = [version]$windowsHealth.DefenderSig
                     $ol = [version]$systemVerify.LatestDefenderSig
                     if ($hl -ge $ol) { 'match' } else { 'mismatch' }
                 } catch { 'unknown' }
             } else { 'unknown' }
[void]$sb.AppendLine("<tr><td><b>Defender Signature</b></td><td>$defLocal</td><td>$defOnline</td><td><span class='$defStatus'>$($defStatus.ToUpper())</span></td></tr>")

# BIOS
if ($motherboard) {
    $biosLocal = "$($motherboard.BiosVendor) $($motherboard.BiosVersion) ($($motherboard.BiosReleaseDate))"
    $biosOnline = if ($systemVerify.LatestBios) { $systemVerify.LatestBios } else { 'not available' }
    $biosStatus = if (-not $systemVerify.LatestBios) { 'unknown' } else { 'match' }
    [void]$sb.AppendLine("<tr><td><b>Motherboard BIOS</b></td><td>$biosLocal</td><td>$biosOnline</td><td><span class='$biosStatus'>$($biosStatus.ToUpper())</span></td></tr>")
    [void]$sb.AppendLine("<tr><td><b>Motherboard</b></td><td colspan='3'>$($motherboard.Manufacturer) $($motherboard.Product) ($($motherboard.Version))</td></tr>")
}

# CPU PassMark
if ($enrichment.CpuScore) {
    [void]$sb.AppendLine("<tr><td><b>CPU Benchmark</b></td><td>$($sys.CPU)</td><td>PassMark CPU Mark: <b>$($enrichment.CpuScore)</b></td><td><span class='match'>VERIFIED</span></td></tr>")
} elseif ($enrichment.OnlineAvailable) {
    [void]$sb.AppendLine("<tr><td><b>CPU Benchmark</b></td><td>$($sys.CPU)</td><td>PassMark lookup failed</td><td><span class='unknown'>UNKNOWN</span></td></tr>")
}

# GPU PassMark
foreach ($gs in $enrichment.GpuScores) {
    $sc = if ($gs.Score) { $gs.Score } else { 'n/a' }
    $st = if ($gs.Score) { 'match' } else { 'unknown' }
    [void]$sb.AppendLine("<tr><td><b>GPU Benchmark</b></td><td>$($gs.Name)</td><td>PassMark G3D Mark: <b>$sc</b></td><td><span class='$st'>$(if ($gs.Score) {'VERIFIED'} else {'UNKNOWN'})</span></td></tr>")
}

# GPU driver version
$installedNvVer = ($sys.GPUs | Where-Object { $_.Name -match 'NVIDIA|GeForce|RTX|Quadro' } | Select-Object -First 1).DriverVersion
if ($installedNvVer -and $enrichment.LatestNvidia) {
    $nvStatus = 'match'
    try {
        $inst5 = ($installedNvVer -replace '\.','')
        if ($inst5.Length -gt 5) { $inst5 = $inst5.Substring($inst5.Length - 5) }
        if ([int]($enrichment.LatestNvidia -replace '\.','') -gt [int]$inst5) { $nvStatus = 'mismatch' }
    } catch { $nvStatus = 'unknown' }
    [void]$sb.AppendLine("<tr><td><b>NVIDIA Driver</b></td><td>$installedNvVer</td><td>Latest: $($enrichment.LatestNvidia)</td><td><span class='$nvStatus'>$($nvStatus.ToUpper())</span></td></tr>")
}
if ($enrichment.LatestAmd) {
    [void]$sb.AppendLine("<tr><td><b>AMD Driver</b></td><td>$(($sys.GPUs | Where-Object { $_.Name -match 'Radeon' } | Select-Object -First 1).DriverVersion)</td><td>Latest: $($enrichment.LatestAmd)</td><td><span class='match'>VERIFIED</span></td></tr>")
}
if ($enrichment.LatestIntelGpu) {
    [void]$sb.AppendLine("<tr><td><b>Intel Graphics Driver</b></td><td>$(($sys.GPUs | Where-Object { $_.Name -match 'Intel' } | Select-Object -First 1).DriverVersion)</td><td>Latest: $($enrichment.LatestIntelGpu)</td><td><span class='match'>VERIFIED</span></td></tr>")
}

[void]$sb.AppendLine("</table></div>")

# RAM modules
if ($systemVerify.RamModules.Count -gt 0) {
    [void]$sb.AppendLine("<h3>RAM Modules (from SPD)</h3><div class='card'><table>")
    [void]$sb.AppendLine("<tr><th>Manufacturer</th><th>Part Number</th><th>Capacity</th><th>Rated MHz</th><th>Configured MHz</th></tr>")
    foreach ($m in $systemVerify.RamModules) {
        $speedFlag = if ($m.ConfiguredMHz -lt $m.SpeedMHz) { "<span class='mismatch'>$($m.ConfiguredMHz) (below rated)</span>" } else { $m.ConfiguredMHz }
        [void]$sb.AppendLine("<tr><td>$($m.Manufacturer)</td><td class='small'>$($m.PartNumber)</td><td>$($m.CapacityGB) GB</td><td>$($m.SpeedMHz)</td><td>$speedFlag</td></tr>")
    }
    [void]$sb.AppendLine("</table></div>")
}

# Disk SMART
if ($systemVerify.DiskReliability.Count -gt 0) {
    [void]$sb.AppendLine("<h3>Disk Health (SMART)</h3><div class='card'><table>")
    [void]$sb.AppendLine("<tr><th>Disk</th><th>Media</th><th>Health</th><th>Wear %</th><th>Temp C</th><th>Power-On Hours</th><th>Read/Write Errors</th></tr>")
    foreach ($d in $systemVerify.DiskReliability) {
        $hCls = if ($d.HealthStatus -eq 'Healthy') { 'green' } else { 'red' }
        $wearCls = if ($d.Wear -and $d.Wear -ge 80) { 'red' } elseif ($d.Wear -and $d.Wear -ge 50) { 'yellow' } else { 'green' }
        $wearCell = if ($d.Wear -ne $null) { "<span class='chip $wearCls'>$($d.Wear)%</span>" } else { 'n/a' }
        [void]$sb.AppendLine("<tr><td>$($d.FriendlyName)</td><td>$($d.BusType)/$($d.MediaType)</td><td><span class='chip $hCls'>$($d.HealthStatus)</span></td><td>$wearCell</td><td>$($d.Temperature)</td><td>$($d.PowerOnHours)</td><td>$($d.ReadErrors) / $($d.WriteErrors)</td></tr>")
    }
    [void]$sb.AppendLine("</table></div>")
}

# Adapter capability
if ($systemVerify.AdapterCapabilities.Count -gt 0) {
    [void]$sb.AppendLine("<h3>Network Adapter Capabilities</h3><div class='card'><table>")
    [void]$sb.AppendLine("<tr><th>Adapter</th><th>Description</th><th>Running</th><th>Capability</th><th>Driver</th></tr>")
    foreach ($a in $systemVerify.AdapterCapabilities) {
        $runCls = if ($a.MaxSpeed -and $a.LinkSpeed -and $a.MaxSpeed -ne $a.LinkSpeed) { 'yellow' } else { 'green' }
        [void]$sb.AppendLine("<tr><td>$($a.Name)</td><td class='small'>$($a.Description)</td><td><span class='chip $runCls'>$($a.LinkSpeed)</span></td><td>$($a.MaxSpeed)</td><td>$($a.DriverVersion)</td></tr>")
    }
    [void]$sb.AppendLine("</table></div>")
}

# Outdated packages
if ($enrichment.Upgradeable.Count -gt 0) {
    [void]$sb.AppendLine("<h3>Outdated packages (from winget)</h3><div class='card'><table>")
    [void]$sb.AppendLine("<tr><th>Name</th><th>Id</th><th>Installed</th><th>Available</th></tr>")
    foreach ($u in ($enrichment.Upgradeable | Select-Object -First 50)) {
        [void]$sb.AppendLine("<tr><td>$($u.Name)</td><td class='small'>$($u.Id)</td><td>$($u.Installed)</td><td><b>$($u.Available)</b></td></tr>")
    }
    [void]$sb.AppendLine("</table></div>")
}

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
    [void]$sb.AppendLine("<div class='card'>No findings. Everything detected is healthy.</div>")
} else {
    foreach ($f in $topFindings) {
        $sevCls = if ($f.Severity -eq 'critical') { 'sev-critical' } else { 'sev-warn' }
        $chipCls = if ($f.Severity -eq 'critical') { 'red' } else { 'yellow' }
        $chipTxt = if ($f.Severity -eq 'critical') { 'CRITICAL' } else { 'ATTENTION' }
        [void]$sb.AppendLine("<div class='finding $sevCls'>")
        [void]$sb.AppendLine("<div class='finding-head'><span class='finding-title'>$($f.Problem)</span><span class='chip $chipCls'>$chipTxt</span></div>")
        [void]$sb.AppendLine("<table class='finding-body'>")
        [void]$sb.AppendLine("<tr><th>Software</th><td>$($f.Software)</td></tr>")
        [void]$sb.AppendLine("<tr><th>Detected</th><td>$($f.Detected)</td></tr>")
        [void]$sb.AppendLine("<tr><th>Why it matters</th><td>$($f.WhyItMatters)</td></tr>")
        [void]$sb.AppendLine("<tr><th>Recommended</th><td>$($f.Recommendation)</td></tr>")
        if ($f.Optional) {
            [void]$sb.AppendLine("<tr><th>Optional</th><td>$($f.Optional)</td></tr>")
        }
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
    @('VC++ Redistributables', $vc.Count),
    @('PowerShell', $PSVersionTable.PSVersion.ToString()),
    @('Admin', $sys.IsAdmin),
    @('Power', $sys.Power.StatusText),
    @('Discrete GPU', $sys.HasDiscreteGPU)
)) {
    [void]$sb.AppendLine("<tr><th style='width:220px'>$($kv[0])</th><td>$($kv[1])</td></tr>")
}
[void]$sb.AppendLine("</table></div>")

# Graphics
[void]$sb.AppendLine("<h2>Graphics</h2><div class='card'><table><tr><th>GPU</th><th>Kind</th><th>Driver</th><th>Date</th><th>VRAM (GB)</th></tr>")
foreach ($g in $sys.GPUs) {
    [void]$sb.AppendLine("<tr><td>$($g.Name)</td><td>$($g.Kind)</td><td>$($g.DriverVersion)</td><td>$($g.DriverDate)</td><td>$($g.VRAM_GB)</td></tr>")
}
[void]$sb.AppendLine("</table></div>")

# Live GPU sample
if ($LiveGpu -and $LiveGpu.Count -gt 0) {
    [void]$sb.AppendLine("<h2>Live GPU Sample</h2><div class='card'><table><tr><th>PID</th><th>Process</th><th>GPU %</th></tr>")
    foreach ($g in $LiveGpu) {
        [void]$sb.AppendLine("<tr><td>$($g.Pid)</td><td>$($g.Process)</td><td>$($g.GPU)%</td></tr>")
    }
    [void]$sb.AppendLine("</table></div>")
}

# Disks
[void]$sb.AppendLine("<h2>Disks</h2><div class='card'><table><tr><th>Drive</th><th>Label</th><th>FS</th><th>Size GB</th><th>Free GB</th><th>Free %</th></tr>")
foreach ($d in $sys.Disks) {
    $cls = if ($d.FreePct -lt 10) { 'red' } elseif ($d.FreePct -lt 20) { 'yellow' } else { 'green' }
    [void]$sb.AppendLine("<tr><td>$($d.Drive)</td><td>$($d.Label)</td><td>$($d.FS)</td><td>$($d.SizeGB)</td><td>$($d.FreeGB)</td><td><span class='chip $cls'>$($d.FreePct)%</span></td></tr>")
}
[void]$sb.AppendLine("</table></div>")

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
[void]$sb.AppendLine("<tr><th>Category score</th><td><b>$($windowsHealth.Score)/100</b></td></tr>")
[void]$sb.AppendLine("</table></div>")

# Power
[void]$sb.AppendLine("<h2>Power</h2><div class='card'><table>")
[void]$sb.AppendLine("<tr><th style='width:220px'>Has battery</th><td>$($sys.Power.HasBattery)</td></tr>")
$acChip = if ($sys.Power.OnAC) { 'Yes' } else { "<span class='chip yellow'>No</span>" }
[void]$sb.AppendLine("<tr><th>On AC power</th><td>$acChip</td></tr>")
if ($sys.Power.Percent -ne $null) {
    [void]$sb.AppendLine("<tr><th>Charge</th><td>$($sys.Power.Percent)%</td></tr>")
}
[void]$sb.AppendLine("<tr><th>Status</th><td>$($sys.Power.StatusText)</td></tr>")
[void]$sb.AppendLine("</table></div>")

# Thermals
if ($sys.ThermalZones.Count -gt 0) {
    [void]$sb.AppendLine("<h2>Thermals</h2><div class='card'><table><tr><th>Zone</th><th>Temperature</th></tr>")
    foreach ($z in $sys.ThermalZones) {
        $cls = if ($z.Celsius -lt 70) { 'green' } elseif ($z.Celsius -lt 85) { 'yellow' } else { 'red' }
        [void]$sb.AppendLine("<tr><td>$($z.Zone)</td><td><span class='chip $cls'>$($z.Celsius) C</span></td></tr>")
    }
    [void]$sb.AppendLine("</table></div>")
}

# Network
[void]$sb.AppendLine("<h2>Network</h2><div class='card'><table>")
[void]$sb.AppendLine("<tr><th style='width:220px'>Link speed</th><td>$($networkHealth.LinkSpeedText)</td></tr>")
$dnsChip = if ($networkHealth.DNS -eq 'OK') { "<span class='chip green'>OK</span>" } else { "<span class='chip red'>$($networkHealth.DNS)</span>" }
[void]$sb.AppendLine("<tr><th>DNS</th><td>$dnsChip</td></tr>")
[void]$sb.AppendLine("<tr><th>Default gateway</th><td>$($networkHealth.DefaultGW)</td></tr>")
[void]$sb.AppendLine("<tr><th>Category score</th><td><b>$($networkHealth.Score)/100</b></td></tr>")
[void]$sb.AppendLine("</table>")
if ($networkHealth.Adapters.Count -gt 0) {
    [void]$sb.AppendLine("<h3 style='margin-top:16px'>Adapters</h3>")
    [void]$sb.AppendLine("<table><tr><th>Name</th><th>Link speed</th><th>MAC</th></tr>")
    foreach ($a in $networkHealth.Adapters) {
        [void]$sb.AppendLine("<tr><td>$($a.Name)</td><td>$($a.LinkSpeed)</td><td>$($a.Mac)</td></tr>")
    }
    [void]$sb.AppendLine("</table>")
}
[void]$sb.AppendLine("</div>")

# License Center
if ($networkHealth.License.Count -gt 0) {
    [void]$sb.AppendLine("<h2>License Center</h2><div class='card'><table>")
    [void]$sb.AppendLine("<tr><th>Product</th><th>Ports</th><th>Local</th></tr>")
    foreach ($l in $networkHealth.License) {
        $chip = if ($l.Local) { "<span class='chip green'>OPEN</span>" } else { "<span class='chip gray'>CLOSED</span>" }
        [void]$sb.AppendLine("<tr><td>$($l.Product)</td><td>$($l.Ports)</td><td>$chip</td></tr>")
    }
    [void]$sb.AppendLine("</table><p class='small'>Ports closed locally is normal for node-locked or remote license servers.</p></div>")
}

# Guardian
if ($guardian) {
    [void]$sb.AppendLine("<h2>Project Guardian</h2><div class='card'>")
    [void]$sb.AppendLine("<p><b>$($guardian.Root)</b></p>")
    [void]$sb.AppendLine("<table>")
    [void]$sb.AppendLine("<tr><th style='width:220px'>Total files</th><td>$($guardian.TotalFiles)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Total size</th><td>$($guardian.TotalGB) GB</td></tr>")
    [void]$sb.AppendLine("<tr><th>Engineering files</th><td>$($guardian.EngineeringFiles)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Long paths</th><td>$($guardian.LongPaths)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Backup/temp files</th><td>$($guardian.BackupFiles) (old: $($guardian.OldBackups))</td></tr>")
    [void]$sb.AppendLine("<tr><th>Large files</th><td>$($guardian.LargeFiles) ($($guardian.LargeGB) GB)</td></tr>")
    [void]$sb.AppendLine("<tr><th>References scanned</th><td>$($guardian.RefTotal)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Broken references</th><td>$($guardian.RefMissing)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Project Health</th><td><b>$($guardian.Health)%</b></td></tr>")
    [void]$sb.AppendLine("</table>")
    if ($guardian.RefMissingList -and $guardian.RefMissingList.Count -gt 0) {
        [void]$sb.AppendLine("<h3 style='margin-top:16px'>Broken references (first 50)</h3>")
        [void]$sb.AppendLine("<table><tr><th>Drawing</th><th>Type</th><th>Reference</th></tr>")
        foreach ($ref in ($guardian.RefMissingList | Select-Object -First 50)) {
            [void]$sb.AppendLine("<tr><td class='small'>$($ref.Drawing)</td><td>$($ref.Type)</td><td class='small'>$($ref.Ref)</td></tr>")
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
    [void]$sb.AppendLine("<div class='disc'><h3>$d <span class='small'>($g healthy / $y attention / $rr critical)</span></h3>")
    [void]$sb.AppendLine("<table><tr><th>Software</th><th>Kind</th><th>Status</th><th>Version</th><th>Findings</th></tr>")
    foreach ($p in $rs) {
        $cls = if ($chipClass.ContainsKey($p.State)) { $chipClass[$p.State] } else { 'gray' }
        $msg = @()
        foreach ($f in $p.Findings) {
            $mark = if ($f.Severity -eq 'critical') { '!!' } else { '!' }
            $msg += "$mark $($f.Problem)"
        }
        foreach ($n in $p.Notes) { $msg += ". $n" }
        $msg = $msg -join '<br>'
        [void]$sb.AppendLine("<tr><td><b>$($p.Name)</b></td><td>$($p.Kind)</td><td><span class='chip $cls'>$($p.State)</span></td><td>$($p.Version)</td><td class='small'>$msg</td></tr>")
    }
    [void]$sb.AppendLine("</table></div>")
}

[void]$sb.AppendLine("<p class='small'>End of report. Findings are advisory, not errors.</p>")
[void]$sb.AppendLine("</body></html>")
$sb.ToString() | Set-Content "$reportBase.html" -Encoding UTF8
Write-Ok

# =============================================================================
# 11. FINAL
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
    '^[Rr]$' {
        Start-Process $exportPath
    }
    '^[Ii]$' {
        Invoke-Installer -Disciplines $Disciplines -InstallList @()
    }
    default { exit 0 }
}
