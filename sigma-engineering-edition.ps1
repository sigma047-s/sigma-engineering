#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sigma Engineer Toolkit - requirement-driven installability scanner + installer.
.DESCRIPTION
    You pick disciplines or specific apps. The toolkit measures this PC against
    every requirement each app declares and online-verifies where possible.
    You can install ANY app, whether or not it meets requirements (a warning
    is shown). The final menu loops so you can scan again and install without
    restarting the script.
#>
[CmdletBinding()]
param(
    [string[]]$Disciplines = @(),
    [string[]]$CheckApps   = @(),
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
Write-Host "[INFO] Requirement-driven installability scanner." -ForegroundColor Cyan
Write-Host "[INFO] Pick what to check - the PC is tested against each app's requirements." -ForegroundColor Cyan
Write-Host "[INFO] The installer works from scan results or interactively." -ForegroundColor Cyan
Write-Host "[INFO] Online: PassMark, winget, vendor feeds." -ForegroundColor Cyan
Write-Host "[WARNING] This scanning tool isn't 100% accurate." -ForegroundColor Yellow
if ($Offline) { Write-Host "[INFO] Offline mode: online enrichment disabled." -ForegroundColor Cyan }
if ($Disciplines.Count -gt 0) { Write-Host "[INFO] Discipline filter: $($Disciplines -join ', ')" -ForegroundColor Cyan }
if ($CheckApps.Count -gt 0)   { Write-Host "[INFO] App filter: $($CheckApps -join ', ')" -ForegroundColor Cyan }
Write-Host ""

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
function Add-Diagnostic { param([string]$Category,[string]$Message)
    "[$(Get-Date -Format 'HH:mm:ss')]  $Category  ::  $Message" | Out-File $errorLog -Append
}
function Ensure-Folder { param([string]$P)
    if (-not (Test-Path $P)) { New-Item -ItemType Directory -Path $P -Force | Out-Null }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-TcpPort {
    param([string]$ComputerName='localhost',[int]$Port,[int]$TimeoutMs=1500)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($iar); return $true
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
                        if (-not $map.ContainsKey($desc) -or $map[$desc] -lt $gb) { $map[$desc] = $gb }
                    }
                }
            } catch { }
        }
    } catch { Add-Diagnostic 'GPU' "VRAM registry read failed: $_" }
    return $map
}

function Resolve-GpuVram {
    param([string]$GpuName,[hashtable]$Map)
    if (-not $GpuName -or -not $Map) { return $null }
    if ($Map.ContainsKey($GpuName)) { return $Map[$GpuName] }
    foreach ($k in $Map.Keys) {
        if ($k -and ($GpuName -like "*$k*" -or $k -like "*$GpuName*")) { return $Map[$k] }
    }
    return $null
}

function Get-PowerState {
    try {
        $b = Get-CimInstance Win32_Battery -ErrorAction Stop
        if (-not $b) {
            return [pscustomobject]@{ HasBattery=$false; OnAC=$true; Percent=$null; StatusCode=$null; StatusText='Desktop / no battery' }
        }
        $b = $b | Select-Object -First 1
        $acCodes = @(2,3,6,7,8,9,11)
        $onAc = $acCodes -contains [int]$b.BatteryStatus
        $text = switch ([int]$b.BatteryStatus) {
            1{'Discharging'}2{'On AC'}3{'Fully charged'}4{'Low'}5{'Critical'}
            6{'Charging'}7{'Charging (High)'}8{'Charging (Low)'}9{'Charging (Critical)'}
            11{'Partially charged'} default{"Unknown ($($b.BatteryStatus))"}
        }
        return [pscustomobject]@{ HasBattery=$true; OnAC=$onAc; Percent=$b.EstimatedChargeRemaining; StatusCode=$b.BatteryStatus; StatusText=$text }
    } catch {
        return [pscustomobject]@{ HasBattery=$false; OnAC=$true; Percent=$null; StatusCode=$null; StatusText='Unknown' }
    }
}

function Get-BatteryHealth {
    $r = [ordered]@{ DesignCapacity=$null; FullCharge=$null; HealthPercent=$null; CycleCount=$null; Manufacture=$null; Chemistry=$null }
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
            {$_ -ge 533320} { return '4.8.1+' } {$_ -ge 528040} { return '4.8' }
            {$_ -ge 461808} { return '4.7.2' }  {$_ -ge 460798} { return '4.7' }
            {$_ -ge 394802} { return '4.6.2' }  {$_ -ge 393295} { return '4.6' }
            {$_ -ge 379893} { return '4.5.2' }  {$_ -ge 378758} { return '4.5.1' }
            {$_ -ge 378389} { return '4.5' }    default { return "Unknown ($rel)" }
        }
    } catch { return 'Not found' }
}

function Compare-NetVersion {
    param([string]$Have,[string]$Need)
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
    param([string]$Id,[string]$Software,[string]$Problem,[string]$Detected,
          [string]$WhyItMatters,[string]$Recommendation,[string]$Optional='',
          [string]$Severity='warn',[double]$RecoverableGB=0)
    [pscustomobject]@{
        Id=$Id; Software=$Software; Problem=$Problem; Detected=$Detected
        WhyItMatters=$WhyItMatters; Recommendation=$Recommendation
        Optional=$Optional; Severity=$Severity; RecoverableGB=$RecoverableGB
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
            [pscustomobject]@{ Pid=$t.Key; Process=$pname; GPU=[math]::Round($t.Value,1) }
        }
        return @($out)
    } catch { Add-Diagnostic 'GPU' "Live GPU sample failed: $_"; return @() }
}

# =============================================================================
# BASELINE
# =============================================================================
Write-Host "[INFO] Baseline: $(Get-Date) on $env:COMPUTERNAME as $env:USERDOMAIN\$env:USERNAME" -ForegroundColor DarkGray

# =============================================================================
# MASTER CATALOG
# =============================================================================
Write-Stage "Loading master catalog..."
$Script:RawCatalog = @(
    @{N='AutoCAD';              D=@('Civil','BIM','AEC','Mechanical');  P=@('AutoCAD 20*','AutoCAD LT 20*','Autodesk AutoCAD*'); K='CAD';         RAM=8;  Disk=20;  GPU=$true;  Net='4.8'; VCPP=$true; DX='11'; Lic='Node'}
    @{N='Civil 3D';             D=@('Civil');                            P=@('Autodesk Civil 3D*');                                 K='Civil';      RAM=16; Disk=30;  GPU=$true;  Net='4.8'; VCPP=$true; DX='11'; Lic='Node'}
    @{N='Revit';                D=@('BIM','AEC','Structural','MEP');     P=@('Autodesk Revit*');                                    K='BIM';        RAM=16; Disk=30;  GPU=$true;  Net='4.8'; VCPP=$true; DX='11'; Lic='Node'}
    @{N='Navisworks';           D=@('BIM','AEC');                        P=@('Autodesk Navisworks*');                               K='BIM';        RAM=16; Disk=20;  GPU=$true;  Net='4.8'; VCPP=$true; DX='11'; Lic='Node'}
    @{N='Archicad';             D=@('BIM','AEC');                        P=@('Archicad*','GRAPHISOFT Archicad*');                   K='BIM';        RAM=16; Disk=25;  GPU=$true;  Net='4.8'; VCPP=$true; Lic='Node'}
    @{N='BricsCAD';             D=@('Civil','AEC');                      P=@('BricsCAD*');                                          K='CAD';        RAM=8;  Disk=15;  GPU=$true;  Net='4.8'; Lic='Node'}
    @{N='Rhino';                D=@('AEC','Marine','Industrial');        P=@('Rhinoceros*','Rhino 7*','Rhino 8*');                  K='CAD';        RAM=8;  Disk=10;  GPU=$true;  Net='4.8'; Lic='Node'}
    @{N='Grasshopper';          D=@('AEC','Computational Design');       P=@('Grasshopper*');                                       K='Plugin';     RAM=8;  Disk=5}
    @{N='Dynamo';               D=@('BIM','AEC');                        P=@('Dynamo*');                                            K='Plugin';     RAM=8;  Disk=5}
    @{N='Bluebeam Revu';        D=@('AEC','Project Mgmt');               P=@('Bluebeam Revu*');                                     K='Docs';       RAM=4;  Disk=5;   Net='4.8'; Lic='Node'}
    @{N='SAP2000';              D=@('Structural');                       P=@('SAP2000*','CSI SAP2000*');                            K='FEA';        RAM=8;  Disk=20;  Net='4.8'; VCPP=$true; Lic='Sentinel'; Lsvc=@('Sentinel*','*hasplm*'); Lport=@(1947)}
    @{N='ETABS';                D=@('Structural');                       P=@('ETABS*','CSI ETABS*');                                K='FEA';        RAM=8;  Disk=20;  Net='4.8'; VCPP=$true; Lic='Sentinel'; Lsvc=@('Sentinel*','*hasplm*'); Lport=@(1947)}
    @{N='SAFE';                 D=@('Structural');                       P=@('SAFE 20*','SAFE 21*','SAFE 22*','CSI SAFE*');         K='FEA';        RAM=8;  Disk=20;  Net='4.8'; VCPP=$true; Lic='Sentinel'}
    @{N='CSiBridge';            D=@('Structural','Bridges');             P=@('CSiBridge*');                                         K='Bridge';     RAM=8;  Disk=20;  Net='4.8'; Lic='Sentinel'}
    @{N='STAAD.Pro';            D=@('Structural');                       P=@('STAAD.Pro*');                                         K='FEA';        RAM=8;  Disk=20;  Net='4.8'; VCPP=$true; Lic='Bentley'; Lsvc=@('*Bentley*','*SelLic*')}
    @{N='Tekla Structures';     D=@('Structural','Steel','BIM');         P=@('Tekla Structures*');                                  K='BIM/FEA';    RAM=16; Disk=30;  GPU=$true;  Net='4.8'; Lic='FlexLM'; Lsvc=@('*Tekla*'); Lport=@(27000)}
    @{N='Tekla Tedds';          D=@('Structural');                       P=@('Tekla Tedds*');                                       K='Design';     RAM=8;  Disk=10;  Net='4.8'; Lic='FlexLM'}
    @{N='RFEM';                 D=@('Structural');                       P=@('RFEM*','Dlubal RFEM*');                               K='FEA';        RAM=8;  Disk=20;  Net='4.8'; Lic='FlexLM'; Lsvc=@('*Dlubal*'); Lport=@(27000)}
    @{N='RISA-3D';              D=@('Structural');                       P=@('RISA-3D*');                                           K='FEA';        RAM=8;  Disk=15;  Net='4.8'; Lic='Node'}
    @{N='MIDAS Civil';          D=@('Structural','Bridges');             P=@('midas Civil*','MIDAS Civil*');                        K='FEA';        RAM=8;  Disk=20;  Lic='Sentinel'}
    @{N='MIDAS Gen';            D=@('Structural');                       P=@('midas Gen*','MIDAS Gen*');                            K='FEA';        RAM=8;  Disk=20;  Lic='Sentinel'}
    @{N='Robot Structural';     D=@('Structural');                       P=@('Autodesk Robot Structural*');                         K='FEA';        RAM=8;  Disk=20;  Net='4.8'; Lic='Node'}
    @{N='IDEA StatiCa';         D=@('Structural','Steel','Concrete');    P=@('IDEA StatiCa*');                                      K='Design';     RAM=8;  Disk=15;  Net='4.8'; Lic='FlexLM'}
    @{N='SCIA Engineer';        D=@('Structural');                       P=@('SCIA Engineer*');                                     K='FEA';        RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='Advance Steel';        D=@('Steel','Structural');               P=@('Advance Steel*');                                     K='Detailing';  RAM=16; Disk=25;  GPU=$true;  Net='4.8'; Lic='Node'}
    @{N='SOLIDWORKS';           D=@('Mechanical','Aerospace','Automotive','Industrial'); P=@('SOLIDWORKS 20*'); K='CAD'; RAM=16; Disk=30; GPU=$true; Net='4.8'; VCPP=$true; DX='11'; Lic='FlexLM'; Lsvc=@('*SolidWorks*','*SW_D*'); Lport=@(25734)}
    @{N='Autodesk Inventor';    D=@('Mechanical','Industrial');          P=@('Autodesk Inventor*');                                 K='CAD';        RAM=16; Disk=30;  GPU=$true;  Net='4.8'; VCPP=$true; Lic='Node'}
    @{N='CATIA';                D=@('Mechanical','Aerospace','Automotive','Marine'); P=@('CATIA*','Dassault Systemes CATIA*'); K='CAD'; RAM=16; Disk=30; GPU=$true; VCPP=$true; Lic='FlexLM'; Lsvc=@('*DS*','*Flex*'); Lport=@(4085)}
    @{N='Siemens NX';           D=@('Mechanical','Aerospace','Automotive','Manufacturing'); P=@('Siemens NX*','NX 20*'); K='CAD'; RAM=16; Disk=30; GPU=$true; VCPP=$true; Lic='FlexLM'; Lsvc=@('*Siemens*','*lmgrd*'); Lport=@(28000)}
    @{N='PTC Creo';             D=@('Mechanical','Aerospace');           P=@('PTC Creo*','Creo Parametric*');                       K='CAD';        RAM=16; Disk=30;  GPU=$true;  VCPP=$true; Lic='FlexLM'; Lsvc=@('*Creo*','*PTC*'); Lport=@(7788)}
    @{N='Solid Edge';           D=@('Mechanical','Industrial');          P=@('Solid Edge*');                                        K='CAD';        RAM=16; Disk=25;  GPU=$true;  Net='4.8'; Lic='FlexLM'}
    @{N='Fusion 360';           D=@('Mechanical','Industrial','CAM');    P=@('Autodesk Fusion*');                                   K='CAD/CAM';    RAM=8;  Disk=15;  GPU=$true;  Net='4.8'; Lic='Cloud'}
    @{N='Siemens Teamcenter';   D=@('PLM','Mechanical');                 P=@('Teamcenter*');                                        K='PLM';        RAM=16; Disk=30;  VCPP=$true; Lic='FlexLM'}
    @{N='ANSYS';                D=@('Simulation','Mechanical','Aerospace','Nuclear'); P=@('ANSYS*','Ansys*'); K='FEA/CFD'; RAM=32; Disk=60; GPU=$true; VCPP=$true; Lic='FlexLM'; Lsvc=@('*ansys*','*lmgrd*'); Lport=@(1055,2325)}
    @{N='Abaqus';               D=@('Simulation','Materials','Aerospace','Biomedical'); P=@('Abaqus*','SIMULIA Abaqus*'); K='FEA'; RAM=32; Disk=50; VCPP=$true; Lic='FlexLM'; Lsvc=@('*SIMULIA*','*lmgrd*'); Lport=@(27000)}
    @{N='COMSOL Multiphysics';  D=@('Simulation','Multiphysics','Bio','Materials'); P=@('COMSOL*'); K='Multiphysics'; RAM=16; Disk=30; VCPP=$true; Lic='FlexLM'; Lsvc=@('*COMSOL*'); Lport=@(1718,1719)}
    @{N='MSC Nastran';          D=@('Simulation','Aerospace');           P=@('MSC Nastran*','Nastran*');                            K='FEA';        RAM=32; Disk=40;  VCPP=$true; Lic='FlexLM'}
    @{N='Patran';               D=@('Simulation','Aerospace');           P=@('Patran*');                                            K='Pre/Post';   RAM=16; Disk=25;  VCPP=$true}
    @{N='LS-DYNA';              D=@('Simulation','Automotive','Aerospace'); P=@('LS-DYNA*');                                        K='Explicit';   RAM=32; Disk=40;  VCPP=$true; Lic='FlexLM'}
    @{N='Altair HyperWorks';    D=@('Simulation','Automotive');          P=@('Altair HyperWorks*','HyperWorks*');                   K='FEA';        RAM=16; Disk=30;  VCPP=$true; Lic='FlexLM'; Lsvc=@('*Altair*','*lmgrd*')}
    @{N='HyperMesh';            D=@('Simulation','Automotive','Aerospace'); P=@('HyperMesh*');                                      K='Meshing';    RAM=16; Disk=20;  VCPP=$true}
    @{N='Simcenter STAR-CCM+';  D=@('Simulation','CFD','Aerospace','Marine'); P=@('STAR-CCM*','Simcenter STAR-CCM*');               K='CFD';        RAM=32; Disk=60;  VCPP=$true; Lic='FlexLM'; Lsvc=@('*CDLMD*','*lmgrd*')}
    @{N='OpenFOAM';             D=@('Simulation','CFD');                 P=@('OpenFOAM*');                                          K='CFD';        RAM=32; Disk=40;  Lic='None'}
    @{N='ANSYS Fluent';         D=@('Simulation','CFD','Chemical');      P=@('ANSYS Fluent*');                                      K='CFD';        RAM=32; Disk=40;  VCPP=$true}
    @{N='MSC Adams';            D=@('Simulation','Automotive','Robotics'); P=@('MSC Adams*','Adams Car*');                          K='Motion';     RAM=16; Disk=25;  VCPP=$true; Lic='FlexLM'}
    @{N='Simulink';             D=@('Simulation','Control','Automotive','Aerospace','Robotics'); P=@('Simulink*','MATLAB*'); K='MBD'; RAM=8; Disk=20; Net='4.8'; Lic='FlexLM'; Lsvc=@('*MATLAB*','*lmgrd*'); Lport=@(27000)}
    @{N='MATLAB';               D=@('Simulation','Math','Robotics','Control','Bio','Materials'); P=@('MATLAB R20*','MATLAB*'); K='Math'; RAM=8; Disk=20; Net='4.8'; Lic='FlexLM'; Lsvc=@('*MATLAB*'); Lport=@(27000)}
    @{N='Wolfram Mathematica';  D=@('Math','Materials');                 P=@('Wolfram Mathematica*','Mathematica*');                K='Math';       RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Maple';                D=@('Math');                             P=@('Maple 20*','Maple*');                                 K='Math';       RAM=8;  Disk=10;  Lic='FlexLM'}
    @{N='Mathcad Prime';        D=@('Math','Structural');                P=@('Mathcad Prime*','PTC Mathcad*');                      K='Math';       RAM=8;  Disk=10;  Net='4.8'; Lic='FlexLM'}
    @{N='Python';               D=@('Math','Data','Engineering');        P=@('Python 3*','Python 3.*');                             K='Lang';       RAM=2;  Disk=2;   Lic='None'}
    @{N='Anaconda';             D=@('Math','Data');                      P=@('Anaconda*','Miniconda*');                             K='Distro';     RAM=2;  Disk=5;   Lic='None'}
    @{N='Jupyter';              D=@('Math','Data');                      P=@('Jupyter*');                                           K='Notebook';   RAM=2;  Disk=2}
    @{N='R';                    D=@('Math','Data');                      P=@('R for Windows*','R 4.*');                             K='Stats';      RAM=4;  Disk=3}
    @{N='OriginPro';            D=@('Math','Data','Materials');          P=@('OriginPro*','OriginLab*');                            K='Plot';       RAM=4;  Disk=5;   Lic='Node'}
    @{N='Altium Designer';      D=@('Electronics','PCB','Electrical');   P=@('Altium Designer*');                                   K='PCB';        RAM=16; Disk=25;  GPU=$true;  Net='4.8'; Lic='FlexLM/Cloud'; Lsvc=@('*Altium*'); Lport=@(27000)}
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
    @{N='ETAP';                 D=@('Electrical Power');                 P=@('ETAP*');                                              K='Power';      RAM=16; Disk=25;  Net='4.8'; Lic='Sentinel'; Lsvc=@('*ETAP*','Sentinel*'); Lport=@(1947)}
    @{N='SKM PowerTools';       D=@('Electrical Power');                 P=@('SKM Power*','PowerTools*');                           K='Power';      RAM=8;  Disk=15;  Lic='Sentinel'}
    @{N='EasyPower';            D=@('Electrical Power');                 P=@('EasyPower*');                                         K='Power';      RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='DIgSILENT PowerFactory';D=@('Electrical Power');                P=@('PowerFactory*','DIgSILENT*');                         K='Power';      RAM=16; Disk=20;  Lic='FlexLM'; Lsvc=@('*DIgSILENT*')}
    @{N='PSS/E';                D=@('Electrical Power');                 P=@('PSS*E*','PSSE*');                                     K='Power';      RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='PSCAD';                D=@('Electrical Power');                 P=@('PSCAD*');                                             K='Power';      RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='EPLAN Electric P8';    D=@('Electrical','Automation');          P=@('EPLAN*');                                             K='ECAD';       RAM=16; Disk=25;  Net='4.8'; Lic='FlexLM'; Lsvc=@('*EPLAN*','*lmgrd*')}
    @{N='AutoCAD Electrical';   D=@('Electrical','Automation');          P=@('AutoCAD Electrical*');                                K='ECAD';       RAM=8;  Disk=20;  GPU=$true;  Net='4.8'; Lic='Node'}
    @{N='SOLIDWORKS Electrical';D=@('Electrical','Mechanical');          P=@('SOLIDWORKS Electrical*');                             K='ECAD';       RAM=16; Disk=25;  Net='4.8'; Lic='FlexLM'}
    @{N='Siemens TIA Portal';   D=@('Automation','Industrial','Electrical'); P=@('TIA Portal*','SIMATIC*TIA*'); K='PLC'; RAM=16; Disk=40; Net='4.8'; Lic='FlexLM'; Lsvc=@('*Automation License*','*Siemens*','*lmgrd*'); Lport=@(27000)}
    @{N='STEP 7';               D=@('Automation');                       P=@('STEP 7*','SIMATIC STEP 7*');                          K='PLC';        RAM=8;  Disk=25;  Lic='FlexLM'}
    @{N='WinCC';                D=@('Automation','SCADA');               P=@('SIMATIC WinCC*','WinCC*');                            K='SCADA';      RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Rockwell Studio 5000'; D=@('Automation','Industrial');          P=@('Studio 5000*','RSLogix*');                            K='PLC';        RAM=16; Disk=30;  Net='4.8'; Lic='Rockwell'; Lsvc=@('*Rockwell*','*FactoryTalk*')}
    @{N='FactoryTalk View';     D=@('Automation','SCADA');               P=@('FactoryTalk*');                                       K='SCADA';      RAM=8;  Disk=20;  Lic='Rockwell'}
    @{N='CODESYS';              D=@('Automation');                       P=@('CODESYS*');                                           K='PLC';        RAM=8;  Disk=15;  Lic='None'}
    @{N='Beckhoff TwinCAT 3';   D=@('Automation');                       P=@('TwinCAT*');                                           K='PLC';        RAM=8;  Disk=20;  Lic='Node'}
    @{N='Schneider EcoStruxure';D=@('Automation');                       P=@('EcoStruxure*','Schneider*');                          K='PLC';        RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='Mitsubishi GX Works';  D=@('Automation');                       P=@('GX Works*');                                          K='PLC';        RAM=8;  Disk=15;  Lic='Node'}
    @{N='Omron Sysmac Studio';  D=@('Automation');                       P=@('Sysmac Studio*');                                     K='PLC';        RAM=8;  Disk=15;  Lic='Node'}
    @{N='AVEVA System Platform';D=@('Automation','SCADA');               P=@('AVEVA*','Wonderware*');                               K='SCADA';      RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Ignition';             D=@('Automation','SCADA');               P=@('Ignition*','Inductive Automation*');                  K='SCADA';      RAM=8;  Disk=10;  Lic='Cloud/Node'}
    @{N='NI LabVIEW';           D=@('Automation','Instrumentation','Electrical','Telecom','Bio'); P=@('LabVIEW*','NI LabVIEW*'); K='Instrument'; RAM=8; Disk=20; Net='4.8'; Lic='FlexLM'; Lsvc=@('*NI*','*National Instruments*')}
    @{N='Factory I/O';          D=@('Automation');                       P=@('Factory IO*','Factory I/O*');                         K='Sim';        RAM=8;  Disk=5;   GPU=$true}
    @{N='Xilinx Vivado';        D=@('Embedded','Electronics','Computer'); P=@('Xilinx Vivado*','Vivado*');                          K='FPGA';       RAM=16; Disk=60;  Lic='FlexLM'}
    @{N='Intel Quartus Prime';  D=@('Embedded','Electronics','Computer'); P=@('Quartus*');                                          K='FPGA';       RAM=16; Disk=50;  Lic='FlexLM'}
    @{N='ModelSim';             D=@('Embedded','Computer');              P=@('ModelSim*','Questa*');                                K='HDL Sim';    RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='STM32CubeIDE';         D=@('Embedded','Robotics');              P=@('STM32CubeIDE*','STM32Cube*');                         K='Embedded';   RAM=8;  Disk=15;  Lic='None'}
    @{N='MPLAB X';              D=@('Embedded');                         P=@('MPLAB X*');                                           K='Embedded';   RAM=4;  Disk=10;  Lic='None'}
    @{N='Keil uVision';         D=@('Embedded');                         P=@('Keil*','uVision*');                                   K='Embedded';   RAM=4;  Disk=10;  Lic='Node'}
    @{N='IAR Embedded Workbench';D=@('Embedded');                        P=@('IAR Embedded*');                                      K='Embedded';   RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Arduino IDE';          D=@('Embedded','Robotics');              P=@('Arduino IDE*','Arduino*');                            K='Embedded';   RAM=2;  Disk=5;   Lic='None'}
    @{N='PlatformIO';           D=@('Embedded');                         P=@('PlatformIO*');                                        K='Embedded';   RAM=4;  Disk=5;   Lic='None'}
    @{N='Visual Studio';        D=@('Computer','Data');                  P=@('Microsoft Visual Studio*20*');                        K='IDE';        RAM=8;  Disk=30;  Net='4.8'; Lic='Node'}
    @{N='Visual Studio Code';   D=@('Computer','Data');                  P=@('Microsoft Visual Studio Code*');                      K='IDE';        RAM=4;  Disk=5;   Lic='None'}
    @{N='Docker Desktop';       D=@('Computer');                         P=@('Docker Desktop*');                                    K='Containers'; RAM=8;  Disk=20;  Lic='Node'}
    @{N='Git';                  D=@('Computer','Data');                  P=@('Git version*');                                       K='VCS';        RAM=1;  Disk=2;   Lic='None'}
    @{N='Wireshark';            D=@('Computer','Telecom');               P=@('Wireshark*');                                         K='Net tool';   RAM=4;  Disk=5;   Lic='None'}
    @{N='Keysight ADS';         D=@('RF','Telecom','Electronics');       P=@('Keysight ADS*','ADS 20*','Advanced Design System*');  K='RF Sim';     RAM=16; Disk=40;  Lic='FlexLM'; Lsvc=@('*Keysight*','*Agilent*','*lmgrd*'); Lport=@(27000)}
    @{N='ANSYS HFSS';           D=@('RF','Telecom','Aerospace');         P=@('ANSYS HFSS*','HFSS*');                                K='EM';         RAM=32; Disk=50;  Lic='FlexLM'}
    @{N='CST Studio Suite';     D=@('RF','Telecom');                     P=@('CST Studio*','CST*');                                 K='EM';         RAM=32; Disk=40;  Lic='FlexLM'}
    @{N='AWR Microwave Office'; D=@('RF');                               P=@('AWR*','Microwave Office*');                           K='RF Sim';     RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='FEKO';                 D=@('RF','Aerospace');                   P=@('FEKO*','Altair FEKO*');                               K='EM';         RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Sonnet Suites';        D=@('RF');                               P=@('Sonnet*');                                            K='EM';         RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='GNU Radio';            D=@('Telecom','RF');                     P=@('GNU Radio*');                                         K='SDR';        RAM=4;  Disk=5;   Lic='None'}
    @{N='Cisco Packet Tracer';  D=@('Telecom','Computer');               P=@('Cisco Packet Tracer*');                               K='Net sim';    RAM=4;  Disk=5;   Lic='Node'}
    @{N='Atoll';                D=@('Telecom');                          P=@('Atoll*');                                             K='RAN';        RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='NS-3';                 D=@('Telecom','Computer');               P=@('ns-3*');                                              K='Net sim';    RAM=4;  Disk=5;   Lic='None'}
    @{N='Aspen Plus';           D=@('Chemical','Process');               P=@('Aspen Plus*');                                        K='Process';    RAM=16; Disk=30;  Net='4.8'; Lic='FlexLM'; Lsvc=@('*Aspen*','*lmgrd*','*SLM*'); Lport=@(27000)}
    @{N='Aspen HYSYS';          D=@('Chemical','Petroleum');             P=@('Aspen HYSYS*');                                       K='Process';    RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='CHEMCAD';              D=@('Chemical');                         P=@('CHEMCAD*');                                           K='Process';    RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='ProMax';               D=@('Chemical','Petroleum');             P=@('ProMax*','BR&E ProMax*');                             K='Process';    RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='DWSIM';                D=@('Chemical');                         P=@('DWSIM*');                                             K='Process';    RAM=4;  Disk=5;   Lic='None'}
    @{N='gPROMS';               D=@('Chemical','Process');               P=@('gPROMS*');                                            K='Process';    RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='OLGA';                 D=@('Petroleum','Chemical');             P=@('OLGA*');                                              K='Flow';       RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='Pipesim';              D=@('Petroleum','Chemical');             P=@('Pipesim*','PIPESIM*');                                K='Flow';       RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='HTRI Xchanger Suite';  D=@('Chemical','Process');               P=@('HTRI*');                                              K='HX design';  RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Petrel';               D=@('Petroleum','Geology');              P=@('Petrel*','Schlumberger Petrel*');                     K='Reservoir';  RAM=32; Disk=50;  GPU=$true;  Lic='FlexLM'; Lsvc=@('*SLB*','*Schlumberger*','*lmgrd*')}
    @{N='Eclipse';              D=@('Petroleum');                        P=@('Eclipse*','Schlumberger Eclipse*');                   K='Reservoir';  RAM=16; Disk=40;  Lic='FlexLM'}
    @{N='CMG GEM';              D=@('Petroleum');                        P=@('CMG*','GEM*');                                        K='Reservoir';  RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Techlog';              D=@('Petroleum','Geology');              P=@('Techlog*');                                           K='Well log';   RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Kingdom';              D=@('Petroleum','Geology');              P=@('Kingdom*','SMT Kingdom*');                            K='Seismic';    RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Deswik';               D=@('Mining');                           P=@('Deswik*');                                            K='Mine plan';  RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Maptek Vulcan';        D=@('Mining','Geology');                 P=@('Maptek Vulcan*','Vulcan*');                           K='Mine';       RAM=16; Disk=30;  Lic='FlexLM'; Lsvc=@('*Maptek*')}
    @{N='Surpac';               D=@('Mining','Geology');                 P=@('Surpac*','Geovia Surpac*');                           K='Mine';       RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Datamine Studio';      D=@('Mining');                           P=@('Datamine*');                                          K='Mine';       RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Micromine';            D=@('Mining','Geology');                 P=@('Micromine*');                                         K='Mine';       RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Leapfrog Geo';         D=@('Mining','Geology','Geotech');       P=@('Leapfrog*');                                          K='Geo model';  RAM=16; Disk=30;  GPU=$true;  Lic='FlexLM'}
    @{N='PLAXIS 2D';            D=@('Geotech','Civil');                  P=@('PLAXIS 2D*');                                         K='Geo FEA';    RAM=8;  Disk=20;  Lic='FlexLM'; Lsvc=@('*Bentley*','*PLAXIS*')}
    @{N='PLAXIS 3D';            D=@('Geotech','Civil');                  P=@('PLAXIS 3D*');                                         K='Geo FEA';    RAM=16; Disk=25;  Lic='FlexLM'}
    @{N='GeoStudio';            D=@('Geotech','Civil','Mining');         P=@('GeoStudio*','GEO-SLOPE*');                            K='Geo';        RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Rocscience RS2';       D=@('Geotech','Mining');                 P=@('RS2*','Rocscience RS2*');                             K='Geo FEA';    RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Rocscience RS3';       D=@('Geotech','Mining');                 P=@('RS3*','Rocscience RS3*');                             K='Geo FEA';    RAM=16; Disk=20;  Lic='FlexLM'}
    @{N='Slide2';               D=@('Geotech','Mining');                 P=@('Slide2*','Slide 2*');                                 K='Slope';      RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='FLAC3D';               D=@('Geotech','Mining');                 P=@('FLAC3D*');                                            K='Geo FEA';    RAM=16; Disk=25;  Lic='FlexLM'}
    @{N='GEO5';                 D=@('Geotech','Civil');                  P=@('GEO5*');                                              K='Geo';        RAM=4;  Disk=10;  Lic='Node'}
    @{N='gINT';                 D=@('Geotech');                          P=@('gINT*');                                              K='Boring log'; RAM=4;  Disk=10;  Lic='FlexLM'}
    @{N='HEC-RAS';              D=@('Water','Civil','Environmental');    P=@('HEC-RAS*');                                           K='Hydraulics'; RAM=8;  Disk=15;  Lic='None'}
    @{N='HEC-HMS';              D=@('Water','Civil','Environmental');    P=@('HEC-HMS*');                                           K='Hydrology';  RAM=8;  Disk=10;  Lic='None'}
    @{N='EPA SWMM';             D=@('Water','Environmental');            P=@('EPA SWMM*','SWMM*');                                  K='Stormwater'; RAM=4;  Disk=5;   Lic='None'}
    @{N='EPANET';               D=@('Water','Environmental');            P=@('EPANET*');                                            K='Water net';  RAM=4;  Disk=5;   Lic='None'}
    @{N='WaterGEMS';            D=@('Water','Civil');                    P=@('WaterGEMS*');                                         K='Water net';  RAM=8;  Disk=20;  Lic='Bentley'; Lsvc=@('*Bentley*','*SelectServer*')}
    @{N='SewerGEMS';            D=@('Water','Civil');                    P=@('SewerGEMS*');                                         K='Sewer';      RAM=8;  Disk=20;  Lic='Bentley'}
    @{N='InfoWorks ICM';        D=@('Water','Civil');                    P=@('InfoWorks*');                                         K='Hydraulic';  RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='MIKE+';                D=@('Water','Civil');                    P=@('MIKE+*','DHI MIKE*');                                 K='Hydraulic';  RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='MODFLOW';              D=@('Water','Geology');                  P=@('MODFLOW*','Visual MODFLOW*');                         K='GW';         RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='AERMOD';               D=@('Environmental');                    P=@('AERMOD*','AERMOD View*');                             K='Air';        RAM=4;  Disk=10;  Lic='None'}
    @{N='CALPUFF';              D=@('Environmental');                    P=@('CALPUFF*');                                           K='Air';        RAM=4;  Disk=10;  Lic='None'}
    @{N='ArcGIS Pro';           D=@('GIS','Geomatics','Environmental','Civil'); P=@('ArcGIS Pro*');                                 K='GIS';        RAM=16; Disk=30;  GPU=$true;  Net='4.8'; Lic='FlexLM/Cloud'; Lsvc=@('*ArcGIS*','*ESRI*','*lmgrd*'); Lport=@(27000)}
    @{N='ArcGIS Desktop';       D=@('GIS');                              P=@('ArcGIS Desktop*','ArcMap*','ArcGIS 10*');             K='GIS';        RAM=8;  Disk=25;  Net='4.8'; Lic='FlexLM'}
    @{N='QGIS';                 D=@('GIS','Geomatics','Environmental');  P=@('QGIS*');                                              K='GIS';        RAM=8;  Disk=10;  Lic='None'}
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
    @{N='Mastercam';            D=@('Manufacturing','CAM');              P=@('Mastercam*');                                         K='CAM';        RAM=16; Disk=25;  GPU=$true;  Net='4.8'; Lic='FlexLM/Node'; Lsvc=@('*Mastercam*','*Sentinel*')}
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
    'Surveying'       = @('Trimble Business Center','Leica Infinity','Carlson Survey','Civil 3D','Autodesk ReCap')
    'PLM'             = @('Siemens Teamcenter','SOLIDWORKS','CATIA','Siemens NX','PTC Creo')
    'CFD'             = @('ANSYS Fluent','Simcenter STAR-CCM+','OpenFOAM','COMSOL Multiphysics','ANSYS')
    'FEA'             = @('ANSYS','Abaqus','MSC Nastran','LS-DYNA','Altair HyperWorks','COMSOL Multiphysics')
    'CAD'             = @('AutoCAD','SOLIDWORKS','Autodesk Inventor','CATIA','Siemens NX','PTC Creo','Solid Edge','BricsCAD','Fusion 360','Rhino')
}
Write-Ok

# =============================================================================
# REQUIREMENTS TABLE (curated per-app)
# =============================================================================
Write-Stage "Loading requirement grids..."
$Script:Requirements = @{
    'AutoCAD' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=4000 }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=10; Rec=20; SSD=$true }
        @{ Type='GPU';      MinVRAM=1; RecVRAM=2; MinDirectX='11' }
        @{ Type='Display';  MinWidth=1920; MinHeight=1080 }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='Admin';    Required=$true }
    )
    'Revit' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=6000 }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=40; SSD=$true }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='Display';  MinWidth=1920; MinHeight=1080 }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'Civil 3D' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=5000 }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=40; SSD=$true }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'Navisworks' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=5000 }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=40; SSD=$true }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'Archicad' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=6000 }
        @{ Type='RAM';      Min=16; Rec=24 }
        @{ Type='Disk';     Min=20; Rec=30 }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'BricsCAD' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=10; Rec=20 }
        @{ Type='GPU';      MinVRAM=1; RecVRAM=2; MinDirectX='11' }
        @{ Type='NetFx';    Min='4.8' }
    )
    'Rhino' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=5;  Rec=10 }
        @{ Type='GPU';      MinVRAM=1; RecVRAM=2; MinDirectX='11' }
        @{ Type='NetFx';    Min='4.8' }
    )
    'SOLIDWORKS' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=6000 }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=60; SSD=$true }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='Display';  MinWidth=1920; MinHeight=1080 }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*SolidWorks*'; Ports=@(25734) }
    )
    'Autodesk Inventor' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=6000 }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=40; SSD=$true }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'CATIA' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=6000 }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=60 }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*DS*'; Ports=@(4085) }
    )
    'Siemens NX' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=6000 }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=60 }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='Java';     Min='8'; Kind='JRE' }
        @{ Type='LicenseSvc'; Pattern='*Siemens*'; Ports=@(28000) }
    )
    'PTC Creo' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=40 }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*Creo*'; Ports=@(7788) }
    )
    'Solid Edge' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=15; Rec=30 }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';    Min='4.8' }
    )
    'Fusion 360' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=10; Rec=20 }
        @{ Type='GPU';      MinVRAM=1; RecVRAM=2; MinDirectX='11' }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'ANSYS' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=12000; InstructionSets=@('AVX2') }
        @{ Type='RAM';      Min=16; Rec=64 }
        @{ Type='Disk';     Min=60; Rec=200; SSD=$true }
        @{ Type='GPU';      MinVRAM=4; RecVRAM=12; MinDirectX='11' }
        @{ Type='Display';  MinWidth=1920; MinHeight=1080 }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*ansys*'; Ports=@(1055,2325) }
    )
    'Abaqus' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=12000; InstructionSets=@('AVX2') }
        @{ Type='RAM';      Min=16; Rec=64 }
        @{ Type='Disk';     Min=50; Rec=150; SSD=$true }
        @{ Type='GPU';      MinVRAM=4; RecVRAM=11; MinDirectX='11' }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*SIMULIA*'; Ports=@(27000) }
    )
    'COMSOL Multiphysics' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=10000 }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=30; Rec=80 }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=8; MinDirectX='11' }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*COMSOL*'; Ports=@(1718,1719) }
    )
    'MSC Nastran' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=32; Rec=64 }
        @{ Type='Disk';     Min=40; Rec=120 }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'LS-DYNA' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=32; Rec=64 }
        @{ Type='Disk';     Min=40; Rec=120 }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'Simcenter STAR-CCM+' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=32; Rec=64 }
        @{ Type='Disk';     Min=60; Rec=200; SSD=$true }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='Java';     Min='11'; Kind='JRE' }
        @{ Type='LicenseSvc'; Pattern='*CDLMD*'; Ports=@() }
    )
    'OpenFOAM' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=64 }
        @{ Type='Disk';     Min=40; Rec=150; SSD=$true }
    )
    'ANSYS Fluent' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=32; Rec=64 }
        @{ Type='Disk';     Min=40; Rec=120 }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'Altair HyperWorks' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=30; Rec=80 }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*Altair*'; Ports=@() }
    )
    'MATLAB' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=4000 }
        @{ Type='RAM';      Min=4;  Rec=16 }
        @{ Type='Disk';     Min=5;  Rec=20; SSD=$true }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='Java';     Min='8'; Kind='JRE' }
        @{ Type='LicenseSvc'; Pattern='*MATLAB*'; Ports=@(27000) }
    )
    'Simulink' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=10; Rec=20 }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='LicenseSvc'; Pattern='*MATLAB*'; Ports=@(27000) }
    )
    'Python' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=2;  Rec=4 }
        @{ Type='Disk';     Min=1;  Rec=2 }
    )
    'Anaconda' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=4;  Rec=8 }
        @{ Type='Disk';     Min=4;  Rec=10 }
    )
    'Wolfram Mathematica' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=4;  Rec=16 }
        @{ Type='Disk';     Min=8;  Rec=20 }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'Altium Designer' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=15; Rec=30 }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*Altium*'; Ports=@(27000) }
    )
    'KiCad' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=4;  Rec=8 }
        @{ Type='Disk';     Min=5;  Rec=10 }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'LTspice' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=2;  Rec=4 }
        @{ Type='Disk';     Min=1;  Rec=2 }
        @{ Type='NetFx';    Min='4.8' }
    )
    'Xilinx Vivado' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=60; Rec=150 }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='Java';     Min='8'; Kind='JRE' }
        @{ Type='Python';   Min='3.8' }
        @{ Type='LicenseSvc'; Pattern='*Xilinx*'; Ports=@() }
    )
    'Intel Quartus Prime' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=50; Rec=120 }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'Siemens TIA Portal' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=40; Rec=80 }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='LicenseSvc'; Pattern='*Automation License*'; Ports=@(27000) }
    )
    'Rockwell Studio 5000' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=30; Rec=60 }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='LicenseSvc'; Pattern='*Rockwell*'; Ports=@() }
    )
    'NI LabVIEW' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=20; Rec=40 }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='LicenseSvc'; Pattern='*National Instruments*'; Ports=@() }
    )
    'Aspen Plus' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=20; Rec=40 }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='LicenseSvc'; Pattern='*Aspen*'; Ports=@(27000) }
    )
    'Petrel' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=30; Rec=80; SSD=$true }
        @{ Type='GPU';      MinVRAM=4; RecVRAM=8; MinDirectX='11' }
        @{ Type='LicenseSvc'; Pattern='*Schlumberger*'; Ports=@() }
    )
    'ArcGIS Pro' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=6000 }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=40; SSD=$true }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='WebView2' }
        @{ Type='LicenseSvc'; Pattern='*ArcGIS*'; Ports=@(27000) }
    )
    'QGIS' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=4;  Rec=8 }
        @{ Type='Disk';     Min=5;  Rec=10 }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'Pix4Dmapper' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=50; SSD=$true }
        @{ Type='GPU';      MinVRAM=4; RecVRAM=6; MinDirectX='11' }
        @{ Type='LicenseSvc'; Pattern='*Pix4D*'; Ports=@() }
    )
    'Agisoft Metashape' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=50; SSD=$true }
        @{ Type='GPU';      MinVRAM=4; RecVRAM=6; MinDirectX='11' }
    )
    'CloudCompare' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=5;  Rec=10 }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
    )
    'Leica Cyclone' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=30; Rec=80; SSD=$true }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='LicenseSvc'; Pattern='*Leica*'; Ports=@() }
    )
    'Revit MEP' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=40; SSD=$true }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';    Min='4.8' }
    )
    'EnergyPlus' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=4;  Rec=16 }
        @{ Type='Disk';     Min=5;  Rec=15 }
    )
    'DIALux evo' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=10; Rec=20; SSD=$true }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
    )
    'PyroSim' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=10; Rec=30; SSD=$true }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='LicenseSvc'; Pattern='*PyroSim*'; Ports=@() }
    )
    'FDS' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=8;  Rec=32 }
        @{ Type='Disk';     Min=10; Rec=30 }
    )
    'ImageJ' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=2;  Rec=4 }
        @{ Type='Disk';     Min=2;  Rec=5 }
        @{ Type='Java';     Min='8'; Kind='JRE' }
    )
    '3D Slicer' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=4;  Rec=8 }
        @{ Type='Disk';     Min=5;  Rec=10 }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
    )
    'Thermo-Calc' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=15; Rec=30 }
        @{ Type='LicenseSvc'; Pattern='*Thermo-Calc*'; Ports=@() }
    )
    'PVsyst' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=4;  Rec=8 }
        @{ Type='Disk';     Min=5;  Rec=10 }
        @{ Type='NetFx';    Min='4.8' }
    )
    'Microsoft Project' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=4;  Rec=8 }
        @{ Type='Disk';     Min=5;  Rec=10 }
        @{ Type='NetFx';    Min='4.8' }
    )
    'Primavera P6' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=15; Rec=30 }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='Java';     Min='8'; Kind='JRE' }
        @{ Type='LicenseSvc'; Pattern='*Primavera*'; Ports=@() }
    )
    'Mastercam' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=50; SSD=$true }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='LicenseSvc'; Pattern='*Mastercam*'; Ports=@() }
    )
    'Visual Studio' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=30; Rec=60; SSD=$true }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'Visual Studio Code' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=4;  Rec=8 }
        @{ Type='Disk';     Min=5;  Rec=10 }
        @{ Type='NetFx';    Min='4.8' }
    )
    'Docker Desktop' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=20; Rec=40; SSD=$true }
        @{ Type='WinFeature'; Name='VirtualMachinePlatform' }
        @{ Type='WinFeature'; Name='Microsoft-Windows-Subsystem-Linux' }
    )
    'Git' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=2;  Rec=4 }
        @{ Type='Disk';     Min=2;  Rec=5 }
    )
    'Wireshark' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=4;  Rec=8 }
        @{ Type='Disk';     Min=5;  Rec=10 }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'Keysight ADS' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=40; Rec=80 }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*Keysight*'; Ports=@(27000) }
    )
    'ANSYS HFSS' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=32; Rec=64 }
        @{ Type='Disk';     Min=50; Rec=120 }
        @{ Type='VCRedist'; Min='14.30' }
    )
    'CST Studio Suite' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=32; Rec=64 }
        @{ Type='Disk';     Min=40; Rec=120 }
    )
    'Mimics Innovation Suite' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=50; SSD=$true }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='LicenseSvc'; Pattern='*Mimics*'; Ports=@() }
    )
    'Siemens Teamcenter' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=30; Rec=60; SSD=$true }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*Teamcenter*'; Ports=@(28000) }
    )
    'Advance Steel' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=40; SSD=$true }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';    Min='4.8' }
    )
    'SAP2000' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=3000 }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=10; Rec=30 }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='Sentinel*'; Ports=@(1947) }
    )
    'ETABS' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='CPU';      MinCores=4; MinPassMark=3000 }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=10; Rec=30 }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='Sentinel*'; Ports=@(1947) }
    )
    'STAAD.Pro' = @(
        @{ Type='OS';       MinVersion='10.0.17763'; Arch='x64' }
        @{ Type='RAM';      Min=8;  Rec=16 }
        @{ Type='Disk';     Min=10; Rec=30 }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='VCRedist'; Min='14.30' }
        @{ Type='LicenseSvc'; Pattern='*Bentley*'; Ports=@() }
    )
    'Tekla Structures' = @(
        @{ Type='OS';       MinVersion='10.0.19041'; Arch='x64' }
        @{ Type='RAM';      Min=16; Rec=32 }
        @{ Type='Disk';     Min=20; Rec=50 }
        @{ Type='GPU';      MinVRAM=2; RecVRAM=4; MinDirectX='11' }
        @{ Type='NetFx';    Min='4.8' }
        @{ Type='LicenseSvc'; Pattern='*Tekla*'; Ports=@(27000) }
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
        [pscustomobject]@{
            Name = $g.Name; Kind = Get-GpuKind -Name $g.Name
            DriverVersion = $g.DriverVersion
            DriverDate = if ($g.DriverDate) { ([datetime]$g.DriverDate).ToString('yyyy-MM-dd') } else { '' }
            VRAM_GB = $finalVram; Resolution = $res
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
    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        User = "$env:USERDOMAIN\$env:USERNAME"
        OS = "$($os.Caption) ($($os.Version), Build $($os.BuildNumber))"
        OSBuild = "$($os.Version).$($os.BuildNumber)"
        OSVersion = $os.Version
        OSBuildNumber = $os.BuildNumber
        Arch = $os.OSArchitecture
        CPU = $cpu.Name
        Cores = $cpu.NumberOfCores
        LogicalCPUs = $cpu.NumberOfLogicalProcessors
        ClockMHz = $cpu.MaxClockSpeed
        RAM_GB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        FreeRAM_GB = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
        GPUs = $gpuInfo
        HasDiscreteGPU = @($gpuInfo | Where-Object Kind -eq 'Discrete').Count -gt 0
        Disks = $disks
        Power = Get-PowerState
        IsAdmin = (Test-IsAdmin)
    }
}
Write-Ok

Write-Stage "Checking prerequisites..."
$netFx = Get-DotNetFrameworkVersion
$vc    = @(Get-VCRedist)
Write-Ok

# =============================================================================
# ONLINE ENRICHMENT
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
    param([string]$Key,[scriptblock]$Fetch,[int]$TtlHours=24)
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
    param([string]$Url,[int]$TimeoutSec=8,[hashtable]$Headers=@{})
    if (-not $Headers.ContainsKey('User-Agent')) {
        $Headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SigmaEngineerToolkit/2.0'
    }
    try {
        return Invoke-WebRequest -Uri $Url -TimeoutSec $TimeoutSec -UseBasicParsing -Headers $Headers -ErrorAction Stop
    } catch { Add-Diagnostic 'Online' "GET $Url failed: $_"; return $null }
}

function Get-CpuPassMarkScore {
    param([string]$CpuName)
    if (-not $CpuName) { return $null }
    $clean = $CpuName -replace '\(R\)','' -replace '\(TM\)','' -replace '\s+CPU\s+@.*$','' `
                      -replace '\s+Processor.*$','' -replace '\s+\d+-Core.*$','' -replace '\s+@.*$','' -replace '\s+',' '
    $clean = $clean.Trim()
    Get-Cached -Key "cpu_passmark_$clean" -TtlHours 168 -Fetch {
        $q = [uri]::EscapeDataString($clean)
        $r = Invoke-SafeWebRequest -Url "https://www.cpubenchmark.net/cpu.php?cpu=$q"
        if ($r) {
            $html = $r.Content
            if ($html -match 'id="mark-neww"[^>]*>\s*([\d,]+)')              { return [int]($matches[1] -replace ',','') }
            if ($html -match 'class="[^"]*mark-neww[^"]*"[^>]*>\s*([\d,]+)') { return [int]($matches[1] -replace ',','') }
        }
        return $null
    }
}

function Get-GpuPassMarkScore {
    param([string]$GpuName)
    if (-not $GpuName) { return $null }
    $clean = ($GpuName -replace '^NVIDIA\s+','' -replace '^AMD\s+','' -replace '^Intel\s+','').Trim()
    Get-Cached -Key "gpu_passmark_$clean" -TtlHours 168 -Fetch {
        $q = [uri]::EscapeDataString($clean)
        $r = Invoke-SafeWebRequest -Url "https://www.videocardbenchmark.net/gpu.php?gpu=$q"
        if ($r) {
            $html = $r.Content
            if ($html -match 'id="mark-neww"[^>]*>\s*([\d,]+)') { return [int]($matches[1] -replace ',','') }
            if ($html -match 'G3D Mark[^<]*<[^>]*>\s*([\d,]+)') { return [int]($matches[1] -replace ',','') }
        }
        return $null
    }
}

function Get-LatestComponentVersion {
    param([string]$Component)
    Get-Cached -Key "latest_comp_$Component" -TtlHours 168 -Fetch {
        switch ($Component) {
            '.NET Framework' {
                $r = Invoke-SafeWebRequest -Url 'https://dotnet.microsoft.com/en-us/download/dotnet-framework'
                if ($r -and $r.Content -match '\.NET Framework (\d+\.\d+(?:\.\d+)?)') { return $matches[1] }
            }
            'VC++ Redistributable' {
                $r = Invoke-SafeWebRequest -Url 'https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist'
                if ($r) {
                    $all = [regex]::Matches($r.Content, 'v14\.(\d+)\.(\d+)\.(\d+)') |
                           ForEach-Object { "14.$($_.Groups[1].Value).$($_.Groups[2].Value).$($_.Groups[3].Value)" }
                    if ($all) { return ($all | Sort-Object { [version]$_ } | Select-Object -Last 1) }
                }
            }
            'Python' {
                $r = Invoke-SafeWebRequest -Url 'https://www.python.org/downloads/'
                if ($r -and $r.Content -match 'Python (\d+\.\d+\.\d+)') { return $matches[1] }
            }
            'Java JRE' {
                $r = Invoke-SafeWebRequest -Url 'https://www.oracle.com/java/technologies/downloads/'
                if ($r -and $r.Content -match 'Java (\d+)') { return $matches[1] }
            }
        }
        return $null
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

function Invoke-OnlineEnrichment {
    param([pscustomobject]$System)
    $enrich = [ordered]@{
        CpuScore = $null; GpuScores = @()
        LatestNetFx = $null; LatestVCRedist = $null
        LatestPython = $null; LatestJava = $null
        DiskMediaTypes = @()
        EnrichedAt = (Get-Date).ToString('s'); OnlineAvailable = $true
    }
    $enrich.DiskMediaTypes = @(Get-DiskMediaTypes)
    if (-not $Script:OnlineEnabled) { $enrich.OnlineAvailable = $false; return [pscustomobject]$enrich }
    Write-Stage "Fetching live online data (PassMark, vendor feeds)..."
    $enrich.CpuScore = Get-CpuPassMarkScore -CpuName $System.CPU
    foreach ($g in $System.GPUs) {
        if ($g.Kind -eq 'Integrated') { continue }
        $score = Get-GpuPassMarkScore -GpuName $g.Name
        $enrich.GpuScores += [pscustomobject]@{ Name = $g.Name; Score = $score }
    }
    $enrich.LatestNetFx    = Get-LatestComponentVersion -Component '.NET Framework'
    $enrich.LatestVCRedist = Get-LatestComponentVersion -Component 'VC++ Redistributable'
    $enrich.LatestPython   = Get-LatestComponentVersion -Component 'Python'
    $enrich.LatestJava     = Get-LatestComponentVersion -Component 'Java JRE'
    if (-not $enrich.CpuScore -and $enrich.GpuScores.Count -eq 0) { $enrich.OnlineAvailable = $false }
    Write-Ok
    return [pscustomobject]$enrich
}

# =============================================================================
# PREFLIGHT / WHY-SLOW DISPATCH
# =============================================================================
function Invoke-Preflight {
    param([string]$ProductName,[array]$Catalog,[pscustomobject]$System,[string]$NetFx,[array]$VC,[array]$Installed,[pscustomobject]$Enrichment)
    Write-Head "PREFLIGHT: $ProductName"
    $entry = $Catalog | Where-Object { $_.N -eq $ProductName } | Select-Object -First 1
    if (-not $entry) { $entry = $Catalog | Where-Object { $_.N -like "*$ProductName*" } | Select-Object -First 1 }
    if (-not $entry) { Write-Host "[ERROR] Product not found: $ProductName" -ForegroundColor Red; return }

    $specs = if ($Script:Requirements.ContainsKey($entry.N)) { @($Script:Requirements[$entry.N]) } else { @() }
    if ($specs.Count -eq 0) { Write-Host "[WARN] No curated requirements; running derived check." -ForegroundColor Yellow }
    foreach ($c in ($specs | ForEach-Object { Test-Requirement -Spec $_ -System $System -Enrichment $Enrichment })) {
        $col = switch ($c.Status) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'Gray' } }
        Write-Host ("    [{0,-7}] {1,-24} need: {2,-30} have: {3}" -f $c.Status, $c.Component, $c.Required, $c.Actual) -ForegroundColor $col
    }
    Write-Host ""
}

function Invoke-WhySlow {
    param([pscustomobject]$System)
    Write-Head "WHY IS MY PC SLOW?"
    $ramPctFree = [math]::Round(($System.FreeRAM_GB / $System.RAM_GB) * 100, 1)
    $critDisk = $System.Disks | Sort-Object FreePct | Select-Object -First 1
    Write-Host "  RAM free            $($System.FreeRAM_GB) GB / $($System.RAM_GB) GB ($ramPctFree%)"
    if ($critDisk) { Write-Host "  Worst disk free     $($critDisk.FreeGB) GB ($($critDisk.FreePct)% on $($critDisk.Drive))" }
    $topMem = Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 5
    Write-Host "  Top memory consumers:"
    foreach ($p in $topMem) { Write-Host ("    {0,-22} {1,6} GB" -f $p.ProcessName, [math]::Round($p.WorkingSet64/1GB,2)) }
    Write-Host ""
}

# =============================================================================
# SOFTWARE INSTALLER
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
    'Revit MEP'           = 'https://www.autodesk.com/products/revit/free-trial'
    'SOLIDWORKS'          = 'https://www.solidworks.com/sw/support/downloads.htm'
    'CATIA'               = 'https://www.3ds.com/products/catia'
    'Abaqus'              = 'https://www.3ds.com/products/simulia/abaqus'
    'Siemens NX'          = 'https://plm.sw.siemens.com/en-US/nx/'
    'Siemens Teamcenter'  = 'https://plm.sw.siemens.com/en-US/teamcenter/'
    'Simcenter STAR-CCM+' = 'https://plm.sw.siemens.com/en-US/simcenter/fluids-thermal-simulation/star-ccm/'
    'Solid Edge'          = 'https://solidedge.siemens.com/'
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
    'OpenFOAM'            = 'https://openfoam.org/download/'
    'Thermo-Calc'         = 'https://thermocalc.com/'
    'Altium Designer'     = 'https://www.altium.com/'
    'Cadence Allegro'     = 'https://www.cadence.com/en_US/home/tools/pcb-design-and-analysis/allegro.html'
    'OrCAD'               = 'https://www.orcad.com/'
    'NI LabVIEW'          = 'https://www.ni.com/en-us/support/downloads/software-products/download.labview.html'
    'NI Multisim'         = 'https://www.ni.com/en-us/support/downloads/software-products/download.multisim.html'
    'Siemens TIA Portal'  = 'https://support.industry.siemens.com/cs/products?dtp=Download&mfn=ps&lc=en-WW'
    'Rockwell Studio 5000'= 'https://www.rockwellautomation.com/en-us/products/software/factorytalk/designsuite/studio-5000.html'
    'Xilinx Vivado'       = 'https://www.xilinx.com/support/download.html'
    'Intel Quartus Prime' = 'https://www.intel.com/content/www/us/en/software-kit/'
    'STM32CubeIDE'        = 'https://www.st.com/en/development-tools/stm32cubeide.html'
    'STAAD.Pro'           = 'https://www.bentley.com/software/staad-pro/'
    'Tekla Structures'    = 'https://www.tekla.com/products/tekla-structures'
    'SAP2000'             = 'https://www.csiamerica.com/products/sap2000'
    'ETABS'               = 'https://www.csiamerica.com/products/etabs'
    'PLAXIS 2D'           = 'https://www.bentley.com/software/plaxis-2d/'
    'PLAXIS 3D'           = 'https://www.bentley.com/software/plaxis-3d/'
    'GeoStudio'           = 'https://www.geoslope.com/'
    'HEC-RAS'             = 'https://www.hec.usace.army.mil/software/hec-ras/downloads.aspx'
    'HEC-HMS'             = 'https://www.hec.usace.army.mil/software/hec-hms/downloads.aspx'
    'EPA SWMM'            = 'https://www.epa.gov/water-research/storm-water-management-model-swmm'
    'EPANET'              = 'https://www.epa.gov/water-research/epanet'
    'WaterGEMS'           = 'https://www.bentley.com/software/watergems/'
    'ArcGIS Pro'          = 'https://www.esri.com/en-us/arcgis/products/arcgis-pro/overview'
    'Agisoft Metashape'   = 'https://www.agisoft.com/downloads/installer/'
    'Pix4Dmapper'         = 'https://www.pix4d.com/product/pix4dmapper-photogrammetry-software'
    'Leica Cyclone'       = 'https://leica-geosystems.com/products/laser-scanners/software/leica-cyclone'
    'Aspen Plus'          = 'https://www.aspentech.com/en/products/engineering/aspen-plus'
    'Petrel'              = 'https://www.software.slb.com/products/petrel'
    'AVEVA Marine'        = 'https://www.aveva.com/en/products/'
    'PyroSim'             = 'https://www.thunderheadeng.com/pyrosim/'
    'FDS'                 = 'https://pages.nist.gov/fds-smv/downloads.html'
    'EnergyPlus'          = 'https://energyplus.net/downloads'
    'DIALux evo'          = 'https://www.dialux.com/en-GB/download'
    'MCNP'                = 'https://mcnp.lanl.gov/'
    'OpenMC'              = 'https://docs.openmc.org/'
    'Mimics Innovation Suite' = 'https://www.materialise.com/en/medical/mimics-innovation-suite'
    'ImageJ'              = 'https://imagej.net/downloads'
    '3D Slicer'           = 'https://download.slicer.org/'
    'Wolfram Mathematica' = 'https://www.wolfram.com/mathematica/'
    'Maple'               = 'https://www.maplesoft.com/products/Maple/'
    'PVsyst'              = 'https://www.pvsyst.com/'
    'WindPRO'             = 'https://www.emdt.co.uk/product/windpro'
    'Microsoft Project'   = 'https://www.microsoft.com/en-us/microsoft-365/project/project-management-software'
    'Primavera P6'        = 'https://www.oracle.com/industries/construction-engineering/primavera-p6/'
    'Mastercam'           = 'https://www.mastercam.com/'
    'Bluebeam Revu'       = 'https://www.bluebeam.com/'
    'Archicad'            = 'https://www.graphisoft.com/archicad/'
    'Rhino'               = 'https://www.rhino3d.com/download/'
    'BricsCAD'            = 'https://www.bricsys.com/en-intl/bricscad/'
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
    param([string]$Name,[bool]$HasWinget,[switch]$NonInteractive)
    $tag = Get-InstallTag -Name $Name
    if ($tag -eq 'winget' -and $HasWinget) {
        $id = $Script:WingetMap[$Name]
        Write-Host "  [INSTALL] $Name via winget ($id)" -ForegroundColor Cyan
        try {
            & winget install --id $id --exact --accept-package-agreements --accept-source-agreements --silent --disable-interactivity
            $code = $LASTEXITCODE
            if ($null -eq $code -or $code -eq 0) { Write-Host "  [ OK ] $Name installed." -ForegroundColor Green; return 'installed' }
            Write-Host "  [FAIL] $Name - exit $code" -ForegroundColor Red; return 'failed'
        } catch { Write-Host "  [FAIL] $Name - $_" -ForegroundColor Red; return 'failed' }
    }
    if ($tag -eq 'winget' -and -not $HasWinget) { Write-Host "  [SKIP] $Name - winget missing." -ForegroundColor Yellow; return 'skipped' }
    if ($tag -eq 'manual') {
        $url = $Script:ManualUrls[$Name]
        Write-Host "  [MANUAL] $Name - vendor page:" -ForegroundColor Yellow
        Write-Host "           $url" -ForegroundColor DarkGray
        if (-not $NonInteractive) {
            $open = Read-Host "  Open the download page? (Y/N)"
            if ($open -match '^[Yy]') { try { Start-Process $url } catch { } }
        }
        return 'manual'
    }
    Write-Host "  [SKIP] $Name - no winget ID, no vendor URL." -ForegroundColor DarkGray
    return 'skipped'
}

function Invoke-Installer {
    param([string[]]$Names,[bool]$HasWinget)
    if (-not $Names -or $Names.Count -eq 0) { Write-Host "  Nothing to install." -ForegroundColor Yellow; return }
    $ok=0;$fail=0;$manual=0;$skipped=0
    foreach ($name in $Names) {
        $entry = $Script:RawCatalog | Where-Object { $_.N -eq $name -or $_.N -like "*$name*" } | Select-Object -First 1
        if (-not $entry) { Write-Host "  [SKIP] Unknown: $name" -ForegroundColor Yellow; $skipped++; continue }
        $res = Install-OneProduct -Name $entry.N -HasWinget $HasWinget
        switch ($res) { 'installed' { $ok++ } 'failed' { $fail++ } 'manual' { $manual++ } 'skipped' { $skipped++ } }
    }
    Write-Host ""
    Write-Host ("  Summary: $ok installed, $fail failed, $manual manual, $skipped skipped.") -ForegroundColor Cyan
}

# -----------------------------------------------------------------------------
# Install from scan - lists EVERY app, verdict is advisory
# -----------------------------------------------------------------------------
function Show-InstallableFromScan {
    param([array]$ScanResults)
    if ($ScanResults.Count -eq 0) {
        Write-Host "  Nothing was scanned yet." -ForegroundColor Yellow
        return
    }
    Write-Head "Install from scan"
    Write-Host "  Any app can be installed. Verdict is shown for information only." -ForegroundColor DarkGray
    Write-Host ""
    for ($i=0; $i -lt $ScanResults.Count; $i++) {
        $r = $ScanResults[$i]
        $tag = Get-InstallTag -Name $r.Product
        $vcol = switch ($r.Verdict) {
            'MEETS'              { 'Green' }
            'MEETS (unverified)' { 'Green' }
            'PARTIALLY MEETS'    { 'Yellow' }
            'DOES NOT MEET'      { 'Red' }
            default              { 'Gray' }
        }
        $tagCol = switch ($tag) { 'winget' { 'Green' } 'manual' { 'Yellow' } default { 'DarkGray' } }
        Write-Host ("    {0,2}. " -f ($i+1)) -NoNewline
        Write-Host ("[{0}]" -f $tag).PadRight(10) -ForegroundColor $tagCol -NoNewline
        Write-Host ("{0,-32}" -f $r.Product) -NoNewline
        Write-Host (" {0}" -f $r.Verdict) -ForegroundColor $vcol -NoNewline
        if ($r.Installed) { Write-Host "  (installed)" -ForegroundColor DarkGray } else { Write-Host "" }
    }
    Write-Host ""
    Write-Host "  0. Cancel"
    $sel = Read-Host "  Numbers (e.g. 1,3,5) or 'all' or 'all-meets'"
    if (-not $sel -or $sel -eq '0') { return }
    $picked = @()
    if ($sel -match '^all$') {
        $picked = $ScanResults | ForEach-Object { $_.Product }
    } elseif ($sel -match '^all-meets$') {
        $picked = $ScanResults | Where-Object { $_.Verdict -in @('MEETS','MEETS (unverified)') } | ForEach-Object { $_.Product }
    } else {
        foreach ($tok in ($sel -split ',')) {
            $n = 0
            if ([int]::TryParse($tok.Trim(),[ref]$n) -and $n -ge 1 -and $n -le $ScanResults.Count) {
                $picked += $ScanResults[$n-1].Product
            }
        }
    }
    if ($picked.Count -eq 0) { Write-Host "  Nothing selected." -ForegroundColor Yellow; return }

    Write-Host ""
    Write-Host "  Install plan:" -ForegroundColor Cyan
    $anyProblem = $false
    foreach ($name in $picked) {
        $r = $ScanResults | Where-Object Product -eq $name | Select-Object -First 1
        $tag = Get-InstallTag -Name $name
        $verdict = if ($r) { $r.Verdict } else { 'not scanned' }
        if ($verdict -notin @('MEETS','MEETS (unverified)')) { $anyProblem = $true }
        $vcol = switch ($verdict) {
            'MEETS'              { 'Green' }
            'MEETS (unverified)' { 'Green' }
            'PARTIALLY MEETS'    { 'Yellow' }
            'DOES NOT MEET'      { 'Red' }
            default              { 'Gray' }
        }
        Write-Host ("    - {0,-32} [{1}] " -f $name, $tag) -NoNewline
        Write-Host $verdict -ForegroundColor $vcol
    }
    if ($anyProblem) {
        Write-Host ""
        Write-Host "  [WARNING] One or more selected apps do not fully meet this PC's requirements." -ForegroundColor Yellow
        Write-Host "            You can still install them; they may run slowly or fail." -ForegroundColor Yellow
    }
    $confirm = Read-Host "  Proceed? (Y/N)"
    if ($confirm -notmatch '^[Yy]') { Write-Host "  Cancelled." -ForegroundColor Yellow; return }
    Invoke-Installer -Names $picked -HasWinget (Test-WingetAvailable)
}

# =============================================================================
# REQUIREMENT DETECTORS
# =============================================================================
function New-ReqResult {
    param([string]$Type,[string]$Component,[string]$Required,[string]$Actual,[string]$Status,[string]$Note)
    [pscustomobject]@{ Type=$Type; Component=$Component; Required=$Required; Actual=$Actual; Status=$Status; Note=$Note }
}

# CORRECT DirectX detection: OS build number is the source of truth.
function Get-DirectXVersion {
    try {
        $build = [int](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).BuildNumber
        if ($build -ge 10240) { return 12 }   # Windows 10 / 11
        if ($build -ge 9200)  { return 11 }   # Windows 8 / 8.1
        if ($build -ge 7601)  { return 11 }   # Windows 7 SP1
        if ($build -ge 7600)  { return 10 }   # Windows 7 RTM
    } catch { }
    if (Test-Path "$env:SystemRoot\System32\d3d12.dll") { return 12 }
    if (Test-Path "$env:SystemRoot\System32\d3d11.dll") { return 11 }
    if (Test-Path "$env:SystemRoot\System32\d3d10.dll") { return 10 }
    if (Test-Path "$env:SystemRoot\System32\d3d9.dll")  { return 9 }
    return $null
}

function Get-CpuInstructionSets {
    $out = @{}
    try { if ([System.Runtime.Intrinsics.X86.Sse42]::IsSupported)   { $out['SSE4.2']  = $true } } catch { }
    try { if ([System.Runtime.Intrinsics.X86.Avx]::IsSupported)     { $out['AVX']     = $true } } catch { }
    try { if ([System.Runtime.Intrinsics.X86.Avx2]::IsSupported)    { $out['AVX2']    = $true } } catch { }
    try { if ([System.Runtime.Intrinsics.X86.Avx512F]::IsSupported) { $out['AVX-512'] = $true } } catch { }
    return $out
}

function Test-ReqOS {
    param([hashtable]$Spec,[pscustomobject]$System)
    $os = Get-CimInstance Win32_OperatingSystem
    $ver = "$($os.Version)"; $arch = $os.OSArchitecture; $ed = $os.Caption
    $req=@(); $fail=$false; $warn=$false
    if ($Spec.MinVersion) { $req += ">= $($Spec.MinVersion)"; try { if ([version]$ver -lt [version]$Spec.MinVersion) { $fail=$true } } catch { $fail=$true } }
    if ($Spec.Arch) {
        $req += $Spec.Arch
        $map = @{ 'x64'='64-bit'; 'x86'='32-bit'; 'ARM64'='ARM 64-bit' }
        $want = $map[$Spec.Arch]
        if ($want -and $arch -ne $want) { $fail=$true }
    }
    $s = if ($fail) { 'FAIL' } elseif ($warn) { 'WARN' } else { 'PASS' }
    $n = if ($fail) { 'OS below minimum' } else { 'Meets OS requirement' }
    New-ReqResult 'OS' 'Operating System' ($req -join ', ') "$ed ($ver, $arch)" $s $n
}

function Test-ReqCPU {
    param([hashtable]$Spec,[pscustomobject]$System,[pscustomobject]$Enrichment)
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $req=@(); $fail=$false; $unk=$false
    if ($Spec.MinCores) { $req += "$($Spec.MinCores)+ cores"; if ($cpu.NumberOfCores -lt $Spec.MinCores) { $fail=$true } }
    if ($Spec.MinPassMark) {
        $req += "$($Spec.MinPassMark)+ PassMark"
        if ($Enrichment -and $Enrichment.CpuScore) { if ($Enrichment.CpuScore -lt $Spec.MinPassMark) { $fail=$true } }
        else { $unk=$true }
    }
    if ($Spec.InstructionSets) {
        $have = Get-CpuInstructionSets
        $missing = @()
        foreach ($set in $Spec.InstructionSets) { if (-not $have.ContainsKey($set)) { $missing += $set } }
        $req += "ISA: $($Spec.InstructionSets -join ',')"
        if ($missing.Count -gt 0) { if ($have.Count -eq 0) { $unk=$true } else { $fail=$true } }
    }
    $actual = @("$($cpu.NumberOfCores)C/$($cpu.NumberOfLogicalProcessors)T")
    if ($Enrichment -and $Enrichment.CpuScore) { $actual += "PassMark $($Enrichment.CpuScore)" }
    $s = if ($fail) { 'FAIL' } elseif ($unk) { 'UNKNOWN' } else { 'PASS' }
    $n = if ($fail) { 'CPU below minimum' } elseif ($unk) { 'Cannot verify (PassMark or ISA unavailable)' } else { 'Meets CPU requirement' }
    New-ReqResult 'CPU' 'Processor' ($req -join ', ') ($actual -join ', ') $s $n
}

function Test-ReqRAM {
    param([hashtable]$Spec,[pscustomobject]$System)
    $have = $System.RAM_GB; $min = [int]$Spec.Min
    $rec = if ($Spec.Rec) { [int]$Spec.Rec } else { $min }
    $s = if ($have -ge $rec) { 'PASS' } elseif ($have -ge $min) { 'WARN' } else { 'FAIL' }
    $n = switch ($s) {
        'PASS' { 'Meets recommended' }
        'WARN' { 'Meets minimum only' }
        'FAIL' { 'Below minimum' }
        default { '' }
    }
    $r = if ($rec -ne $min) { "$min GB min / $rec GB rec" } else { "$min GB" }
    New-ReqResult 'RAM' 'Memory' $r "$have GB" $s $n
}

function Test-ReqDisk {
    param([hashtable]$Spec,[pscustomobject]$System,[pscustomobject]$Enrichment)
    $sysd = $System.Disks | Where-Object Drive -eq "$($env:SystemDrive)" | Select-Object -First 1
    if (-not $sysd) { return New-ReqResult 'Disk' 'System drive' "$($Spec.Min) GB" 'unknown' 'UNKNOWN' 'Cannot read system drive' }
    $have = $sysd.FreeGB; $min = [int]$Spec.Min
    $rec = if ($Spec.Rec) { [int]$Spec.Rec } else { $min }
    $s = if ($have -ge $rec) { 'PASS' } elseif ($have -ge $min) { 'WARN' } else { 'FAIL' }
    $n = switch ($s) {
        'PASS' { 'Meets recommended' }
        'WARN' { 'Meets minimum only' }
        'FAIL' { 'Insufficient free space' }
        default { '' }
    }
    if ($Spec.SSD -and $Enrichment -and $Enrichment.DiskMediaTypes) {
        $ssd = @($Enrichment.DiskMediaTypes | Where-Object { $_.MediaType -in @('SSD','NVMe') -or $_.BusType -eq 'NVMe' }).Count -gt 0
        if (-not $ssd) { if ($s -eq 'PASS') { $s='WARN' }; $n += ' · SSD not detected' }
    }
    $r = if ($rec -ne $min) { "$min GB min / $rec GB rec" } else { "$min GB" }
    if ($Spec.SSD) { $r += ' (SSD)' }
    New-ReqResult 'Disk' 'Free disk space' $r "$have GB" $s $n
}

function Test-ReqGPU {
    param([hashtable]$Spec,[pscustomobject]$System,[pscustomobject]$Enrichment)
    $best=0; $bestGPU=$null
    foreach ($g in $System.GPUs) {
        if ($g.VRAM_GB -and $g.VRAM_GB -gt $best) { $best = $g.VRAM_GB; $bestGPU = $g }
    }
    $req=@(); $fail=$false; $warn=$false; $unk=$false
    if ($Spec.MinVRAM) {
        $min = [int]$Spec.MinVRAM
        $rec = if ($Spec.RecVRAM) { [int]$Spec.RecVRAM } else { $min }
        $req += if ($rec -ne $min) { "$min GB VRAM min / $rec GB rec" } else { "$min GB VRAM min" }
        if ($best -ge $rec)     { }
        elseif ($best -ge $min) { $warn = $true }
        else                    { $fail = $true }
    }
    if ($Spec.Vendor) {
        $req += "vendor: $($Spec.Vendor)"
        $hit=$false
        foreach ($g in $System.GPUs) { if ($g.Name -match $Spec.Vendor) { $hit=$true } }
        if (-not $hit) { $fail=$true }
    }
    if ($Spec.MinDirectX) {
        $req += "DirectX $($Spec.MinDirectX)+"
        $dx = Get-DirectXVersion
        if ($dx) { if ([int]$dx -lt [int]$Spec.MinDirectX) { $fail=$true } } else { $unk=$true }
    }
    if ($Spec.MinPassMark) {
        $req += "G3D $($Spec.MinPassMark)+"
        if ($Enrichment -and $Enrichment.GpuScores) {
            $top = ($Enrichment.GpuScores | Where-Object Score | Sort-Object Score -Descending | Select-Object -First 1)
            if ($top) { if ($top.Score -lt $Spec.MinPassMark) { $fail=$true } } else { $unk=$true }
        } else { $unk=$true }
    }
    if ($Spec.RequiresCUDA) {
        $req += 'CUDA'
        if (-not (Test-Path "$env:SystemRoot\System32\nvcuda.dll")) { $fail=$true }
    }
    $s = if ($fail) { 'FAIL' } elseif ($unk) { 'UNKNOWN' } elseif ($warn) { 'WARN' } else { 'PASS' }
    $actual = if ($bestGPU) { "$($bestGPU.Name) · $best GB" } else { 'no GPU detected' }
    $n = switch ($s) {
        'PASS' { 'Meets GPU requirement' }
        'WARN' { 'Meets minimum VRAM only' }
        'FAIL' { 'GPU below requirement' }
        'UNKNOWN' { 'Cannot verify API locally' }
    }
    New-ReqResult 'GPU' 'Graphics' ($req -join ', ') $actual $s $n
}

function Test-ReqDisplay {
    param([hashtable]$Spec,[pscustomobject]$System)
    $g = $System.GPUs | Where-Object { $_.Resolution } | Select-Object -First 1
    if (-not $g -or $g.Resolution -notmatch '(\d+)x(\d+)') {
        return New-ReqResult 'Display' 'Display resolution' "$($Spec.MinWidth)x$($Spec.MinHeight)" 'unknown' 'UNKNOWN' 'No display detected'
    }
    $w=[int]$matches[1]; $h=[int]$matches[2]
    $ok = ($w -ge $Spec.MinWidth) -and ($h -ge $Spec.MinHeight)
    New-ReqResult 'Display' 'Display resolution' "$($Spec.MinWidth)x$($Spec.MinHeight)" "$w x $h" $(if ($ok) {'PASS'} else {'FAIL'}) $(if ($ok) {'Meets minimum'} else {'Resolution too low'})
}

function Test-ReqNetFx {
    param([hashtable]$Spec)
    $have = Get-DotNetFrameworkVersion
    $ok = Compare-NetVersion -Have $have -Need $Spec.Min
    New-ReqResult 'NetFx' '.NET Framework' ".NET $($Spec.Min)+" $have $(if ($ok){'PASS'}else{'FAIL'}) $(if ($ok){'Installed'}else{'Must be installed'})
}

function Test-ReqVCRedist {
    param([hashtable]$Spec)
    $vc = @(Get-VCRedist)
    if ($vc.Count -eq 0) { return New-ReqResult 'VCRedist' 'VC++ Redistributable' "$($Spec.Min)+" 'not found' 'FAIL' 'Must be installed' }
    $best = $vc | ForEach-Object { if ($_.DisplayVersion -match '(\d+\.\d+\.\d+)') { [version]$matches[1] } } | Sort-Object -Descending | Select-Object -First 1
    $ok = if ($best) { $best -ge [version]$Spec.Min } else { $false }
    New-ReqResult 'VCRedist' 'VC++ Redistributable' "$($Spec.Min)+" $(if($best){$best.ToString()}else{$vc[0].DisplayVersion}) $(if ($ok){'PASS'}else{'FAIL'}) $(if ($ok){'Installed'}else{'Version too old'})
}

function Test-ReqJava {
    param([hashtable]$Spec)
    $have = $null
    try {
        $out = & java -version 2>&1 | Out-String
        if ($out -match 'version "(\d+)(?:\.(\d+))?') { $have = if ($matches[2]) { "$($matches[1]).$($matches[2])" } else { $matches[1] } }
    } catch { }
    if (-not $have) {
        $pat = if ($Spec.Kind -eq 'JDK') { 'Java.*Development Kit|JDK' } else { 'Java.*Runtime|JRE|Java \d' }
        $hit = Get-InstalledSoftware | Where-Object { $_.DisplayName -match $pat } | Select-Object -First 1
        if ($hit) { $have = $hit.DisplayVersion }
    }
    $ok = $false
    if ($have) { try { $ok = [double]($have -replace '[^0-9\.]','') -ge [double]$Spec.Min } catch { } }
    $label = if ($Spec.Kind) { "Java $($Spec.Kind)" } else { 'Java' }
    New-ReqResult 'Java' $label "$($Spec.Min)+" $(if($have){$have}else{'not found'}) $(if($ok){'PASS'}else{'FAIL'}) $(if($ok){'Installed'}else{'Must be installed'})
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
    New-ReqResult 'Python' 'Python' "$($Spec.Min)+" $(if($have){$have}else{'not found'}) $(if($ok){'PASS'}else{'FAIL'}) $(if($ok){'Installed'}else{'Must be installed'})
}

function Test-ReqWebView2 {
    $hit = Get-InstalledSoftware | Where-Object { $_.DisplayName -match 'WebView2 Runtime' } | Select-Object -First 1
    New-ReqResult 'WebView2' 'WebView2 Runtime' 'Evergreen' $(if($hit){$hit.DisplayVersion}else{'not found'}) $(if($hit){'PASS'}else{'FAIL'}) $(if($hit){'Installed'}else{'Must be installed'})
}

function Test-ReqWinFeature {
    param([hashtable]$Spec)
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName $Spec.Name -ErrorAction Stop
        $ok = $f.State -eq 'Enabled'
        New-ReqResult 'WinFeature' "Windows feature: $($Spec.Name)" 'Enabled' $f.State $(if($ok){'PASS'}else{'FAIL'}) $(if($ok){'Enabled'}else{'Not enabled'})
    } catch {
        New-ReqResult 'WinFeature' "Windows feature: $($Spec.Name)" 'Enabled' 'unknown' 'UNKNOWN' 'Cannot query feature'
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
    New-ReqResult 'LicenseSvc' "License service ($($Spec.Pattern))" 'Service running OR port reachable' $actual $(if($ok){'PASS'}else{'FAIL'}) $(if($ok){'License path available'}else{'Cannot acquire license'})
}

function Test-ReqAdmin {
    param([hashtable]$Spec)
    $isAdmin = Test-IsAdmin
    $ok = (-not $Spec.Required) -or $isAdmin
    New-ReqResult 'Admin' 'Admin rights' $(if($Spec.Required){'Required'}else{'Optional'}) $(if($isAdmin){'Yes'}else{'No'}) $(if($ok){'PASS'}else{'FAIL'}) $(if($ok){'Admin present'}else{'Run elevated'})
}

function Test-Requirement {
    param([hashtable]$Spec,[pscustomobject]$System,[pscustomobject]$Enrichment)
    switch ($Spec.Type) {
        'OS'          { Test-ReqOS         -Spec $Spec -System $System }
        'CPU'         { Test-ReqCPU        -Spec $Spec -System $System -Enrichment $Enrichment }
        'RAM'         { Test-ReqRAM        -Spec $Spec -System $System }
        'Disk'        { Test-ReqDisk       -Spec $Spec -System $System -Enrichment $Enrichment }
        'GPU'         { Test-ReqGPU        -Spec $Spec -System $System -Enrichment $Enrichment }
        'Display'     { Test-ReqDisplay    -Spec $Spec -System $System }
        'NetFx'       { Test-ReqNetFx      -Spec $Spec }
        'VCRedist'    { Test-ReqVCRedist   -Spec $Spec }
        'Java'        { Test-ReqJava       -Spec $Spec }
        'Python'      { Test-ReqPython     -Spec $Spec }
        'WebView2'    { Test-ReqWebView2 }
        'WinFeature'  { Test-ReqWinFeature -Spec $Spec }
        'LicenseSvc'  { Test-ReqLicenseSvc -Spec $Spec }
        'Admin'       { Test-ReqAdmin      -Spec $Spec }
        default       { New-ReqResult $Spec.Type $Spec.Type 'unknown' 'unknown' 'UNKNOWN' 'No detector' }
    }
}

function Get-RequirementsForApp {
    param([object]$Entry)
    if ($Script:Requirements.ContainsKey($Entry.N)) { return @{ Source='Verified'; Specs=@($Script:Requirements[$Entry.N]) } }
    $specs = @()
    if ($Entry.RAM)  { $specs += @{ Type='RAM';  Min=[int][math]::Ceiling($Entry.RAM*0.5); Rec=[int]$Entry.RAM } }
    if ($Entry.Disk) { $specs += @{ Type='Disk'; Min=[int][math]::Ceiling($Entry.Disk*0.5); Rec=[int]$Entry.Disk } }
    if ($Entry.GPU)  { $specs += @{ Type='GPU';  MinVRAM=1; RecVRAM=2; MinDirectX=($(if ($Entry.DX) { $Entry.DX } else { '11' })) } }
    if ($Entry.Net)  { $specs += @{ Type='NetFx'; Min=$Entry.Net } }
    if ($Entry.VCPP) { $specs += @{ Type='VCRedist'; Min='14.30' } }
    if ($Entry.Lsvc) { foreach ($pat in $Entry.Lsvc) { $specs += @{ Type='LicenseSvc'; Pattern=$pat; Ports=@($Entry.Lport) } } }
    return @{ Source='Catalog-derived'; Specs=$specs }
}

function Check-App {
    param([object]$Entry,[pscustomobject]$System,[pscustomobject]$Enrichment,[array]$Installed)
    $reqSet = Get-RequirementsForApp -Entry $Entry
    $checks = New-Object System.Collections.Generic.List[object]
    foreach ($spec in $reqSet.Specs) {
        $checks.Add((Test-Requirement -Spec $spec -System $System -Enrichment $Enrichment))
    }
    foreach ($c in $checks) {
        if ($c.Type -in @('NetFx','VCRedist','Java','Python','WebView2')) {
            $latest = Get-LatestComponentVersion -Component $c.Component
            if ($latest) { $c | Add-Member -NotePropertyName LatestOnline -NotePropertyValue $latest -Force }
        }
    }
    $fail = @($checks | Where-Object Status -eq 'FAIL').Count
    $warn = @($checks | Where-Object Status -eq 'WARN').Count
    $unk  = @($checks | Where-Object Status -eq 'UNKNOWN').Count
    $verdict = if ($fail -gt 0) { 'DOES NOT MEET' } elseif ($warn -gt 0) { 'PARTIALLY MEETS' } elseif ($unk -gt 0) { 'MEETS (unverified)' } else { 'MEETS' }
    $installed = $false
    foreach ($pat in @($Entry.P)) { if (@($Installed | Where-Object { $_.DisplayName -like $pat }).Count -gt 0) { $installed = $true; break } }
    [pscustomobject]@{
        Product = $Entry.N; Disciplines = ($Entry.D -join ', '); Kind = $Entry.K
        Verdict = $verdict; Failures = $fail; Warnings = $warn; Unverified = $unk
        Installed = $installed; RequirementSource = $reqSet.Source; Checks = $checks
    }
}

function Select-ScanTargets {
    param([array]$Catalog)
    $byDisc = @{}
    foreach ($e in $Catalog) { foreach ($d in $e.D) { if (-not $byDisc.ContainsKey($d)) { $byDisc[$d] = @() }; $byDisc[$d] += $e } }
    $disc = @($byDisc.Keys | Sort-Object)
    Write-Head "Choose what to scan"
    Write-Host "  Picking a discipline checks every app in it against this PC's requirements." -ForegroundColor DarkGray
    Write-Host ""
    for ($i = 0; $i -lt $disc.Count; $i++) {
        Write-Host ("    {0,3}. {1,-24} ({2} apps)" -f ($i+1), $disc[$i], $byDisc[$disc[$i]].Count)
    }
    Write-Host ""
    $sel = Read-Host "  Numbers to scan (e.g. 1,4,7) or 'all'"
    if (-not $sel) { return @() }
    if ($sel -match '^all$') { return $disc }
    $picked = @()
    foreach ($tok in ($sel -split ',')) {
        $n = 0
        if ([int]::TryParse($tok.Trim(),[ref]$n) -and $n -ge 1 -and $n -le $disc.Count) { $picked += $disc[$n-1] }
    }
    return $picked
}

function Get-ScanTargets {
    param([array]$Catalog,[string[]]$Disciplines,[string[]]$Apps)
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($e in $Catalog) {
        $match = $false
        if ($Disciplines.Count -gt 0) { foreach ($d in $e.D) { if ($Disciplines -contains $d) { $match = $true; break } } }
        if (-not $match -and $Apps.Count -gt 0) {
            foreach ($a in $Apps) { if ($e.N -eq $a -or $e.N -like "*$a*" -or $a -like "*$e.N*") { $match = $true; break } }
        }
        if ($match -and -not $seen.ContainsKey($e.N)) { $seen[$e.N] = $true; $out.Add($e) }
    }
    return $out
}

# =============================================================================
# DISPATCH: Preflight / WhySlow
# =============================================================================
$motherboard = $null
try {
    $bb = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
    $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
    $motherboard = [pscustomobject]@{
        Manufacturer=$bb.Manufacturer; Product=$bb.Product; Version=$bb.Version
        BiosVendor=$bios.Manufacturer; BiosVersion=$bios.SMBIOSBIOSVersion
        BiosReleaseDate=if ($bios.ReleaseDate) { ([datetime]$bios.ReleaseDate).ToString('yyyy-MM-dd') } else { '' }
    }
} catch { }

if ($Preflight) {
    $enrich = Invoke-OnlineEnrichment -System $sys
    Invoke-Preflight -ProductName $Preflight -Catalog $Script:RawCatalog -System $sys -NetFx $netFx -VC $vc -Installed $installed -Enrichment $enrich
    exit 0
}
if ($WhySlow) { Invoke-WhySlow -System $sys; exit 0 }

# =============================================================================
# ONLINE ENRICHMENT + REQUIREMENT SCAN
# =============================================================================
$enrichment = Invoke-OnlineEnrichment -System $sys

if (-not $Disciplines -and -not $CheckApps -and -not $NonInteractive) {
    $Disciplines = Select-ScanTargets -Catalog $Script:RawCatalog
    if ($Disciplines.Count -eq 0) { Write-Host "  No selection. Exiting." -ForegroundColor Yellow; exit 0 }
}

$targets = Get-ScanTargets -Catalog $Script:RawCatalog -Disciplines $Disciplines -Apps $CheckApps

$scanResults = @()
if ($targets.Count -gt 0) {
    Write-Head "Requirement check - $($targets.Count) app(s)"
    Write-Host ""
    foreach ($entry in $targets) {
        $scanResults += Check-App -Entry $entry -System $sys -Enrichment $enrichment -Installed $installed
    }
    $scanResults = @($scanResults | Sort-Object Failures, Warnings, Product)

    foreach ($r in $scanResults) {
        $col = switch ($r.Verdict) {
            'MEETS'              { 'Green' }
            'MEETS (unverified)' { 'Green' }
            'PARTIALLY MEETS'    { 'Yellow' }
            'DOES NOT MEET'      { 'Red' }
            default              { 'Gray' }
        }
        $instTag = if ($r.Installed) { ' [installed]' } else { '' }
        Write-Host ("  {0,-32} {1}{2}" -f $r.Product, $r.Verdict, $instTag) -ForegroundColor $col
        foreach ($c in $r.Checks) {
            $mark = switch ($c.Status) { 'PASS' { '  +' } 'WARN' { '  ~' } 'FAIL' { '  !' } 'UNKNOWN' { '  ?' } }
            $line = "{0} [{1,-7}] {2,-24} need: {3,-32} have: {4}" -f $mark, $c.Status, $c.Component, $c.Required, $c.Actual
            if ($c.PSObject.Properties.Match('LatestOnline').Count -and $c.LatestOnline) { $line += "  (latest: $($c.LatestOnline))" }
            $lineCol = switch ($c.Status) { 'PASS' { 'DarkGray' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'DarkGray' } }
            Write-Host $line -ForegroundColor $lineCol
        }
        Write-Host ""
    }
    $meets   = @($scanResults | Where-Object Verdict -eq 'MEETS').Count
    $partial = @($scanResults | Where-Object Verdict -eq 'PARTIALLY MEETS').Count
    $fails   = @($scanResults | Where-Object Verdict -eq 'DOES NOT MEET').Count
    $unver   = @($scanResults | Where-Object Verdict -eq 'MEETS (unverified)').Count
    Write-Host ("  SUMMARY: $meets MEETS · $partial PARTIAL · $fails FAILS · $unver UNVERIFIED") -ForegroundColor Cyan
    Write-Host ""
} else {
    Write-Host "  No apps matched the selection." -ForegroundColor Yellow
}

# =============================================================================
# DISCIPLINE ROLLUP
# =============================================================================
if ($scanResults.Count -gt 0) {
    Write-Head "Discipline rollup"
    $byDisc = @{}
    foreach ($r in $scanResults) {
        foreach ($d in ($r.Disciplines -split ',\s*')) {
            if (-not $byDisc.ContainsKey($d)) { $byDisc[$d] = @() }
            $byDisc[$d] += $r
        }
    }
    foreach ($d in $byDisc.Keys | Sort-Object) {
        $rs = $byDisc[$d]
        $g  = @($rs | Where-Object Verdict -eq 'MEETS').Count
        $y  = @($rs | Where-Object Verdict -eq 'PARTIALLY MEETS').Count
        $rr = @($rs | Where-Object Verdict -eq 'DOES NOT MEET').Count
        $u  = @($rs | Where-Object Verdict -eq 'MEETS (unverified)').Count
        Write-Host ("  {0,-18} {1,2} meets  {2,2} partial  {3,2} fails  {4,2} unverified (of {5})" `
            -f $d, $g, $y, $rr, $u, $rs.Count) -ForegroundColor Cyan
    }
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
                $refs.Add([pscustomobject]@{ Type='XREF'; Path=$m.Groups[1].Value })
            }
        } elseif ($ext -eq '.dwg') {
            $fi = Get-Item -LiteralPath $FilePath
            if ($fi.Length -gt 250MB) { return $refs }
            $bytes = [System.IO.File]::ReadAllBytes($FilePath)
            $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
            foreach ($m in [regex]::Matches($ascii, "[A-Za-z]:\\\\[^\x00-\x1F`"<>|]{0,250}\.(dwg|dxf|pdf|jpg|png|tif|shx|ttf|shp|dgn|dwf)", 'IgnoreCase')) {
                $refs.Add([pscustomobject]@{ Type='REF'; Path=$m.Value })
            }
        }
    } catch { Add-Diagnostic 'XREF' "Failed to parse ${FilePath}: $_" }
    return $refs
}

function Invoke-ProjectGuardian {
    param([string]$Root)
    if (-not (Test-Path $Root)) { Write-Host "[ERROR] Path not found: $Root" -ForegroundColor Red; return $null }
    Write-Head "Project Guardian: $Root"
    $scan = @(Get-ChildItem -LiteralPath $Root -Recurse -Force -File -ErrorAction SilentlyContinue)
    $totalBytes = ($scan | Measure-Object -Property Length -Sum).Sum
    $longPaths = @($scan | Where-Object { $_.FullName.Length -gt 240 }).Count
    $backupExt = @('.bak','.tmp','.sv$','.dwl','.dwl2')
    $backupFiles = @($scan | Where-Object { $backupExt -contains $_.Extension.ToLower() }).Count
    $dwgFiles = @($scan | Where-Object { $_.Extension -in @('.dwg','.dxf') })
    $refTotal = 0; $refMissing = 0
    foreach ($dwg in ($dwgFiles | Select-Object -First 200)) {
        foreach ($r in (Get-DwgReferences -FilePath $dwg.FullName)) {
            $refTotal++
            $p = $r.Path -replace '/', '\'
            if (-not [System.IO.Path]::IsPathRooted($p)) { $p = Join-Path $dwg.DirectoryName $p }
            if (-not (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) { $refMissing++ }
        }
    }
    Write-Host ("  Total files: {0}" -f $scan.Count)
    Write-Host ("  Total size:  {0} GB" -f [math]::Round($totalBytes/1GB, 2))
    Write-Host ("  Long paths:  {0}" -f $longPaths)
    Write-Host ("  Backup files:{0}" -f $backupFiles)
    Write-Host ("  References:  {0} found, {1} missing" -f $refTotal, $refMissing)
    $penalty = 0
    if ($longPaths -gt 0) { $penalty += [math]::Min(25, $longPaths) }
    if ($refTotal -gt 0) { $penalty += [math]::Min(30, [int](($refMissing/$refTotal)*100)) }
    $health = [math]::Max(0, 100 - $penalty)
    Write-Host ("  Project Health: $health%") -ForegroundColor Cyan
    Write-Host ""
    return [pscustomobject]@{
        Root=$Root; TotalFiles=$scan.Count; TotalGB=[math]::Round($totalBytes/1GB,2)
        LongPaths=$longPaths; BackupFiles=$backupFiles
        RefTotal=$refTotal; RefMissing=$refMissing; Health=$health
    }
}
$guardian = $null
if ($ProjectGuardian) { $guardian = Invoke-ProjectGuardian -Root $ProjectGuardian }

# =============================================================================
# WRITE REPORT
# =============================================================================
Write-Stage "Writing report (HTML / JSON / CSV)..."
Ensure-Folder $exportPath

[pscustomobject]@{
    GeneratedAt         = (Get-Date).ToString('s')
    System              = $sys
    Motherboard         = $motherboard
    NetFx               = $netFx
    VCRedist            = $vc
    Enrichment          = $enrichment
    SelectedDisciplines = $Disciplines
    SelectedApps        = $CheckApps
    Guardian            = $guardian
    Results             = $scanResults
} | ConvertTo-Json -Depth 12 | Set-Content "$reportBase.json" -Encoding UTF8

$rows = foreach ($r in $scanResults) {
    foreach ($c in $r.Checks) {
        [pscustomobject]@{
            Product   = $r.Product; Verdict = $r.Verdict; Component = $c.Component
            Type      = $c.Type; Required = $c.Required; Actual = $c.Actual
            Status    = $c.Status; Note = $c.Note
            LatestOnline = if ($c.PSObject.Properties.Match('LatestOnline').Count) { $c.LatestOnline } else { '' }
        }
    }
}
$rows | Export-Csv "$reportBase.csv" -NoTypeInformation -Encoding UTF8

$style = @'
<style>
 body{font-family:'Segoe UI',Arial,sans-serif;margin:24px;color:#1a1a1a;background:#f7f8fa}
 h1{color:#0b5394;margin-bottom:4px}
 h2{color:#0b5394;margin-top:32px;border-bottom:2px solid #dde3ec;padding-bottom:4px}
 .sub{color:#555;font-size:12px;margin-top:0}
 .card{background:#fff;border:1px solid #e0e4ea;border-radius:8px;padding:14px 18px;margin:10px 0}
 table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px;background:#fff}
 th,td{border:1px solid #e0e4ea;padding:6px 8px;text-align:left;vertical-align:top}
 th{background:#eef2f8}
 .chip{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff}
 .chip.green{background:#1c9b4b}.chip.yellow{background:#d18b00}.chip.red{background:#c23636}
 .chip.gray{background:#8b95a5}.chip.blue{background:#2b6cb0}
 .small{font-size:11px;color:#666}
 .product{margin:16px 0;padding:14px 18px;background:#fff;border-left:5px solid #8b95a5;border-radius:6px}
 .product.meets{border-left-color:#1c9b4b}
 .product.partial{border-left-color:#d18b00}
 .product.fails{border-left-color:#c23636}
 .product.unverified{border-left-color:#2b6cb0}
 .product-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
 .product-name{font-size:15px;font-weight:700}
</style>
'@

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("<!doctype html><html><head><meta charset='utf-8'><title>Sigma Requirement Report</title>$style</head><body>")
[void]$sb.AppendLine("<h1>Sigma Engineer Toolkit - Requirement Report</h1>")
[void]$sb.AppendLine("<p class='sub'>Generated $(Get-Date) on $($sys.ComputerName) by $($sys.User)</p>")

[void]$sb.AppendLine("<h2>Machine</h2><div class='card'><table>")
[void]$sb.AppendLine("<tr><th style='width:220px'>OS</th><td>$($sys.OS)</td></tr>")
[void]$sb.AppendLine("<tr><th>CPU</th><td>$($sys.CPU) ($($sys.Cores)C/$($sys.LogicalCPUs)T @ $($sys.ClockMHz) MHz)</td></tr>")
$cpuMark = if ($enrichment.CpuScore) { $enrichment.CpuScore } else { 'unavailable' }
[void]$sb.AppendLine("<tr><th>PassMark CPU Mark</th><td>$cpuMark</td></tr>")
[void]$sb.AppendLine("<tr><th>RAM</th><td>$($sys.RAM_GB) GB</td></tr>")
foreach ($g in $sys.GPUs) {
    [void]$sb.AppendLine("<tr><th>GPU ($($g.Kind))</th><td>$($g.Name) - $($g.VRAM_GB) GB VRAM</td></tr>")
}
[void]$sb.AppendLine("<tr><th>.NET Framework</th><td>$netFx</td></tr>")
[void]$sb.AppendLine("<tr><th>VC++ Redistributables</th><td>$($vc.Count) installed</td></tr>")
[void]$sb.AppendLine("</table></div>")

[void]$sb.AppendLine("<h2>Requirement Scan</h2>")
[void]$sb.AppendLine("<p class='small'>Disciplines: $($Disciplines -join ', ')  ·  Apps: $($CheckApps -join ', ')</p>")

foreach ($r in $scanResults) {
    $cls = switch ($r.Verdict) {
        'MEETS'              { 'meets' }
        'MEETS (unverified)' { 'unverified' }
        'PARTIALLY MEETS'    { 'partial' }
        'DOES NOT MEET'      { 'fails' }
        default              { '' }
    }
    $chipCls = switch ($r.Verdict) {
        'MEETS'              { 'green' }
        'MEETS (unverified)' { 'blue' }
        'PARTIALLY MEETS'    { 'yellow' }
        'DOES NOT MEET'      { 'red' }
        default              { 'gray' }
    }
    [void]$sb.AppendLine("<div class='product $cls'>")
    [void]$sb.AppendLine("<div class='product-head'>")
    [void]$sb.AppendLine("<div><div class='product-name'>$($r.Product)</div><div class='small'>$($r.Disciplines) · $($r.Kind) · source: $($r.RequirementSource)$(if ($r.Installed) { ' · installed' })</div></div>")
    [void]$sb.AppendLine("<span class='chip $chipCls'>$($r.Verdict)</span>")
    [void]$sb.AppendLine("</div>")
    [void]$sb.AppendLine("<table>")
    [void]$sb.AppendLine("<tr><th style='width:170px'>Requirement</th><th style='width:240px'>Required</th><th style='width:240px'>Actual</th><th style='width:90px'>Status</th><th>Note</th></tr>")
    foreach ($c in $r.Checks) {
        $sc = switch ($c.Status) { 'PASS'{'green'} 'WARN'{'yellow'} 'FAIL'{'red'} default{'gray'} }
        $latest = ''
        if ($c.PSObject.Properties.Match('LatestOnline').Count -and $c.LatestOnline) {
            $latest = " <span class='small'>(latest online: $($c.LatestOnline))</span>"
        }
        [void]$sb.AppendLine("<tr><td><b>$($c.Component)</b></td><td>$($c.Required)$latest</td><td>$($c.Actual)</td><td><span class='chip $sc'>$($c.Status)</span></td><td class='small'>$($c.Note)</td></tr>")
    }
    [void]$sb.AppendLine("</table></div>")
}

if ($guardian) {
    [void]$sb.AppendLine("<h2>Project Guardian</h2><div class='card'><table>")
    [void]$sb.AppendLine("<tr><th style='width:220px'>Root</th><td>$($guardian.Root)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Total files</th><td>$($guardian.TotalFiles)</td></tr>")
    [void]$sb.AppendLine("<tr><th>Total size</th><td>$($guardian.TotalGB) GB</td></tr>")
    [void]$sb.AppendLine("<tr><th>Long paths</th><td>$($guardian.LongPaths)</td></tr>")
    [void]$sb.AppendLine("<tr><th>References</th><td>$($guardian.RefTotal) found, $($guardian.RefMissing) missing</td></tr>")
    [void]$sb.AppendLine("<tr><th>Project health</th><td><b>$($guardian.Health)%</b></td></tr>")
    [void]$sb.AppendLine("</table></div>")
}

[void]$sb.AppendLine("<p class='small'>End of report. Requirements are curated from vendor docs; verify before critical deployments.</p>")
[void]$sb.AppendLine("</body></html>")
$sb.ToString() | Set-Content "$reportBase.html" -Encoding UTF8
Write-Ok

# =============================================================================
# FINAL
# =============================================================================
if (Test-Path $errorLog) { Remove-Item $errorLog -Force -ErrorAction SilentlyContinue }

Write-Host "[SUCCESS] Requirement scan complete." -ForegroundColor Green
Write-Host "[INFO] HTML : $reportBase.html" -ForegroundColor Cyan
Write-Host "[INFO] JSON : $reportBase.json" -ForegroundColor Cyan
Write-Host "[INFO] CSV  : $reportBase.csv"  -ForegroundColor Cyan
Write-Host ""

# Batch install mode
if ($Install) {
    $names = if ($InstallList.Count -gt 0) { $InstallList }
             else { @($scanResults | Where-Object { $_.Verdict -in @('MEETS','MEETS (unverified)') -and -not $_.Installed } | ForEach-Object { $_.Product }) }
    Write-Head "Installing ($($names.Count) app(s))"
    Invoke-Installer -Names $names -HasWinget (Test-WingetAvailable)
    exit 0
}

if ($NonInteractive) { exit 0 }

# Interactive loop - R = open report folder, I = install, S = scan again, Q = quit
while ($true) {
    $finalChoice = Read-Host "Press R to open report folder, I to install, S to scan again, Q to quit"
    switch -Regex ($finalChoice) {
        '^[Rr]$' {
            Start-Process $exportPath
        }
        '^[Ii]$' {
            Show-InstallableFromScan -ScanResults $scanResults
        }
        '^[Ss]$' {
            $newDisc = Select-ScanTargets -Catalog $Script:RawCatalog
            if ($newDisc.Count -eq 0) { continue }
            $newTargets = Get-ScanTargets -Catalog $Script:RawCatalog -Disciplines $newDisc -Apps @()
            Write-Head "Requirement check - $($newTargets.Count) app(s)"
            Write-Host ""
            $scanResults = @()
            foreach ($entry in $newTargets) {
                $r = Check-App -Entry $entry -System $sys -Enrichment $enrichment -Installed $installed
                $scanResults += $r
                $col = switch ($r.Verdict) {
                    'MEETS'              { 'Green' }
                    'MEETS (unverified)' { 'Green' }
                    'PARTIALLY MEETS'    { 'Yellow' }
                    'DOES NOT MEET'      { 'Red' }
                    default              { 'Gray' }
                }
                $instTag = if ($r.Installed) { ' [installed]' } else { '' }
                Write-Host ("  {0,-32} {1}{2}" -f $r.Product, $r.Verdict, $instTag) -ForegroundColor $col
                foreach ($c in $r.Checks) {
                    $mark = switch ($c.Status) { 'PASS' { '  +' } 'WARN' { '  ~' } 'FAIL' { '  !' } 'UNKNOWN' { '  ?' } }
                    $line = "{0} [{1,-7}] {2,-24} need: {3,-32} have: {4}" -f $mark, $c.Status, $c.Component, $c.Required, $c.Actual
                    if ($c.PSObject.Properties.Match('LatestOnline').Count -and $c.LatestOnline) { $line += "  (latest: $($c.LatestOnline))" }
                    $lineCol = switch ($c.Status) { 'PASS' { 'DarkGray' } 'WARN' { 'Yellow' } 'FAIL' { 'Red' } default { 'DarkGray' } }
                    Write-Host $line -ForegroundColor $lineCol
                }
                Write-Host ""
            }
            $scanResults = @($scanResults | Sort-Object Failures, Warnings, Product)
            $meets   = @($scanResults | Where-Object Verdict -eq 'MEETS').Count
            $partial = @($scanResults | Where-Object Verdict -eq 'PARTIALLY MEETS').Count
            $fails   = @($scanResults | Where-Object Verdict -eq 'DOES NOT MEET').Count
            $unver   = @($scanResults | Where-Object Verdict -eq 'MEETS (unverified)').Count
            Write-Host ("  SUMMARY: $meets MEETS · $partial PARTIAL · $fails FAILS · $unver UNVERIFIED") -ForegroundColor Cyan
            Write-Host ""
        }
        '^[Qq]$' {
            Write-Host "  Bye." -ForegroundColor Cyan
            exit 0
        }
        default {
            Write-Host "  Bye." -ForegroundColor Cyan
            exit 0
        }
    }
}
