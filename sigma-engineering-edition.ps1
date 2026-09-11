#Requires -RunAsAdministrator
# -----------------------------------------------------------------------------
# SIGMA ENGINEER TOOLKIT
# -----------------------------------------------------------------------------
# One-shot read-only diagnostic pass over every engineering discipline:
#   - Detects installed software from the master catalog
#   - Checks per-product prerequisites, license services, license ports, caches
#   - Captures system inventory (CPU, RAM, GPU, disks, pagefile)
#   - Produces a colour-coded HTML dashboard + JSON + CSV
#
# Makes NO changes to the machine.
# -----------------------------------------------------------------------------

Write-Host "`n========== SIGMA ENGINEER TOOLKIT ==========" -ForegroundColor Green
Write-Host ""
Write-Host "[INFO] Scans every engineering discipline on this workstation." -ForegroundColor Cyan
Write-Host "[INFO] Detects installed software, checks prerequisites, writes a report." -ForegroundColor Cyan
Write-Host "[WARNING] A full scan can take 2-5 minutes on a loaded machine." -ForegroundColor Yellow
Write-Host "[WARNING] Deep cache scan adds 1-3 minutes per large product." -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "Proceed with the engineering diagnostic scan? (Y/N)"
if ($confirm -ne "Y" -and $confirm -ne "y") {
    Write-Host "Exiting. No scan performed." -ForegroundColor Cyan
    exit 0
}

Write-Host ""
Write-Host "[INFO] Starting Sigma Engineer Toolkit..." -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
$errorLog   = "$env:TEMP\sigma_engineer_toolkit_errors.log"
$deepScan   = $false
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

# -----------------------------------------------------------------------------
# Save baseline
# -----------------------------------------------------------------------------
$baseline = [pscustomobject]@{
    When       = Get-Date
    Computer   = $env:COMPUTERNAME
    User       = "$env:USERDOMAIN\$env:USERNAME"
    IsAdmin    = (Test-IsAdmin)
    PSVersion  = $PSVersionTable.PSVersion.ToString()
    ReportPath = $reportBase
}
Write-Host "[INFO] Baseline: $($baseline.When) on $($baseline.Computer) as $($baseline.User)" -ForegroundColor DarkGray

# -----------------------------------------------------------------------------
# 1. Master catalog
# -----------------------------------------------------------------------------
Write-Stage "Loading master catalog..."
$Script:RawCatalog = @(
    # ---------- CIVIL / AEC / BIM ----------
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

    # ---------- STRUCTURAL ----------
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

    # ---------- MECHANICAL / AEROSPACE / AUTOMOTIVE ----------
    @{N='SOLIDWORKS';           D=@('Mechanical','Aerospace','Automotive','Industrial'); P=@('SOLIDWORKS 20*'); K='CAD'; RAM=16; Disk=30; GPU=$true; Net='4.8'; VCPP=$true; DX='11'; Lic='FlexLM'; Lsvc=@('*SolidWorks*','*SW_D*'); Lport=@(25734); Cache=@('%LOCALAPPDATA%\SolidWorks','%APPDATA%\SolidWorks')}
    @{N='Autodesk Inventor';    D=@('Mechanical','Industrial');          P=@('Autodesk Inventor*');                                 K='CAD';        RAM=16; Disk=30;  GPU=$true;  Net='4.8'; VCPP=$true; Lic='Node';     Cache=@('%LOCALAPPDATA%\Autodesk\Inventor')}
    @{N='CATIA';                D=@('Mechanical','Aerospace','Automotive','Marine'); P=@('CATIA*','Dassault Systemes CATIA*'); K='CAD'; RAM=16; Disk=30; GPU=$true; VCPP=$true; Lic='FlexLM'; Lsvc=@('*DS*','*Flex*'); Lport=@(4085)}
    @{N='Siemens NX';           D=@('Mechanical','Aerospace','Automotive','Manufacturing'); P=@('Siemens NX*','NX 20*'); K='CAD'; RAM=16; Disk=30; GPU=$true; VCPP=$true; Lic='FlexLM'; Lsvc=@('*Siemens*','*lmgrd*'); Lport=@(28000)}
    @{N='PTC Creo';             D=@('Mechanical','Aerospace');           P=@('PTC Creo*','Creo Parametric*');                       K='CAD';        RAM=16; Disk=30;  GPU=$true;  VCPP=$true; Lic='FlexLM'; Lsvc=@('*Creo*','*PTC*'); Lport=@(7788)}
    @{N='Solid Edge';           D=@('Mechanical','Industrial');          P=@('Solid Edge*');                                        K='CAD';        RAM=16; Disk=25;  GPU=$true;  Net='4.8'; Lic='FlexLM'}
    @{N='Fusion 360';           D=@('Mechanical','Industrial','CAM');    P=@('Autodesk Fusion*');                                   K='CAD/CAM';    RAM=8;  Disk=15;  GPU=$true;  Net='4.8'; Lic='Cloud'; Cache=@('%LOCALAPPDATA%\Autodesk\Fusion360')}
    @{N='Siemens Teamcenter';   D=@('PLM','Mechanical');                 P=@('Teamcenter*');                                        K='PLM';        RAM=16; Disk=30;  VCPP=$true; Lic='FlexLM'}

    # ---------- SIMULATION / MULTIPHYSICS ----------
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

    # ---------- MATH / DATA ----------
    @{N='Wolfram Mathematica';  D=@('Math','Materials');                 P=@('Wolfram Mathematica*','Mathematica*');                K='Math';       RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Maple';                D=@('Math');                             P=@('Maple 20*','Maple*');                                 K='Math';       RAM=8;  Disk=10;  Lic='FlexLM'}
    @{N='Mathcad Prime';        D=@('Math','Structural');                P=@('Mathcad Prime*','PTC Mathcad*');                      K='Math';       RAM=8;  Disk=10;  Net='4.8'; Lic='FlexLM'}
    @{N='Python';               D=@('Math','Data','Engineering');        P=@('Python 3*','Python 3.*');                             K='Lang';       RAM=2;  Disk=2;   Lic='None'}
    @{N='Anaconda';             D=@('Math','Data');                      P=@('Anaconda*','Miniconda*');                             K='Distro';     RAM=2;  Disk=5;   Lic='None'}
    @{N='Jupyter';              D=@('Math','Data');                      P=@('Jupyter*');                                           K='Notebook';   RAM=2;  Disk=2}
    @{N='R';                    D=@('Math','Data');                      P=@('R for Windows*','R 4.*');                             K='Stats';      RAM=4;  Disk=3}
    @{N='OriginPro';            D=@('Math','Data','Materials');          P=@('OriginPro*','OriginLab*');                            K='Plot';       RAM=4;  Disk=5;   Lic='Node'}

    # ---------- ELECTRONICS / PCB ----------
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

    # ---------- ELECTRICAL POWER ----------
    @{N='ETAP';                 D=@('Electrical Power');                 P=@('ETAP*');                                              K='Power';      RAM=16; Disk=25;  Net='4.8'; Lic='Sentinel'; Lsvc=@('*ETAP*','Sentinel*'); Lport=@(1947); Cache=@('%LOCALAPPDATA%\ETAP')}
    @{N='SKM PowerTools';       D=@('Electrical Power');                 P=@('SKM Power*','PowerTools*');                           K='Power';      RAM=8;  Disk=15;  Lic='Sentinel'}
    @{N='EasyPower';            D=@('Electrical Power');                 P=@('EasyPower*');                                         K='Power';      RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='DIgSILENT PowerFactory';D=@('Electrical Power');                P=@('PowerFactory*','DIgSILENT*');                         K='Power';      RAM=16; Disk=20;  Lic='FlexLM'; Lsvc=@('*DIgSILENT*')}
    @{N='PSS/E';                D=@('Electrical Power');                 P=@('PSS*E*','PSSE*');                                     K='Power';      RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='PSCAD';                D=@('Electrical Power');                 P=@('PSCAD*');                                             K='Power';      RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='EPLAN Electric P8';    D=@('Electrical','Automation');          P=@('EPLAN*');                                             K='ECAD';       RAM=16; Disk=25;  Net='4.8'; Lic='FlexLM'; Lsvc=@('*EPLAN*','*lmgrd*'); Cache=@('%APPDATA%\EPLAN')}
    @{N='AutoCAD Electrical';   D=@('Electrical','Automation');          P=@('AutoCAD Electrical*');                                K='ECAD';       RAM=8;  Disk=20;  GPU=$true;  Net='4.8'; Lic='Node'}
    @{N='SOLIDWORKS Electrical';D=@('Electrical','Mechanical');          P=@('SOLIDWORKS Electrical*');                             K='ECAD';       RAM=16; Disk=25;  Net='4.8'; Lic='FlexLM'}

    # ---------- AUTOMATION / PLC / SCADA ----------
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

    # ---------- EMBEDDED / COMPUTER ENGINEERING ----------
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

    # ---------- TELECOM / RF / MICROWAVE ----------
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

    # ---------- CHEMICAL / PETROLEUM ----------
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

    # ---------- MINING / GEOLOGY / GEOTECH ----------
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

    # ---------- WATER / HYDRO / ENVIRONMENTAL ----------
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

    # ---------- GIS / GEOMATICS / SURVEY ----------
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

    # ---------- MARINE / NAVAL ----------
    @{N='AVEVA Marine';         D=@('Marine','Naval');                   P=@('AVEVA Marine*','AVEVA*');                             K='Ship CAD';   RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='ShipConstructor';      D=@('Marine','Naval');                   P=@('ShipConstructor*');                                   K='Ship CAD';   RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='Maxsurf';              D=@('Marine','Naval');                   P=@('Maxsurf*');                                           K='Naval arch'; RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='NAPA';                 D=@('Marine','Naval');                   P=@('NAPA*');                                              K='Naval arch'; RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='ANSYS AQWA';           D=@('Marine','Naval','Offshore');        P=@('ANSYS AQWA*','AQWA*');                                K='Hydro';      RAM=16; Disk=30;  Lic='FlexLM'}
    @{N='MOSES';                D=@('Marine','Offshore');                P=@('MOSES*','Bentley MOSES*');                            K='Hydro';      RAM=8;  Disk=20;  Lic='Bentley'}

    # ---------- RAILWAY ----------
    @{N='Bentley OpenRail';     D=@('Railway','Civil');                  P=@('OpenRail*');                                          K='Rail CAD';   RAM=16; Disk=30;  GPU=$true;  Lic='Bentley'; Lsvc=@('*Bentley*','*SelectServer*')}
    @{N='OpenTrack';            D=@('Railway');                          P=@('OpenTrack*');                                         K='Rail sim';   RAM=8;  Disk=15;  Lic='None'}
    @{N='RailSys';              D=@('Railway');                          P=@('RailSys*');                                           K='Rail sim';   RAM=8;  Disk=15;  Lic='FlexLM'}

    # ---------- FIRE PROTECTION ----------
    @{N='AutoSPRINK';           D=@('Fire','MEP');                       P=@('AutoSPRINK*');                                        K='Fire';       RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='HydraCALC';            D=@('Fire','MEP');                       P=@('HydraCALC*');                                         K='Fire';       RAM=4;  Disk=10;  Lic='Node'}
    @{N='PyroSim';              D=@('Fire');                             P=@('PyroSim*');                                           K='Fire sim';   RAM=16; Disk=20;  GPU=$true;  Lic='Node'}
    @{N='FDS';                  D=@('Fire');                             P=@('FDS*','NIST FDS*');                                   K='Fire sim';   RAM=16; Disk=20;  Lic='None'}
    @{N='Pathfinder';           D=@('Fire');                             P=@('Pathfinder*');                                        K='Egress';     RAM=8;  Disk=15;  Lic='Node'}
    @{N='CONTAM';               D=@('Fire','HVAC');                      P=@('CONTAM*','NIST CONTAM*');                             K='Airflow';    RAM=4;  Disk=10;  Lic='None'}

    # ---------- HVAC / BUILDING SYSTEMS ----------
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

    # ---------- NUCLEAR ----------
    @{N='MCNP';                 D=@('Nuclear');                          P=@('MCNP*');                                              K='Neutronics'; RAM=8;  Disk=20;  Lic='Node'}
    @{N='SCALE';                D=@('Nuclear');                          P=@('SCALE*','ORNL SCALE*');                               K='Neutronics'; RAM=8;  Disk=20;  Lic='Node'}
    @{N='SERPENT';              D=@('Nuclear');                          P=@('Serpent*','SERPENT*');                                K='Neutronics'; RAM=8;  Disk=20;  Lic='None'}
    @{N='RELAP5';               D=@('Nuclear');                          P=@('RELAP5*');                                            K='Thermal';    RAM=8;  Disk=20;  Lic='Node'}
    @{N='TRACE';                D=@('Nuclear');                          P=@('TRACE*','NRC TRACE*');                                K='Thermal';    RAM=8;  Disk=20;  Lic='None'}
    @{N='OpenMC';               D=@('Nuclear');                          P=@('OpenMC*');                                            K='Neutronics'; RAM=8;  Disk=20;  Lic='None'}

    # ---------- BIOMEDICAL / MATERIALS ----------
    @{N='Mimics Innovation Suite';D=@('Biomedical');                     P=@('Mimics*','Materialise Mimics*');                      K='Bio model';  RAM=16; Disk=25;  GPU=$true;  Lic='FlexLM'}
    @{N='Simpleware';           D=@('Biomedical');                       P=@('Simpleware*','Synopsys Simpleware*');                 K='Bio model';  RAM=16; Disk=25;  Lic='FlexLM'}
    @{N='ImageJ';               D=@('Biomedical','Materials');           P=@('ImageJ*','Fiji*');                                    K='Imaging';    RAM=4;  Disk=5;   Lic='None'}
    @{N='3D Slicer';            D=@('Biomedical');                       P=@('3D Slicer*');                                         K='Imaging';    RAM=8;  Disk=10;  Lic='None'}
    @{N='Thermo-Calc';          D=@('Materials');                        P=@('Thermo-Calc*');                                       K='Thermo';     RAM=8;  Disk=20;  Lic='FlexLM'}
    @{N='JMatPro';              D=@('Materials');                        P=@('JMatPro*');                                           K='Materials';  RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='FactSage';             D=@('Materials');                        P=@('FactSage*');                                          K='Thermo';     RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Materials Studio';     D=@('Materials');                        P=@('Materials Studio*','BIOVIA*');                        K='MD';         RAM=16; Disk=25;  Lic='FlexLM'}

    # ---------- RENEWABLE / BATTERY ----------
    @{N='PVsyst';               D=@('Renewable','Solar');                P=@('PVsyst*');                                            K='Solar';      RAM=4;  Disk=10;  Lic='Node'}
    @{N='HOMER Pro';            D=@('Renewable');                        P=@('HOMER*');                                             K='Microgrid';  RAM=4;  Disk=10;  Lic='Node'}
    @{N='SAM';                  D=@('Renewable');                        P=@('SAM 20*','System Advisor Model*');                    K='Renewable';  RAM=4;  Disk=10;  Lic='None'}
    @{N='RETScreen Expert';     D=@('Renewable');                        P=@('RETScreen*');                                         K='Feasibility';RAM=4;  Disk=5;   Lic='Node'}
    @{N='HelioScope';           D=@('Renewable','Solar');                P=@('HelioScope*');                                        K='Solar';      RAM=4;  Disk=5;   Lic='Cloud'}
    @{N='WindPRO';              D=@('Renewable','Wind');                 P=@('WindPRO*');                                           K='Wind';       RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='WAsP';                 D=@('Renewable','Wind');                 P=@('WAsP*');                                              K='Wind';       RAM=4;  Disk=10;  Lic='FlexLM'}
    @{N='GT-AutoLion';          D=@('Battery');                          P=@('GT-AutoLion*','AutoLion*');                           K='Battery';    RAM=8;  Disk=15;  Lic='FlexLM'}
    @{N='Battery Design Studio';D=@('Battery');                          P=@('Battery Design Studio*','CD-adapco BDS*');            K='Battery';    RAM=8;  Disk=15;  Lic='FlexLM'}

    # ---------- PROJECT / MANUFACTURING / SYSTEMS ----------
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
Write-Ok

# -----------------------------------------------------------------------------
# 2. Discipline profiles
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# 3. Detect installed software
# -----------------------------------------------------------------------------
Write-Stage "Scanning installed software..."
$installed = Get-InstalledSoftware
Write-Host " $($installed.Count) entries." -ForegroundColor Green

# -----------------------------------------------------------------------------
# 4. System inventory
# -----------------------------------------------------------------------------
Write-Stage "Capturing system inventory..."
$sys = (function {
    $os   = Get-CimInstance Win32_OperatingSystem
    $cs   = Get-CimInstance Win32_ComputerSystem
    $cpu  = Get-CimInstance Win32_Processor | Select-Object -First 1
    $gpus = @(Get-CimInstance Win32_VideoController)

    $gpuInfo = foreach ($g in $gpus) {
        $mem = if ($g.AdapterRAM -and $g.AdapterRAM -gt 0) { [math]::Round($g.AdapterRAM / 1GB, 2) } else { $null }
        [pscustomobject]@{
            Name          = $g.Name
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

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        User         = "$env:USERDOMAIN\$env:USERNAME"
        OS           = "$($os.Caption) ($($os.Version), Build $($os.BuildNumber))"
        Arch         = $os.OSArchitecture
        LastBoot     = $os.LastBootUpTime
        CPU          = $cpu.Name
        Cores        = $cpu.NumberOfCores
        LogicalCPUs  = $cpu.NumberOfLogicalProcessors
        ClockMHz     = $cpu.MaxClockSpeed
        RAM_GB       = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        FreeRAM_GB   = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
        GPUs         = $gpuInfo
        Disks        = $disks
        PageFile     = $pf
        IsAdmin      = (Test-IsAdmin)
    }
}) 
Write-Ok

# -----------------------------------------------------------------------------
# 5. Prerequisites
# -----------------------------------------------------------------------------
Write-Stage "Checking prerequisites..."
$netFx = Get-DotNetFrameworkVersion
$vc    = @(Get-VCRedist)
Write-Host " .NET=$netFx, VC++=$($vc.Count) entries." -ForegroundColor Green

# -----------------------------------------------------------------------------
# 6. Per-product checks
# -----------------------------------------------------------------------------
function Get-ProductStatus {
    param([hashtable]$Entry, [array]$Installed, [pscustomobject]$System,
          [string]$NetFx, [array]$VC, [switch]$DeepScan)

    $status = [ordered]@{
        Name        = $Entry.N
        Disciplines = ($Entry.D -join ', ')
        Kind        = $Entry.K
        Installed   = $false
        Version     = ''
        Match       = ''
        State       = 'Red'
        Issues      = @()
        Notes       = @()
        CacheGB     = 0
    }

    $hits = @()
    foreach ($pat in $Entry.P) {
        $hits += $Installed | Where-Object { $_.DisplayName -like $pat }
    }
    $hits = $hits | Sort-Object DisplayName -Unique

    if (-not $hits) {
        $status.State  = 'Red'
        $status.Issues += 'Not installed / not detected on this PC'
        return [pscustomobject]$status
    }
    $status.Installed = $true
    $status.Version   = (($hits | ForEach-Object { $_.DisplayVersion } |
                          Where-Object { $_ } | Sort-Object -Unique) -join ', ')
    $status.Match     = ($hits.DisplayName -join ' | ')

    if ($Entry.RAM -and $System.RAM_GB -lt $Entry.RAM) {
        $status.Issues += "RAM below recommended minimum ($($System.RAM_GB) GB < $($Entry.RAM) GB)"
    }
    if ($Entry.Disk) {
        $sysd = $System.Disks | Where-Object Drive -eq "$($env:SystemDrive)"
        if ($sysd -and $sysd.FreeGB -lt $Entry.Disk) {
            $status.Issues += "Free disk on $($sysd.Drive) low ($($sysd.FreeGB) GB < $($Entry.Disk) GB recommended)"
        }
    }
    if ($Entry.GPU) {
        $hasDedicated = $false
        foreach ($g in $System.GPUs) { if ($g.VRAM_GB -and $g.VRAM_GB -ge 2) { $hasDedicated = $true } }
        if (-not $hasDedicated) { $status.Issues += 'Dedicated GPU with >=2 GB VRAM recommended' }
    }
    if ($Entry.Net) {
        if (-not (Compare-NetVersion -Have $NetFx -Need $Entry.Net)) {
            $status.Issues += ".NET Framework $($Entry.Net) or newer required (have: $NetFx)"
        }
    }
    if ($Entry.VCPP -and (-not $VC -or $VC.Count -eq 0)) {
        $status.Issues += 'Microsoft Visual C++ Redistributables not detected'
    }
    if ($Entry.Lsvc) {
        $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object {
            $n = $_.Name + ' ' + $_.DisplayName
            foreach ($pat in $Entry.Lsvc) { if ($n -like $pat) { return $true } }
            return $false
        }
        if ($svc) {
            $running = @($svc | Where-Object Status -eq 'Running').Count
            if ($running -eq 0) { $status.Issues += 'License/vendor services installed but not running' }
        }
    }
    if ($Entry.Lport) {
        $openAny = $false
        foreach ($p in $Entry.Lport) {
            try {
                $t = Test-NetConnection -ComputerName 'localhost' -Port $p -InformationLevel Quiet `
                                        -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                if ($t) { $openAny = $true }
            } catch { }
        }
        if (-not $openAny) {
            $status.Notes += "License ports not open locally ($($Entry.Lport -join ', ')) — normal for node-locked or remote licence servers"
        }
    }
    if ($DeepScan -and $Entry.Cache) {
        $total = 0
        foreach ($c in $Entry.Cache) { $total += (Get-FolderSizeGB -Path (Expand-Env $c)) }
        $status.CacheGB = [math]::Round($total, 2)
        if ($total -gt 20) {
            $status.Notes += "Cache is large ($($status.CacheGB) GB) — safe to clear if the app is closed"
        }
    }

    if (-not $status.Installed)         { $status.State = 'Red' }
    elseif ($status.Issues.Count -gt 0) { $status.State = 'Yellow' }
    else                                { $status.State = 'Green' }

    return [pscustomobject]$status
}

Write-Stage "Checking every product in the catalog..."
$allResults = New-Object System.Collections.Generic.List[object]
foreach ($entry in $Script:RawCatalog) {
    $allResults.Add((Get-ProductStatus -Entry $entry -Installed $installed -System $sys `
                                        -NetFx $netFx -VC $vc -DeepScan:$deepScan))
}
$gCount = @($allResults | Where-Object State -eq 'Green').Count
$yCount = @($allResults | Where-Object State -eq 'Yellow').Count
$rCount = @($allResults | Where-Object State -eq 'Red').Count
Write-Host " $gCount green / $yCount yellow / $rCount red." -ForegroundColor Green

# -----------------------------------------------------------------------------
# 7. Discipline rollup
# -----------------------------------------------------------------------------
Write-Head "Discipline rollup"
$byDisc = @{}
foreach ($r in $allResults) {
    foreach ($d in ($r.Disciplines -split ',\s*')) {
        if (-not $byDisc.ContainsKey($d)) { $byDisc[$d] = @() }
        $byDisc[$d] += $r
    }
}
foreach ($d in $byDisc.Keys | Sort-Object) {
    $rs    = $byDisc[$d]
    $green = @($rs | Where-Object State -eq 'Green').Count
    $yell  = @($rs | Where-Object State -eq 'Yellow').Count
    $red   = @($rs | Where-Object State -eq 'Red').Count
    $total = $rs.Count
    $bar   = ('#' * $green) + ('=' * $yell) + ('.' * $red)
    Write-Host ("  {0,-18} {1,2}/{2,2} green  {3,2} yellow  {4,2} red   [{5}]" `
                -f $d, $green, $total, $yell, $red, $bar) -ForegroundColor Cyan
}

# -----------------------------------------------------------------------------
# 8. Write report
# -----------------------------------------------------------------------------
Write-Stage "Writing report (HTML / JSON / CSV)..."
Ensure-Folder $exportPath

[pscustomobject]@{
    GeneratedAt = (Get-Date).ToString('s')
    System      = $sys
    NetFx       = $netFx
    VCRedist    = $vc
    Results     = $allResults
} | ConvertTo-Json -Depth 8 | Set-Content "$reportBase.json" -Encoding UTF8

$allResults | Select-Object Name, Disciplines, Kind, State, Version, Installed,
                              @{n='Issues';e={$_.Issues -join ' | '}},
                              @{n='Notes'; e={$_.Notes  -join ' | '}} |
    Export-Csv "$reportBase.csv" -NoTypeInformation -Encoding UTF8

$style = @"
<style>
 body{font-family:'Segoe UI',Arial,sans-serif;margin:24px;color:#1a1a1a;background:#f7f8fa}
 h1{color:#0b5394;margin-bottom:4px}
 h2{color:#0b5394;margin-top:28px;border-bottom:2px solid #dde3ec;padding-bottom:4px}
 h3{color:#222;margin-top:20px}
 .sub{color:#555;font-size:12px;margin-top:0}
 .card{background:#fff;border:1px solid #e0e4ea;border-radius:8px;padding:14px 18px;margin:10px 0;box-shadow:0 1px 2px rgba(0,0,0,.03)}
 table{border-collapse:collapse;width:100%;margin:8px 0 16px 0;font-size:13px;background:#fff}
 th,td{border:1px solid #e0e4ea;padding:6px 8px;text-align:left;vertical-align:top}
 th{background:#eef2f8}
 tr:nth-child(even) td{background:#fafbfd}
 .chip{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff}
 .green{background:#1c9b4b}.yellow{background:#d18b00}.red{background:#c23636}
 .small{font-size:12px;color:#666}
 .disc{border-left:4px solid #0b5394;padding-left:10px;margin-top:22px}
</style>
"@
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("<!doctype html><html><head><meta charset='utf-8'><title>Sigma Engineer Toolkit — Report</title>$style</head><body>")
[void]$sb.AppendLine("<h1>Sigma Engineer Toolkit</h1>")
[void]$sb.AppendLine("<p class='sub'>Generated $(Get-Date) on $($sys.ComputerName) by $($sys.User)</p>")

[void]$sb.AppendLine("<div class='card'><h3>Machine</h3><table>")
foreach ($kv in @(
    @('OS',$sys.OS), @('Architecture',$sys.Arch),
    @('CPU',"$($sys.CPU) ($($sys.Cores)C/$($sys.LogicalCPUs)T)"),
    @('RAM',"$($sys.RAM_GB) GB (free $($sys.FreeRAM_GB) GB)"),
    @('.NET Framework',$netFx),
    @('VC++ Redistributables', $vc.Count),
    @('PowerShell', $PSVersionTable.PSVersion.ToString()),
    @('Admin', $sys.IsAdmin)
)) { [void]$sb.AppendLine("<tr><th style='width:220px'>$($kv[0])</th><td>$($kv[1])</td></tr>") }
[void]$sb.AppendLine("</table></div>")

[void]$sb.AppendLine("<div class='card'><h3>Graphics</h3><table><tr><th>GPU</th><th>Driver</th><th>Date</th><th>VRAM (GB)</th></tr>")
foreach ($g in $sys.GPUs) {
    [void]$sb.AppendLine("<tr><td>$($g.Name)</td><td>$($g.DriverVersion)</td><td>$($g.DriverDate)</td><td>$($g.VRAM_GB)</td></tr>")
}
[void]$sb.AppendLine("</table></div>")

[void]$sb.AppendLine("<div class='card'><h3>Disks</h3><table><tr><th>Drive</th><th>Label</th><th>FS</th><th>Size GB</th><th>Free GB</th><th>Free %</th></tr>")
foreach ($d in $sys.Disks) {
    $cls = if ($d.FreePct -lt 10) {'red'} elseif ($d.FreePct -lt 20) {'yellow'} else {'green'}
    [void]$sb.AppendLine("<tr><td>$($d.Drive)</td><td>$($d.Label)</td><td>$($d.FS)</td><td>$($d.SizeGB)</td><td>$($d.FreeGB)</td><td><span class='chip $cls'>$($d.FreePct)%</span></td></tr>")
}
[void]$sb.AppendLine("</table></div>")

$green = @($allResults | Where-Object State -eq 'Green').Count
$yell  = @($allResults | Where-Object State -eq 'Yellow').Count
$red   = @($allResults | Where-Object State -eq 'Red').Count
$total = $allResults.Count
[void]$sb.AppendLine("<h2>Overall</h2><div class='card'>")
[void]$sb.AppendLine("<p><span class='chip green'>$green green</span> &nbsp; <span class='chip yellow'>$yell yellow</span> &nbsp; <span class='chip red'>$red red</span> &nbsp; of $total checked</p></div>")

[void]$sb.AppendLine("<h2>Disciplines</h2>")
foreach ($d in $byDisc.Keys | Sort-Object) {
    $rs = $byDisc[$d] | Sort-Object State, Name
    $g  = @($rs | Where-Object State -eq 'Green').Count
    $y  = @($rs | Where-Object State -eq 'Yellow').Count
    $rr = @($rs | Where-Object State -eq 'Red').Count
    [void]$sb.AppendLine("<div class='disc'><h3>$d <span class='small'>($g green / $y yellow / $rr red)</span></h3>")
    [void]$sb.AppendLine("<table><tr><th>Software</th><th>Kind</th><th>Status</th><th>Version</th><th>Issues / Notes</th></tr>")
    foreach ($p in $rs) {
        $cls = switch ($p.State) { 'Green'{'green'} 'Yellow'{'yellow'} default {'red'} }
        $msg = @()
        foreach ($i in $p.Issues) { $msg += "! $i" }
        foreach ($n in $p.Notes ) { $msg += ". $n" }
        $msg = $msg -join '<br>'
        [void]$sb.AppendLine("<tr><td><b>$($p.Name)</b></td><td>$($p.Kind)</td><td><span class='chip $cls'>$($p.State)</span></td><td>$($p.Version)</td><td class='small'>$msg</td></tr>")
    }
    [void]$sb.AppendLine("</table></div>")
}

[void]$sb.AppendLine("<p class='small'>End of report. Yellows and reds are advisory, not errors.</p>")
[void]$sb.AppendLine("</body></html>")
$sb.ToString() | Set-Content "$reportBase.html" -Encoding UTF8
Write-Ok

# -----------------------------------------------------------------------------
# 9. Final commit
# -----------------------------------------------------------------------------
Write-Stage "Finalising..."
$null = Get-Item "$reportBase.html" -ErrorAction SilentlyContinue
Write-Ok

# -----------------------------------------------------------------------------
# 10. Error summary
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# 11. Final prompt
# -----------------------------------------------------------------------------
$finalChoice = Read-Host "Press R to open the report folder, or Q to quit"

if ($finalChoice -eq "R" -or $finalChoice -eq "r") {
    Start-Process $exportPath
} else {
    exit 0
}
