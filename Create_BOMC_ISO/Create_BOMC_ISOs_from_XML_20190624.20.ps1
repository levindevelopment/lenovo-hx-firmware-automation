# Script: Create_BOMC_ISOs_from_XML_20190624.20.ps1
# Version: 20190624 rev 20
# 
# This script will:
# - automatically download Lenovo OneCLI and BOMC using BITS
# - download BOMC Boot files and XClarity Update XPress using OneCLI
# - download the specified Best Recipe firmware files for particular models of ThinkAgile HX Servers
# - create a Best Recipe ISO for the specified models based on pre-created Best Recipe XML policy files in the .\policies folder

# The latest versions/URLs for the tools must be manually specified in the swection below.

# The Best Recipes must be stored as XML files in the .\policies folder
# The ISO will be named according to suppored models in the Best Recipe policy

#ThinkAgile Best Recipe Webpage: https://support.lenovo.com/au/en/solutions/HT505413
#OneCli Webpage: https://support.lenovo.com/au/en/solutions/lnvo-tcli
#BOMC Webpage: https://datacentersupport.lenovo.com/au/en/solutions/lnvo-bomc

#Update the following URLs etc to the latest supported versions
$OneCliUrl = "http://download.lenovo.com/servers/mig/2019/04/10/19876/lnvgy_utl_lxce_onecli01v-2.5.0_winsrv_x86-64.zip"
$BomcUrl = "http://download.lenovo.com/servers/mig/2019/05/30/20316/lnvgy_utl_lxce_bomc01m-11.5.1_windows_i386.exe"
$UXVersion = "lnvgy_utl_lxce_ux_2.5.0_anyos_x86-64" #Note: must be anyos
$BomcBoot = "lnvgy_utl_boot_bomc-1.0.0-1.3.6" #won't autodownload from bomc cli, but can download from bomcgui


Import-Module BitsTransfer

#Ensure Powershell is running as Admin
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    Break
}

$ScriptPath = $MyInvocation.MyCommand.Path | Split-Path
$PoliciesPath = $ScriptPath + "\policies"
$TAPath = "$env:HOMEDRIVE\ThinkAgile"
$UtilPath = $TAPath + "\1\utils"
$UpdatesDLPath = $TAPath + "\1\UpdateDownloads"
$OneCliFile = $UtilPath + "\" + (split-path $OneCliUrl -Leaf)
$BomcExe = $UtilPath + "\bomc\" + (split-path $BomcUrl -Leaf)
$OneCliExe = "$UtilPath\onecli\onecli.exe"

#============================================
#FUNCTIONS

#Check if a file/folder exists and output status.
function CheckPath ($folder) {
    write-host "Checking for " -NoNewLine
    write-host $folder -NoNewline -fore Cyan
    write-host ". " -NoNewline
    if (Test-Path $folder) {
        write-host "Success!" -fore Green
        return $True
    } else {
        write-host "Failed!" -fore Red
        return $False
    }
}

#Attempt to create a folder and BREAK if it fails
function CreateFolder ($folder) {
    write-host "Creating " -NoNewLine
    write-host $folder -NoNewline -fore Cyan
    write-host ". " -NoNewline
    mkdir $folder -Force 2>&1
    if (Test-Path $folder) {
        write-host "Success!" -fore Green
    } else {
        write-host "Failed!" -fore Red
        break
    }
}

#------------------------------------------------------------------------------
write-host "PREPARING TOOLSET"
write-host "=================`n"

#Create Folder Structure if it doesn't exist
if (-not (CheckPath "$UtilPath\bomc\log")) { CreateFolder "$UtilPath\bomc\log" }
if (-not (CheckPath $UpdatesDLPath)) { CreateFolder $UpdatesDLPath }

#Copy the required tools across
#NOT CURRENTLY REQUIRED
#if (CheckPath "$ScriptPath\stage") {
#    write-host "Copying required tools from " -NoNewLine
#    write-host "$ScriptPath\stage" -fore Cyan -NoNewline
#    write-host " to " -NoNewline
#    write-host "$UtilPath. " -fore Cyan -NoNewLine
#    copy "$ScriptPath\stage\*" "$UtilPath\" -Recurse -Exclude "wget.exe", "unzip.exe"
#    write-host "Done!" -fore Green
#}

#Download OneCli and BOMC if they don't exist
if (-not (CheckPath $BomcExe)) {
    write-host 'Downloading BOMC using BITS...' -NoNewLine
    Start-BitsTransfer -source $BomcUrl -Destination "$UtilPath\bomc" -DisplayName "Downloading BOMC..."
    write-host "Done!" -fore Green
    if (-not (CheckPath $BomcExe)) {
        write-host "$BomcExe still missing! Download Failed!" -fore Red
        Break
    }
}

#Download and Extract OneCLI if OneCli.exe is missing
$haveOneCliExe = $False
$haveOneCliFile = $False

if (-not (CheckPath $OneCliExe)) {
    if (-not(CheckPath $OneCliFile)) {
        write-host "Downloading OneCLI using BITS..." -NoNewLine
        Start-BitsTransfer -source $OneCliUrl -Destination "$UtilPath\" -DisplayName "Downloading OneCLI..."
        write-host "Done!" -fore Green
        if (CheckPath $OneCliFile) {
            $haveOneCliFile = $True
        } else {
            write-host "$OneCliFile still missing! EXITING!" -fore Red
            break
        }
    } else {
        $haveOneCliFile = $True
    }
} else {
    $haveOneCliExe = $True
}

#script only gets here if OneCliFile and/or OneCliExe exist
if (-not $haveOneCliExe -and $haveOneCliFile) {
    Write-Host "Extracting OneCLI..." -NoNewLine
    Expand-Archive $OneCliFile -DestinationPath "$UtilPath\onecli" -force
    write-host "Done!" -fore Green
    if (-not (CheckPath $OneCliExe)) {
        write-host "$OneCliExe still missing! EXITING!" -fore Red
        break
     }
}

#script only gets here once OneCliExe exists
$OneCliVersion = ((&"$OneCliExe") 2>&1 | Out-String).Split("`n") | where {$_ -Like "Lenovo*"}
write-host "OneCli Version: " -NoNewLine
write-host $OneCliVersion -fore Green

#Download LXCE UpdateExpress
if (-not (CheckPath "$UtilPath\bomc\$UXVersion.tgz")) {
    write-host "Downloading LXCE Update Xpress..." -NoNewLine
    $params = ("update acquire --scope individual --includeid $UXVersion --dir $UtilPath\bomc --output $UtilPath\bomc\log").split(" ")
    (& "$OneCliExe" $params)
    if ($LastExitCode -eq 1) {
        write-host "FAILED!" -fore Red
        break
    } else {
        write-host "Done!" -fore Green
    }
}

#Download BOMC Boot files
if (-not (CheckPath "$UtilPath\bomc\$BomcBoot.zip")) {
    write-host "Downloading BOMC Boot Files (640MB+ this will take a while)..." -NoNewLine
    $params = ("update acquire --scope individual --includeid $BomcBoot --dir $UtilPath\bomc --output $UtilPath\bomc\log").split(" ")
    (& "$OneCliExe" $params)
    if ($LastExitCode -eq 1) {
        write-host "FAILED!" -fore Red
        break
    } else {
        write-host "Done!" -fore Green
    }
}

if (-not (CheckPath $PoliciesPath)) {
    write-host "$PoliciesPath does not exist! Please create and populate with Best Recipe Policy XMLs." -fore Red
    break
}
write-host "`nTOOLSET READY!`n"
#------------------------------------------------------------------------------

#Process the Policy Files; each policy file creates one ISO
foreach ($PolicyFile in (Get-ChildItem $PoliciesPath | where {! $_.PSIsContainer})) {
    write-host "Processing: " -NoNewLine
    write-host $PolicyFile -fore Cyan
    [xml]$PolicyXML = Get-Content $PolicyFile.FullName
    #Create the list of supported systems 
    $Models = ""
    foreach ($SystemType in $PolicyXML.policy.details.mt.systemtype) {
    #foreach ($SystemType in $SystemTypes) {
        if ($Models -eq "") {
            $Models = $SystemType
        } elseif (! $Models.Contains($SystemType)) {
            $Models = $Models + "_" + $SystemType
        }
    }
    write-host "Supported Models:" -NoNewLine
    write-host $Models -fore Cyan
    $ModelPath = "$TAPath\1\$Models"

    #Wipe/Recreate the Model folders
    if (CheckPath "$ModelPath") { Remove-Item $ModelPath -Recurse -Force } 
    CreateFolder "$ModelPath\update"
 
            
    #Copy LXCE UX
    write-host "Copying LXCE Update Xpress from " -NoNewline
    write-host $UtilPath\bomc -Fore Cyan -NoNewline
    write-host " to " -NoNewline
    write-host "$ModelPath\update. " -NoNewline -fore cyan
    copy "$UtilPath\bomc\$UXversion.*" "$ModelPath\update\"
    write-host "Done!" -fore Green
    
    #Copy BOMC Boot
    write-host "Copying BOMC Boot from " -NoNewline
    write-host $UtilPath\bomc -Fore Cyan -NoNewline
    write-host " to " -NoNewline
    write-host "$ModelPath " -NoNewline -fore cyan
    copy "$UtilPath\bomc\$BomcBoot.*" "$ModelPath\"
    write-host "Done!" -fore Green
    

    #Generate an array with the required updates
    $Updates = @()
    foreach ($update in $PolicyXML.policy.details.mt.components.component.targetVersion) {
        if ((! $update.Contains("DoNotUpdate")) -and (! $Updates.Contains($update))) {
            $Updates += $update
        }
    }
 
    #Download Best Recipe Update files
    write-host "`nAcquiring updates..."
    $haveUpdates = $True
    $count = 0
    foreach ($Update in $Updates) {
        $count += 1
        write-host "  OneCLI acquiring " -NoNewLine
        write-host "$Update " -NoNewline -fore cyan
        $params = ("update acquire --scope individual --nosupersede --includeid $Update --dir $UpdatesDLPath --output $UpdatesDLPath\logs").split(" ")
        write-host ((((& "$OneCliExe" $params) 2>&1 | Out-String).Split("`n") | where {$_ -like "*$Update*"}).ToString().Replace($Update,"")).Trim() -fore Green
        if ($LastExitCode -eq 1) {
            write-host "OneCli FAILED!" -fore Red
            $haveUpdates = $False
            break
        }
    }
    write-host "$count updates acquired for $Models."

    #Copy the updates to the Model Folder
    foreach ($Update in $Updates) {
        write-host "Copying " -NoNewline
        write-Host "$Update" -NoNewLine -fore Cyan
        copy "$UpdatesDLPath\$Update.*" "$ModelPath"
    }
    write-host "Required Update files have been copied to " -NoNewline
    write-host $ModelPath -fore Cyan
    write-host "`n"
    
    #Make ISO if Update downloads didn't error
    if ($haveUpdates) {
        $ISOpath = "$TAPath\1\" + $PolicyFile.BaseName + ".iso"
        $ModelList = $Models.Replace("_", ",")
        
        write-host "Generating " -NoNewLine
        write-host $ISOpath -fore cyan
        
        $params = ("--description=$Models --force --function=update --arch=x64 --no-acquire --tui -m $ModelList --iso=$ISOpath -l $ModelPath").split(" ")
        write-host "$params"
		(& "$BomcExe" $params) 2>&1 | %{ "$_" }
        if ($LastExitCode -eq 1) {
            write-host "FAILED!" -fore Red
            break
        } else {
            write-host "Done!`n" -fore Green
        }
    }
}
