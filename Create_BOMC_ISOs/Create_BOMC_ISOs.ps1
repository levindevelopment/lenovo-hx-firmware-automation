# This script will:
# - automatically download Lenovo OneCLI and BOMC using BITS
# - download BOMC Boot files and XClarity Update XPress using OneCLI
# - download the specified Best Recipe firmware files for particular models of ThinkAgile HX Servers
# - create a Best Recipe ISO for the specified models

# The latest versions/URLs for the tools must be manually specified in the swection below.

# The Best Recipes must be stored as TXT files using the following example 7X83_7Y89_7Z04.txt
# The TXT file must contain one firware version per line; lines containing '#' will be ignored


#ThinkAgile Best Recipe Webpage: https://support.lenovo.com/au/en/solutions/HT505413
#OneCli Webpage: https://support.lenovo.com/au/en/solutions/lnvo-tcli
#BOMC Webpage: https://datacentersupport.lenovo.com/au/en/solutions/lnvo-bomc

#Update the following URLs etc to the latest supported versions
$OneCliUrl = "http://download.lenovo.com/servers/mig/2018/11/16/19601/lnvgy_utl_lxce_onecli01a-2.4.1_winsrv_x86-64.zip"
$BomcUrl = "http://download.lenovo.com/servers/mig/2018/10/01/19235/lnvgy_utl_lxce_bomc01r-11.4.0_windows_i386.exe"
$UXVersion = "lnvgy_utl_lxce_ux_2.4.0_anyos_x86-64" #Note: must be anyos
$BomcBoot = "lnvgy_utl_boot_bomc-1.0.0-1.2.1" #won't autodownload from bomc cli, but can download from bomcgui

#Best Recipe txt files must be created for these models to automatically download the firmware files
$Models = @("7X83_7Y89_7Z04","7X84_7Y90_7Z05","7X82_7Y88_7Z03")

Import-Module BitsTransfer

#Ensure Powershell is running as Admin
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    Break
}


$ScriptPath = $MyInvocation.MyCommand.Path | Split-Path
$TAPath = "$env:HOMEDRIVE\ThinkAgile"
$UtilPath = $TAPath + "\1\utils"
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

write-host "`nTOOLSET READY!`n"
#------------------------------------------------------------------------------


foreach ($Model in $Models) {
    write-host "Processing: " -NoNewLine
    write-host $Model -fore Cyan
    $ModelPath = "$TAPath\1\$Model"
    $BRfile = "$ScriptPath\$Model.txt"
    if (CheckPath $BRfile) {
    #create the folders
    if (-not (CheckPath "$ModelPath\update")) { CreateFolder "$ModelPath\update" }
    if (-not (CheckPath "$ModelPath\logs")) {
        CreateFolder "$ModelPath\logs"
    } else {
        Remove-Item "$ModelPath\logs\*" -Recurse
    }

    #Check/Copy LXCE UX
    if (-not (CheckPath "$ModelPath\update\$UXversion.tgz")) {
        write-host "Copying LXCE Update Xpress from " -NoNewline
        write-host $UtilPath\bomc -Fore Cyan -NoNewline
        write-host " to " -NoNewline
        write-host "$ModelPath\update. " -NoNewline -fore cyan
        copy "$UtilPath\bomc\$UXversion.*" "$ModelPath\update\"
        write-host "Done!" -fore Green
    }

    #Check/Copy BOMC Boot
    if (-not (CheckPath "$ModelPath\$BomcBoot.zip")) {
        write-host "Copying BOMC Boot from " -NoNewline
        write-host $UtilPath\bomc -Fore Cyan -NoNewline
        write-host " to " -NoNewline
        write-host "$ModelPath " -NoNewline -fore cyan
        copy "$UtilPath\bomc\$BomcBoot.*" "$ModelPath\"
        write-host "Done!" -fore Green
    }

    #Download Best Recipe Firmware files
        write-host "`nAcquiring firmwares..."
        $haveFirmware = $True
        $count = 0
        $FWlist = (gc -Path $BRfile | Where-Object {$_ -notlike '*#*'}).Split("`n")
        foreach ($FW in $FWlist) {
            $count += 1
            write-host "  OneCLI acquiring " -NoNewLine
            write-host $FW -NoNewline -fore cyan
            $params = ("update acquire --scope individual --nosupersede --includeid $FW --dir $TAPath\1\7X83_7Y89_7Z04 --output $TAPath\1\7X83_7Y89_7Z04\logs").split(" ")
            write-host ((((& "$OneCliExe" $params) 2>&1 | Out-String).Split("`n") | where {$_ -like "*$FW*"}).ToString().Replace($FW,"")).Trim() -fore Green
            if ($LastExitCode -eq 1) {
                write-host "OneCli FAILED!" -fore Red
                $haveFirmware = $False
                break
            }
        }
        write-host "$count firmware packages acquired for $Model."
    } else {
        write-host "Best Recipe is missing! Skipping Models $Model!" -fore Red
        $haveFirmware = $False
    }
    write-host "`n"
    
    #Make ISO if Firmware update didn't error
    if ($haveFirmware) {
        write-host "Generating " -NoNewLine
        write-host "$Model.iso..." -NoNewline -fore cyan
        $ISOpath = "$TAPath\1\$Model.iso"
        $ModelList = $Model.Replace("_", ",")
        $params = ("--description=$Model --force --boot-by-thinksystem --function=update --arch=x64 --no-acquire --tui -m $ModelList --iso=$TAPath\1\$Model.iso -l $ModelPath").split(" ")
        (&"$BomcExe" $params) 2>&1
        if ($LastExitCode -eq 1) {
            write-host "FAILED!" -fore Red
            break
        } else {
            write-host "Done!" -fore Green
        }
    }
}     