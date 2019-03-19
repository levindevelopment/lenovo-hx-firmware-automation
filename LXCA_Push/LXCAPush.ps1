# LXCAPush.ps1
# This script will:
# - Display text box for LXCA Server IP(name), username, password and source firmware directory
# - Create a job on LXCA Server and upload firmware


[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 

$objForm = New-Object System.Windows.Forms.Form 
$objForm.Text = "LXCA Upload"
$objForm.Size = New-Object System.Drawing.Size(300,300) 
$objForm.StartPosition = "CenterScreen"

$objForm.KeyPreview = $True
$objForm.Add_KeyDown({if ($_.KeyCode -eq "Enter") 
    {$x=$objTextBox.Text;$objForm.Close()}})
$objForm.Add_KeyDown({if ($_.KeyCode -eq "Escape") 
    {$objForm.Close()}})

$OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Size(75,200)
$OKButton.Size = New-Object System.Drawing.Size(75,23)
$OKButton.Text = "OK"
$OKButton.Add_Click({$objForm.Close()})
$objForm.Controls.Add($OKButton)

$CancelButton = New-Object System.Windows.Forms.Button
$CancelButton.Location = New-Object System.Drawing.Size(150,200)
$CancelButton.Size = New-Object System.Drawing.Size(75,23)
$CancelButton.Text = "Cancel"
$CancelButton.Add_Click({$objForm.Close()})
$objForm.Controls.Add($CancelButton)
##################1
$objLabel = New-Object System.Windows.Forms.Label
$objLabel.Location = New-Object System.Drawing.Size(10,20) 
$objLabel.Size = New-Object System.Drawing.Size(280,20) 
$objLabel.Text = "Please enter LXCA Server Name below:"
$objForm.Controls.Add($objLabel) 

$objTextBox = New-Object System.Windows.Forms.TextBox 
$objTextBox.Location = New-Object System.Drawing.Size(10,40) 
$objTextBox.Size = New-Object System.Drawing.Size(260,20) 
$objForm.Controls.Add($objTextBox) 
#################2
$objLabel2 = New-Object System.Windows.Forms.Label
$objLabel2.Location = New-Object System.Drawing.Size(10,60) 
$objLabel2.Size = New-Object System.Drawing.Size(280,20) 
$objLabel2.Text = "Please enter User below:"
$objForm.Controls.Add($objLabel2) 

$objTextBox2 = New-Object System.Windows.Forms.TextBox 
$objTextBox2.Location = New-Object System.Drawing.Size(10,80) 
$objTextBox2.Size = New-Object System.Drawing.Size(260,20) 
$objForm.Controls.Add($objTextBox2) 
###############3
$objLabel3 = New-Object System.Windows.Forms.Label
$objLabel3.Location = New-Object System.Drawing.Size(10,100) 
$objLabel3.Size = New-Object System.Drawing.Size(280,20) 
$objLabel3.Text = "LxcaPasss:"
$objForm.Controls.Add($objLabel3) 

$objTextBox3 = New-Object System.Windows.Forms.TextBox 
$objTextBox3.Location = New-Object System.Drawing.Size(10,120) 
$objTextBox3.Size = New-Object System.Drawing.Size(260,20) 
$objForm.Controls.Add($objTextBox3) 
###############4
$objLabel4 = New-Object System.Windows.Forms.Label
$objLabel4.Location = New-Object System.Drawing.Size(10,140) 
$objLabel4.Size = New-Object System.Drawing.Size(280,20) 
$objLabel4.Text = "Please enter Local dir below:"
$objForm.Controls.Add($objLabel4) 

$objTextBox4 = New-Object System.Windows.Forms.TextBox 
$objTextBox4.Location = New-Object System.Drawing.Size(10,160) 
$objTextBox4.Size = New-Object System.Drawing.Size(260,20) 
$objForm.Controls.Add($objTextBox4) 

$objForm.Topmost = $True

$objForm.Add_Shown({$objForm.Activate()})
[void] $objForm.ShowDialog()

####

$LxcaIPs=$objTextBox.Text
$LxcaUsers=$objTextBox2.Text
$LxcaPasss=$objTextBox3.Text
$folder=$objTextBox4.Text; 

#### show
$LxcaUsers
$LxcaPasss
$LxcaIPs
$folder
################# VARS
$LxcaUserName = $LxcaUsers
$LxcaPassword = ConvertTo-SecureString $LxcaPasss -AsPlainText –Force
$LxcaIP = $LxcaIPs
#$folder = 


### Parse creds - Do this with above instead
#$cred = Get-Credential
#Connect-LXCA -Host lxca.example.somewhere -Port 443 -Credential $cred -SkipCertificateCheck

#Connect to LXCA server
$cred = New-Object System.Management.Automation.PSCredential($LxcaUserName, $LxcaPassword)
Connect-LXCA $LxcaIP -Credential $cred -SkipCertificateCheck


#####################
$job = Import-LXCAUpdatePackage -Folder $folder -AsJob
while ($job.State -eq "Running") 
{
    Start-Sleep -Seconds 5 
}