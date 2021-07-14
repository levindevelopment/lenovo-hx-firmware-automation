Lenovo ThinkAgile HX Firmware Automation Tool 

Performs download/iso creation purely in powershell with TXT config files for storing the best recipe firmware names.
No external tools like wget and unzip are required, since Powershell has built in functionality for performing downloads and unzips.

Requires manually specifying the version of BOMC (if change required) in the script so it can download it and then copy it where it’s required to create the ISOs.

After the Boot files are extracted, the ZIP file is left behind in the working dir and included in the ISO. Which means the boot files are on the iso twice, once where they are actually used and once as an archive adding 640MB to the image size.

Updated to allow local policies file processing of firmware updates.

Use:
- Create_BOMC_ISOs_from_XML.ps1
- Policy folder with applicable XML for *only* your deployed systems should be placed in the same directory as the powershell


![Directory Structure](/Create_BOMC_ISO/staging_structure.png)


Lenovo HX Best Recipe 4.9
https://support.lenovo.com/au/en/solutions/ht505413-thinkagile-hx-best-recipes
