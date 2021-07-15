Lenovo ThinkAgile HX Firmware Automation Tool 

Performs download/iso creation purely in powershell with TXT config files for storing the best recipe firmware names.
No external tools like wget and unzip are required, since Powershell has built in functionality for performing downloads and unzips.


Changes:

- Updated to allow local policies file processing of firmware updates.

Use:
- Place the Create_BOMC_ISOs_from_XML.ps1 powershell script in any directory
- Policy folder with applicable XML for *only* your deployed systems should be placed in the same directory as the powershell
- Start Powershell with Administrator privledges
- Run the powershell script. No options are required.

The script will create a directory named ThinkAgile on your primary volume and download all required files to create the ISO.


![Directory Structure](/Create_BOMC_ISO/staging_structure.png)


Lenovo HX Best Recipe 4.9
https://support.lenovo.com/au/en/solutions/ht505413-thinkagile-hx-best-recipes
