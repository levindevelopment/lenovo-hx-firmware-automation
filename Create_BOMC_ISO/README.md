
  _                                  _______ _     _       _                  _ _        _    ___   __
 | |                                |__   __| |   (_)     | |      /\        (_| |      | |  | \ \ / /
 | |     ___ _ __   _____   _____      | |  | |__  _ _ __ | | __  /  \   __ _ _| | ___  | |__| |\ V / 
 | |    / _ | '_ \ / _ \ \ / / _ \     | |  | '_ \| | '_ \| |/ / / /\ \ / _` | | |/ _ \ |  __  | > <  
 | |___|  __| | | | (_) \ V | (_) |    | |  | | | | | | | |   < / ____ | (_| | | |  __/ | |  | |/ . \ 
 |______\___|_| |_|\___/ \_/ \___/     |_|  |_| |_|_|_| |_|_|\_/_/    \_\__, |_|_|\___| |_|  |_/_/ \_\
 Firmware Automation PS                                                  __/ |                        
                                                                        |___/                         

Performs download/iso creation purely in powershell with TXT config files for storing the best recipe firmware names.
No external tools like wget and unzip are required, since Powershell has built in functionality for performing downloads and unzips.

Requires manually specifying the version of BOMC (if change required) in the script so it can download it and then copy it where it’s required to create the ISOs.

After the Boot files are extracted, the ZIP file is left behind in the working dir and included in the ISO. Which means the boot files are on the iso twice, once where they are actually used and once as an archive adding 640MB to the image size.

Updated to allow local policies file processing of firmware updates.

Use:
- Create_BOMC_ISOs_from_XML.ps1
- Policy folder with applicable XML for *only* your deployed systems should be placed in the same directory as the powershell

/
├── <Staging dir>/
    ├── Create_BOMC_ISOs_from_XML.ps1
    └── policies/
        ├── BestRecipe_4-0_7X82-7Y88-7Z03_HX372x.xml
        ├── BestRecipe_4-0_7X83-7Y89-7Z04_HXx32x.xml
        └── BestRecipe_4-0_7X84-7Y90-7Z05_HXx52x.xml


NOTE: The latest 2.4.0 version of Lenovo XClarity Administrator must be used with this script.
https://support.lenovo.com/au/en/solutions/lnvo-lxcaupd

Lenovo HX Best Recipe 4.0
https://support.lenovo.com/us/en/solutions/ht508432
