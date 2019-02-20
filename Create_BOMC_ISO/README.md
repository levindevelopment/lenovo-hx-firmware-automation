Performs download/iso creation purely in powershell with TXT config files for storing the best recipe firmware names.
No external tools like wget and unzip are required, since Powershell has built in functionality for performing downloads and unzips.

Still requires manual download the BOMC Boot archive (640MB).
When you just run BOMC (gui), it will download missing LXCE UX and BOMC Boot as part of the process, but when running in CLI mode it fails to do that.

Requires manually specifying the version of BOMC in the script so it can download it and then copy it where it’s required to create the ISOs.

After the Boot files are extracted, the ZIP file is left behind in the working dir and included in the ISO. Which means the boot files are on the iso twice, once where they are actually used and once as an archive adding 640MB to the image size.
