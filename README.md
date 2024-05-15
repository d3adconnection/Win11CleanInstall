# Windows 11 Clean Install

### Very small and compatible script to streamline, optimize and automatically cleanup Windows 11 upon install of any official version.

Automatically bypasses hardware checks, optimizes the NTFS file system on your drives, removes the majority of the bloat, and adjusts a few QoL registry tweaks/policies.

Recommended to use with Windows 11 Pro or Enterprise edition, but should still work effectively on Home edition.

Designed to be as vanilla as possible, with no visibility or interaction, and very compatible with updates.

#### How to use:
 1. Get the latest Windows 11 install media on your USB/ISO (see https://www.microsoft.com/software-download/windows11)
 2. Download this repo and place "sources" and "autounattend.xml" into the root of your Windows 11 install media
 3. Install Windows 11 with a fresh install from boot (upgrading/refreshing will probably not work)

To disable automatically setting Dark theme on login, delete the "Roaming" folder under "sources\\$OEM$\\$1\\Users\\Default\\AppData". _Do not delete "Local"!_

To see what the script changes, open "sources\\$OEM$\\$$\\Setup\\Scripts\\specialize.ps1".