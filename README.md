# Windows 11 Clean Install

### Very small and compatible set of scripts to streamline, optimize and automatically cleanup Windows 11 upon install of any official version.

Automatically bypasses hardware checks, optimizes the NTFS file system on your drives, removes the majority of the bloat, and adjusts a few QoL registry tweaks/policies.
The install process is streamlined to get you into a local user account as soon as possible. No Microsoft account needed.

Recommended to use with Windows 11 Pro or Enterprise (IoT/LTSC) edition. Home edition is untested, but should still work effectively.
(Group Policy tweaks do not work on Home edition.)

These scripts are designed to be as vanilla as possible, with no visibility or interaction, and very compatible with updates.

The main script is split between _specialize.ps1_ during the initial setup on first boot; and _setupcomplete.ps1_ on the second boot before the OOBE starts.

These scripts and all registry tweaks can be found and customized for your needs under _sources\\$OEM$\\$$\\Setup\\Scripts_.

#### How to use:
 1. Get the latest Windows 11 install media on your USB/ISO (see https://www.microsoft.com/software-download/windows11)
 2. Download this repo and place "sources" and "autounattend.xml" into the root of your Windows 11 install media
 3. Install Windows 11 with a fresh install from boot (upgrading/refreshing will probably not work)
 4. Don't forget to set your time zone in Settings! (unfortunately not available during setup)

To disable automatically setting Dark theme on first login, delete the "Roaming" folder under "sources\\$OEM$\\$1\\Users\\Default\\AppData". _Do not delete "Local"!_
