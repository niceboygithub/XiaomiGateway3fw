# Xiaomi Gateway 3 python utils (This script is still under developing)
supported: Windows/MacOS/Ubuntu

1. Generated firmware for fw_update.
2. Generate the commands to write boot_info in bootloader
3. Generate the commands for command line of kernel
4. Flash the firmware in bootloader via ethernet/xmodem/uart

# Howto:
How to use this uilts to flash firmware:

1. install Pythone 3.7 above (if do not want to install Python, use gateway3utils.exe instand)
2. pip install -r requirements.txt
3a. Update stock firmware by xmodem.
	`python gateway3utils.py -x -c [COM PORT] -t all_1 -f firmware_1.4.6_0012.bin`
3b. Update linux in slot 0 by xmodem.
	`python gateway3utils.py -x -c [COM PORT] -t linux_0 -f linux_1.4.6_0012.bin_raw`
3c. Update rootfs in slot 0 by xmodem.
	`python gateway3utils.py -x -c [COM PORT] -t rootfs_0 -f rootfs_1.4.6_0012.bin_raw`
