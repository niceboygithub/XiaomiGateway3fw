# Xiaomi Gateway3 (ZNDMWG03LM, ZNDMWG02LM) Firmware

The repository includes the following feature.

1. binutils

	a. Use fw_update to update firmware.

	b. User boot_ctrl switch slot 0 or slot 1.

	c. Better Busybox

	d. Dropbearmulti for ssh
 
2. raw firmware

	If using dd to flash, need to use raw typen with padded (boundary 0x20000).

3. modified firmware

	a. The modified firmwares was enabled tty rx and telnetd.

	b. Use fw_update to update.

4. original firmware

	a. Roll back to original firmware by fw_update.

	b. Update Silicon Lab. EFR32BG by run_ble_dfu.sh
		for example
		'''
		run_ble_dfu.sh /dev/ttyS1 full.gbl_1.4.7_0065.bin 107 1
		'''

5. stock firmware

6. scripts

   The python script utility to generate firmware and other functions.
