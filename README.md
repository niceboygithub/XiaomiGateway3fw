# Xiaomi Gateway3 (ZNDMWG03LM, ZNDMWG02LM) Firmware

The repository includes the following feature.

1. binutils

- Use fw_update to update firmware.
- User boot_ctrl switch slot 0 or slot 1.
- Better Busybox
- Dropbearmulti for ssh

2. raw firmware

    If using dd to flash, need to use raw typen with padded (boundary 0x20000).

3. modified firmware

    a. The modified firmwares was enabled tty rx and telnetd.

    b. Use fw_update to update.

4. original firmware

- Roll back to original firmware or upgrade firmware by fw_update.
```
fw_update linux.bin
```
- Update Silicon Lab. EFR32BG by run_ble_dfu.sh, for example:
```
run_ble_dfu.sh /dev/ttyS1 full.gbl_1.4.7_0065.bin 107 1
```

5. stock firmware

6. scripts

   The python script utility to generate firmware, calcuate checksum of boot_info and other functions.
