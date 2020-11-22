# Xiaomi Gateway 3 python utils
supported: Windows/MacOS/Ubuntu

1. Generated firmware for fw_update.
2. Generate the commands to write boot_info in bootloader
3. Generate the commands for command line of kernel
4. Flash the firmware in bootloader via ethernet/xmodem/uart

# Howto:
##How to flash firmware:

1- install Pythone 3.7 above (if do not want to install Python, use gateway3utils.exe instand)

2- install pip and install requirements
```bash
pip install -r requirements.txt`
```
3-a Update stock firmware to slot 1 by xmodem.
```bash
python gateway3utils.py -x -c [COM PORT] -t all_1 -f firmware_1.4.6_0012.bin
```
3-b Update linux to slot 0 by xmodem.
```bash
python gateway3utils.py -x -c [COM PORT] -t linux_0 -f linux_1.4.6_0012.bin_raw
```
3-c. Update rootfs to slot 0 by xmodem.
```bash
python gateway3utils.py -x -c [COM PORT] -t rootfs_0 -f rootfs_1.4.6_0012.bin_raw
```


##How to backup boot_info/factory/homekit parition:
* Backup factory partition

```bash
python gateway3utils.py -x -c [COM PORT] -t factory -f factory.bin
```
* Backup boot_info partition

```bash
python gateway3utils.py -x -c [COM PORT] -t boot_info -f boot_info.bin
```

##How to generate firmware for fw_update from raw:
* Generate linux firmware for slot 0

```bash
python gateway3utils.py -t linux_0 -f linux_1.4.6_0043.bin
```

##How to generate commands to programming boot_info
1. create boot_info.yaml and fill up sum and size of linux and rootfs etc. (see example boot_info.yaml)
2. then use this util

```bash
python gateway3utils.py -i boot_info.yaml
```

##How to generate password of telnet
Get device id, key, and mac of gateway3
```bash
python gateway3utils.py -e 123668888 -m 80:90:A0:C0:D0:E0 -k XW1ayuHmgLcKlNlL
```
