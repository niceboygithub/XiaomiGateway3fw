""" burn firmware of gateway 3 """
# pylint: disable=unused-import, too-many-lines
import sys
import os
import time
import threading
import argparse
import binascii
import hashlib
import hmac
import base64
import re

try:
    import tkinter
    import serial
    from serial.tools import list_ports
    from xmodem import XMODEM, XMODEM1k
except ImportError:
    pass
import yaml
try:
    import tftpy
except ImportError:
    pass
try:
    import pyprind
except ImportError:
    pass


def convert_cmdline(cmdline):
    # pylint: disable=line-too-long
    """ convert cmdline string to binary """
    if len(cmdline) <= 1:
        cmdline = "root=/dev/mtdblock6 console=ttyS0,38400 rootfstype=squashfs"
        # cmdline = "root=/dev/ram0 initrd=0x81000000,0x310000 rdinit=/init console=ttyS0,38400 rootfstype=squashfs" # noqa
        # cmdline = "root=/dev/mtdblock8 initrd=0x81000000,0x310000 rdinit=/init console=ttyS0,38400 rootfstype=squashfs" # noqa

    if '\0' not in cmdline[-1]:
        cmdline = '{}\0'.format(cmdline)
    for i in range(0, len(cmdline), 16):
        data = " ".join("{:02x}".format(ord(c)) for c in cmdline[i:i+16])
        print("eb {} {}".format(hex(0x81f00000 + i), data))


def calc_checksum_of_firmware(fwfile, log=False):
    """ calc checksum of firmware """
    if log:
        print("The size of the firmware file {} is {} ({}).".format(
            os.path.basename(fwfile),
            os.stat(fwfile).st_size,
            hex(os.stat(fwfile).st_size)))
    with open(fwfile, 'rb') as f_in:
        raw = f_in.read()
    checksum = 0
    for i in range(0, len(raw), 2):
        data = "{:02x}{:02x}".format(raw[i], raw[i+1])
        checksum = checksum + int(data, 16)
    if log:
        print("Sum: {}, Invert Sum: {}".format(
            hex(checksum & 0xffff),
            hex((0x10000 - (checksum & 0xffff)) & 0xffff)))
    return (0x10000 - (checksum & 0xffff)) & 0xffff


def calc_sum_of_firmware(fwfile, log=False):
    """ calc sum of firmware """
    official_firmware_sum = {
        "linux_1.4.7_0065.bin": 0xcb43,
        "rootfs_1.4.7_0065.bin": 0x742c,
        "linux_1.4.6_0043.bin": 0xc8cc,
        "rootfs_1.4.6_0043.bin": 0x742c,
        "linux_1.4.6_0012.bin": 0xc8cf,
        "rootfs_1.4.6_0012.bin": 0x62c6,
        "linux_1.4.5_0016.bin": 0xe87e,
        "rootfs_1.4.5_0016.bin": 0xa40a
    }
    modified_firmware_sum = {
        "rootfs_1.4.7_0065_modified.bin": 0x742c
    }

    last_calc = False
    nsum = 0xffff
    with open(fwfile, 'rb') as f_in:
        # Read first 4 bytes of data
        while True:
            byte = f_in.read(4)
            if not byte:
                break
            byte0 = int.from_bytes(byte[0:1], byteorder='little')
            byte1 = int.from_bytes(byte[1:2], byteorder='little')
            byte2 = int.from_bytes(byte[2:3], byteorder='little')
            byte3 = int.from_bytes(byte[3:4], byteorder='little')

            if ((byte0 >= 1) or (byte1 >= 1) or (byte2 >= 0xfe)
                    or (byte3 >= 0xfe)):
                nsum = nsum - 1
            if byte0 >= 1 and last_calc:
                if (byte1 >= 1) and (byte2 >= 0xfe):
                    nsum = nsum - 1
            last_calc = ((byte0 >= 1) and (byte1 >= 1) and
                         (byte2 >= 0xfe) and (byte3 >= 0xfe))
            # print(last_calc)
    # The result is wrong, still working on it
    if log:
        print('{}'.format(hex(nsum & 0xFFFF)))

    for key, val in official_firmware_sum.items():
        if key in os.path.basename(fwfile):
            nsum = val
            break

    for key, val in modified_firmware_sum.items():
        if key in os.path.basename(fwfile):
            nsum = val
            break

    if log:
        print('{}'.format(hex(nsum & 0xFFFF)))
    return "{}".format(hex(nsum & 0xFFFF))


def calc_checksum_boot_info(info_file, log=False):
    """ calc_boot_info """
    boot_info = {
        'magic_1': 0x7c,
        'magic_2': 0x91,
        'vernum_1': 0x00,
        'vernum_2': 0x00,
        'check_sum_1': 0xff,
        'check_sum_2': 0xff,
        'kernel_curr': 0x0,
        'rootfs_curr': 0x0,
        'kernel_newest': 0x0,
        'rootfs_newest': 0x0,
        'kernel0_size_1': 0x00,
        'kernel0_size_2': 0x20,
        'kernel0_size_3': 0xec,
        'kernel0_size_4': 0x04,
        'kernel0_checksum_1': 0xcb,
        'kernel0_checksum_2': 0x43,
        'kernel0_fail': 0x0,
        'kernel1_size_1': 0x0,
        'kernel1_size_2': 0x20,
        'kernel1_size_3': 0x74,
        'kernel1_size_4': 0x04,
        'kernel1_checksum_1': 0xe8,
        'kernel1_checksum_2': 0x7e,
        'kernel1_fail': 0x0,
        'rootfs0_size_1': 0x0,
        'rootfs0_size_2': 0x9a,
        'rootfs0_size_3': 0x40,
        'rootfs0_size_4': 0x04,
        'rootfs0_checksum_1': 0x74,
        'rootfs0_checksum_2': 0x2c,
        'rootfs0_fail': 0x0,
        'rootfs1_size_1': 0x0,
        'rootfs1_size_2': 0x75,
        'rootfs1_size_3': 0x90,
        'rootfs1_size_4': 0x04,
        'rootfs1_checksum_1': 0xa4,
        'rootfs1_checksum_2': 0x0a,
        'rootfs1_fail': 0x0,
        'root_sum_check': 0x0,
        'watchdog_time': 0x0,
        'priv_mode': 0x1,
        # 'version': '1.0.2.005',
        'version_1': 0x31,
        'version_2': 0x2e,
        'version_3': 0x30,
        'version_4': 0x2e,
        'version_5': 0x32,
        'version_6': 0x2e,
        'version_7': 0x30,
        'version_8': 0x30,
        'version_9': 0x35,
        'reserved_1': 0x0,
        'reserved_2': 0x0,
        'reserved_3': 0x0,
        'reserved_4': 0x0,
        'reserved_5': 0x0,
    }
    if "yaml" not in sys.modules or not os.path.isfile(info_file):
        print("Yaml file Error!")
        return ""

    with open(info_file, "r") as f_in:
        conf = yaml.safe_load(f_in)
    for i in range(4, 0, -1):
        boot_info['kernel0_size_{}'.format(5 - i)] = (
            conf.get('kernel0_size', 0x0) >> (i - 1) * 8) & 0xff
        boot_info['kernel1_size_{}'.format(5 - i)] = (
            conf.get('kernel1_size', 0x0) >> (i - 1) * 8) & 0xff
        boot_info['rootfs0_size_{}'.format(5 - i)] = (
            conf.get('rootfs0_size', 0x0) >> (i - 1) * 8) & 0xff
        boot_info['rootfs1_size_{}'.format(5 - i)] = (
            conf.get('rootfs1_size', 0x0) >> (i - 1) * 8) & 0xff

    for i in range(2, 0, -1):
        boot_info['kernel0_checksum_{}'.format(3 - i)] = (
            conf.get('kernel0_checksum', 0x0) >> (i - 1) * 8) & 0xff
        boot_info['kernel1_checksum_{}'.format(3 - i)] = (
            conf.get('kernel1_checksum', 0x0) >> (i - 1) * 8) & 0xff
        boot_info['rootfs0_checksum_{}'.format(3 - i)] = (
            conf.get('rootfs0_checksum', 0x0) >> (i - 1) * 8) & 0xff
        boot_info['rootfs1_checksum_{}'.format(3 - i)] = (
            conf.get('rootfs1_checksum', 0x0) >> (i - 1) * 8) & 0xff
    boot_info['kernel0_fail'] = conf.get('kernel0_fail', 0x0)
    boot_info['kernel1_fail'] = conf.get('kernel1_fail', 0x0)
    boot_info['rootfs0_fail'] = conf.get('rootfs0_fail', 0x0)
    boot_info['rootfs1_fail'] = conf.get('rootfs1_fail', 0x0)

    boot_info['kernel_curr'] = conf.get('kernel_curr', 0x0)
    boot_info['rootfs_curr'] = conf.get('rootfs_curr', 0x0)
    boot_info['kernel_newest'] = conf.get('kernel_newest', 0x0)
    boot_info['rootfs_newest'] = conf.get('rootfs_newest', 0x0)

    keys = list(boot_info.keys())
    values = list(boot_info.values())
    for i in range(6, len(keys)):
        if i % 2 == 0:
            if values[i] > values[4]:
                values[5] = values[5] - 1
                values[4] = 256 + values[4] - values[i]
            else:
                values[4] = values[4] - values[i]
        else:
            if values[i] > values[5]:
                values[4] = values[4] - 1
                values[5] = 256 + values[5] - values[i]
            else:
                values[5] = values[5] - values[i]
    new_checksum_1 = '0x{:02x}'.format(values[4])
    new_checksum_2 = '0x{:02x}'.format(values[5])
    if log:
        print('New checksum: {} {}'.format(new_checksum_1, new_checksum_2))
        for i in range(0, len(values), 16):
            data = " ".join("{:02x}".format(c) for c in values[i:i+16])
            print("eb {} {}".format(hex(0xa0a00000 + i), data))
        print("NANDW 0xa0000 0xa0a00000 55")
    commands = ""
    for i in range(0, len(values), 16):
        data = " ".join("{:02x}".format(c) for c in values[i:i+16])
        commands = "{}eb {} {}\n".format(commands, hex(0xa0a00000 + i), data)
    return "{}NANDW 0xa0000 0xa0a00000 55\n".format(commands)


def generate_firmware_for_fw_update(fwfile, fwtype):
    """ generate firmware for fw_update """
    firmware_type = {
        'header': '4D494F540011001307110F05',
        'gbl': '0F133FCDA8FC0404FC040000',
        'linux_0': '6372366380A0000000800000',
        'linux_1': '6372366380A0000000800000',
        'ota-file test': '0002D1DC020003F25318',
        'rootfs_0': '72366372002D000000E00000',
        'rootfs_1': '72366372002D000000E00000',
        'cert': '4D49EF54464F5441'
    }
    firmware_align_size = {
        'linux_0': 0x200,
        'linux_1': 0x200,
        'rootfs_0': 0x800,
        'rootfs_1': 0x800
    }

    if not os.path.exists(fwfile):
        print("The file {} is not exist!".format(fwfile))
        return
    if not firmware_type.get(fwtype):
        print("The type {} is incorrect!".format(fwtype))
        return
    with open(fwfile, 'rb') as f_in:
        raw = f_in.read(16)
        if raw[:4] == b'cr6c' or raw[:4] == b'r6cr':
            print("It is ready for fw_update!")
            return
    data = calc_checksum_of_firmware(fwfile)
    fwsize = os.stat(fwfile).st_size
    filename = "{}_fw_update.bin".format(os.path.splitext(fwfile)[0])
    align_size = firmware_align_size.get(fwtype, 0x200)
    with open(filename, "wb") as f_out:
        if fwsize % align_size >= 1:
            pad_number = align_size - (fwsize % align_size)
        else:
            pad_number = 0
        padding = [0 for _ in range(pad_number + align_size)]
        f_out.write(binascii.unhexlify(firmware_type[fwtype]))
        f_out.write((fwsize + pad_number + align_size + 4).to_bytes(
            4, byteorder='big', signed=False))
        f_out.write(raw)
        if data >= 1:
            f_out.write(bytearray(padding))
            f_out.write(data.to_bytes(4, byteorder='big', signed=False))
    print("Generated {} ({}) done.".format(
        filename, os.stat(filename).st_size))


def extract_firmwares(fwfile):
    """ extract firmwares """

    # 0x2e00 (apploader.bin)
    # sizeof(full.gbl)_and_other_10bytes
    # full.gbl 10bytes linux  ota-files.bin 10bytes rootfs.bin cert

    with open(fwfile, 'rb') as f_in:
        pos = 0x2e03
        # bypass bootloader.gbl
        f_in.seek(pos)
        data = f_in.read(4).hex()
        full_gbl_length = int(data, 16)
        # bypass full.gbl
        f_in.seek(pos + full_gbl_length)
        data = f_in.read(4).hex()
        linux_length = int(data, 16)
        f_in.seek(pos + full_gbl_length + 10)
        data = f_in.read(linux_length - 10)
        if data[:4] != b'cr6c':
            return False
        with open('linux.bin', 'wb') as f_out:
            f_out.write(data)
        f_in.seek(pos + full_gbl_length + linux_length)
        data = f_in.read(4).hex()
        ota_file_length = int(data, 16)
        # bypass ota-file
        f_in.seek(pos + full_gbl_length + linux_length + ota_file_length)
        data = f_in.read(4).hex()
        rootfs_length = int(data, 16)
        f_in.seek(pos + full_gbl_length + linux_length + ota_file_length + 10)
        data = f_in.read(rootfs_length - 10)
        if data[:4] != b'r6cr':
            return False
        with open('rootfs.bin', 'wb') as f_out:
            f_out.write(data)
        return True


def clear_serial_buffer(console):
    """ clear the buffer of serail """
    if console.in_waiting:
        console.read(console.in_waiting)
    console.reset_input_buffer()
    console.reset_output_buffer()
    console.flush()


def wait_for_realtek_cli(console):
    """ wait cli of <RealTek> """
    data = str(console.read_until(), encoding="utf-8")
    while "<RealTek>" not in data:
        data = str(console.read_until(), encoding="utf-8")


def enter_bootrom_console_and_get_ready(console, debug=False):
    """ Enter bootrom cli and init ddr and flash """
    print("Please power up gateway3!")
    print("If your gateway3 is powered up,"
          " disconnect usb cable and reconnect it.")

    data = ""
    console.write(b"u")
    while "Enter ROM console" not in data:
        console.write(b"u")
        console.flush()
        time.sleep(.05)
        if console.in_waiting:
            try:
                data = str(console.read_until(), encoding="utf-8")
            except UnicodeDecodeError:
                pass
            if debug:
                print(data)
        if "rlxlinux login" in data or "Linux version" in data:
            return False
        if "<RealTek>" in data:
            break
    command = "\n"
    console.write(command.encode())

    time.sleep(1)
    if console.in_waiting:
        console.read(console.in_waiting)
    command = "\n"
    console.write(command.encode())
    time.sleep(1)
    command = "dbgmsg 3\n"
    console.write(command.encode())
    command = "ri 0 1 1\n"
    console.write(command.encode())

    wait_for_realtek_cli(console)
    time.sleep(3)
    clear_serial_buffer(console)
    if debug:
        print("Enter bootrom cli!")
    return True


def check_comport_exist(comport):
    """ check_comport_exist """
    comports = list_ports.comports()
    comport_exist = False
    for port in comports:
        if comport in port[0]:
            comport_exist = True
            break
    if not comport_exist:
        print('{} is not the com ports list!'.format(comport))
        return False
    return True


def generate_padded_firmware(fwfile):
    """ prepare padded firmware """
    fwsize = os.stat(fwfile).st_size

    # RAW filename including inverted checksum bytes.
    # The return value is zero.
    if calc_checksum_of_firmware(fwfile) >= 1:
        print("The raw firmware is invaild format.")
        return False

    if fwsize % 0x20000 >= 1:
        pad_number = 0x20000 - (fwsize % 0x20000)
    else:
        pad_number = 0

    with open(fwfile, 'rb') as fw_flie:
        data = fw_flie.read()
    with open("{}_padding".format(fwfile), 'wb') as fw_flie:
        padding = [0xff for _ in range(pad_number)]
        fw_flie.write(data)
        fw_flie.write(bytearray(padding))
    return True


def update_boot_info(console, fw_type, new_sum, new_size):
    """ update boot info partition """

    command = "boot_ctrl set_{} {} {}\n".format(
        fw_type.replace('_', '').replace('linux', 'kernel'),
        new_size, new_sum)
    console.write(command.encode())

    command = "boot_ctrl set_{}_newest {}\n".format(
        fw_type[:-1], fw_type[-1:])
    console.write(command.encode())


def burn_by_uart(params, in_flasher=False):
    # pylint: disable=too-many-statements, unused-argument
    """ burn by uart command """

    with open(params['fwfile'], 'rb') as f_in:
        raw = f_in.read(16)
        if raw[:4] == b'cr6c' or raw[:4] == b'r6cr':
            with open("{}_raw".format(params['fwfile']), 'wb') as f_out:
                f_out.write(f_in.read())
            params['fwfile'] = "{}_raw".format(params['fwfile'])

    if not generate_padded_firmware(params['fwfile']):
        print("Generate padded firmware Failed!")
        return False

    try:
        console = serial.Serial(params['comport'], params['baudrate'])
    except serial.serialutil.SerialException:
        print("Open COM Port ({}) Error!".format(params['comport']))
        os.remove("{}_padding".format(params['fwfile']))
        return False

    def getc(size, timeout=1):
        return console.read(size)

    def putc(data, timeout=1):
        return console.write(data)

    modem = XMODEM(getc, putc)

    if not in_flasher:
        if not enter_bootrom_console_and_get_ready(console):
            print("The gateway is not ready for download!")
            return False

        console.write("xmrx 0xa0000000\n".encode())
        time.sleep(1)
        console.write(b"\n\n\n\n\n")

        clear_serial_buffer(console)

        with open("./flasher.bin", 'rb') as f_in:
            modem.send(f_in)

        console.write("j a0000000\n".encode())
        time.sleep(3)  # wait flasher boot up

    console.write(b'\n')

    wait_for_realtek_cli(console)

    with open("{}_padding".format(params['fwfile']), 'rb') as fw_flie:
        raw = fw_flie.read()
    j = 0
    for i in range(0, len(raw), 16):
        data = " ".join("{:02x}".format(c) for c in raw[i:i+16])
        command = "eb {} {}\n".format(
            hex(int(params['ddr_base'], 0) + j), data)
        console.write(command.encode())
        time.sleep(.1)
        j = j + 16
        if i % 8192 == 0 and int(i/8192) >= 1:
            command = 'NANDW {} {} {}\n'.format(
                hex(int(params['offset'], 0) + i),
                params['ddr_base'], hex(8192))
            console.write(command.encode())
            console.write(b'y\n')
            time.sleep(1)
            console.write(b'\n')
            params['ddr_base'] = '0x81000000'
            j = 0
        data = (int(((i + 15) / len(raw)) * 100))
        sys.stdout.write("Download progress: %d%%   \r" % (data))
        sys.stdout.flush()
#            print(command)
#            if i > 1000:
#                break
    console.close()
    os.remove("{}_padding".format(params['fwfile']))
    print("Program flash Done!")


def burn_by_xmodem(params, in_flasher=False):
    # pylint: disable=too-many-statements, unused-argument, too-many-branches
    """ burn by xmodem """
    # (100MHz >> 4) / baud rate
    # 38400 0.0046875
    # 115200 0.0046875
    # 230400 0.004691840277777777
    # 460800 0.043335503472222224
    flasher_baudrate = 230400

    with open(params['fwfile'], 'rb') as f_in:
        data = f_in.read(16)
        if data[:4] == b'cr6c' or data[:4] == b'r6cr':
            with open("{}_raw".format(params['fwfile']), 'wb') as f_out:
                f_out.write(f_in.read())
            params['fwfile'] = "{}_raw".format(params['fwfile'])

    if not generate_padded_firmware(params['fwfile']):
        print("Generate padded firmware Failed!")
        return False

    try:
        if not in_flasher:
            data = params['baudrate']
        else:
            data = flasher_baudrate
        console = serial.Serial(params['comport'], data, timeout=10)
    except serial.serialutil.SerialException:
        print("Open COM Port ({}) Error!".format(params['comport']))
        os.remove("{}_padding".format(params['fwfile']))
        return False

    def getc(size, timeout=1):
        return console.read(size)

    def putc(data, timeout=1):
        return console.write(data)

    fwsize = os.stat("./flasher.bin").st_size

    if 'pyprind' in sys.modules:
        def putc_user(data, timeout=1):
            bar_user.update(force_flush=True)
            return console.write(data)

        bar_user = pyprind.ProgBar(fwsize/128 - 1)

        modem = XMODEM(getc, putc_user)
    else:
        modem = XMODEM(getc, putc)

    if not in_flasher:
        if not enter_bootrom_console_and_get_ready(console, params['debug']):
            print("The gateway is not ready for download!")
            return False

        print("Downloading the flasher.")
        console.write("xmrx 0xa0000000\n".encode())
        time.sleep(1)

        clear_serial_buffer(console)
        if sys.platform == 'darwin':
            console.close()
            time.sleep(1)
            console = serial.Serial(params['comport'],
                                    params['baudrate'],
                                    timeout=10)

        with open("./flasher.bin", 'rb') as f_in:
            modem.send(f_in)

        console.write("j a0000000\n".encode())

        console.close()

        time.sleep(3)  # wait flasher boot up
        console = serial.Serial(params['comport'],
                                flasher_baudrate,
                                timeout=3)
    console.write(b'\n\n')

    wait_for_realtek_cli(console)

    command = "xmod {}\n".format(params['ddr_base'])
    console.write(command.encode())
    time.sleep(1)

    clear_serial_buffer(console)

    print("Now transmitting {}".format(params['fwfile']))
    fwsize = os.stat("{}_padding".format(params['fwfile'])).st_size

    if 'pyprind' in sys.modules:
        bar_user.stop()
        bar_user = pyprind.ProgBar(fwsize/1024 - 1, width=60)
        modem = XMODEM1k(getc, putc_user)
    else:
        modem = XMODEM1k(getc, putc)

    with open("{}_padding".format(params['fwfile']), 'rb') as f_in:
        modem.send(f_in)

    data = str(console.read(console.in_waiting), encoding="utf-8")
    if "Rx len=" not in data:
        print("Transmit Error!")
        console.close()
        os.remove("{}_padding".format(params['fwfile']))
        return False

    print("Transmit Done! Please wait for programming to flash.")

    command = 'NANDW {} {} {}\n'.format(
        hex(int(params['offset'], 0)), params['ddr_base'], hex(fwsize))
    console.write(command.encode())
    console.write(b'y\n')
    time.sleep(1)
    wait_for_realtek_cli(console)

    sum_firmware = calc_sum_of_firmware(params['fwfile'])
    update_boot_info(console, params['fwtype'], sum_firmware, fwsize)

    console.close()
    os.remove("{}_padding".format(params['fwfile']))
    print("Programming {} Done!".format(params['fwfile']))
    return True


def _tftp_server():
    thread = threading.currentThread()
    while getattr(thread, "running", True):
        try:
            server = tftpy.TftpServer(getattr(thread, "path", '.'))
            server.listen('0.0.0.0', 69)
        except KeyboardInterrupt:
            break


def burn_by_tftp(params, in_flasher=False):
    # pylint: disable=too-many-statements, unused-argument
    """ burn by tftp """
    flasher_baudrate = 230400

    with open(params['fwfile'], 'rb') as f_in:
        raw = f_in.read(16)
        if raw[:4] == b'cr6c' or raw[:4] == b'r6cr':
            with open("{}_raw".format(params['fwfile']), 'wb') as f_out:
                f_out.write(f_in.read())
            params['fwfile'] = "{}_raw".format(params['fwfile'])

    if not generate_padded_firmware(params['fwfile']):
        print("Generate padded firmware Failed!")
        return False

    if "tftpy" not in sys.modules:
        print("Please install tftpy!")
        return False

    try:
        if not in_flasher:
            baudrate = params['baudrate']
        else:
            baudrate = flasher_baudrate
        console = serial.Serial(params['comport'],
                                baudrate,
                                timeout=10)
    except serial.serialutil.SerialException:
        print("Open COM Port ({}) Error!".format(params['comport']))
        os.remove("{}_padding".format(params['fwfile']))
        return False

    def getc(size, timeout=1):
        return console.read(size)

    def putc(data, timeout=1):
        return console.write(data)

    if 'pyprind' in sys.modules:
        def putc_user(data, timeout=1):
            bar_user.update()
            return console.write(data)

        bar_user = pyprind.ProgBar(
            os.stat(params['fwfile']).st_size/128+64)

        modem = XMODEM(getc, putc_user)
    else:
        modem = XMODEM(getc, putc)

    if not in_flasher:
        if not enter_bootrom_console_and_get_ready(console):
            print("The gateway is not ready for download!")
            return False

        console.write("xmrx 0xa0000000\n".encode())
        time.sleep(3)

        clear_serial_buffer(console)

        with open("./flasher.bin", 'rb') as f_in:
            modem.send(f_in)

        console.write("j a0000000\n".encode())
        console.close()

        time.sleep(3)  # wait flasher boot up
        console = serial.Serial(params['comport'],
                                flasher_baudrate,
                                timeout=10)

    thread = threading.Thread(target=_tftp_server)
    thread.running = True
    thread.path = os.path.dirname(os.path.abspath(params['fwfile']))
    thread.start()

    command = "tftp {} {}_padding\n".format(
        params['ddr_base'], os.path.basename(params['fwfile']))
    console.write(command.encode())

    wait_for_realtek_cli(console)
    thread.running = False
    time.sleep(1)

    command = 'NANDW {} {} {}\n'.format(
        hex(int(params['offset'], 0)),
        params['ddr_base'],
        hex(os.stat(params['fwfile']).st_size))
    console.write(command.encode())
    console.write(b'y\n')
    thread.join()
    print("Program {} Done!".format(params['fwfile']))
    return True


def burn_all_firmwares(params):
    """ burn all firmwares by tftp """
    if not params['tftp'] and not params['xmodem']:
        print("Currently only support tftp or xmodem!")
        return

    if not extract_firmwares(params['fwfile']):
        print("The {} is invaild!".format(params['fwfile']))
        return
    fwversion = re.search(
        r'([0-9].[0-9].[0-9]_[0-9]+)', params['fwfile']).group(1)

    if fwversion is None:
        fwversion = ''
    else:
        fwversion = "_{}".format(fwversion)

    with open('linux.bin', 'rb') as f_in:
        f_in.seek(16)
        with open('linux{}.bin_raw'.format(fwversion), 'wb') as f_out:
            f_out.write(f_in.read())
    os.remove('linux.bin')
    params['fwfile'] = 'linux{}.bin_raw'.format(fwversion)
    params['fwtype'] = 'kernel{}'.format(params['fwtype'][-2:])
    params['offset'] = params['linux_offset']
    if params['tftp']:
        burn_by_tftp(params, in_flasher=False)
    elif params['xmodem']:
        burn_by_xmodem(params, in_flasher=False)
    os.remove('linux{}.bin_raw'.format(fwversion))

    with open('rootfs.bin', 'rb') as f_in:
        f_in.seek(16)
        with open('rootfs{}.bin_raw'.format(fwversion), 'wb') as f_out:
            f_out.write(f_in.read())
    os.remove('rootfs.bin')
    params['fwfile'] = 'rootfs{}.bin_raw'.format(fwversion)
    params['fwtype'] = 'rootfs{}'.format(params['fwtype'][-2:])
    params['offset'] = params['rootfs_offset']
    if params['tftp']:
        burn_by_tftp(params, in_flasher=True)
    elif params['xmodem']:
        burn_by_xmodem(params, in_flasher=True)
    os.remove('rootfs{}.bin_raw'.format(fwversion))


def burn_firmware(params):
    # pylint: disable=too-many-return-statements, too-many-branches
    """ burn_firmware """
    firmware_info = {
        "bootloader": "0x00000000",
        "boot_info": "0x000a0000",
        "factory": "0x000c0000",
        "mtd_oops": "0x000e0000",
        "bbt": "0x00100000",
        'linux_0': '0x00200000',
        'rootfs_0': '0x00500000',
        'linux_1': '0x01e00000',
        'rootfs_1': '0x02100000',
        "homekit": "0x03a00000",
        "AppData": "0x03b00000",
        "resvered_bb": "0x7320000"
    }

    if not os.path.exists("./flasher.bin"):
        print("The flahser.bin is not exist!")
        return
    if not os.path.exists(params['fwfile']):
        print("The {} is not exist!".format(params['fwfile']))
        return

    offset = firmware_info.get(params['fwtype'], '0')

    if 'all' in params['fwtype']:
        with open(params['fwfile'], 'rb') as f_in:
            data = f_in.read()
        if data[:4] != b'MIOT':
            print('{} is not vaild firmware file'.format(params['fwfile']))
            return
    else:
        if offset == '0':
            print('Unknow firmware type!')
            return

    params['ddr_base'] = '0xa1000000'
    if "serial" not in sys.modules:
        print("Need install pyserial for python!")
        return

    if not check_comport_exist(params['comport']):
        return
    if params['tftp']:
        if 'all' in params['fwtype']:
            params['linux_offset'] = firmware_info.get(
                'linux{}'.format(params['fwtype'][-2:]), '0')
            params['rootfs_offset'] = firmware_info.get(
                'rootfs{}'.format(params['fwtype'][-2:]), '0')
            burn_all_firmwares(params)
        else:
            params['offset'] = offset
            if burn_by_tftp(params):
                print("Need to update boot info according to {}.".format(
                    params['fwfile']))
        return
    if params['xmodem']:
        if 'all' in params['fwtype']:
            params['linux_offset'] = firmware_info.get(
                'linux{}'.format(params['fwtype'][-2:]), '0')
            params['rootfs_offset'] = firmware_info.get(
                'rootfs{}'.format(params['fwtype'][-2:]), '0')
            burn_all_firmwares(params)
        else:
            params['offset'] = offset
            if burn_by_xmodem(params):
                print("Need to update boot info according to {}.".format(
                    params['fwfile']))
        return
    # just for test
    burn_by_uart(params)
    return


def generate_telnet_password(did, mac, key):
    """ generate telnet password """
    print("did={}\nmac={}\nkey={}".format(did, mac, key))
    print("base64(hmac_sha256(key, sha256(did+mac+key)))")

    data = "{}{}{}".format(did, mac, key)
    message = hashlib.sha256(data.encode('utf-8'))
    signature = base64.b64encode(hmac.new(message.hexdigest().encode(),
                                          msg=key.encode(),
                                          digestmod=hashlib.sha256).digest())
    print(signature[-16:])


def main():
    # pylint: disable=too-many-return-statements, too-many-branches
    '''
    Using Python to burn firmware via UART/Xmodem/Tftp
    '''

    basic_version = "0.0.2"

    parser = argparse.ArgumentParser(
        description='Gateway 3 Utils {}'.format(basic_version),
        epilog="Gateway 3 Utils",
        formatter_class=argparse.RawTextHelpFormatter)
    group = parser.add_argument_group()
    group.add_argument('-d', '--debug', action='store_true',
                       help='Enable debugging')
    group.add_argument('-x', '--xmodem', action='store_true',
                       help='Use xmodem')
    group.add_argument('-p', '--tftp', action='store_true',
                       help='Use tftp')
    group.add_argument('-f', '--fle', dest='fwfile',
                       help='firmware file')
    group.add_argument('-t', '--fwype', dest='fwtype',
                       help='The type of firmware,'
                       '[linux_0|linux_1|rootfs_0|rootfs_1|all_0|all_1]')
    group.add_argument('-c', '--comport', dest='comport',
                       help='The com port')
    group.add_argument('-b', '--baudrate', dest='baudrate',
                       help='baudrate')
    group.add_argument('-i', '--boot_info', dest='info_file',
                       help='Calc boot_info')
    group.add_argument('-l', '--cmdline', dest='cmdline',
                       help='Convert cmdline string')
    group.add_argument('-s', '--sum', action='store_true',
                       help='Sum of firmware file')
    group.add_argument('-u', '--checksum', action='store_true',
                       help='checkum of firmware file')
    group.add_argument('-g', '--generate', action='store_true',
                       help='Generate firmware file for fw_update')
    group.add_argument('-k', '--key', dest='key',
                       help='Xiaomi key')
    group.add_argument('-m', '--mac', dest='mac',
                       help='Device Mac Address')
    group.add_argument('-e', '--did', dest='did',
                       help='Device ID')
    args = parser.parse_args()

    if sys.version_info < (3, 6):
        print("Please install Python3.7 and above!")
        return

    if args.key and args.mac and args.did:
        generate_telnet_password(args.did, args.mac, args.key)
        return

    if args.generate and args.fwfile and args.fwtype:
        generate_firmware_for_fw_update(args.fwfile, args.fwtype)
        return

    if args.sum and args.fwfile:
        calc_sum_of_firmware(args.fwfile, log=True)
        return

    if args.checksum and args.fwfile:
        calc_checksum_of_firmware(args.fwfile, log=True)
        return

    if args.info_file:
        calc_checksum_boot_info(args.info_file, log=True)
        return

    if args.cmdline:
        convert_cmdline(args.cmdline)
        return

    if args.fwfile and args.fwtype and args.comport:
        if "serial" not in sys.modules or "xmodem" not in sys.modules:
            print("Notice: serial or xmodem module is not installed!")
            print("        pip install -r requirements.txt")
        baudrate = 38400
        if args.baudrate:
            baudrate = args.baudrate
        if args.xmodem and args.tftp:
            print("Please choose one transmit type!")
            return
        params = {'xmodem': args.xmodem,
                  'tftp': args.tftp,
                  'comport': args.comport,
                  'baudrate': baudrate,
                  'fwtype': args.fwtype,
                  'fwfile': args.fwfile,
                  'debug': args.debug}
        burn_firmware(params)
        return
    print("Invaild arguments")


if __name__ == "__main__":
    main()
