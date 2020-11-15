""" burn firmware of gateway 3 """
import sys
import os
import time
import threading
import argparse
import binascii
import hashlib
import hmac
import base64
try:
    import serial
    from serial.tools import list_ports
    from xmodem import XMODEM
except ImportError:
    pass
import yaml
try:
    import tftpy
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


def calc_checksum_of_firmware(fwfile):
    """ calc checksum of firmware """
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
    print("Sum: {}, Invert Sum: {}".format(
        hex(checksum & 0xffff), hex(0x10000 - (checksum & 0xffff))))
    return 0x10000 - (checksum & 0xffff)


def calc_checksum_boot_info(info_file):
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
    if "yaml" in sys.modules:
        if os.path.isfile(info_file):
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
    print('New checksum: {} {}'.format(new_checksum_1, new_checksum_2))
    for i in range(0, len(values), 16):
        data = " ".join("{:02x}".format(c) for c in values[i:i+16])
        print("eb {} {}".format(hex(0xa0a00000 + i), data))
    print("NANDW 0xa0000 0xa0a00000 55")


def generate_firmware_for_fw_update(fwfile, fwtype):
    """ generate firmware for fw_update """
    firmware_type = {
        'header': '4D494F540011001307110F05',
        'gbl': '0F133FCDA8FC0404FC040000',
        'linux_1': '6372366380A0000000800000',
        'linux_2': '6372366380A0000000800000',
        'ota-file test': '0002D1DC020003F25318',
        'rootfs_1': '72366372002D000000E00000',
        'rootfs_2': '72366372002D000000E00000',
        'cert': '4D49EF54464F5441'
    }
    firmware_align_size = {
        'linux_1': 0x200,
        'linux_2': 0x200,
        'rootfs_1': 0x800,
        'rootfs_2': 0x800
    }

    # 0x2e00 (apploader.bin)
    # sizeof(full.gbl)_and_other_10bytes
    # full.gbl 10bytes linux 10bytes ota-files.bin 10bytes rootfs.bin cert
    if not os.path.exists(fwfile):
        print("The file {} is not exist!".format(fwfile))
        return
    if not firmware_type.get(fwtype):
        print("The type {} is incorrect!".format(fwtype))
        return
    with open(fwfile, 'rb') as f_in:
        raw = f_in.read()
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
        f_out.write(bytearray(padding))
        f_out.write(data.to_bytes(4, byteorder='big', signed=False))
    print("Generated {} ({}) done.".format(
        filename, os.stat(filename).st_size))


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


def burn_by_uart(params, offset, ddr_base):
    """ burn by uart command """
    console = serial.Serial(params['comport'], params['baud_rates'])
    with open(params['fwfile'], "rb") as f_in:
        raw = f_in.read()
    j = 0
    for i in range(0, len(raw), 16):
        data = " ".join("{:02x}".format(c) for c in raw[i:i+16])
        command = "eb {} {}\n".format(hex(int(ddr_base, 0) + j), data)
        console.write(command.encode())
        time.sleep(.1)
        j = j + 16
        if i % 8192 == 0 and int(i/8192) >= 1:
            command = 'NANDW {} {} {}\n'.format(
                hex(int(offset, 0) + i), ddr_base, 8192)
            console.write(command.encode())
            command = 'y\n'
            console.write(command.encode())
            time.sleep(1)
            console.write(b'\n')
            ddr_base = '0x81000000'
            j = 0
        data = (int(((i + 15) / len(raw)) * 100))
        sys.stdout.write("Download progress: %d%%   \r" % (data))
        sys.stdout.flush()
#            print(command)
#            if i > 1000:
#                break
    console.close()


def burn_by_xmodem(params, offset, ddr_base):
    # pylint: disable=too-many-statements
    """ burn by xmodem """
    fwsize = os.stat(params['fwfile']).st_size

    if fwsize % 0x20000 >= 1:
        pad_number = 0x20000 - (fwsize % 0x20000)
    else:
        pad_number = 0

    with open(params['fwfile'], 'rb') as f_in:
        raw = f_in.read()
    with open("{}_padding".format(params['fwfile']), 'wb') as f_out:
        padding = [0xff for _ in range(pad_number)]
        f_out.write(raw)
        f_out.write(bytearray(padding))

    console = serial.Serial(params['comport'], params['baud_rates'])
    data = str(console.read_until(), encoding="utf-8")
    while ("rom_progress: 0x1100006d" not in data and
            "load img fail" not in data):
        data = str(console.read_until(), encoding="utf-8")

    print("Please release the TP16 button")
    time.sleep(2)
    console.read(console.inWaiting())
    command = "\n\n"
    console.write(command.encode())
    time.sleep(1)
    data = str(console.read_until(), encoding="utf-8")
    while "<RealTek>" not in data:
        data = str(console.read_until(), encoding="utf-8")
    time.sleep(.1)
    command = "snwbi\n"
    console.write(command.encode())

    command = "xmrx {}\n".format(ddr_base)
    console.write(command.encode())
    time.sleep(3)
    print("Now transmit {}".format(params['fwfile']))
    console.read(console.inWaiting())
    console.reset_input_buffer()
    console.reset_output_buffer()

    def getc(size):
        return console.read(size)

    def putc(data):
        return console.write(data)

    modem = XMODEM(getc, putc)
    with open("{}_padding".format(params['fwfile']), "rb") as f_in:
        modem.send(f_in)

    data = str(console.read(console.inWaiting()), encoding="utf-8")
    if "recv data ok len:" not in data:
        print("Transmit Error!")
    else:
        print("Transmit Done!")
        command = "snwbrecc 0x80000000 0 10000\n"
        console.write(command.encode())
        command = "j 80000000\n"
        console.write(command.encode())
        time.sleep(1)
        data = str(console.read_until(), encoding="utf-8")
        while "<RealTek>" not in data:
            data = str(console.read_until(), encoding="utf-8")
        command = 'NANDW {} {} {}\n'.format(
            hex(int(offset, 0)), ddr_base, fwsize)
        console.write(command.encode())
        command = 'y\n'
        console.write(command.encode())
        time.sleep(1)
        console.write(b'\n')

    console.close()
    os.remove("{}_padding".format(params['fwfile']))


def _tftp_server():
    thread = threading.currentThread()
    while getattr(thread, "running", True):
        try:
            server = tftpy.TftpServer(getattr(thread, "path", '.'))
            server.listen('0.0.0.0', 69)
        except KeyboardInterrupt:
            break


def burn_by_tftp(params, offset, ddr_base):
    # pylint: disable=too-many-statements
    """ burn by tftp """
    fwsize = os.stat(params['fwfile']).st_size
    console = serial.Serial(params['comport'], params['baud_rates'])
    if "tftpy" not in sys.modules:
        print("Please install tftpy!")
        return

    thread = threading.Thread(target=_tftp_server)
    thread.running = True
    thread.path = os.path.dirname(os.path.abspath(params['fwfile']))
    thread.start()

    command = "tftp {}\n".format(ddr_base)
    console.write(command.encode())

    data = str(console.read_until(), encoding="utf-8")
    while "<RealTek>" not in data:
        data = str(console.read_until(), encoding="utf-8")
    thread.running = False

    command = 'NANDW {} {} {}\n'.format(
        hex(int(offset, 0)), ddr_base, fwsize)
    console.write(command.encode())
    command = 'y\n'
    console.write(command.encode())
    thread.join()


def burn_firmware(params):
    """ burn_firmware """
    firmware_info = {
        "bootloader": "0x00000000",
        "boot_info": "0x000a0000",
        "factory": "0x000c0000",
        "mtd_oops": "0x000e0000",
        "bbt": "0x00100000",
        'linux_1': '0x00200000',
        'rootfs_1': '0x00500000',
        'linux_2': '0x01e00000',
        'rootfs_2': '0x02100000',
        "homekit": "0x03a00000",
        "AppData": "0x03b00000",
        "resvered_bb": "0x7320000"
    }

    offset = firmware_info.get(params['fwtype'], '0')

    if offset == '0':
        print('Unknow firmware type!')
        return

    print("The size of the firmware file {} is {} ({}).".format(
        os.path.basename(params['fwfile']),
        os.stat(params['fwfile']).st_size,
        hex(os.stat(params['fwfile']).st_size)))
    ddr_base = '0x81000000'
    if "serial" in sys.modules:
        if not check_comport_exist(params['comport']):
            return
        if params['tftp']:
            burn_by_tftp(params, offset, ddr_base)
        elif params['xmodem']:
            burn_by_xmodem(params, offset, ddr_base)
        else:
            # just for test
            burn_by_uart(params, offset, ddr_base)


def generate_telnet_password(did, mac, key):
    """ generate telnet password """
    print("did={}\nmac={}\nkey={}".format(did, mac, key))
    print("base64(hmac_sha256(key, sha256(did+mac+key)))")

    data = "{}{}{}".format(did, mac, key)
    message = hashlib.sha256(data.encode())
    signature = base64.b64encode(hmac.new(key.encode('utf-8'),
                                          message.digest(),
                                          digestmod=hashlib.sha256).digest())
    print(signature)
    print(signature[-16:])


def main():
    '''
    Using Python to burn firmware via UART
    '''

    basic_version = "0.0.1"

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
                       '[linux_1|linux_2|rootfs_1|rootfs_2]')
    group.add_argument('-c', '--comport', dest='comport',
                       help='The com port')
    group.add_argument('-b', '--baudrates', dest='baudrates',
                       help='baudrates')
    group.add_argument('-i', '--boot_info', dest='info_file',
                       help='Calc boot_info')
    group.add_argument('-l', '--cmdline', dest='cmdline',
                       help='Convert cmdline string')
    group.add_argument('-s', '--sum', action='store_true',
                       help='Sum of firmware file')
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
        calc_checksum_of_firmware(args.fwfile)
        return

    if args.info_file:
        calc_checksum_boot_info(args.info_file)
        return

    if args.cmdline:
        convert_cmdline(args.cmdline)
        return

    if args.fwfile and args.fwtype and args.comport:
        if "serial" not in sys.modules or "xmodem" not in sys.modules:
            print("Notice: serial or xmodem is not installed!")
        baudrates = 38400
        if args.baudrates:
            baudrates = args.baudrates
        print("Please press/hold the TP16 button and power up gateway3!")
        params = {'xmodem': args.xmodem,
                  'tftp': args.tftp,
                  'comport': args.comport,
                  'baud_rates': baudrates,
                  'fwtype': args.fwtype,
                  'fwfile': args.fwfile}
        burn_firmware(params)
    else:
        print("Invaild arguments")


if __name__ == "__main__":
    main()
