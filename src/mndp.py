#!/usr/bin/env python

import random
import string
from time import sleep
from datetime import datetime
from argparse import ArgumentParser
from configparser import ConfigParser
from scapy.all import Packet, ShortField, MACField, ByteField, LEIntField, StrField, send, IP, UDP


def random_bytes(num=6):
    return [random.randrange(256) for _ in range(num)]


def random_letters(num=4):
    letters = string.ascii_uppercase + string.digits
    return random.choices(letters, k=num)


def generate_mac(oui=None):
    if oui:
        oui = [int(chunk, 16) for chunk in oui.split(':')]
        mac = oui + random_bytes(num=6-len(oui))
    else:
        mac = random_bytes()
        mac[0] &= ~1  # unicast
        mac[0] &= ~(1 << 1)  # uaa
    return ':'.join('%02x' % b for b in mac)


def generate_software_id():
    return ''.join(random_letters()) + '-' + ''.join(random_letters())


class MNDP(Packet):
    name = "MNDP"

    fields_desc = [
        ShortField("header", 0),
        ShortField("SeqNo", 0),

        ShortField("TlvTypeMAC_Address", 1),
        ShortField("TlvLengthMAC", 6),
        MACField("MAC",  "ca:fe:ca:fe:ca:fe"),

        ShortField("TlvTypeIdentity", 5),
        ShortField("TlvLengthIdentity", 4),
        StrField("Identity", "test"),

        ShortField("TlvTypeVersion", 7),
        ShortField("TlvLengthVersion", 4),
        StrField("Version", "test"),

        ShortField("TlvTypePlatform", 8),
        ShortField("TlvLengthPlatform", 4),
        StrField("Platform", "test"),

        ShortField("TlvTypeUptime", 10),
        ShortField("TlvLengthUptime", 4),
        LEIntField("Uptime",  0x0),

        ShortField("TlvTypeSoftware_ID", 11),
        ShortField("TlvLengthSoftware", 4),
        StrField("Software", "test"),

        ShortField("TlvTypeBoard", 12),
        ShortField("TlvLengthBoard", 4),
        StrField("Board", "test"),

        ShortField("TlvTypeUnpack_ID", 14),
        ShortField("TlvLengthUnpack", 1),
        ByteField("Unpack", 0),

        ShortField("TlvTypeInterface", 16),
        ShortField("TlvLengthInterface", 6),
        StrField("Interface", "ether3"),

    ]


def get_ip_packet():
    pkt = IP()
    pkt.dst = "255.255.255.255"
    pkt.ihl = 5

    return pkt


def get_udp_packet():
    pkt = UDP()
    pkt.sport = 5678
    pkt.dport = 5678

    return pkt


def get_mndp_packet(config):
    pkt = MNDP()

    identity = config['identity']
    version = config['version']
    platform = config['platform']
    board = config['board']

    if 'mac' in config:
        mac = config['mac']
    elif 'mac_oui' in config:
        mac = generate_mac(config['mac_oui'])
    else:
        mac = generate_mac()

    if 'software_id' in config:
        software_id = config['software_id']
    else:
        software_id = generate_software_id()

    print(f'identity: {identity}')
    print(f'version: {version}')
    print(f'platform: {platform}')
    print(f'board: {board}')
    print(f'mac: {mac}')
    print(f'software_id: {software_id}')

    pkt.Identity = identity
    pkt.TlvLengthIdentity = len(identity)
    pkt.Version = version
    pkt.TlvLengthVersion = len(version)
    pkt.Platform = platform
    pkt.TlvLengthPlatform = len(platform)
    pkt.Software = software_id
    pkt.TlvLengthSoftware = len(software_id)
    pkt.Board = board
    pkt.TlvLengthBoard = len(board)
    pkt.MAC = mac
    pkt.Uptime = 0

    return pkt


if __name__ == '__main__':

    parser = ArgumentParser()
    parser.add_argument("--config", help="Alternative configuration file path")
    args = parser.parse_args()

    if args.config:
        config_path = args.config
    else:
        config_path = 'config.ini'

    config = ConfigParser()
    config.read(config_path)

    pkt_ip = get_ip_packet()
    pkt_udp = get_udp_packet()
    pkt_mndp = get_mndp_packet(config['mndp'])

    start = datetime.now()

    pkt = pkt_ip/pkt_udp/pkt_mndp
    while True:
        now = datetime.now()
        pkt.Uptime = (now-start).seconds
        send(pkt)
        sleep(5)
