"""Handle locating all the available access points."""

import collections
import scapy.layers.dot11 as dot11
from robophisher.common.constants import ALL_2G_CHANNELS


def is_packet_valid(packet):
    # type: (dot11.RadioTap) -> bool
    """Return whether a packet is valid.

    packet is valid if the following condtions are met:
        1. Is a Dot11Beacon frame
        2. Is not malformed
        3. The channel is in range of 1..13
    """
    return (packet.haslayer(dot11.Dot11Beacon) and hasattr(packet.payload, "info") and packet.info
            and not packet.info.startswith(b"\x00") and len(packet[dot11.Dot11Elt:3].info) == 1
            and ord(packet[dot11.Dot11Elt:3].info) in ALL_2G_CHANNELS)


def get_new_ap(interface_name):
    # type: (str) -> Tuple[str, int, str, bool]
    """Return a new access point.

    :Example:
        >>> interface = "wlan0"
        >>> get_new_ap()
        AccessPoint("NEW AP", 2, 00:11:22:33:44:55, True)

    .. Note: This function has the possibility of blocking if it can't
        find a valid packet. However in practice this never happens.
    """
    access_point = collections.namedtuple("AccessPoint", "name channel mac_address is_encrypted")
    packet = dot11.sniff(iface=interface_name, count=1, lfilter=is_packet_valid)[0]

    name = packet.info
    channel = ord(packet[dot11.Dot11Elt:3].info)
    mac_address = packet.addr3
    is_encrypted = "privacy" in packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")

    return access_point(name, channel, mac_address, is_encrypted)
