# pylint: skip-file
""" This module tests the deauth module in extensions """
import mock
import scapy.layers.dot11 as dot11
import scapy.arch.linux as linux
import robophisher.deauth as deauth
import robophisher.common.constants as constants


def test_craft_deauth_packet_normal_packet():
    """
    Test craft_disas_packet function
    """
    sender = "00:11:22:33:44:55"
    receiver = "11:22:33:44:55:66"
    expected_packet = (dot11.RadioTap() / dot11.Dot11(
        type=0, subtype=12, addr1=receiver, addr2=sender, addr3=sender) / dot11.Dot11Deauth())

    assert deauth.craft_deauth_packet(sender, receiver, sender) == expected_packet


def test_craft_disass_packet_normal_packet():
    """
    Test craft_disass_packet function
    """
    sender = "00:11:22:33:44:55"
    receiver = "11:22:33:44:55:66"
    expected_packet = (dot11.RadioTap() / dot11.Dot11(
        type=0, subtype=10, addr1=receiver, addr2=sender, addr3=sender) / dot11.Dot11Disas())

    assert deauth.craft_disas_packet(sender, receiver, sender) == expected_packet


def test_craft_packets_normal_packets():
    """
    Test craft_packets function
    """
    broadcast = "ff:ff:ff:ff:ff:ff"
    client = "00:11:22:33:44:55"
    access_point = "11:22:33:44:55:66"
    expected_packets = [
        (dot11.RadioTap() / dot11.Dot11(
            type=0, subtype=12, addr1=client, addr2=access_point, addr3=access_point) /
         dot11.Dot11Deauth()),
        (dot11.RadioTap() / dot11.Dot11(
            type=0, subtype=12, addr1=access_point, addr2=client, addr3=access_point) /
         dot11.Dot11Deauth()),
        (dot11.RadioTap() / dot11.Dot11(
            type=0, subtype=12, addr1=broadcast, addr2=access_point, addr3=access_point) /
         dot11.Dot11Deauth()),
        (dot11.RadioTap() / dot11.Dot11(
            type=0, subtype=10, addr1=client, addr2=access_point, addr3=access_point) /
         dot11.Dot11Disas()),
        (dot11.RadioTap() / dot11.Dot11(
            type=0, subtype=10, addr1=access_point, addr2=client, addr3=access_point) /
         dot11.Dot11Disas()),
        (dot11.RadioTap() / dot11.Dot11(
            type=0, subtype=10, addr1=broadcast, addr2=access_point, addr3=access_point) /
         dot11.Dot11Disas()),
    ]

    assert list(deauth.craft_packets(client, access_point)) == list(expected_packets)


def test_find_client_from_ap_to_client():
    """
    Test find_client function when the packet is from ap to client
    """
    client = "00:11:22:33:44:55"
    ap = "66:77:88:99:AA:BB:CC"
    packet = (dot11.RadioTap(version=0, pad=0, len=36) / dot11.Dot11(
        type=2, subtype=1, addr1=client, addr2=ap, addr3=ap) / dot11.Dot11Elt(len=1, info='\x01') /
              dot11.Dot11Elt(len=4))
    mock_socket = mock.Mock()
    mock_socket.sniff.return_value = list(packet)

    assert client == deauth.find_client(ap, mock_socket)


def test_find_client_from_client_to_ap():
    """
    Test find_client function when the packet is from client to ap
    """
    client = "00:11:22:33:44:55"
    ap = "66:77:88:99:AA:BB:CC"
    packet = (dot11.RadioTap(version=0, pad=0, len=36) / dot11.Dot11(
        type=2, subtype=1, addr1=ap, addr2=client, addr3=ap) / dot11.Dot11Elt(len=1, info='\x01') /
              dot11.Dot11Elt(len=4))
    mock_socket = mock.Mock()
    mock_socket.sniff.return_value = list(packet)

    assert client == deauth.find_client(ap, mock_socket)


def test_find_client_not_client():
    """
    Test find_client function when the packet is not from the same
    access point
    """
    client = "00:11:22:33:44:55"
    ap0 = "66:77:88:99:AA:BB:CC"
    ap1 = "12:34:56:78:90:AB"
    packet = (dot11.RadioTap(version=0, pad=0, len=36) / dot11.Dot11(
        type=2, subtype=1, addr1=ap1, addr2=client, addr3=ap1) / dot11.Dot11Elt(
            len=1, info='\x01') / dot11.Dot11Elt(len=4))
    mock_socket = mock.Mock()
    mock_socket.sniff.return_value = list(packet)

    assert None == deauth.find_client(ap0, mock_socket)


def test_is_packet_relevant_true():
    """
    Test is_packet_relevant function with a valid packet
    """
    client = "00:11:22:33:44:55"
    ap = "66:77:88:99:AA:BB:CC"
    packet = (dot11.RadioTap(version=0, pad=0, len=36) / dot11.Dot11(
        type=2, subtype=1, addr1=ap, addr2=client, addr3=ap) / dot11.Dot11Elt(len=1, info='\x01') /
              dot11.Dot11Elt(len=4) / dot11.Dot11Elt(len=1, info='\x01'))

    assert True == deauth.is_packet_relevant(packet)


def test_is_packet_relevant_false():
    """
    Test is_packet_relevant function with an invalid packet
    """
    client = "00:11:22:33:44:55"
    ap = "66:77:88:99:AA:BB:CC"
    packet = (dot11.RadioTap(version=0, pad=0, len=36) / dot11.Dot11(
        type=0, subtype=1, addr1=ap, addr2=client, addr3=ap) / dot11.Dot11Elt(len=1, info='\x01') /
              dot11.Dot11Elt(len=4) / dot11.Dot11Elt(len=1, info='\x01'))

    assert False == deauth.is_packet_relevant(packet)
