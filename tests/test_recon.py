import mock
import collections
import scapy.layers.dot11 as dot11
import robophisher.recon as recon


def test_is_packet_valid_packet_not_beacon():
    """
    Test is_packet_valid function with an packet that is not Dot11Beacon
    """
    address = "FF:FF:FF:FF:FF:FF"
    packet = (dot11.RadioTap() / dot11.Dot11(type=0, subtype=10, addr3=address) /
              dot11.Dot11Disas())

    assert recon.is_packet_valid(packet) == False


def test_is_packet_valid_packet_malformed():
    """
    Test is_packet_valid function with an packet that is not Dot11Beacon
    """
    address = "FF:FF:FF:FF:FF:FF"
    packet = (dot11.RadioTap() / dot11.Dot11(type=0, subtype=10, addr1=address) /
              dot11.Dot11Beacon())

    assert recon.is_packet_valid(packet) == False


def test_is_packet_valid_packet_valid():
    """
    Test is_packet_valid function with an packet that is not Dot11Beacon
    """
    address = "FF:FF:FF:FF:FF:FF"
    packet = (dot11.Dot11(type=0, subtype=10, addr3=address)
              / dot11.Dot11Beacon() / dot11.Dot11Elt(ID=0, info="MY AP") / dot11.Dot11Elt()
              / dot11.Dot11Elt(ID=3, info=chr(2)))

    assert recon.is_packet_valid(packet) == True


@mock.patch("robophisher.recon.dot11.sniff")
def test_get_new_ap_valid_packet(sniff):
    """
    Test get_new_ap function with a valid(standard) packet
    """
    name = "MY_AP"
    channel = 2
    address = "FF:FF:FF:FF:FF:FF"
    packet = (dot11.Dot11(type=0, subtype=10, addr3=address)
              / dot11.Dot11Beacon(cap=0x1111) / dot11.Dot11Elt(ID=0, info=name)
              / dot11.Dot11Elt() / dot11.Dot11Elt(ID=3, info=chr(channel)))

    sniff.return_value = [packet]

    assert recon.get_new_ap("wlan0") == (name, channel, address, True)


@mock.patch("robophisher.recon.dot11.sniff")
def test_get_new_ap_packet_no_encryption(sniff):
    """
    Test get_new_ap function with a packet where AP is not encrypted
    """
    name = "MY_AP"
    channel = 2
    address = "FF:FF:FF:FF:FF:FF"
    packet = (dot11.Dot11(type=0, subtype=10, addr3=address)
              / dot11.Dot11Beacon(cap=0x0000) / dot11.Dot11Elt(ID=0, info=name)
              / dot11.Dot11Elt() / dot11.Dot11Elt(ID=3, info=chr(channel)))

    sniff.return_value = [packet]

    assert recon.get_new_ap("wlan0") == (name, channel, address, False)
