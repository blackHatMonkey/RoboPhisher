import mock
import pytest
import argparse
import robophisher.arguments as arguments


@mock.patch("robophisher.arguments.pyric.pyw")
def test_validate_ap_interface_valid(pyric):
    """
    Test validate_ap_interface when the interface is valid
    """
    pyric.isinterface.return_value = True
    pyric.iswireless.return_value = True
    pyric.getcard.return_value = "Card"
    pyric.devmodes.return_value = ["AP"]

    interface = "wlan0"
    assert arguments.validate_ap_interface(interface) == None


@mock.patch("robophisher.arguments.pyric.pyw")
def test_validate_ap_interface_invalid(pyric):
    """
    Test validate_ap_interface when the interface is invalid and it
    raises an error
    """
    pyric.isinterface.return_value = True
    pyric.iswireless.return_value = False
    pyric.getcard.return_value = "Card"
    pyric.devmodes.return_value = []

    interface = "wlan0"
    with pytest.raises(argparse.ArgumentTypeError):
        arguments.validate_ap_interface(interface)
