"""
This module is responsible for handling all the validation for the
arguments the user provides in command line
"""
import argparse
import robophisher.interfaces as interfaces
import pyric.pyw


def validate_ap_interface(interface):
    """
    Raise an error if the given interface does not support AP mode

    :param interface: Name of an interface
    :type interface: str
    :return: None
    :rtype: None
    :raises argparse.ArgumentTypeError: in case of invalid interface
    """
    if not (pyric.pyw.iswireless(interface) and interfaces.does_have_mode(interface, "AP")):
        message = ("Provided interface ({}) either does not exist or does not support AP mode".
                   format(interface))
        raise argparse.ArgumentTypeError(message)


def validate_monitor_interface(interface):
    """
    Raise an error if the given interface does not support monitor mode

    :param interface: Name of an interface
    :type interface: str
    :return: None
    :rtype: None
    :raises argparse.ArgumentTypeError: in case of invalid interface
    """
    if not (pyric.pyw.iswireless(interface) and interfaces.does_have_mode(interface, "monitor")):
        message = (
            "Provided interface ({}) either does not exist or does not support monitor mode".
            format(interface))
        raise argparse.ArgumentTypeError(message)
