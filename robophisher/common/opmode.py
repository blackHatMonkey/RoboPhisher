"""
All logic regarding the Operation Modes (opmodes).

The opmode is defined based on the user's arguments and the available
resources of the host system
"""
import sys
import os
import logging
import argparse
import pyric
import robophisher.common.interfaces as interfaces
import robophisher.common.constants as constants
import robophisher.extensions.handshakeverify as handshakeverify

logger = logging.getLogger(__name__)


class OpMode(object):
    """
    Manager of the operation mode
    """

    def __init__(self):
        """
        Construct the class
        :param self: An OpModeManager object
        :type self: OpModeManager
        :return: None
        :rtype: None
        """

        self.op_mode = 0x0
        # True if the system only contains one phy interface
        self._is_one_phy_interface = False
        # The card which supports monitor and ap mode
        self._perfect_card = None

    def initialize(self, args):
        """
        Initialize the opmode manager
        :param self: An OpModeManager object
        :param args: An argparse.Namespace object
        :type self: OpModeManager
        :type args: argparse.Namespace
        :return: None
        :rtype: None
        """

        self._perfect_card, self._is_one_phy_interface =\
            interfaces.is_add_vif_required(args)
        self._check_args(args)

    def _check_args(self, args):
        """
        Checks the given arguments for logic errors.
        :param self: An OpModeManager object
        :param args: An argparse.Namespace object
        :type self: OpModeManager
        :type args: argparse.Namespace
        :return: None
        :rtype: None
        """

        if args.presharedkey and \
            (len(args.presharedkey) < 8 or
             len(args.presharedkey) > 64):
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] Pre-shared key must be between 8 and 63 printable'
                     'characters.')

        if args.handshake_capture and not os.path.isfile(args.handshake_capture):
            sys.exit('[' + constants.R + '-' + constants.W + '] handshake capture does not exist.')
        elif args.handshake_capture and not handshakeverify.\
                is_valid_handshake_capture(args.handshake_capture):
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] handshake capture does not contain valid handshake')

        if ((args.jamminginterface and not args.apinterface) or
                (not args.jamminginterface and args.apinterface)) and \
                not (args.nojamming and args.apinterface):
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] --apinterface (-aI) and --jamminginterface (-jI)'
                     '(or --nojamming (-nJ)) are used in conjuction.')

        if args.nojamming and args.jamminginterface:
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] --nojamming (-nJ) and --jamminginterface (-jI)'
                     'cannot work together.')

        if (args.mac_ap_interface and args.no_mac_randomization) or \
                (args.mac_deauth_interface and args.no_mac_randomization):
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] --no-mac-randomization (-iNM) cannot work together with'
                     '--mac-ap-interface or --mac-deauth-interface (-iDM)')

        # if args.deauth_essid is set we need the second card to
        # do the frequency hopping
        if args.deauth_essid and self._is_one_phy_interface:
            print('[' + constants.R + '!' + constants.W +
                  '] Only one card was found. Wifiphisher will deauth only '
                  'on the target AP channel')

    def set_opmode(self, args, network_manager):
        """
        Sets the operation mode.

        :param self: An OpModeManager object
        :param args: An argparse.Namespace object
        :param network_manager: A NetworkManager object
        :type self: OpModeManager
        :type args: argparse.Namespace
        :type network_manager: NetworkManager
        :return: None
        :rtype: None

        ..note: An operation mode resembles how the tool will best leverage
        the given resources.

        Modes of operation
        1) Advanced 0x1
          2 cards, 2 interfaces
          i) AP, ii) EM
        2) Advanced and Internet 0x2
          3 cards, 3 interfaces
          i) AP, ii) EM iii) Internet
        3) AP-only and Internet 0x3
          2 cards, 2 interfaces
          i) AP, ii) Internet
        4) AP-only 0x4
          1 card, 1 interface
          i) AP
        5) Advanced w/ 1 vif support AP/Monitor 0x5
          1 card, 2 interfaces
          i) AP, ii) Extensions
        6) Advanced and Internet w/ 1 vif support AP/Monitor 0x6
          2 cards, 3 interfaces
          i) AP, ii) Extensions, iii) Internet
        """

        if not args.internetinterface and not args.nojamming:
            if not self._is_one_phy_interface:
                self.op_mode = constants.OP_MODE1
                logger.info("Starting OP_MODE1 (0x1)")
            else:
                if self._perfect_card is not None:
                    network_manager.add_virtual_interface(self._perfect_card)
                self.op_mode = constants.OP_MODE5
                logger.info("Starting OP_MODE5 (0x5)")
        if args.internetinterface and not args.nojamming:
            if not self._is_one_phy_interface:
                self.op_mode = constants.OP_MODE2
                logger.info("Starting OP_MODE2 (0x2)")
            else:
                if self._perfect_card is not None:
                    network_manager.add_virtual_interface(self._perfect_card)
                self.op_mode = constants.OP_MODE6
                logger.info("Starting OP_MODE6 (0x6)")

        if args.internetinterface and args.nojamming:
            self.op_mode = constants.OP_MODE3
            logger.info("Starting OP_MODE3 (0x3)")
        if args.nojamming and not args.internetinterface:
            self.op_mode = constants.OP_MODE4
            logger.info("Starting OP_MODE4 (0x4)")

    def internet_sharing_enabled(self):
        """
        :param self: An OpModeManager object
        :type self: OpModeManager
        :return: True if we are operating in a mode that shares Internet
        access.
        :rtype: bool
        """

        return self.op_mode in [constants.OP_MODE2, constants.OP_MODE3]

    def advanced_enabled(self):
        """
        :param self: An OpModeManager object
        :type self: OpModeManager
        :return: True if we are operating in an advanced
        mode (a mode that leverages two network cards)
        :rtype: bool
        """

        return self.op_mode in [
            constants.OP_MODE1, constants.OP_MODE2, constants.OP_MODE5, constants.OP_MODE6
        ]

    def deauth_enabled(self):
        """
        :param self: An OpModeManager object
        :type self: OpModeManager
        :return: True if we are operating in a mode
        that deauth is enabled.
        :rtype: bool
        """

        return self.op_mode in [
            constants.OP_MODE1, constants.OP_MODE2, constants.OP_MODE5, constants.OP_MODE6
        ]

    def freq_hopping_enabled(self):
        """
        :param self: An OpModeManager object
        :type self: OpModeManager
        :return: True if we are separating the wireless cards
        for jamming and lunching AP.
        :rtype: bool
        ..note: MODE5 and MODE6 only use one card to do deauth and
        lunch ap so it is not allowed to do frequency hopping.
        """

        return self.op_mode in [constants.OP_MODE1, constants.OP_MODE2]
