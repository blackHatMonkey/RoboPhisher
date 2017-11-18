#!/usr/bin/env python
"""
This module tries to install all the required software.
"""

from __future__ import print_function
import sys
import re
import os
from ctypes.util import find_library
from setuptools import setup, find_packages, Command
import robophisher.common.constants as constants

with open('robophisher/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', fd.read(),
                        re.MULTILINE).group(1)


def read_long_description():
    """
    Return the long description of the project
    """
    try:
        with open('README.rst') as readme:
            return readme.read()
    except IOError:
        return None


class CleanCommand(Command):
    """Custom clean command to tidy up the project root."""
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        os.system('rm -vrf ./build ./dist ./*.pyc ./*.tgz ./*.egg-info')


def get_dnsmasq():
    """
    Try to install dnsmasq on host machine if not present

    :return: None
    :rtype: None
    """

    if not os.path.isfile("/usr/sbin/dnsmasq"):
        install = raw_input(("[" + constants.T + "*" + constants.W + "] dnsmasq not found " +
                             "in /usr/sbin/dnsmasq, " + "install now? [y/n] "))

        if install == "y":
            if os.path.isfile("/usr/bin/pacman"):
                os.system("pacman -S dnsmasq")
            elif os.path.isfile("/usr/bin/yum"):
                os.system("yum install dnsmasq")
            else:
                os.system("apt-get -y install dnsmasq")
        else:
            sys.exit(("[" + constants.R + "-" + constants.W + "] dnsmasq " +
                      "not found in /usr/sbin/dnsmasq"))

    if not os.path.isfile("/usr/sbin/dnsmasq"):
        dnsmasq_message = (
            "\n[" + constants.R + "-" + constants.W +
            "] Unable to install the \'dnsmasq\' package!\n" + "[" + constants.T + "*" +
            constants.W + "] This process requires a persistent internet " +
            "connection!\nPlease follow the link below to configure your " + "sources.list\n" +
            constants.B + "http://docs.kali.org/general-use/" +
            "kali-linux-sources-list-repositories\n" + constants.W + "[" + constants.G + "+" +
            constants.W + "] Run apt-get update for changes " + "to take effect.\n" + "[" +
            constants.G + "+" + constants.W + "] " + "Rerun the script to install dnsmasq.\n[" +
            constants.R + "!" + constants.W + "] Closing")

        sys.exit(dnsmasq_message)


def get_hostapd():
    """
    Try to install hostapd on host system if not present

    :return: None
    :rtype: None
    """

    if not os.path.isfile("/usr/sbin/hostapd"):
        install = raw_input(("[" + constants.T + "*" + constants.W + "] hostapd not found in " +
                             "/usr/sbin/hostapd, install now? [y/n] "))

        if install == "y":
            if os.path.isfile("/usr/bin/pacman"):
                os.system("pacman -S hostapd")
            elif os.path.isfile("/usr/bin/yum"):
                os.system("yum install hostapd")
            else:
                os.system("apt-get -y install hostapd")
        else:
            sys.exit(("[" + constants.R + "-" + constants.W + "] hostapd not found in " +
                      "/usr/sbin/hostapd"))

    if not os.path.isfile("/usr/sbin/hostapd"):
        hostapd_message = ("\n[" + constants.R + "-" + constants.W + "] Unable to install the " +
                           "\'hostapd\' package!\n[" + constants.T + "*" + constants.W + "] " +
                           "This process requires a persistent internet connection!\nPlease " +
                           "follow the link below to configure your sources.list\n" + constants.B +
                           "http://docs.kali.org/general-use/kali-linux-sources-list-" +
                           "repositories\n" + constants.W + "[" + constants.G + "+" + constants.W +
                           "] Run apt-get update for changes to take effect.\n[" + constants.G +
                           "+" + constants.W + "] Rerun the script to install hostapd.\n[" +
                           constants.R + "!" + constants.W + "] Closing")

        sys.exit(hostapd_message)


def get_libdbus():
    """
    Try to install the libdbus
    return: None
    retype: None
    """

    # install the libdbus-1
    if not find_library("dbus-1"):
        install = raw_input(("[" + constants.T + "*" + constants.W + "] libdbus-1 not found " +
                             "install now? [y/n] "))

        if install == "y":
            if os.path.isfile("/usr/bin/apt-get"):
                os.system("apt-get -y install libdbus-1-dev")
            else:
                sys.exit(("[" + constants.R + "-" + constants.W + "] libdbus-1 not found. "
                          "Please install libdbus-1 (i.e. using your package manager)"))
        else:
            sys.exit(("[" + constants.R + "-" + constants.W + "] libdbus-1 not found. "
                      "Please install libdbus-1 (i.e. using your package manager)"))

    # install the dbus-glib-1
    if not find_library("dbus-glib-1"):
        install = raw_input(("[" + constants.T + "*" + constants.W + "] dbus-glib-1 "
                             "not found install now? [y/n] "))

        if install == "y":
            if os.path.isfile("/usr/bin/apt-get"):
                os.system("apt-get -y install libdbus-glib-1-dev")
            else:
                sys.exit(("[" + constants.R + "-" + constants.W + "] libdbus-glib-1 not found. "
                          "Please install libdbus-glib-1 (i.e. using your package manager)"))
        else:
            sys.exit(("[" + constants.R + "-" + constants.W + "] libdbus-glib-1 not found. "
                      "Please install libdbus-glib-1 (i.e. using your package manager)"))


# check the dbus related libraries first
get_libdbus()

# setup settings
NAME = "robophisher"
AUTHOR = "blackHatMonkey"
AUTHOR_EMAIL = "brian.smith@riseup.net"
URL = "https://github.com/blackHatMonkey/RoboPhisher"
DESCRIPTION = "Automated phishing attacks against Wi-Fi networks"
LICENSE = "GPL"
KEYWORDS = ["robophisher", "evil", "twin", "phishing"]
PACKAGES = find_packages(exclude=["docs", "tests"])
INCLUDE_PACKAGE_DATA = True
VERSION = version
CLASSIFIERS = [
    "Development Status :: 5 - Production/Stable",
    "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
    "Natural Language :: English", "Operating System :: Unix",
    "Programming Language :: Python :: 2", "Programming Language :: Python :: 2.7",
    "Programming Language :: Python :: 2 :: Only", "Topic :: Security",
    "Topic :: System :: Networking", "Intended Audience :: End Users/Desktop",
    "Intended Audience :: System Administrators", "Intended Audience :: Information Technology"
]
ENTRY_POINTS = {"console_scripts": ["robophisher= robophisher.pyrobophisher:run"]}
INSTALL_REQUIRES = ["PyRIC", "tornado", "blessings>=1.6", "dbus-python", "pbkdf2", "roguehostapd"]
CMDCLASS = {
    "clean": CleanCommand,
}

# run setup
setup(
    name=NAME,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    description=DESCRIPTION,
    long_description=read_long_description(),
    license=LICENSE,
    keywords=KEYWORDS,
    packages=PACKAGES,
    include_package_data=INCLUDE_PACKAGE_DATA,
    version=VERSION,
    entry_points=ENTRY_POINTS,
    install_requires=INSTALL_REQUIRES,
    classifiers=CLASSIFIERS,
    url=URL,
    cmdclass=CMDCLASS)

# Get hostapd or dnsmasq if needed
get_hostapd()
get_dnsmasq()
