#!/usr/bin/env python
"""
This module handles the setup for package distribution
"""

from __future__ import print_function
import re
from setuptools import setup, find_packages


def read_long_description():
    """
    Return the long description of the project
    """
    try:
        with open('README.rst') as readme:
            return readme.read()
    except IOError:
        return None


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
INSTALL_REQUIRES = ["PyRIC", "tornado", "pbkdf2", "roguehostapd"]

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
    version="1.3.0",
    entry_points=ENTRY_POINTS,
    install_requires=INSTALL_REQUIRES,
    classifiers=CLASSIFIERS,
    url=URL)
