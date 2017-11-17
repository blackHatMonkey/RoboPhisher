[![Build Status](https://travis-ci.org/blackHatMonkey/RoboPhisher.svg?branch=master)](https://travis-ci.org/blackHatMonkey/RoboPhisher)
![Python Version](https://img.shields.io/badge/python-2.7-blue.svg)
![License](https://img.shields.io/badge/license-GPL-blue.svg)

## About
RoboPhisher is a security tool that mounts automated victim-customized phishing attacks against WiFi clients in order to obtain credentials or infect the victims with malwares. It is primarily a social engineering attack that unlike other methods it does not include any brute forcing. It is an easy way for obtaining credentials from captive portals and third party login pages (e.g. in social networks) or WPA/WPA2 pre-shared keys.

RoboPhisher works on Kali Linux and is licensed under the GPL license.

## How it works
After achieving a man-in-the-middle position using the Evil Twin or KARMA attack, RoboPhisher redirects all HTTP requests to an attacker-controlled phishing page.

From the victim's perspective, the attack makes use in three phases:

1. **Victim is being deauthenticated from her access point**. RoboPhisher continuously jams all of the target access point's wifi devices within range by forging “Deauthenticate” or “Disassociate” packets to disrupt existing associations.
2. **Victim joins a rogue access point**. RoboPhisher sniffs the area and copies the target access point's settings. It then creates a rogue wireless access point that is modeled by the target. It also sets up a NAT/DHCP server and forwards the right ports. Consequently, because of the jamming, clients will eventually start connecting to the rogue access point. After this phase, the victim is MiTMed. Furthermore, RoboPhisher listens to probe request frames and spoofs "known" open networks to cause automatic association.
3. **Victim is being served a realistic specially-customized phishing page**. RoboPhisher employs a minimal web server that responds to HTTP & HTTPS requests. As soon as the victim requests a page from the Internet, robophisher will respond with a realistic fake page that asks for credentials or serves malwares. This page will be specifically crafted for the victim. For example, a router config-looking page will contain logos of the victim's vendor. The tool supports community-built templates for different phishing scenarios.


## Requirements
Following are the requirements for getting the most out of RoboPhisher:

* Kali Linux. Although people have made RoboPhisher work on other distros, Kali Linux is the officially supported distribution, thus all new features are primarily tested on this platform.
* One wireless network adapter that supports AP & Monitor mode and is capable of injection. For advanced mode, you need two cards; one that supports AP mode and another that supports Monitor mode. Drivers should support netlink.

## Installation

To install the latest development version type the following commands:

```bash
git clone https://github.com/robophisher/robophisher.git # Download the latest revision
cd robophisher # Switch to tool's directory
sudo python setup.py install # Install any dependencies (Currently, hostapd, dnsmasq, PyRIC, blessings)
```

Alternatively, you can download the latest stable version from the <a href="https://github.com/wifiphisher/wifiphisher/releases">Releases page</a>.

## Usage

Run the tool by typing `robophisher` or `python bin/robophisher` (from inside the tool's directory).

By running the tool without any options, it will find the right interfaces and interactively ask the user to pick the ESSID of the target network (out of a list with all the ESSIDs in the around area) as well as a phishing scenario to perform. By default, the tool will perform both Evil Twin and KARMA attacks.

***

```shell
robophisher -aI wlan0 -jI wlan4 -p firmware-upgrade --handshake_capture handshake.pcap
```

Use wlan0 for spawning the rogue Access Point and wlan4 for DoS attacks. Select the target network manually from the list and perform the "Firmware Upgrade" scenario. Verify that the captured Pre-Shared Key is correct by checking it against the handshake in the handshake.pcap file.

Useful for manually selecting the wireless adapters. The "Firmware Upgrade" scenario is an easy way for obtaining the PSK from a password-protected network.

***

```shell
robophisher --essid CONFERENCE_WIFI -p plugin_update
```

Automatically pick the right interfaces. Target the Wi-Fi with ESSID "CONFERENCE_WIFI" and perform the "Plugin Update" scenario.
Useful against networks with disclosed PSKs (e.g. in conferences). The "Plugin Update" scenario provides an easy way for getting the victims to download malicious executables (e.g. malwares containing a reverse shell payload).

***

```shell
robophisher --nojamming --essid "FREE WI-FI" -p oauth-login
```

Do not target any network. Simply spawn an open Wi-Fi network with ESSID "FREE WI-FI" and perform the "OAuth Login" scenario.

Useful against victims in public areas. The "OAuth Login" scenario provides a simple way for capturing credentials from social networks, like Facebook.

Following are all the options along with their descriptions (also available with `robophisher -h`):

| Short form | Long form | Explanation |
| :----------: | :---------: | :-----------: |
|-h | --help| show this help message and exit |
|-jI JAMMINGINTERFACE| --jamminginterface JAMMINGINTERFACE|	Manually choose an interface that supports monitor mode for deauthenticating the victims. Example: -jI wlan1|
|-aI APINTERFACE| --apinterface APINTERFACE|	Manually choose an interface that supports AP mode for spawning an AP. Example: -aI wlan0|
|-nJ| --nojamming|	Skip the deauthentication phase. When this option is used, only one wireless interface is required|
|-e ESSID| --essid ESSID|	Enter the ESSID of the rogue Access Point. This option will skip Access Point selection phase. Example: --essid 'Free WiFi'|
|-p PHISHINGSCENARIO| --phishingscenario PHISHINGSCENARIO	|Choose the phishing scenario to run.This option will skip the scenario selection phase. Example: -p firmware_upgrade|
|-qS| --quitonsuccess|	Stop the script after successfully retrieving one pair of credentials.|
|-iAM| --mac-ap-interface| Specify the MAC address of the AP interface. Example: -iAM 38:EC:11:00:00:00|
|-iDM| --mac-deauth-interface| Specify the MAC address of the jamming interface. Example: -iDM E8:2A:EA:00:00:00|
|-iNM| --no-mac-randomization| Do not change any MAC address.|
|-hC|--handshake-capture|Capture of the WPA/WPA2 handshakes for verifying passphrase. Example: -hC capture.pcap|
|-dE|--deauth-essid|Deauth all the BSSIDs having same ESSID from AP selection or the ESSID given by -e option.|
||--logging| Enable logging. Output will be saved to robophisher.log file.|
||--payload-path| Enable the payload path. Intended for use with scenarios that serve payloads.|

## Help needed
If you are a Python developer or a web designer you can help us improve RoboPhisher. Feel free to take a look at the <a href="https://github.com/blackHatMonkey/RoboPhisher/issues">bug tracker</a> for some tasks to do.

If you don't know how to code, you can help us by <a href="https://github.com/blackHatMonkey/RoboPhisher/issues">proposing improvements or reporting bugs</a>.
Please have a look at the <a href="https://github.com/blackHatMonkey/RoboPhisher/wiki/Bug-reporting-guidelines">Bug Reporting Guidelines</a> beforehand.
Note that the tool does not aim to be script-kiddie friendly. Make sure you do understand how the tool works before opening an issue.

A full list of contributors lies <a href="https://github.com/blackHatMonkey/RoboPhisher/graphs/contributors">here</a>.

## License
RoboPhisher is licensed under the GPL license. See [LICENSE](LICENSE) for more information.

## Disclaimer
* Usage of RoboPhisher for attacking infrastructures without prior mutual consistency can be considered as an illegal activity. It is the final user's responsibility to obey all applicable local, state and federal laws. Authors assume no liability and are not responsible for any misuse or damage caused by this program.
