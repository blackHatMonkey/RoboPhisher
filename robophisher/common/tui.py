"""
This module was made to handle the curses sections for the ap selection,
template selection and the main window
"""

import os
import time
import re
from collections import namedtuple
from subprocess import check_output
import curses
import robophisher.common.constants as constants
import robophisher.common.recon as recon

# information for the main terminal
MainInfo = namedtuple("MainInfo", constants.MAIN_TUI_ATTRS)


class TuiMain(object):
    """
    TuiMain class to represent the main terminal window
    """

    def __init__(self):
        """
        Construct the class
        :param self: A TuiMain object
        :type self: TuiMain
        :return: None
        :rtype: None
        """

        self.blue_text = None
        self.orange_text = None
        self.yellow_text = None

    def gather_info(self, screen, info):
        """
        Get the information from pyrobophisher and print them out
        :param self: A TuiMain object
        :param screen: A curses window object
        :param info: A namedtuple of printing information
        :type self: TuiMain
        :type screen: _curses.curses.window
        :type info: namedtuple
        :return: None
        :rtype: None
        """

        # setup curses
        curses.curs_set(0)
        screen.nodelay(True)
        curses.init_pair(1, curses.COLOR_BLUE, screen.getbkgd())
        curses.init_pair(2, curses.COLOR_YELLOW, screen.getbkgd())
        self.blue_text = curses.color_pair(1) | curses.A_BOLD
        self.yellow_text = curses.color_pair(2) | curses.A_BOLD

        while True:
            # catch the exception when screen size is smaller than
            # the text length
            is_done = self.display_info(screen, info)
            if is_done:
                return

    def print_http_requests(self, screen, start_row_num, http_output):
        """
        Print the http request on the main terminal
        :param self: A TuiMain object
        :type self: TuiMain
        :param start_row_num: start line to print the http request
        type start_row_num: int
        :param http_output: string of the http requests
        :type http_output: str
        """

        requests = http_output.splitlines()
        match_str = r"(.*\s)(request from\s)(.*)(\sfor|with\s)(.*)"
        for request in requests:
            # match the information from the input string
            match = re.match(match_str, request)
            if match is None:
                continue

            # POST or GET
            request_type = match.group(1)
            # requst from
            request_from = match.group(2)
            # ip address or http address
            ip_address = match.group(3)
            # for or with
            for_or_with = match.group(4)
            resource = match.group(5)

            start_col = 0
            screen.addstr(start_row_num, start_col, '[')
            start_col += 1
            screen.addstr(start_row_num, start_col, '*', self.yellow_text)
            start_col += 1
            screen.addstr(start_row_num, start_col, '] ')
            start_col += 2

            # concatenate GET or POST
            screen.addstr(start_row_num, start_col, request_type, self.yellow_text)
            start_col += len(request_type)

            # concatenate the word 'request from'
            screen.addstr(start_row_num, start_col, request_from)
            start_col += len(request_from)

            # concatenate the ip address
            screen.addstr(start_row_num, start_col, ip_address, self.yellow_text)
            start_col += len(ip_address)

            # concatenate with or for
            screen.addstr(start_row_num, start_col, for_or_with)
            start_col += len(for_or_with)

            # resource url
            screen.addstr(start_row_num, start_col, resource, self.yellow_text)

            start_row_num += 1

    def display_info(self, screen, info):
        """
        Print the information of Victims on the terminal
        :param self: A TuiMain object
        :param screen: A curses window object
        :param info: A nameduple of printing information
        :type self: TuiMain
        :type screen: _curses.curses.window
        :type info: namedtuple
        :return True if users have pressed the Esc key
        :rtype: bool
        """

        is_done = False
        screen.erase()

        _, max_window_length = screen.getmaxyx()
        try:
            # print the basic info on the right top corner
            screen.addstr(0, max_window_length - 30, "|")
            screen.addstr(1, max_window_length - 30, "|")
            # continue from the "Wifiphisher"
            screen.addstr(1, max_window_length - 29, " RoboPhisher" + info.version, self.blue_text)

            screen.addstr(2, max_window_length - 30, "|" + " ESSID: " + info.essid)
            screen.addstr(3, max_window_length - 30, "|" + " Channel: " + str(info.channel))
            screen.addstr(4, max_window_length - 30, "|" + " AP interface: " + info.ap_iface)
            screen.addstr(5, max_window_length - 30, "|" + " Options: [Esc] Quit")
            screen.addstr(6, max_window_length - 30, "|" + "_" * 29)

            # make Deauthenticating clients to blue color
            # print the deauthentication section
            screen.addstr(1, 0, "Deauthenticating clients: ", self.blue_text)
        except curses.error:
            pass

        if info.em:
            # start raw number from 2
            raw_num = 2
            for client in info.em.get_output()[-5:]:
                screen.addstr(raw_num, 0, client)
                raw_num += 1
        try:
            # print the dhcp lease section
            screen.addstr(7, 0, "DHCP Leases", self.blue_text)
            if os.path.isfile('/var/lib/misc/dnsmasq.leases'):
                dnsmasq_output = check_output(['tail', '-5', '/var/lib/misc/dnsmasq.leases'])
                screen.addstr(8, 0, dnsmasq_output)

            # print the http request section
            screen.addstr(13, 0, "HTTP requests: ", self.blue_text)
            if os.path.isfile('/tmp/robophisher-webserver.tmp'):
                http_output = check_output(['tail', '-5', '/tmp/robophisher-webserver.tmp'])
                self.print_http_requests(screen, 14, http_output)
        except curses.error:
            pass

        # detect if users have pressed the Esc Key
        if screen.getch() == 27:
            is_done = True

        if info.phishinghttp.terminate and info.args.quitonsuccess:
            is_done = True

        screen.refresh()
        return is_done


def display_string(w_len, target_line):
    """
    Display the line base on the max length of window length
    :param w_len: length of window
    :param target_line: the target display string
    :type w_len: int
    :type target_line: str
    :return: The final displaying string
    :rtype: str
    """

    return target_line if w_len >= len(target_line) else target_line[:w_len]


def line_splitter(num_of_words, line):
    """
    Split line to the shorter lines
    :param num_of_words: split the line into the line with lenth equeal
    to num_of_words
    :type num_of_words: int
    :param line: A sentence
    :type line: str
    :return: tuple of shorter lines
    :rtype: tuple
    """
    pieces = line.split()
    return (" ".join(pieces[i:i + num_of_words]) for i in xrange(0, len(pieces), num_of_words))
