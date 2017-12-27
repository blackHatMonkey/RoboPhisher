"""
This module hosts the helper commands used by other modules
"""
from __future__ import print_function
import subprocess
import robophisher.common.constants as constants


def run_command(command):
    """
    Run the given command and return status of completion and any
    possible errors

    :param command: The command that should be run
    :type command: list
    :return: A namedtuple containing completion status followed by an error
        or None
    :rtype: namedtuple(status=bool, error_message=None or str)
    :raises OSError: In case the command does not exist
    :Example:

        >>> command = ["ls", "-l"]
        >>> run_command(command)
        Result(status=True, error_message=None)

        >>> command = ["ls", "---"]
        >>> run_command(command)
        Result(status=False, error_message="ls: cannot access ' ---'")
    """
    _, error = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

    return constants.RESULT(False, error) if error else constants.RESULT_NO_ERROR


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
            print("Please Enter An Integer:", end="")

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
            print(
                "Please Enter An Integer Between {} and {}: ".format(lower_bound, upper_bound),
                end="")
        else:
            break

    return user_input


def wait_on_input():
    """
    Wait untill user presses Enter key

    :return: None
    :rtype: None
    """
    raw_input()


def get_fields_from_string(string, *indexes):
    """
    Return a list of words separated by whitespace with the given
        indexes

   :param string: A string to use
   :param indexes: Indexes of desired positions
   :type string: str
   :type indexes: tuple
   :return: List of words separated by delimiter at given indexes
   :rtype: list
   :Example:

       >>> string = "This Is My String"
       >>> get_fields_from_string(string, 0, 2)
       ['This', 'MY']
    """
    separated_string = string.rstrip().split()
    return list(map(lambda index: separated_string[index], indexes))
