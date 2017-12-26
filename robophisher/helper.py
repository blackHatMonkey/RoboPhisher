"""
This module hosts the helper commands used by other modules
"""
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
