import mock
import robophisher.helper as helper


@mock.patch("robophisher.helper.subprocess.Popen")
def test_run_command_no_error(popen):
    """
    Test run_command which results in no errors
    """
    popen.return_value.communicate.return_value = (None, "")

    command = "ls -l".split()

    assert helper.run_command(command) == (True, None)


@mock.patch("robophisher.helper.subprocess.Popen")
def test_run_command_error(popen):
    """
    Test run_command which results in an errors
    """
    error_message = "SOME ERROR"
    popen.return_value.communicate.return_value = (None, error_message)

    command = "ls -l".split()

    assert helper.run_command(command) == (False, error_message)
