import mock
import robophisher.common.firewall as firewall
import robophisher.helper as helper


@mock.patch("robophisher.common.firewall.helper.run_command")
def test_clear_rules_no_error(run_command):
    """
    Test clear_rules which results in no errors
    """
    run_command.return_value = (True, None)

    assert firewall.clear_rules() == (True, None)


@mock.patch("robophisher.common.firewall.helper.run_command")
def test_clear_rules_error(run_command):
    """
    Test clear_rules which results in an error
    """
    error_message = "ERROR"
    run_command.return_value = (False, error_message)

    assert firewall.clear_rules() == (False, error_message)


@mock.patch("robophisher.common.firewall.helper.run_command")
def test_redirect_to_localhost_no_error(run_command):
    """
    Test redirect_to_localhost which results in no error
    """
    run_command.return_value = (True, None)

    assert firewall.redirect_to_localhost() == (True, None)


@mock.patch("robophisher.common.firewall.helper.run_command")
def test_redirect_to_localhost_error(run_command):
    """
    Test redirect_to_localhost which results in an error
    """
    error_message = "ERROR"
    run_command.return_value = (False, error_message)

    assert firewall.redirect_to_localhost() == (False, error_message)
