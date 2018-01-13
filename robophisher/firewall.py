"""
This module handles all the routing and firewall related tasks
"""
import robophisher.constants as constants
import robophisher.helper as helper


def clear_rules():
    """
    Clear(reset) all the firewall rules back to default state and
    return a tuple containing completion status followed by the first
    error that occurred or None

    :return: A tuple containing completion status followed by an error
        or None
    :rtype: namedtuple(status=bool, error_message=None or str)
    :Example:

        >>> clear_rules()
        Result(status=True, error_message=None)

        >>> clear_rules()
        Result(status=False, error_message="SOME ERROR HAPPENED")
    """
    base0 = "iptables -{}"
    base1 = "iptables -t nat -{}"
    commands = [
        base0.format("F").split(),
        base0.format("X").split(),
        base1.format("F").split(),
        base1.format("X").split()
    ]

    error = list(filter(lambda result: result[1], map(helper.run_command, commands)))

    return error[0] if error else constants.RESULT_NO_ERROR


def redirect_to_localhost():
    """
    Configure firewall such that all request are redirected to local
    host

    :return: A namedtuple containing completion status followed by an error
        or None
    :rtype: Result(status=bool, error_message=None or str)
    :Example:

        >>> redirect_to_localhost()
        Result(status=True, error_message=None)

        >>> redirect_to_localhost()
        Result(status=False, error_message="SOME ERROR HAPPNED")
    """
    base = "iptables -t nat -A PREROUTING -p {} --dport {} -j DNAT --to-destination {}:{}"
    commands = [
        base.format("tcp", 80, constants.NETWORK_GW_IP, constants.PORT).split(),
        base.format("tcp", 53, constants.NETWORK_GW_IP, 53).split(),
        base.format("tcp", constants.SSL_PORT, constants.NETWORK_GW_IP,
                    constants.SSL_PORT).split(),
        base.format("udp", 53, constants.NETWORK_GW_IP, 53).split(),
        "sysctl -w net.ipv4.conf.all.route_localnet=1".split()
    ]

    error = list(filter(lambda result: result[1], map(helper.run_command, commands)))

    return error[0] if error else constants.RESULT_NO_ERROR
