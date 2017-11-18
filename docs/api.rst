==============
API Refrence
==============

-----------------------
Command Line Arguments
-----------------------

.. _help:
.. function:: -h
              --help

    Show this help message and exit

    .. hint::
      .. code-block:: bash

        [sudo] RoboPhisher -h

      .. code-block:: bash

        [sudo] RoboPhisher --help

.. _jamming interface:
.. function:: -jI
              --jamminginterface

    Manually choose an interface that supports monitor mode for deauthenticating the victims.

    .. hint::
      .. code-block:: bash

        [sudo] RoboPhisher -jI wlan1

      .. code-block:: bash

        [sudo] RoboPhisher --jamminginterface wlan1

    .. warning::
      The same interface can **not** be used for both `jamming interface`_ and `ap interface`_ .

.. _ap interface:
.. function:: -aI
              --apinterface

    Manually choose an interface that supports AP mode for spawning an AP.

    .. hint::
      .. code-block:: bash

        [sudo] RoboPhisher -aI wlan1

      .. code-block:: bash

        [sudo] RoboPhisher --apinterface wlan1

    .. warning::
      The same interface can **not** be used for both `jamming interface`_ and `ap interface`_ .

.. _no jamming:
.. function:: -nJ
              --nojamming

    Skip the deauthentication phase. When this option is used, only one wireless interface is
    required.

    .. hint::
      .. code-block:: bash

        [sudo] RoboPhisher -nJ

      .. code-block:: bash

        [sudo] RoboPhisher -nojamming

.. _essid:
.. function:: -e
              --essid

    Enter the ESSID of the rogue access point you would like to create.

    .. hint::
      .. code-block:: bash

        [sudo] RoboPhisher -e "FREE WIFI"

      .. code-block:: bash

        [sudo] RoboPhisher --essid "FREE WIFI"

    .. warning::
      This option will skip access point selection phase.

.. _phishing scenario:
.. function:: -p
              --phishingscenario

    Choose the phishing scenario to run.This option will skip the scenario selection phase.

    .. hint::
      .. code-block:: bash

        [sudo] RoboPhisher -p firmware_upgrade

      .. code-block:: bash

        [sudo] RoboPhisher --phishingscenario firmware_upgrade

    .. note::
      The name of the phishing scenario you specify here must match the folder name of the
      phishing scenario not it's actual name.

    .. warning::
      This option will skip phishing scenario selection phase. This option will also raise an error
      if the specified phishing scenario is not found.

.. _pre shared key:
.. function:: -pk
              --presharedkey

    Add WPA/WPA2 protection on the rogue access point.

    .. hint::
      .. code-block:: bash

        [sudo] RoboPhisher -pk s3cr3tp4ssw0rd

      .. code-block:: bash

        [sudo] RoboPhisher --presharedkey s3cr3tp4ssw0rd


.. _logging:
.. function:: --log-file

    Enable logging information to a file.

    .. hint::
        .. code-block:: bash

            [sudo] RoboPhisher --log-file

    .. warning::
        This argument will only keep the three most recent logs. This means that after the fifth
        execution with the logging option it will overwrite the oldest log.
