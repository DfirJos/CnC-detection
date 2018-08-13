# Detecting (domain fronted) C&C channels

C&C beacons are used to poll the C&C server for further instructions. These beacons often have a stream of packets sharing the same payload size which provides chances for detection. Bro scripts cnc_type1 and cnc_type2 aim to detect C&C traffic leveraging the lack of payload size variance in a stream of TCP packets in a TCP flow. When C&C traffic is detected it requests process information on the end-point such as the process-name and path responsible for initiating the C&C traffic. Providing an analyst with information on both the host-level and network-level allows for faster decision making, an example of the alert is as follows:

![Image of alert](https://raw.githubusercontent.com/sjosz/CnC-detection/master/Images/alert.png)

Two Bro script are developed which can be run simultaneously. The first Bro script (cnc_type1.bro) detects C&C traffic leveraging the lack of payload size variance in a sequence of packets in one TCP flow. Since malware agents often creates a new connection for each call to the C&C server, a second script was needed. This script detects C&C traffic leveraging the lack of TCP flow size variance in a sequence of TCP flows to the same IP address.

The script succesfully detects C&C channels configured with PowerShell Empire, Metasploit Meterpreter and Cobalt Strike.

## Requirements
- Bro: https://github.com/bro
- Bro-Osquery: https://github.com/bro/bro-osquery
