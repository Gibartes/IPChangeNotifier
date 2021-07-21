# IPChangeNotifier
## Overview
This python script is designed to detect changes in external IP address. When the host's IP address changes, IPChangeNotifier uses an encrypted token to send that information to the registered email. User information token, including passwords and email accounts, is encrypted and stored separately. Security tokens are not available on other computers unless you configure maliciously manipulated settings or steal Windows' credentials from that system. You can review operational logs in Windows event log.

## Dependency
This program is currently only available on Windows. It uses the third party python library listed below. 
- pywin32
- wmi
- requests

## How to use it
First, run the python script to register the sender and listener. Then register the script with the task scheduler to start automatically at boot time. If you get some errors, look for event logs with the event code 587XX.
