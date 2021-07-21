# IPChangeNotifier
## Overview
This python script is designed to detect changes in external IP address. When the host's IP address changes, IPChangeNotifier uses an encrypted token to send that information to the registered email. User information token, including passwords and email accounts, is encrypted and stored separately. You cannot use secure tokens on other computers without malicious settings. You can review the operational logs in the Windows event log.

## Dependency
This program is currently only available on Windows. It uses the third party python library listed below. 
- pywin32
- wmi
- requests

## How to use it
First, run the python script to register the sender and listener. Then register the script with the task scheduler to start automatically at boot time.
