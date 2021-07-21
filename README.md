# IPChangeNotifier
## Overview
This Python script is designed to detect changes in external IP addresses. When the host's IP address changes, IPChangeNotifier uses an encrypted token to send that information to the registered email. User information token, including passwords and email accounts, is encrypted and stored separately. You cannot use secure tokens on other computers without malicious settings. You can review the operational logs in the Windows event log.

## Depeneency
This program is currently only available on Windows. It uses the third party Python library listed below. 
- pywin32
- wmi
- requests
