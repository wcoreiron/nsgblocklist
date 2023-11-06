Leveraging Azure SDK for Automated IP Analysis and Network Security Enhancements
Description:
This repository contains a Python script that automates the process of IP address analysis, blocklist updating, and Network Security Group management using Azure SDK.

Prerequisites:

Python 3.x
A GitHub repository for the blocklist
VirusTotal API key
AbuseIPDB API key
Azure account credentials


Usage:

Run the script:
Copy code
python nsgcheckwithvtaip.py
When prompted, input the IP address you wish to analyze.
Follow the subsequent prompts to update the GitHub blocklist and Azure NSGs if necessary.
Required Libraries:
Please ensure you have the following libraries installed (also found in requirements.txt):

requests
azure-identity
azure-mgmt-network
emoji (optional for flag display)
Other dependencies as needed

Configuration:

Enter your API keys and Azure credentials in the config.py file.
Update the nsgs_to_update list with your Azure NSG details.
Contributing:
Contributions to this project are welcome! Please read CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.

Support:
For help and support, please open an issue in the GitHub issue tracker.

License:
This project is licensed under the MIT License - see the LICENSE file for details.
