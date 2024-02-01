# Packet Sniffer Project

## Description

This packet sniffer is a Python-based tool designed for network monitoring and analysis. It captures and processes network packets in real-time to display network interface details, sniff HTTP packets, and extract useful information such as MAC and IP addresses, URLs, and potential login credentials.

## Features

* Retrieves MAC and IP addresses of network interfaces.
* Sniffs network packets on specified interfaces with a focus on HTTP traffic.
* Extracts URLs and potential login information from captured packets.
* Displays captured information in a user-friendly manner using PrettyTable and Colorama for enhanced readability.

## Prerequisites

Before running the packet sniffer, you need to have Python 3.6 or later installed on your system. All necessary Python libraries are listed in the requirements.txt file, which simplifies the installation process.

## Installation

1. Clone the repository to your local machine:
* `git clone https://github.com/Mberra6/Packet-Sniffer.git`
2. Navigate to the project directory:
* `cd Packet-Sniffer`
3. Install the required dependencies:
* `pip install -r requirements.txt`

## Usage

To run the packet sniffer, execute the following command in the terminal. Note that you may need to run it with root privileges to enable packet capturing capabilities.

* On Linux/macOS:
  * `sudo python3 main.py`
* On Windows (run Command Prompt or PowerShell as Administrator):
  * `python main.py`


Follow the on-screen prompts to select the network interface you wish to monitor and any other options the script may offer.

## Ethical Considerations

This tool is intended for educational and legitimate security testing purposes only. Always ensure you have explicit permission to monitor and analyze network traffic on the network being tested. Unauthorized use of this tool against networks you do not own or without permission is against the law.

## Acknowledgments

* This project was inspired by the need for accessible network analysis tools for educational purposes.
* Thanks to the developers of the libraries used in this project.
