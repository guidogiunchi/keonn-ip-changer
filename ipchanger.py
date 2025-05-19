##### IMPORTANT #####
# run on cmd:
# netsh interface ip delete arpcache 
# before running this script to clear the ARP cache

import websocket
import json
import time
import socket
import ipaddress
import ping3
from scapy.all import ARP, Ether, srp
import csv
from datetime import datetime
import os

TARGET_SUBNET = "192.168.1.0/24" #your pc must be on the keonn network
GATEWAY = "192.168.1.1"
CLEAR_CACHE_ON_ALREADY_CHANGED = False # if the IP is ok, decide to clear the cache or noe
ERROR_LOG_FILE = "keonn_errors.csv"
ERROR_HEADERS = ["Timestamp", "IP", "MAC", "Error"]


def load_csv(file_path):
    devices = []
    with open(file_path, mode='r', encoding='utf-8-sig') as csvfile:  #using UTF-8-SIG to be excel compatible, remove -sig if you have import errors
        reader = csv.DictReader(csvfile)
        for row in reader:
            device = {
                "MAC_ADDRESS": row["MACADDRESS"],
                "IP": row["IP"],
                "Hostname": row["HOSTNAME"]
            }
            devices.append(device)
    return devices


def get_ip(mac):
    # Create the ARP request packet
    print(f"Scanning {TARGET_SUBNET} for {mac}...............", end="")
    arp = ARP(pdst=TARGET_SUBNET)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # broadcast
    packet = ether / arp

    # Send the packet and receive responses
    result = srp(packet, timeout=2, verbose=0)[0]
    # Check if the IP is in the result
    for sent, received in result:
        if received.hwsrc == mac:
            print(f"OK, IP {received.psrc}")
            return received.psrc
    # If the MAC address is not found, return None    
    print(f"ERROR, MAC {mac} not found in the network.")
    return None
        

#try to ping the device
def ping_device(ip):
    return isinstance(ping3.ping(ip), float)


def log_error(ip, mac, error_msg):
    """Log errors to CSV file with timestamp, IP, MAC and error message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Create file with headers if it doesn't exist
    if not os.path.exists(ERROR_LOG_FILE):
        with open(ERROR_LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(ERROR_HEADERS)
    
    # Append error
    with open(ERROR_LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, ip, mac, error_msg])


def keonn_ws_change_ip(old_ip, new_ip, port=11987, hostname="",mac_address=""):
    # Connect to the websocket server
    print(f"Connecting to websocket server at ..........................", end="")
    ws = websocket.create_connection(f"ws://{old_ip}:{port}/")
    print(f"OK, ws server at {old_ip}:{port}")
    
    # Prepare the test command
    test_command = {
        "type": "REST",
        "url": "/status",
        "method": "GET",
        "id": 0,
        "data": None
    }
    
    # Send command as JSON string
    ws.send(json.dumps(test_command))
    
    # Receive the response
    response = ws.recv()
    print(f"Checking if the hostname is correct.........................", end="")
    if hostname in response:
        print(f"OK, {hostname} found.")
    else:
        print(f"ERROR, {hostname} mismatch.")
        ws.close()
        return None
    
    print(f"Changing IP address.........................................", end="")
    # TODO: Add the IP change command here
    network = ipaddress.ip_network("192.168.6.0/24", strict=False)
    subnet_mask = str(network.netmask)
    prefix_length = str(network.prefixlen)
    change_ip_command = {"type":"REST","url":"/devices/"+ hostname +"/networkDevice/network","method":"PUT","id":2,"data":"<request>\n                        <ip>"+new_ip+"</ip>\n                        <dns>8.8.8.8,8.8.4.4</dns>\n                        <mode>STATIC</mode>\n                        <subnet>"+ subnet_mask +"</subnet>\n                        <subnet-prefix>"+prefix_length+"</subnet-prefix>\n                        <gateway>"+GATEWAY+"</gateway>\n                        <mac>"+mac_address+"</mac>\n                        <ntp>0.europe.pool.ntp.org,1.europe.pool.ntp.org,0.north-america.pool.ntp.org,1.north-america.pool.ntp.org,0.south-america.pool.ntp.org,1.south-america.pool.ntp.org,0.africa.pool.ntp.org,1.africa.pool.ntp.org,0.asia.pool.ntp.org,1.asia.pool.ntp.org,0.oceania.pool.ntp.org,1.oceania.pool.ntp.org</ntp>\n                    </request>"}
    
    # Send command as JSON string
    ws.send(json.dumps(change_ip_command))
    print(f"OK, command sent.")
    # Close the connection
    ws.close()
    return True


def keonn_ws_clear_cache(ip, port=11987):
    # Connect to the websocket server
    print(f"Sending reset cache command.................................", end="")
    ws = websocket.create_connection(f"ws://{ip}:{port}/")
    
    # Prepare the clear cache command
    clear_cache_command = {
       "type":"REST",
       "url":"/system/os/DataReset",
       "method":"GET",
       "id":0,
       "data":None
    }
    
    # Send command as JSON string
    ws.send(json.dumps(clear_cache_command))
    print(f"OK, closing connection.")
    
    # Close the connection
    ws.close()


#do a main function to test the functions
if __name__ == "__main__":
    csv_file_path = "keonn_csv.csv"
    print("Loading CSV file............................................", end="")
    csv_devices = load_csv(csv_file_path)
    print("OK, loaded "+ str(len(csv_devices)) + " devices.")
    for device in csv_devices:

        # Get the IP address of the device
        previous_ip = get_ip(device["MAC_ADDRESS"])
        if previous_ip is None:
            log_error(device["IP"], device["MAC_ADDRESS"], "MAC not found in network")
            continue
        # Check if the IP address is already equalt to the new IP address
        if previous_ip == device["IP"]:
            if CLEAR_CACHE_ON_ALREADY_CHANGED:
                print(f"IP address already set to {device['IP']}, clearing cache.")
                keonn_ws_clear_cache(device["IP"], port=11987)
            else:
                print(f"IP address already set to {device['IP']}, not clearing cache.")
            continue

        #try to ping the device
        print(f"Pinging the device..........................................", end="")
        if not ping_device(previous_ip):
            log_error(previous_ip, device["MAC_ADDRESS"], "Device not reachable")
            print(f"ERROR, {previous_ip} is not reachable.")
            continue
        else:
            print(f"OK")
        
        #verify tat the new ip is not already in use
        #ping the new ip
        print(f"Checking if the new IP address is free......................", end="")
        if ping_device(device["IP"]):
            log_error(device["IP"], device["MAC_ADDRESS"], "New IP already in use")
            print(f"ERROR, {device['IP']} already in use, only clearing cache.")
            continue
        else:
            print(f"OK, {device['IP']} free, changing.")
            #modify the IP address using the websocket command
            result = keonn_ws_change_ip(previous_ip, device["IP"], port=11987,hostname=device["Hostname"],mac_address=device["MAC_ADDRESS"])
            if result is None:
                log_error(previous_ip, device["MAC_ADDRESS"], f"Hostname mismatch: {device['Hostname']}")
                print(f"ERROR! {device['Hostname']}, continuing to next device.")
                continue
            #ping the device until it is reachable
            print(f"Waiting for the device to be reachable......................", end="")
            while not ping_device(device["IP"]):
                print(f"WAIT {device['IP']} is not reachable, waiting.")
                print(f"Waiting for the device to be reachable......................", end="")
                time.sleep(2)
            print(f"OK {device['IP']} is reachable, clearing cache.")
            keonn_ws_clear_cache(device["IP"], port=11987)
