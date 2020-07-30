import sys
import os
from datetime import datetime
from shodan import Shodan
from shodan.exception import APIError as ShodanErr
from socket import timeout as PortTimeout
from time import sleep
from telnetlib import Telnet

# Store api in same directory as script
API_FILE_NAME = ".shodan_api"
absolute_dir = os.path.dirname(__file__)
API_CACHE = os.path.join(absolute_dir, API_FILE_NAME)

# Prompt user for API Key
while True:
    try:
        api_key_file = open(API_CACHE)
        api_key_str = api_key_file.read()
        if len(api_key_str) < 1 or len(api_key_str) > 1000:
            raise Exception("Bad API key")
    except:
        api_key_str = input("Please enter your Shodan API key: ")
        api_key_file = open(API_CACHE, 'w')
        api_key_file.write(api_key_str)
        api_key_file.close()
    if len(api_key_str) > 1 and len(api_key_str) < 1000:
        break
    else:
        print("Invalid API key. Please try again.")

# Setup
API_KEY = api_key_str
api = Shodan(API_KEY)
input_file_loc = str(input("Path to input file: "))
output_file_loc = str(input("Path to output file: "))
time = datetime.now().strftime("%Y-%m-%d %H:%M")
defaultPorts = ["20", "21", "22", "53", "2000", "3389", "6001"]
defaultModules = ["rdp", "ssh", "ftp", "telnet"]
desiredPorts = defaultPorts
desiredModules = defaultModules

# Open the output file
outputFile = open(output_file_loc, 'a')
outputFile.write("Port survey " + time + ":\n")

# Read lines from input file into list
rangeList = open(input_file_loc).read().splitlines()

# Main loop runs on each line from input
for row in rangeList:

    # Blank lines
    if row == '':
        outputFile.write(row + "\n")
        outputFile.flush()
        continue
        
    charOne = row[0]

    # Comments
    if charOne == '#':
        outputFile.write(row + "\n")
        outputFile.flush()
        print("\n" + row)
        continue
    
    # Port changes
    if charOne == "P" or charOne == "p":
        spacelessRow = row.replace(' ', '')
        if spacelessRow[1] == "=":
            desiredPorts = spacelessRow[2:].split(",")
            if len(desiredPorts) == 1 and desiredPorts[0] == "default":
                desiredPorts = defaultPorts
            print("\nScanning for ports: " + ", ".join(desiredPorts))
            continue
    
    # Module changes
    if charOne == "M" or charOne == "m":
        spacelessRow = row.replace(' ', '')
        if spacelessRow[1] == "=":
            desiredModules = spacelessRow[2:].split(",")
            if len(desiredModules) == 1 and desiredModules[0] == "default":
                desiredModules = defaultModules
            print("\nScanning for modules: " + ", ".join(desiredModules))
            continue

    # Saves a low and high IP for comparison
    subnetArr = []
    entry_int = []
    entry = row.replace(' ', '').split("/")
    for IP in entry:
        IP_num_arr = IP.split(".")
        for IP_num in IP_num_arr:
            entry_int.append(int(IP_num))
        subnetArr.append(entry_int)
        entry_int = []
        IP_num_arr = []
        
    # For signle IP cases
    if len(subnetArr) == 1:
        subnetArr.append(subnetArr[0])
    
    x = []
    x.append(subnetArr[0][0])
    x.append(subnetArr[0][1])
    x.append(subnetArr[0][2])
    x.append(subnetArr[0][3])
    y = []
    y.append(subnetArr[1][0])
    y.append(subnetArr[1][1])
    y.append(subnetArr[1][2])
    y.append(subnetArr[1][3])

    low_IP  = int(str(x[0]) + str(x[1]) + str(x[2]) + str(x[3]))
    high_IP = int(str(y[0]) + str(y[1]) + str(y[2]) + str(y[3]))

    # Scans through each IP in range
    while True:
        low_IP  = int(str(x[0]) + str(x[1]) + str(x[2]) + str(x[3]))
        IP = str(x[0]) + '.' + str(x[1]) + '.' +  str(x[2]) + '.' +  str(x[3])
        
        # Keeps name of current IP on screen
        print ("Scanning IP: ", end='')
        print(IP + "        ", end="\r", flush=True)

        # Writes addresses to file
        try:
            shodanOutput = api.host(IP)
            if shodanOutput is not None:
                for info in shodanOutput['data']:
                    port = (str(info['port']))
                    module = (str(info['_shodan']['module']))
                    if (port in desiredPorts) or (module in desiredModules):
                        try:
                            temp = Telnet(IP, port, 5)
                            line = (IP + ":" + port + "  " + module + "\n")
                            outputFile.write(line)
                        except (PortTimeout, ConnectionError) as e:
                            # Cached port has already been closed
                            pass
        except ShodanErr as e:
            if str(e) == "Invalid API key":
                api_key_file = open(API_CACHE, 'w')
                api_key_file.close()
                print("\nInvalid API key!")
                exit()
            pass
            
        # Calculates next IP
        x[3] += 1
        if x[3] > 255:
            x[3] = 0
            x[2] += 1
            if x[2] > 255:
                x[2] = 0
                x[1] += 1
                if x[1] > 255:
                    x[1] = 0
                    x[0] += 1
        
        # Rests for one second between requests, per Shodan requirements
        sleep(1)
        if low_IP == high_IP:
            break
            
    outputFile.flush()
        
# Ends program
print("\n\nAll Set!")
outputFile.write("\n")
outputFile.close()
