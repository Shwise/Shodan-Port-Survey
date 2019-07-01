import sys
from datetime import datetime
from shodan import Shodan
from time import sleep
from telnetlib import Telnet

# Setup
API_KEY = ''
api = Shodan(API_KEY)
input = sys.argv[1]
output = sys.argv[2]
time = datetime.now().strftime("%Y-%m-%d %H:%M")
defaultPorts = ["20", "21", "22", "23", "53", "2000", "3389", "6001"]

# Open the output file
outputFile = open(output, 'a')
outputFile.write("Port survey " + time + ":\n")

# Read lines from input file into list
rangeList = open(input).read().splitlines()

# List of desired ports
first_line = rangeList[0].replace(' ', '')
desired_Ports = first_line.split(",")
if len(desired_Ports) < 2 or desired_Ports[0][0] == '#':
    desired_Ports = defaultPorts
else:
    rangeList.pop(0)
print("Scanning for ports: " + ", ".join(desired_Ports))

# Main loop runs on each line from input
for row in rangeList:

    # Blank lines and comments
    if row == '' or row[0] == '#':
        outputFile.write(row + "\n")
        outputFile.flush()
        if row != '':
            print("\n" + row)
        continue

    # Saves a low and high IP for comparison
    subnetArr = []
    entry_int = []
    entry = row.split("/")
    for IP in entry:
        IP_num_arr = IP.split(".")
        for IP_num in IP_num_arr:
            entry_int.append(int(IP_num))
        subnetArr.append(entry_int)
        entry_int = []
        IP_num_arr = []
    
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
            for info in shodanOutput['data']:
                port = (str(info['port']))
                if port in desired_Ports:
                    try:
                        temp = Telnet(IP, port)
                        line = (IP + ":" + port + "\n")
                        outputFile.write(line)
                    except:
                        pass
        except:
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
