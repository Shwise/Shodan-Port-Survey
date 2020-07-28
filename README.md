# Shodan Port Survey
> Python script to scan for specified open ports across ranges of IPv4 addresses

<br/>

Using the port-survey.py found in this folder, anyone can scan for open ports on a subnet. The user must have a Shodan account and can access the associated API here: https://account.shodan.io/

<br/>

### Python File

Ensure the latest version of Python is installed on your machine.

At the first execution, the program will prompt for an API key, which it will store in the current directory in a text file named '.shodan_api'. To clear the API key, simply delete this folder.

<br/>

### Input File

You can now add your own ranges into the input document. The format is as follows.

Lines containing IP addresses may include either a single IP address or two IP addresses separated by a /. Examples:
```
192.168.1.1
1.1.1.1/8.8.8.8
10.10.10.10 / 10.10.10.15
```

While a default list of ports and modules for which to scan is included, these can individually be overridden at any time by using lines of these formats:
```
# For ports
p = 21, 53, 443
# For modules
m = telnet, x11
```

To reset use:
```
p = default
m = default
```

Any line beginning with a # will be treated as a comment. Empty lines will be ignored.

<br/>

### Running the Script

Run the script using this command:
```
python port-survey.py input.txt output.txt
```
Or alternatively:
```
python3 port-survey.py input.txt output.txt
```

<br/><br/>

Please submit any bug reports through the Issues tab. Thank you.
