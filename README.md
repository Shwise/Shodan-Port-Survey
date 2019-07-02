# Shodan Port Survey
> Python script to scan for specified open ports across ranges of IPv4 addresses

<br/>

Using the port-survey.py found in this folder, anyone can scan for open ports on a subnet. The user must have a Shodan account and can access the associated API here: https://account.shodan.io/

### Python File

First, download each of the files. Open the Python file in a text editor and paste your Shodan API key between the single quotes on line 8 ("API_KEY = ''"). Save and close the file.

Ensure the latest version of Python is installed on your machine.

### Input File

You can now add your own ranges into the input document. The format is as follows:

Lines containing IP addresses may include either a single IP address or two IP addresses separated by a /. Examples:
```
<br/>192.168.1.1
<br/>1.1.1.1/8.8.8.8
<br/>10.10.10.10 / 10.10.10.15
```

While a default list of ports and modules for which to scan is included, these can individually be overridden at any time by using lines of these formats:
```
<br/># For ports
<br/>p = 21, 53, 443
<br/># For modules
<br/>m = telnet, x11
```

To reset use:
```
<br/>p = default
<br/>m = default
```

Any line beginning with a # will be treated as a comment. Empty lines will be ignored.

### Running the Script

Run the script using this command:
<br/>```python port-survey.py input.txt output.txt```

<br/><br/>

Please submit any bug reports through the Issues tab. Thank you.
