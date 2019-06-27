# Shodan-Port-Survey
## Python script to scan for specified open ports across ranges of IPv4 addresses

Using the port-survey.py found in this folder, anyone can scan for open ports on a subnet.

### Python File

First, download each of the files. Open the python file in a text editor and paste your Shodan API key between the single quotes on line 7 ("API_KEY = ''"). Save and close the file.

### Input File

You can now add your own ranges into the input document. The format is as follows:

The first line is optional. Here, one can include comma-separated ports for which to scan. These will override the default list. Example:
\n20, 21, 22, 4443

To only scan for one port, use this format:
\n20, 20

All subsequent lines must include TWO IP addresses, representing the high and low ends of the given subnet. Examples:
\n1.1.1.1/8.8.8.8
\n10.10.10.10/10.10.10.10

Any line beginning with a # will be treated as a comment. Empty lines will be ignored.

### Running the Script

Run the script using this command:
\npython port-survey.py input.txt output.txt



Please submit any bugs through the Issues tab. Thank you.
