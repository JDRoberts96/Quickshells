# Quickshells
A simple command-line Python3 program to generate a variety of reverse shell codes with custom IP address and port numbers, copy it to the clipboard and open a netcat listener. Primarily works for Linux distributions with the 'nc' version of netcat installed at the moment.

Future improvements include:
* Selecting shell to spawn - i.e. /bin/bash, /bin/sh etc.
* Supporting Ncat installations

## Supported Reverse Shell Codes
The reverse shell code has been taken from the following sources:

* https://gtfobins.github.io/gtfobins/
* http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
* https://www.hackersinterview.com/oscp/reverse-shell-one-liners-oscp-cheatsheet/

The current implementation is capable of generating reverse shell code for the following languages/programs:


| _ | _ | _ | _
| :---: | :---: | :---: | :--: | 
| Bash    | PHP             | Java | Socat
| Perl    | Ruby            | xterm | Awk
| Python  | Netcat (-e)     | Telnet | Powershell x2
| Python3 | Netcat (mkfifo) | GoLang | C

## Demonstration - netcat (-e)
Demonstration below was tested on Kali Linux 2020.2 within VirtualBox 6.1

## Download
```
git clone https://JDRoberts96/Quickshells
```

## Setup / Install and Run
This program has the following dependencies:

* [ipaddress](https://pypi.org/project/ipaddress/) - IP address validation
* [pyfiglet](https://pypi.org/project/pyfiglet/) - Banner printing
* [colorama](https://pypi.org/project/colorama/) - Coloured output
* [netifaces](https://pypi.org/project/netifaces/) - Displaying/using available IP addresses
* [pyperclip](https://pypi.org/project/pyperclip/) - Copying reverse shell code to the clipboard

To set this up, use the following:

```
python3 setup.py install
```

The script can be ran using the following on the command-line:

```
python3 Quickshells.py
```

##
This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details
