# Quickshells
A simple command-line Python3 program to generate a variety of reverse shell codes with custom IP address and port numbers, copy it to the clipboard and open a netcat listener.

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


## Download
```
git clone https://JDRoberts96/Quickshells
```

## Setup / Install
This program has the following dependencies:

* **ipaddress** - IP address validation
* **pyfiglet** - Banner printing
* **colorama** - Coloured output
* **netifaces** - Displaying/using available IP addresses
* **pyperclip** - Copying reverse shell code to the clipboard

To set this up, use the following:

....

##
This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details
