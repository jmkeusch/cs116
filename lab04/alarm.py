#!/usr/bin/python3

from scapy.all import *
import argparse
import base64

global tcp_user
global tcp_pw
inc_num = 1

def packetcallback(packet):
  global inc_num
  try:
    # Store common vars from packet
    source = packet[IP].src
    protocol = packet[TCP].dport
    flags = packet[TCP].flags

    #Detect NULL scan
    if packet.haslayer(TCP) and flags == '':
      print(f"ALERT #{inc_num}: #Null scan is detected from {source} (#{protocol})!")
      inc_num += 1
    
    #Detect FIN scan
    if packet.haslayer(TCP) and flags == 'F':
      print(f"ALERT #{inc_num}: #FIN scan is detected from {source} (#{protocol})!")
      inc_num += 1

    #Detect Xmas scan
    if packet.haslayer(TCP) and ('F' in flags and 'P' in flags and 'U' in flags):
      print(f"ALERT #{inc_num}: #Xmas scan is detected from {source} (#{protocol})!")
      inc_num += 1

    #Nikto scan
    if protocol == 80 and packet.haslayer(TCP) and packet.haslayer(Raw):
      data = str(packet.load)
      #print("Data is:", type(data))
      if "Nikto" in data:
        print(f"ALERT #{inc_num}: #Nikto scan is detected from {source} (#{protocol})!")
        inc_num += 1

    #Scan for server message protocol (SMB)
    if protocol == 445 and packet.haslayer(TCP):
      print(f"ALERT #{inc_num}: #SMB scan is detected from {source} (#{protocol})!")
      inc_num += 1

    #Detect scans for Remote Desktop Protocol (RDP) connection 
    if protocol == 3389 and packet.haslayer(TCP):
      print(f"ALERT #{inc_num}: #RDP scan is detected from {source} (#{protocol})!")
      inc_num += 1

    #Detect scans for Virtual Network Computing (VNC) instance(s)
    if protocol == 5900 and packet.haslayer(TCP):
      print(f"ALERT #{inc_num}: #VNC scan is detected from {source} (#{protocol})!")
      inc_num += 1

    #Credentials in the clear
    #HTTP: 80, FTP: 21, IMAP: 143
    #Case 1: HTTP
    if (protocol == 80 or protocol == 8000) and packet.haslayer(TCP) and packet.haslayer(Raw):
      #Check for HTTP credentials (Chat-GPT helped with next 2 lines):
      if b"GET" in packet[Raw].load or b"POST" in packet[Raw].load:
        #Extract credentials
        credentials_match = re.search(b'Authorization: Basic (.+?)(\\r|\\n)', packet[Raw].load)
        if credentials_match:
          credentials_base64 = credentials_match.group(1)
          try: #Decode from base64, parse username, password
            creds_decoded = base64.b64decode(credentials_base64).decode('utf-8')
            unamepw = creds_decoded.split(':')
            uname = unamepw[0]
            pw = unamepw[1]
            print(f"ALERT #{inc_num}: Usernames and passwords sent in-the-clear (HTTP) (username:{uname}, password:{pw})")
            inc_num += 1
          except (UnicodeDecodeError, binascii.Error):
            print("Unable to decode credentials.")

    #Case 2: IMAP 
    if protocol == 143 and packet.haslayer(TCP) and packet.haslayer(Raw):
      if b'LOGIN' in packet[Raw].load:
        credentials_match = re.search(b'LOGIN (.+?)(\\r|\\n)', packet[Raw].load)
        if credentials_match:
          try: #parse strings
            creds_string = str(packet[Raw].load)
            string_list = creds_string.split()
            uname = string_list[2]
            pw_raw = string_list[3]
            pw_len = len(pw_raw)
            pw = pw_raw[1:pw_len-6]
            print(f"ALERT #{inc_num}: Usernames and passwords sent in-the-clear (IMAP) (username:{uname}, password:{pw})")
            inc_num += 1
          except (UnicodeDecodeError, binascii.Error):
            print("Unable to decode credentials.")

    #Case 3: FTP 
    if protocol == 21:
      global tcp_user
      global tcp_pw
      if b"USER" in packet[Raw].load:
        try: #parse username, set as global var
          match = re.search(b'(USER) (.+?)(\\r|\\n)', packet[Raw].load)
          if match:
            uname = match.group(2).decode('utf-8')
            tcp_user = uname
        except (UnicodeDecodeError, ValueError):
          print("Unable to decode or extract a credentials match")
      if b"PASS" in packet[Raw].load:
        try: #parse password, set as global var
          match = re.search(b'(PASS) (.+?)(\\r|\\n)', packet[Raw].load)
          if match:
            pw = match.group(2).decode('utf-8')
            tcp_pw = pw
            if tcp_user and tcp_pw:
              print(f"ALERT #{inc_num}: Usernames and passwords sent in-the-clear (FTP) (username:{tcp_user}, password:{tcp_pw})")
              inc_num += 1
              #Clear vars for next pairing case.
              tcp_user.clear()
              tcp_pw.clear()
        except (UnicodeDecodeError, ValueError):
          print("Unable to decode or extract a credentials match")
        
  except Exception as e:
    # Uncomment the below and comment out `pass` for debugging, find error(s)
    #print(e)
    pass

# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")