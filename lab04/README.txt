README 
Jonathan Keusch
CS116 - Lab04: The Incident Alarm
Feb 25, 2024


WORK IMPLEMENTED

Completed packetcallback(packet) function definition, including the following detections: 

- NULL Scan (testing successful per null.pcap)
- FIN Scan (testing successful per fin.pcap)
- Xmas Scan (testing successful per xmas.pcap)
- Nikto Scan (testing successful per nikto.pcap)
- Usage of SMB (testing successful per smb.pcap)
- Usage of RDP connection (testing successful per rdp.pcap)
- Usage of Virtual network Computing (VNC) (testing successful per null.pcap)

-Sent-in-the-clear usernames, passwords:
     - HTTP (testing successful per set2.pcap, set3.pcap)
     - FTP (testing successful per set1.pcap)
     - IMAP (testing successful per set3.pcap)

HOURS SPENT

This lab took me about 9-10 hours total. 

DEPENDENCIES
- Functional dependencies include import base64 and declaration of global variables outside the packetcallback(packet) function definition. 

- Resource dependencies include: 
     - https://scapy.readthedocs.io/en/latest/usage.html#interactive-tutorial
     - WireShark for analyzing packets
     - Piazza posts (e.g., Lab04 FAQ)
     - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
     - https://medium.com/@adityachavda2106/wireshark-capturing-user-password-a55c0efbbb7d
     - https://www.geeksforgeeks.org/encoding-and-decoding-base64-strings-in-python/
     - https://www.geeksforgeeks.org/file-transfer-protocol-ftp-in-application-layer/
     - https://stackoverflow.com/questions/68551960/how-to-decode-text-with-base64-in-python
     - https://stackoverflow.com/questions/423379/how-to-use-a-global-variable-in-a-function
     - https://www.hackingarticles.in/understanding-nmap-scan-wireshark/
     - https://regex101.com/

- CHAT-GPT:

I did use Chat-GPT to obtain the regex and decode methods used in the in-the-clear scans. I started with HTTP and extrapolated similar methods for IMAP and FTP. 

Prompts included: 
"How to get a username password combination from a raw layer of a pcap file I have stored in a string variable."
 Response: it gave me a function using pychark

"How would I do so without importing anything? I have scapy."

Then it gave me the REGEX re.search(), group(), and decode() methods, which proved useful knowing I had stored the text from [Raw].load. 

However, the original suggestions did not at all work and I essentially used them as starting point with many iterations of print statements to properly parse the usernames and passwords. Once I had the regex text decoded, it was somewhat straightforward.

QUESTIONS:
1. No, I would not say these detections are airtight at all, and seem moreso to detect the presence of a certain event but I wouldn't trust that I have found every case for a specific type of scan. I was surprised at the reverse-engineering it took to even detect the scans. For example, detecting the null or fin scans was simply checking the destination port and flags on the packet, which did not seem like something I would approach someone in confidence about in a professional setting. 

2. Assuming more time, flexibility, I'd consider a more executable solution that could track common or uncommon IP addresses on the network and alert an Admin of repeated attempts from unusual source IPs. The alert system itself could perhaps also be more proactive such as generating reports or providing immediate or conditional alerts to Admins/other stakeholders.

