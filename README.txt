RFC 793 in TCP by Mark Quimpo



This is second attempt for this homework number 2 and not working program.
I spent to much time for this and felt so depress I could not complete the program.
I finally implemented the Go-Back-In and Sliding Window. And the last attempt is to
Convert everything to bytes so I should not use the pickle. From there, everything is so messy. I did try to use the bytes to send over in socket and able to do it and incomplete.
I could not finish it terrible and my whole time was wasted. I have a sleepless night this week just to focus this but I could not.
Please take a look the code and run the same command provided below.
please If this is more grades deduction than compare the one I submitted last week, Can I use that score whichever. Feel so drained right now.




Files:

*Mage.txt
*README.txt
*TFTP_Client.py
*TFTP_Server.py

====================================================================
RUN:
====================================================================
Server:
$ python3 TFTP_Server.py -a 6110

Client:
Read Request:
$ python3 TFTP_Client.py -l 127.0.0.1 -g Mage.txt -a 6110

Write Request
$ python3 TFTP_Client.py -l 127.0.0.1 -p Mage.txt -a 6110
====================================================================

Implemented:
> RFC 793 TCP Header
    -[16 bits] Source Port
    -[16 bits] Destination Port
    -[32 bits] Sequence Number
    -[32 bits] Acknowledgment Number
    -[16 bits] Offset Flag
    -[16 bits] Windows size
    -[16 bits] Checksum
    -[32 bits] Data

>Checksum Output
>Windows size random between 3 to 10
>Basic Go-Back-N protocol
>Sequence and Acknowledge Number
>TCP Connection in RFC 792 Figure 6


