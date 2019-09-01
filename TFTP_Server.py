import socket
import threading
import argparse
import pickle
import os
import binascii
import random
import time


parser = argparse.ArgumentParser()
parser.add_argument('-a', dest='port', default=12000)
args = parser.parse_args()


def TCP_Header(sourceport, destport, seqnum, acknum, offsetflag, window, data):
    offset = (offsetflag >> 12) * 4
    urg = (offsetflag & 32) >> 5
    ack = (offsetflag & 16) >> 4
    psh = (offsetflag & 8) >> 3
    rst = (offsetflag & 4) >> 2
    syn = (offsetflag & 2) >> 1
    fin = offsetflag & 1
    return sourceport, destport, seqnum, acknum, offsetflag, urg, ack, psh, rst, syn, fin, window, data[offset:]

#Intiger to Bytes
def ToBytes(intiger, Bytes):
    return intiger.to_bytes(Bytes, byteorder='big', signed=True)

#Bytes to Intiger = FOR PRINT
def FromBytes(intiger):
    return int.from_bytes(intiger, byteorder='big', signed=True)

#Checksum of 16 bits out of 32 bits (one's complement)
def Checksum(data):
    checks = binascii.crc32(data)
    while (checks >> 16) > 0:
        checks = (checks & 0xFFFF) + (checks >> 16)
        checks = ~checks
    return checks & 0xFFFF

seqnum = 0
acknum = 0

port = int(args.port) #dest
source_port = 12000
windowsize = random.randint(3,9)
#2 bytes = 16 bits of Destination Port
dest_port = ToBytes(port, 2)
#2 bytes = 16 bits of Source Port
source_port = ToBytes(source_port, 2)
#3 bytes = 32 bits of Sequence Number
sseqnum = ToBytes(seqnum, 3)
#3 bytes = 32 bits of Acknowledge Number
sacknum = ToBytes(acknum, 3)
#2 bytes = 16 bits of WindowSize
window = ToBytes(windowsize, 2)


def file():

    try:
        global host
        global port
        global s
        host = ""
        port = args.port
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    except socket.error as msg:
        print("Socket creation error " + str(msg))

    port = args.port
    if int(port) in range(0, 5000):
        print('UNKNOWN TRANSFER ID')
        return port
    else:
        pass

    s.bind((host, int(port)))
    print("Binding the Port: " + str(port))


    windowsize = random.randint(3, 9)
    source_port = 12000
    seqnum = 40


    recvSYN, addr = s.recvfrom(1024)

    print("[Establishing Connection]")

    print('recv: [ACK: {} | SYN: {} | FIN: {} | URG: {}], <seq = {}>'
          .format(recvSYN[4],recvSYN[7], recvSYN[8], recvSYN[3], recvSYN[0]))

    if recvSYN[2] == 2:
        offsetflag = recvSYN[2] + 16
        sdata = recvSYN[9:]
        seqnum = 40
        acknum = recvSYN[0] + 1


        TCP_Header_Dumps = TCP_Header(dest_port, source_port, seqnum, acknum, offsetflag, recvSYN[9], sdata)
        TCP_header = bytearray()
        TCP_header.append(TCP_Header_Dumps[2])
        TCP_header.append(TCP_Header_Dumps[3])
        TCP_header.append(TCP_Header_Dumps[4])  # Offsetflag
        TCP_header.append(TCP_Header_Dumps[5])  # URG
        TCP_header.append(TCP_Header_Dumps[6])  # ACK
        TCP_header.append(TCP_Header_Dumps[7])  # PSH
        TCP_header.append(TCP_Header_Dumps[8])  # RST
        TCP_header.append(TCP_Header_Dumps[9])  # SYN
        TCP_header.append(TCP_Header_Dumps[10]) # FIN
        TCP_header.append(windowsize)           # Windowsize

        sendSYN = bytearray(TCP_header + TCP_Header_Dumps[12])
        s.sendto(sendSYN, addr)

        print('sent: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | ack = {}>'
              .format(sendSYN[4], sendSYN[7], sendSYN[8], sendSYN[0], sendSYN[1]))

        recvACK, addr = s.recvfrom(1024)


        print('recv: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | ack = {}>'
              .format(recvACK[4], recvACK[7], recvACK[8], recvACK[0], recvACK[1]))

        print("[Sending Data]")

        if os.path.isfile(recvACK[9:]):

            data_name = recvACK[9:].decode()
            file_exist = 'get_' + data_name

            if os.path.isfile(file_exist):
                offsetflag = 1 + 16
                seqnum = recvACK[1]
                acknum = recvACK[0] + 1
                Err_Header = TCP_Header(source_port, dest_port, seqnum, acknum, offsetflag, recvACK[9], recvACK[10:])
                TCP_header = bytearray()
                TCP_header.append(Err_Header[2])
                TCP_header.append(Err_Header[3])
                TCP_header.append(Err_Header[4])  # Offsetflag
                TCP_header.append(Err_Header[5])  # URG
                TCP_header.append(Err_Header[6])  # ACK
                TCP_header.append(Err_Header[7])  # PSH
                TCP_header.append(Err_Header[8])  # RST
                TCP_header.append(Err_Header[9])  # SYN
                TCP_header.append(Err_Header[10]) # FIN

                sendERR = bytearray(TCP_header + Err_Header[12])
                s.sendto(sendERR, addr)


                #PRINT
                print('sent: [ACK: {} | SYN: {} | FIN: {} | {}] <FILE ALREADY EXIST>'
                      .format(sendERR[4], sendERR[7], sendERR[8], data_name))

            else:
                f = open(recvACK[9:], 'rb')
                sdata = f.read(512)

                TCP_Data_Dumps = TCP_Header(source_port, dest_port, seqnum, acknum, offsetflag, window, sdata)
                TCP_header = bytearray()
                TCP_header.append(TCP_Data_Dumps[2])
                TCP_header.append(TCP_Data_Dumps[3])
                TCP_header.append(TCP_Data_Dumps[4])  # Offsetflag
                TCP_header.append(TCP_Data_Dumps[5])  # URG
                TCP_header.append(TCP_Data_Dumps[6])  # ACK
                TCP_header.append(TCP_Data_Dumps[7])  # PSH
                TCP_header.append(TCP_Data_Dumps[8])  # RST
                TCP_header.append(TCP_Data_Dumps[9])  # SYN
                TCP_header.append(TCP_Data_Dumps[10])  # FIN
                TCP_header.append(windowsize)  # Windowsize

                seqnum_int = 0
                sizedata = 0


                while True:
                    sdata = f.read(512)
                    offsetflag = 0
                    seqnum_int += 1
                    sizedata += len(sdata)

                    TCP_Data_Dumps = TCP_Header(source_port, dest_port, seqnum_int, acknum, offsetflag, window, sdata)
                    TCP_header = bytearray()
                    TCP_header.append(TCP_Data_Dumps[2])
                    TCP_header.append(TCP_Data_Dumps[3])
                    TCP_header.append(TCP_Data_Dumps[4])  # Offsetflag
                    TCP_header.append(TCP_Data_Dumps[5])  # URG
                    TCP_header.append(TCP_Data_Dumps[6])  # ACK
                    TCP_header.append(TCP_Data_Dumps[7])  # PSH
                    TCP_header.append(TCP_Data_Dumps[8])  # RST
                    TCP_header.append(TCP_Data_Dumps[9])  # SYN
                    TCP_header.append(TCP_Data_Dumps[10]) # FIN
                    TCP_header.append(windowsize)         # Windowsize


                    sendDAT = bytearray(TCP_header + TCP_Data_Dumps[12])
                    time.sleep(0.005)
                    s.sendto(sendDAT, addr)

                    #PRINT
                    print('sent: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | data = {}>'
                            .format(sendDAT[4], sendDAT[7], sendDAT[8], sendDAT[0], sizedata))


                    if sendDAT[9] == seqnum_int:

                        ackrecv = s.recv(1024)
                        recvack = pickle.loads(ackrecv)
                        recv_ack = FromBytes(recvack[2])

                        if recv_ack == seqnum_int:
                            acknum_int = FromBytes(recvack[12])
                            print('recv: [ACK: {} | SYN: {} | FIN: {}], <ack = {}>| {}'
                                .format(recvack[6], recvack[9], recvack[10], acknum_int, recvack[13]))
                            print('Next Window')
                            seqnum_to_int = FromBytes(recvack[2])
                            seqnum_int = seqnum_to_int - windows_size

                        if recvack[6] != 1:
                            seqnum_int = FromBytes(recvack[2])
                            print('recv: PACKET LOST! [ACK: {} | SYN: {} | FIN: {}], <seq = {} |  <ack = {}>'
                                .format(recvack[6], recvack[9], recvack[10], seqnum_int, acknum_int))
                            print('Resending...')
                            sizedata = -len(sdata)
                            seqnum_int = recv_ack - 1




                    #CLOSING SEASSION
                    if len(sdata) < 512:
                        print("[Closing Session]")
                        offsetflag = 1
                        final_windowsize = recvack[11]
                        seqnum = acknum_int + 1
                        #3 bytes = 32 bits of Sequence Number
                        sseqnum_fin = ToBytes(seqnum, 3)
                        checksum = Checksum(sseqnum_fin)

                        TCP_Fin_Dumps = TCP_Header(source_port, dest_port, sseqnum_fin, acknum, offsetflag, final_windowsize, sdata, checksum)
                        TCP_Fin_Send = pickle.dumps(TCP_Fin_Dumps)
                        s.sendto(TCP_Fin_Send, addr)


                        #PRINT
                        seqnum_to_int = FromBytes(TCP_Fin_Dumps[2])
                        print('sent: [ACK: {} | SYN: {} | FIN: {}], <seq = {}>| {}'
                              .format(TCP_Data_Dumps[6], TCP_Fin_Dumps[9], TCP_Fin_Dumps[10], seqnum_to_int, TCP_Fin_Dumps[13]))


                        finrecv = s.recv(1024)
                        recvfin = pickle.loads(finrecv)
                        seqnum_to_int = FromBytes(recvfin[2])
                        acknum_to_int = FromBytes(recvfin[3])
                        print('recv: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | ack = {}>| {}'
                              .format(recvfin[6], recvfin[9], recvfin[10], seqnum_to_int, acknum_to_int, recvfin[13]))


                        seqnum = acknum_to_int + 1
                        acknum = seqnum_to_int + 1
                        offsetflag = recvfin[4] - 1
                        #3 bytes = 32 bits of Sequence Number
                        sseqnum_fin = ToBytes(seqnum, 3)
                        #3 bytes = 32 bits of Sequence Number
                        sacknum_fin = ToBytes(acknum, 3)
                        checksum = Checksum(sseqnum_fin)
                        TCP_Fin_Dumps = TCP_Header(source_port, dest_port, sseqnum_fin, sacknum_fin, offsetflag, recvfin[11], sdata, checksum)
                        TCP_Fin_Send = pickle.dumps(TCP_Fin_Dumps)
                        s.sendto(TCP_Fin_Send, addr)

                        #PRINT
                        seqnum_to_int = FromBytes(TCP_Fin_Dumps[2])
                        acknum_to_int = FromBytes(TCP_Fin_Dumps[3])
                        print('sent: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | ack = {}>| {}'
                                .format(TCP_Fin_Dumps[6], TCP_Fin_Dumps[9], TCP_Fin_Dumps[10], seqnum_to_int, acknum_to_int, TCP_Fin_Dumps[13]))


                        break


                print("Complete")


        else:
            offsetflag = 1
            seqnum = recvACK[1]
            acknum = recvACK[0] + 1
            data_name = recvACK[9:].decode()
            Err_Header = TCP_Header(source_port, dest_port, seqnum, acknum, offsetflag, recvACK[9], recvACK[9:])
            TCP_header = bytearray()
            TCP_header.append(Err_Header[2])
            TCP_header.append(Err_Header[3])
            TCP_header.append(Err_Header[4])  # Offsetflag
            TCP_header.append(Err_Header[5])  # URG
            TCP_header.append(Err_Header[6])  # ACK
            TCP_header.append(Err_Header[7])  # PSH
            TCP_header.append(Err_Header[8])  # RST
            TCP_header.append(Err_Header[9])  # SYN
            TCP_header.append(Err_Header[10])  # FIN


            sendERR = bytearray(TCP_header + Err_Header[12])
            s.sendto(sendERR, addr)

            #PRINT
            print('sent: [ACK: {} | SYN: {} | FIN: {} | {}] <FILE NOT FOUND>'
                  .format(sendERR[4], sendERR[7], sendERR[8], data_name))

    elif recvingheader[4] == 34:

        offsetflag = recvingheader[4] + 16
        sdata = recvingheader[12]

        #ACK number = SEQ + 1
        acknum_int = FromBytes(recvingheader[2])
        acknum = acknum_int + 1

        #3 bytes = 32 bits of Sequence Number
        sseqnum = ToBytes(seqnum, 3)
        #3 bytes = 32 bits of Acknowledge Number
        sacknum = ToBytes(acknum, 3)
        checksum = Checksum(sseqnum)

        TCP_Header_Dumps = TCP_Header(dest_port, source_port, sseqnum, sacknum, offsetflag, window, sdata, checksum)
        TCP_Header_Send = pickle.dumps(TCP_Header_Dumps)
        s.sendto(TCP_Header_Send, addr)

        seqnum_int = FromBytes(TCP_Header_Dumps[2])
        acknum_int = FromBytes(TCP_Header_Dumps[3])
        print('sent: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | ack = {}>| {}'
              .format(TCP_Header_Dumps[6], TCP_Header_Dumps[9], TCP_Header_Dumps[10], seqnum_int, acknum_int, TCP_Header_Dumps[13]))

        filenameByte, addr = s.recvfrom(1024)
        recvingack = pickle.loads(filenameByte)

        seqnum_int = FromBytes(recvingack[2])
        acknum_int = FromBytes(recvingack[3])
        print('recv: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | ack = {}>| {}'
              .format(recvingack[6], recvingack[9], recvingack[10], seqnum_int, acknum_int, recvingack[13]))

        print("[Receiving Data]")
        datarecv, addr = s.recvfrom(1024)
        recvingdata = pickle.loads(datarecv)

        if recvingdata[6] == 1:
            data_name = recvingack[12].decode()
            f = open("put_" + data_name, 'wb')
            f.write(recvingdata[12])
            sizedata = 0
            expectedseqnum = 1

            while True:
                datarecv, addr = s.recvfrom(1024)
                recvingdata = pickle.loads(datarecv)

                #PRINT
                sizedata += len(recvingdata[12])
                seqnum_int = FromBytes(recvingdata[2])
                window_size = FromBytes(recvingdata[11])

                if seqnum_int == expectedseqnum:
                    f.write(recvingdata[12])
                    print('recv: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | data = {}>| {}'
                          .format(recvingdata[6], recvingdata[9], recvingdata[10], seqnum_int, sizedata, recvingdata[13]))
                    expectedseqnum = expectedseqnum + 1

                    if window_size == seqnum_int:
                        #3 bytes = 32 bits of Acknowledge Number
                        sacknum_bytes = ToBytes(acknum, 3)
                        sizedata1 = sizedata + 1
                        sizedata_bytes = ToBytes(sizedata1, 3)
                        checksum = Checksum(sizedata_bytes)

                        send_ACK = TCP_Header(dest_port, source_port, recvingdata[2], sacknum_bytes, offsetflag, window, sizedata_bytes, checksum)
                        TCP_Header_ACK = pickle.dumps(send_ACK)
                        s.sendto(TCP_Header_ACK, addr)

                        # PRINT
                        sizedata_int = FromBytes(send_ACK[12])
                        print('sent: [ACK: {} | SYN: {} | FIN: {}], <ack = {}>| {}'
                              .format(send_ACK[6], send_ACK[9], send_ACK[10], sizedata_int, send_ACK[13]))
                        expectedseqnum = 1

                #Receive Out-Of-Order
                else:
                    #3 bytes = 32 bits of Acknowledge Number
                    sacknum_bytes = ToBytes(acknum, 3)
                    sizedata = sizedata + 1
                    sizedata_bytes = ToBytes(sizedata, 3)
                    send_ACK = TCP_Header(dest_port, source_port, recvingdata[2], sacknum_bytes, offsetflag, window, sizedata_bytes)
                    TCP_Header_ACK = pickle.dumps(send_ACK)
                    s.sendto(TCP_Header_ACK, addr)

                    #PRINT
                    sizedata_int = FromBytes(send_ACK[12])
                    print('sent: OUT OF ORDER:  [ACK: {} | SYN: {} | FIN: {}], <ack = {}>'
                           .format(send_ACK[6], send_ACK[9], send_ACK[10], sizedata_int))
                    expectedseqnum = 1

                #CLOSING SESSION
                if len(recvingdata[12]) < 512:
                    print("[Closing Session]")
                    acknum_int = 0
                    datarecv, addr = s.recvfrom(1024)
                    recvingdata = pickle.loads(datarecv)

                    #PRINT
                    seqnum_int = FromBytes(recvingdata[2])
                    print('recv: [ACK: {} | SYN: {} | FIN: {}], <seq = {}>| {}'
                          .format(recvingdata[6], recvingdata[9], recvingdata[10], seqnum_int, recvingdata[13]))

                    offsetflag = recvingdata[4] + 16
                    acknum_int += seqnum_int + 1
                    acknum_bytes = ToBytes(acknum_int, 3)
                    checksum = Checksum(acknum_bytes)

                    TCP_Fin_Dumps = TCP_Header(dest_port, source_port, recvingdata[2], acknum_bytes, offsetflag,recvingdata[11], sdata, checksum)
                    send_Fin = pickle.dumps(TCP_Fin_Dumps)
                    s.sendto(send_Fin, addr)

                    #PRINT
                    seqnum_int = FromBytes(TCP_Fin_Dumps[2])
                    acknum_int = FromBytes(TCP_Fin_Dumps[3])
                    print('sent: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | ack = {}>| {}'
                          .format(TCP_Fin_Dumps[6], TCP_Fin_Dumps[9], TCP_Fin_Dumps[10], seqnum_int, acknum_int, TCP_Fin_Dumps[13]))

                    finrecv = s.recv(1024)
                    recvfin = pickle.loads(finrecv)
                    seqnum_to_int = FromBytes(recvfin[2])
                    acknum_to_int = FromBytes(recvfin[3])
                    print('recv: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | ack = {}>| {}'
                          .format(recvfin[6], recvfin[9], recvfin[10], seqnum_to_int, acknum_to_int, recvfin[13]))

                    break

            print("Complete")


        elif recvingdata[10] == 0:
            Filename_Header = recvingdata[12].decode()
            print('recv: [ACK: {} | SYN: {} | FIN: {} | {}] <FILE NOT FOUND>| {}'
                  .format(recvingdata[6], recvingdata[9], recvingdata[10], Filename_Header, recvingdata[13]))

        else:
            Filename_Header = recvingdata[12].decode()
            print('recv: [[ACK: {} | SYN: {} | FIN: {} | {}] <FILE ALREADY EXIST>| {}'
                  .format(recvingdata[6], recvingdata[9], recvingdata[10], Filename_Header, recvingdata[13]))

    else:
        print("Unknown Error")



def main():
    file()




main()

