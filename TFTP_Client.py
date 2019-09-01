import socket
import argparse
import pickle
import binascii
import random
import os
import time


BAD_PACKET = 0.05

parser = argparse.ArgumentParser()
parser.add_argument('-g', dest='get_filename')
parser.add_argument('-p', dest='put_filename')
parser.add_argument('-l', dest='host', default= 'localhost')
parser.add_argument('-a', dest='port', default= 12000)
args = parser.parse_args()



def TCP_Header(sourceport, destport, seqnum, acknum, offsetflag, window, data):
    offset = (offsetflag >> 12) * 4
    urg = (offsetflag & 32) >> 5
    ack = (offsetflag & 16) >> 4
    psh = (offsetflag & 8) >> 3
    rst = (offsetflag & 4) >> 2
    syn = (offsetflag & 2) >> 1
    fin = (offsetflag & 1)
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

port = int(args.port) #dest
source_port = 80
host = args.host
data_get = args.get_filename
data_put = args.put_filename


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((host, port))
s.settimeout(3)




windowsize = random.randint(3,9)
#2 bytes = 16 bits of Destination Port
dest_port = ToBytes(port, 2)
#2 bytes = 16 bits of Source Port
source_port = ToBytes(source_port, 2)



def getfile():
    sdata = str.encode(data_get)
    offsetflag = 2
    seqnum = 100
    acknum = 0

    TCP_Header_Dumps = TCP_Header(dest_port, source_port, seqnum , acknum, offsetflag, windowsize, sdata)
    TCP_header = bytearray()
    TCP_header.append(TCP_Header_Dumps[2])
    TCP_header.append(TCP_Header_Dumps[3])
    TCP_header.append(TCP_Header_Dumps[4])  #Offsetflag
    TCP_header.append(TCP_Header_Dumps[5])  #URG
    TCP_header.append(TCP_Header_Dumps[6])  #ACK
    TCP_header.append(TCP_Header_Dumps[7])  #PSH
    TCP_header.append(TCP_Header_Dumps[8])  #RST
    TCP_header.append(TCP_Header_Dumps[9])  #SYN
    TCP_header.append(TCP_Header_Dumps[10]) #FIN


    sendSYN = bytearray(TCP_header + TCP_Header_Dumps[12])
    s.send(sendSYN)

    print("[Establishing Connection]")
    print('sent: [ACK: {} | SYN: {} | FIN: {} | URG: {}], <seq = {}>'
          .format(sendSYN[4], sendSYN[7], sendSYN[8], sendSYN[3], sendSYN[0]))


    recvACK, addr = s.recvfrom(1024)


    print('recv: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | ack = {}>'
          .format(recvACK[4], recvACK[7], recvACK[8], recvACK[0], recvACK[1]))

    if recvACK[2] == 18:
        offsetflag = 16
        sdata = recvACK[10:]
        seqnum = recvACK[1]
        acknum = recvACK[0] + 1

        TCP_Header_Dumps = TCP_Header(dest_port, source_port, seqnum, acknum, offsetflag, recvACK[9], sdata)
        TCP_header = bytearray()
        TCP_header.append(TCP_Header_Dumps[2])
        TCP_header.append(TCP_Header_Dumps[3])
        TCP_header.append(TCP_Header_Dumps[4])  # Offsetflag
        TCP_header.append(TCP_Header_Dumps[5])  # URG
        TCP_header.append(TCP_Header_Dumps[6])  # ACK
        TCP_header.append(TCP_Header_Dumps[7])  # PSH
        TCP_header.append(TCP_Header_Dumps[8])  # RST
        TCP_header.append(TCP_Header_Dumps[9])  # SYN
        TCP_header.append(TCP_Header_Dumps[10])  # FIN

        sendACK = bytearray(TCP_header + TCP_Header_Dumps[12])
        s.send(sendACK)

        print('sent: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | ack = {}>'
              .format(sendACK[4], sendACK[7], sendACK[8], sendACK[0], sendACK[1]))
    
        print("[Receiving Data]")

        recvDAT, addr = s.recvfrom(1024)

        if recvDAT[2] == 0:

            f = open("get_" + data_get, 'wb')
            sizedata = 0


            seqnum_int = 0

            while True:

                recvDAT, addr = s.recvfrom(1024)


                if BAD_PACKET < random.random():

                    seqnum_int += 1
                    sizedata += len(recvDAT[10:])


                    f.write(recvDAT[10:])
                    print('recv: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | data = {}>'
                          .format(recvDAT[4], recvDAT[7], recvDAT[8], seqnum_int, sizedata))



                    #3 bytes = 32 bits of Acknowledge Number
                    if recvDAT[9] == seqnum_int:
                        offsetflag = 16
                        seqnum_sent = ToBytes(seqnum_int, 3)
                        sacknum_bytes = ToBytes(acknum, 3)
                        sizedata = sizedata + 1
                        sizedata_bytes = ToBytes(sizedata, 3)
                        checksum = Checksum(sizedata_bytes)

                        send_ACK = TCP_Header(dest_port, source_port, seqnum_sent, sacknum_bytes, offsetflag, window, sizedata_bytes, checksum)
                        TCP_Header_ACK = pickle.dumps(send_ACK)
                        time.sleep(0.5)
                        s.send(TCP_Header_ACK)


                        #PRINT
                        sizedata_int = FromBytes(send_ACK[12])
                        print('sent: [ACK: {} | SYN: {} | FIN: {}], <ack = {}>| {}'
                                .format(send_ACK[6], send_ACK[9], send_ACK[10], sizedata_int, send_ACK[13]))
                        print("Next Window")
                        seqnum_sent = FromBytes(recvingdata[2])
                        seqnum_int = seqnum_sent


                    #CLOSING SESSION
                    if len(recvDAT[10:]) < 512:
                        print("[Closing Session]")
                        acknum_int = 0
                        datarecv, addr = s.recvfrom(1024)
                        recvingdata = pickle.loads(datarecv)

                        #PRINT
                        seqnum_int1 = FromBytes(recvingdata[2])
                        print('recv: [ACK: {} | SYN: {} | FIN: {}], <seq = {}>| {}'
                                .format(recvingdata[6], recvingdata[9], recvingdata[10], seqnum_int1, recvingdata[13]))

                        offsetflag = recvingdata[4] + 16
                        acknum_int += seqnum_int + 1
                        acknum_bytes = ToBytes(acknum_int, 3)
                        checksum = Checksum(acknum_bytes)

                        TCP_Fin_Dumps = TCP_Header(dest_port, source_port, recvingdata[2], acknum_bytes, offsetflag, recvingdata[11], sdata, checksum)
                        send_Fin = pickle.dumps(TCP_Fin_Dumps)
                        s.send(send_Fin)

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


                # Receive Out-Of-Order
                else:
                    print('send loss')
                    offsetflag = 0
                    seqnum_sent = seqnum_int + 1
                    acknum = 0
                    send_ACK = TCP_Header(dest_port, source_port, seqnum_sent, acknum, offsetflag, recvDAT[9], sizedata_bytes)
                    TCP_header = bytearray()
                    TCP_header.append(TCP_Header_Dumps[2])
                    TCP_header.append(TCP_Header_Dumps[3])
                    TCP_header.append(TCP_Header_Dumps[4])  # Offsetflag
                    TCP_header.append(TCP_Header_Dumps[5])  # URG
                    TCP_header.append(TCP_Header_Dumps[6])  # ACK
                    TCP_header.append(TCP_Header_Dumps[7])  # PSH
                    TCP_header.append(TCP_Header_Dumps[8])  # RST
                    TCP_header.append(TCP_Header_Dumps[9])  # SYN
                    TCP_header.append(TCP_Header_Dumps[10])  # FIN

                    sendLOSS = bytearray(TCP_header + TCP_Header_Dumps[12])
                    s.send(sendLOSS)



                    print('sent: PACKET LOST! [ACK: {} | SYN: {} | FIN: {}], <seq = {} |  <ack = {}>'
                            .format(send_ACK[6], send_ACK[9], send_ACK[10], seq_number, sizedata_int))
                    sizedata = sizedata_int
                    seqnum_int = seq_number - 1


            print("Download Complete")


        elif recvDAT[2] == 1:
            Filename = recvDAT[9:].decode()
            print('recv: [ACK: {} | SYN: {} | FIN :{} | {}] <FILE NOT FOUND>'
                  .format(recvDAT[4], recvDAT[7], recvDAT[8], Filename))


        else:
            Filename = recvDAT[9:].decode()
            print('recv: [ACK: {} | SYN: {} | FIN :{}] | {}] <FILE ALREADY EXIST>'
                  .format(recvDAT[4], recvDAT[7], recvDAT[8], Filename))

    else:
        print('Unkown Error')


    s.close()



def putfile():

    sdata = str.encode(data_put)
    offsetflag = 2 + 32
    checksum = Checksum(sseqnum)
    TCP_Header_Dumps = TCP_Header(dest_port, source_port, sseqnum, sacknum, offsetflag, window, sdata, checksum)
    TCP_Header_Send = pickle.dumps(TCP_Header_Dumps)
    s.send(TCP_Header_Send)

    seqnum_int = FromBytes(TCP_Header_Dumps[2])
    print("[Establishing Connection]")
    print('sent: [ACK: {} | SYN: {} | URG: {}], <seq = {}>| {}'
        .format(TCP_Header_Dumps[6], TCP_Header_Dumps[9], TCP_Header_Dumps[5], seqnum_int, TCP_Header_Dumps[13]))

    ackrecv, addr = s.recvfrom(1024)
    recvingheader = pickle.loads(ackrecv)

    seqnum_int = FromBytes(recvingheader[2])
    acknum_int = FromBytes(recvingheader[3])

    print('recv: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | ack = {}>| {}'
          .format(recvingheader[6], recvingheader[9], recvingheader[10], seqnum_int, acknum_int, recvingheader[13]))

    if recvingheader[4] == 50:
        offsetflag = 16
        seqnum = acknum_int
        acknum = seqnum_int + 1
        checksum = Checksum(sseqnum)

        #3 bytes = 32 bits of Sequence Number
        sseqnum_bytes = ToBytes(seqnum, 3)
        #3 bytes = 32 bits of Acknowledge Number
        sacknum_bytes = ToBytes(acknum, 3)

        TCP_Header_Dumps = TCP_Header(dest_port, source_port, sseqnum_bytes, sacknum_bytes, offsetflag, window, sdata, checksum)
        TCP_Header_Send = pickle.dumps(TCP_Header_Dumps)
        s.send(TCP_Header_Send)
        seqnum_int = FromBytes(TCP_Header_Dumps[2])
        acknum_int = FromBytes(TCP_Header_Dumps[3])
        print('sent: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | ack = {}>| {}'
              .format(TCP_Header_Dumps[6], TCP_Header_Dumps[9], TCP_Header_Dumps[10], seqnum_int, acknum_int, TCP_Header_Dumps[13]))


        print("[Sending Data]")

        if os.path.isfile(TCP_Header_Dumps[12]):

            data_name = TCP_Header_Dumps[12].decode()
            file_exist = 'put_' + data_name

            if os.path.isfile(file_exist):
                offsetflag = 1
                sseqnum1 = acknum_int + 1
                sseqnum2 = ToBytes(sseqnum1, 3)
                checksum = Checksum(sseqnum2)
                Err_Header = TCP_Header(source_port, dest_port, sseqnum2, sacknum, offsetflag, window, sdata, checksum)
                Err_Header_Dumps = pickle.dumps(Err_Header)
                s.send(Err_Header_Dumps)

                # PRINT
                Filename_Header = Err_Header[12].decode()
                print('sent: [ACK: {} | SYN: {} | FIN: {} | {}] <FILE ALREADY EXIST>| {}'.
                      format(Err_Header[6], Err_Header[9], Err_Header[10], Filename_Header, Err_Header[13]))

            else:
                f = open(TCP_Header_Dumps[12], 'rb')
                sdata = f.read(512)
                checksum = Checksum(sdata)
                TCP_Data_Dumps = TCP_Header(source_port, dest_port, seqnum, acknum, offsetflag, window, sdata, checksum)
                TCP_Data_Send = pickle.dumps(TCP_Data_Dumps)
                s.send(TCP_Data_Send)
                seqnum_int = 0
                sizedata = 0

                while True:
                    sdata = f.read(512)
                    offsetflag = 16

                    seqnum_int += 1
                    acknum_int += 1

                    sizedata += len(sdata)
                    #3 bytes = 32 bits of Sequence Number
                    seqnum = ToBytes(seqnum_int, 3)
                    #3 bytes = 32 bits of Acknowledge Number
                    acknum = ToBytes(acknum_int, 3)
                    sizedata_bytes = ToBytes(sizedata, 3)
                    checksum = Checksum(sizedata_bytes)

                    TCP_Data_Dumps = TCP_Header(source_port, dest_port, seqnum, acknum, offsetflag, window, sdata, checksum)
                    TCP_Data_Send = pickle.dumps(TCP_Data_Dumps)
                    time.sleep(0.005)
                    s.send(TCP_Data_Send)

                    #PRINT
                    seqnum_to_int = FromBytes(TCP_Data_Dumps[2])
                    windows_size = FromBytes(TCP_Data_Dumps[11])
                    print('sent: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | data = {}>| {}'
                          .format(TCP_Data_Dumps[6], TCP_Data_Dumps[9], TCP_Header_Dumps[10], seqnum_to_int, sizedata, TCP_Data_Dumps[13]))

                    if windows_size == seqnum_to_int:
                        ackrecv = s.recv(1024)
                        recvack = pickle.loads(ackrecv)
                        acknum_int = FromBytes(recvack[12])
                        print('recv: [ACK: {} | SYN: {} | FIN: {}], <ack = {}>| {}'
                              .format(recvack[6], recvack[9], recvack[10], acknum_int, recvack[13]))
                        seqnum_to_int = FromBytes(recvack[2])
                        seqnum_int = seqnum_to_int - windows_size

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
                        s.send(TCP_Fin_Send)

                        #PRINT
                        seqnum_to_int = FromBytes(TCP_Fin_Dumps[2])
                        print('sent: [ACK: {} | SYN: {} | FIN: {}], <seq = {}>| {}'
                              .format(TCP_Data_Dumps[6], TCP_Fin_Dumps[9], TCP_Fin_Dumps[10], seqnum_to_int, TCP_Fin_Dumps[13]))

                        finrecv = s.recv(1024)
                        recvfin = pickle.loads(finrecv)
                        seqnum_to_int = FromBytes(recvfin[2])
                        acknum_to_int = FromBytes(recvfin[3])
                        print('recv: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | ack = {}>| {}'
                              .format(recvfin[6], recvfin[9], recvfin[10], seqnum_to_int, acknum_to_int, TCP_Fin_Dumps[13]))

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
                        s.send(TCP_Fin_Send)

                        # PRINT
                        seqnum_to_int = FromBytes(TCP_Fin_Dumps[2])
                        acknum_to_int = FromBytes(TCP_Fin_Dumps[3])
                        print('sent: [ACK: {} | SYN: {} | FIN: {}], <seq = {} | ack = {}>| {}'
                              .format(TCP_Fin_Dumps[6], TCP_Fin_Dumps[9], TCP_Fin_Dumps[10], seqnum_to_int, acknum_to_int, TCP_Fin_Dumps[13]))

                        break




                print("Upload Complete")

        else:
            offsetflag = 0
            sseqnum1 = acknum_int + 1
            sseqnum2 = ToBytes(sseqnum1, 3)
            checksum = Checksum(sseqnum2)
            Err_Header = TCP_Header(source_port, dest_port, sseqnum, sacknum, offsetflag, window, sdata, checksum)
            Err_Header_Dumps = pickle.dumps(Err_Header)

            s.send(Err_Header_Dumps)

            #PRINT
            Filename_Header = Err_Header[12].decode()
            print('sent: [ACK: {} | SYN: {} | FIN: {} | {}] <FILE NOT FOUND>| {}'
                  .format(Err_Header[6], Err_Header[9], Err_Header[10], Filename_Header, Err_Header[13]))


    else:
        print("DONE")

    s.close()


def main():
    if args.get_filename:
        getfile()
    else:
        putfile()

main()

