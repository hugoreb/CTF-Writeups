#First, we open the binary. Disassembling with the help of ghidra gives us an interesting function :
void transform(long param_1)

{
  size_t sVar1;
  uint local_24;
  char *local_20;
  
  local_24 = 0;
  while( true ) {
    sVar1 = strlen("wAPcULZh\x7f\x06x\x04LDd\x06~Z\"YtJNice flag");
    if (sVar1 <= (ulong)(long)(int)local_24) break;
    if ((local_24 & 1) == 0) {
      local_20[(int)local_24] = *(byte *)(param_1 + (int)local_24) ^ 0x13;
    }
    else {
      local_20[(int)local_24] = *(byte *)(param_1 + (int)local_24) ^ 0x37;
    }
    local_24 = local_24 + 1;
  }
  strncmp("wAPcULZh\x7f\x06x\x04LDd\x06~Z\"YtJNice flag",local_20,0x16);
  return;
}

#So, it is an encryption of a string (which is the flag) which should be equal - once encrypted - to wAPcULZh\x7f\x06x\x04LDd\x06~Z\"Yt
#The encryption is simple : each even letter is xored (operate a xor) with 0x13 (in hexa) and each odd letter ix xored with 0x37 
#So we convert every letter of the encrypted flag in hexa and then we take python and z3 to decrypt

from z3 import *


conditions = ["((flag[0] + 0) ^ 0x13 == 0x77)",
"((flag[1] + 0) ^ 0x37 == 0x41)",
"((flag[2] + 0) ^ 0x13 == 0x50)",
"((flag[3] + 0) ^ 0x37 == 0x63)",
"((flag[4] + 0) ^ 0x13 == 0x55)",
"((flag[5] + 0) ^ 0x37 == 0x4c)",
"((flag[6] + 0) ^ 0x13 == 0x5a)",
"((flag[7] + 0) ^ 0x37 == 0x68)",
"((flag[8] + 0) ^ 0x13 == 0x7f)",
"((flag[9] + 0) ^ 0x37 == 0x06)",
"((flag[10] + 0) ^ 0x13 == 0x78)",
"((flag[11] + 0) ^ 0x37 == 0x04)",
"((flag[12] + 0) ^ 0x13 == 0x4c)",
"((flag[13] + 0) ^ 0x37 == 0x44)",
"((flag[14] + 0) ^ 0x13 == 0x64)",
"((flag[15] + 0) ^ 0x37 == 0x06)",
"((flag[16] + 0) ^ 0x13 == 0x7e)",
"((flag[17] + 0) ^ 0x37 == 0x5a)",
"((flag[18] + 0) ^ 0x13 == 0x22)",
"((flag[19] + 0) ^ 0x37 == 0x59)",
"((flag[20] + 0) ^ 0x13 == 0x74)",
"((flag[21] + 0) ^ 0x37 == 0x4a)"
]


flag = [BitVec(f'arr[{i}]',9) for i in range(32)] # 32 -> length of the flag!

s = Solver()

for i in conditions:
    s.add(eval(i))

print(s.check())
print(s.model())


# And we convert the hex answer to text 
