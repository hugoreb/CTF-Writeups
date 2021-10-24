


Hello, thank you for reading my writeup, if anything isn’t clear don’t hesitate to contact me to have further information.

It was my first heap exploit. I found this challenge very good to learn about heap exploitation.



First, this challenge is a rust one where the entire code has been placed in the unsafe function.

I won’t use the rust code given for this writeup, I’ll only use the binary given. 

To link the binary to the given libc, I used patchelf .


$ checksec pack/challenge
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled

We try to run it

1. Add patient
2. View patient
3. Modify patient infos
4. Remove patient
5. View hospital
6. Exit

We’ve got a menu. We can guess that’s an heap exploit.

First, we create a patient (option 1 ), we change his name ( 3 ) to something with 33 characters and we choose the fifth option to view if we

For example, let’s try 33 ‘’a’’.

1
Patient name : 
aaaa
Successfully added patient
1. Add patient
2. View patient
3. Modify patient infos
4. Remove patient
5. View hospital
6. Exit
3
Patient index : 
0
Enter new name : 
aaaabbbbaaaabbbbaaaabbbbaaaabbbba
Successfully modified patient
1. Add patient
2. View patient
3. Modify patient infos
4. Remove patient
5. View hospital
6. Exit
5
Patient #0 : ��PB
1. Add patient
2. View patient
3. Modify patient infos
4. Remove patient
5. View hospital
6. Exit
> 

Here, we can guess that’s we overwrote the LSB of the pointer of patient 0 name, and we leaked 4 bytes, corresponding to the number of bytes in the first patient name ( aaaa )


We are going to use that to do arbitrary read of any location in the binary.

After analyzing with gdb, we see that we overwrote the pointer who points at the beginning of the patient name  

When we create only one patient, we have  this architecture :

the given name stored in 32 bytes followed by the pointer to these data (thus containing its address)

This looks like that :
address : data
address + 0x32 : address

But we have to get better understand of what’s happening. To do so, let’s open an other terminal and run 

$ gdb attack \`pidof challenge\`

gdb will help us building our exploit.

With gdb, we use info proc map. 

I found that the heap is between 0x555f62266000  and 0x555f62287000 . Its size is 0x21000.

Your heap size should be the same, but you should not have the same addresses for the heap due to ASLR.

So here, I want to find where is located my payload. To do so, I explored the heap. 

I found that base heap address was located with an offset of  11328 (in decimal) compared to the address leaked (which represents the address after the data, so the data is at an offset of 11328 – 32).

The remote offset wasn’t exactly the same, it was 11104. 

The least significant byte of the address is 60, that’s why we leak a part of the address with our « a » ( a’s ascii code is \x61 )


While reading the heap, I was searching after addresses starting with 0x7f because I knew that it could be interesting.
 
Doing that I found a very interessant address : at address base_heap_address +  0x2e8 (+0x308 remotely), I found the address of « _IO_2_1_stderr_ » … which has a constant offset with every libc functions ! 

I found that system was located 0x191b80 before stderr.

The leaking part is achieved, now we just want to overwrite RIP. But wait, it’s a heap based buffer overflow, not a stack buffer overflow… How could we do that ?

By using hook function !

I found that we can overwrite malloc_hook which will– when the function malloc will be used – put what is at malloc_hook address inside RIP. So we can use one gadget. 



So first, we had to find a way to overwrite anything anywhere… but wait, we saw that the pointer of the patient 0 name was overwritable … we just have to overwrite it to the desired location and then write whatever we want at it.

Not sure it is clear. To recap :

The first state of the patient info :

address : data
address + 0x32 : address

We change patient 0 info and overwrite the pointer after the data with malloc_hook address :

address : data
address + 0x32 : malloc_hook_address

Now, if we change patient 0 info, we will write in malloc_hook_address ! Exactly what we aimed to do.

A little problem about that is that we can do that only once ; once it is done we point to an other location.

My first idea was about using a one_gadget.

To find one, I installed a tool using 

$ gem install one_gadget

Then I used the tool :

$ one_gadget libc-2.33.so

output :
0xde78c execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xde78f execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xde792 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL


The problem is that we can overwrite RIP only once with this one_gadget, and none of these constraints could be satisfied without a ropchain.

So I searched about an other solution and found that with the address of system, we can overwrite free_hook with system address

I did it locally, it worked, I did it remotely, it worked too !

I give you my exploit code, don’t hesitate to contact me in my discord ( hugore#0260 ) for any question !
