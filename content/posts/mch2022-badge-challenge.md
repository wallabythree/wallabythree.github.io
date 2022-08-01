---
title: "MCH2022 badge challenge: \"Hack Me If You Can\""
date: 2022-08-01T11:03:21+02:00
cover: "/img/badge-challenge-cover.png"
description: "The badge for the [MCH2022](https://www.mch2022.org) hacker camp
comes with a CTF challenge, which, thanks to the ESP32's Xtensa architecture,
appears to be somewhat protected against classic stack overflow attacks.
However, thanks to recursion in the main loop, a buffer overflow is all that is
needed to solve it. This post will walk through the vulnerability and explain
how it can be exploited to steal the flag."
draft: false
---

> The full exploit is available on
> [Github](https://github.com/wallabythree/mch2022-hack-me-if-you-can).

The badge for the [MCH2022](https://www.mch2022.org) hacker camp comes with a
CTF challenge, which, thanks to the ESP32's Xtensa architecture, appears to be
somewhat protected against classic stack overflow attacks. However, thanks to 
recursion in the main loop, a buffer overflow is all that is needed to solve
it. This post will walk through the vulnerability and explain how it can be
exploited to steal the flag.


## 0. Setup

["Hack Me If You Can"](https://mch2022.badge.team/projects/hack_me_if_you_can)
comes preinstalled on the badge. For the duration of the competition, a copy of
`hack_me_if_you_can.elf` could also be downloaded from the
[CTF website](https://ctf.mch2022.org). Although the CTF has now ended, you can
still exploit this vulnerability on your own badge.

On badges: you technically don't need one to solve this challenge. However, it
would be tough to develop an exploit without it. A badge also gives you access
to the ESP32's debug log, which can be read via the USB serial interface:

```
screen /dev/[tty_usb_device_name] 115200
```

**Note:** Only organisers' badges contained the real flag. At the camp,
participants were instructed to develop a proof of concept against their own
badge and find an organiser once they had a working exploit.

## 1. Finding the vulnerability

### 1.1 A mysterious crash

The badge's challenge app consists of a simple echo server hosted on port
`1337`. When a client attempts to connect, the badge will prompt its owner for
approval, after which the service will repeat anything sent by the client:

```
$ nc badge.ip 1337
Connection accepted!
> hello
< hello
> echo
< echo
```

Being CTF players, our first instinct should be to stuff a very long input
buffer into the prompt. When we do, we find that the service crashes as soon as
inputs exceed 48 bytes. Let's circle back to why this is strange behaviour for
an ESP32-style chip later.

At this point we can crash the app, but we can't do much else. We need to
analyse the programme further to find out where to go next. Fortunately, there
is an open source [Xtensa module](https://github.com/yath/ghidra-xtensa) for
Ghidra that will let us disassemble the compiled binary.

### 1.2 Digging for the flag

First things first: let's find our flag.  The app's main function is called
`app_main()`. This function calls into `start_service()`, which does the heavy
lifting for our echo service. Aside from setting up the WiFi and calling into
`echo_server()`,  it also attempts to read a value from the ESP32's non-volatile
storage (a key-value store) with the key `hackmeifyoucan`. This value, if found,
gets copied to an uninitialised array named `flag`.

![](/img/ghidra-1.png)

Further down, we observe that the string `flag{not_a_real_flag}` gets copied to
the same location if the key-value store query is unsuccesful. Putting two and
two together, we can safely assume the flag will be at address `0x3ffb5358`
during runtime.

![](/img/ghidra-2.png)


### 1.3 A not-so-mysterious crash?

We need to understand why the programme crashes when the input buffer
exceeds 48 bytes. This is unusual because Xtensa processors like the ESP32 do
not, as a rule, store return addresses on the stack. Rather, they are stored in
a dedicated register, **a0**. On chips like the ESP32, there are 64 registers,
of which 16 are visible to the CPU at any given time. When a function is called, the
['window'](https://projects.cerias.purdue.edu/stackghost/stackghost/node5.html)
of visible registers shifts forward, giving the callee a fresh set of registers
to work with. (Note here that the callee's register **a0** is not the same as
the caller's register **a0**.) When the callee returns, the window shifts back
so that the caller can pick up where it left off. The benefit of this
arrangement is not having to offload memory to the stack, which results in
increased performance. It also means we cannot overwrite the return address with
a stack overflow.

However, the debug log reveals that we definitely are overwriting a return
address when we send buffers larger than 48 bytes. How can this be?

![](/img/gdbstub-1.png)

Let's take another look at Ghidra. At the time our corrupted return address gets
loaded into the program counter we are returning from the recursive function
`do_echo_recursive()`. This function calls itself nine times before calling into
the actual echo function, `do_echo()`. We said earlier that the register window
shifts every time a function is called to provide clean registers to the callee.
But the ESP32 only contains 64 registers, and each call to `do_echo_recursive()`
moves the window to the right by eight. Here we see a problem: we will run out
of registers.

![](/img/ghidra-3.png)

What happens in these cases is that the ESP32
[will loop back around](https://sachin0x18.github.io/posts/demystifying-xtensa-isa/)
and overwrite registers that were allocated to earlier function calls, but not
before saving their contents onto the stack. Of course, as soon as values get
pushed to the stack, we can use our stack overflow to manipulate them. This
appears to be what happened when we managed to overwrite a return address with
our long input buffer. Thanks to the recursion employed by 
`do_echo_recursive()`, we can hijack execution flow as if it were a regular x86
or ARM processor.

### 1.4 Finding offsets and fixing registers

Before we can exploit this vulnerability, we need to find out what else we
control and how we can use this to our advantage. The easiest way to do this is
to send an input pattern in which every byte is unique.

![](/img/gdbstub-2.png)

At first glance, it appears we can only control the return address (see the
program counter `PC`). However, we can also try overwriting more registers,
particularly to see if we can play with the stack pointer in register **a1**.
Because the return address and the stack pointer are stored next to each other
in memory, we simply need to write four bytes beyond the return address to
control the stack pointer. We start at the original value for our frame
(`0x3ffbf1d0`) and play around with it until we find that address `0x3ffbb1b0`
will result in values from our input buffer being stored in registers **a10**
and **a11**.

![](/img/gdbstub-3.png)

This is extremely helpful because the Xtensa calling convention reserves
registers **a10**-**a13** as the first four arguments to any function call that
is made with a `call8` instruction. Controlling some of these registers will
help us make our own function calls.

Finally, we have a slightly annoying problem to solve. In the examples above,
we had to terminate our TCP connection in order to trigger the crash and obtain
the register dump. This is because `do_echo()` only returns under one of two
conditions: the connection gets closed, or a newline character (`0x0a`) is
received. Closing the connection is bad for us, because we won't  be able to
send data back to our machine. However, sending an extra `0x0a` character ends
up overwriting the first argument to `do_echo_recursive()`, which happens to be
the socket descriptor for our TCP connection. Let's make a mental note here that
this appears to always be set to `0x37`.

## 2. Developing the exploit

At this point we have all we need to start developing an exploit. We can control
execution flow, pass arguments to function calls, and keep the connection alive
to send data back to our machine.

### 2.1 Finding a ROP gadget

First some advice: *do your homework*. If I had done mine, I would have known
that **the Xtensa stack is not executable**. Hopefully this will save you from
trying to write shellcode for an architecture that essentially only supports
relative addressing, which, I learned, is not fun.

Just because we cannot run our own shellcode does not mean we can't tell the
programme what to do, however. We can use
[return-oriented programming](https://en.wikipedia.org/wiki/Return-oriented_programming)
to make use of any instructions already present, including those related to
sending data over TCP.

One function stands out in particular: `ssize_t lwip_write(int socket, void*
data, size_t size)`. This function invokes `lwip_send()` to send data over TCP
and takes three arguments, of which we can set the first two via **a10** and
**a11**. Further, the register dumps show that **a12** -- the third argument --
already contains a large value at the time our return address gets loaded. If we
set our return address to `lwip_write()`, **a10** to our socket descriptor
(`0x37`), and **a11** to the flag address we found earlier, we should be able to
send the flag back to our client. Helpfully, `lwip_write()` also sets **a13**
(the TCP `flags` argument to `lwip_send()`) to `0x0`, so we don't have to figure
out how to do it ourselves.

![](/img/ghidra-4.png)

### 2.2 Writing the exploit

If we bring all this together, we get a fairly straightforward Python exploit:

```python
import socket
import argparse

def main():
    parser = argparse.ArgumentParser(
            description="Exploit for the 'Hack Me If You "
                        "Can' challenge for the MCH2022 CTF."
    )
    parser.add_argument('target', type=str, help='target IP / hostname')
    parser.add_argument('port', type=int, help='target port')
    args = parser.parse_args()

    # Exploit constants
    A10 = b"\x37\x00\x00\x00" # socket descriptor (first argument)
    A11 = b"\x58\x53\xfb\x3f" # flag address (second argument)
    PC  = b"\xb8\x76\x0d\x40" # call8 lwip_write(a10, a11, a12)
    A1  = b"\xb0\xf1\xfb\x3f" # stack pointer (req'd to return from do_echo())

    exploit(args.target, args.port, A10, A11, PC, A1)

def exploit(target, port, a10, a11, pc, a1):
    buffer = b"\x65" * 40 + a10 + a11 + pc + a1 + b"\n"

    print(f"Connecting to {target}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target, port))

    print(f"Waiting for user to accept connection...")
    r = s.recv(128)
    status = r.decode()
    print(status)

    if "denied" in status:
        s.close()
        return

    print(f"Sending malicious buffer...")
    s.sendall(buffer)

    print(f"Buffer sent, awaiting reply...")

    # Discard output of do_echo() 
    s.recv(len(buffer))

    r = s.recv(39)
    s.close()

    print(f"Flag: {r.decode()}")

if __name__ == "__main__":
    main()
```

When we run the exploit, we can see that we did it! We can successfully
retrieve the placeholder flag from our badge. A CTF organiser has kindly
confirmed the exploit also works against badges containing the real flag.

[![proof](/img/proof.png)](/img/proof.png)

## 3. Conclusion

This was an extremely fun and rewarding badge challenge. What's interesting is
that none of techniques involved are particularly esoteric. Rather, the
challenge lies in getting to grips with a new processor architecture and
working without a debugger. Above all, it teaches you that appearances can be
deceiving, and that it pays dig deeper when things don't add up.

Sadly I didn't win any points for this challenge -- I solved it two days after
getting home. The two teams who did manage to solve it while at MCH2022 were
[Bratzenamt](https://dojoe.github.io/hackmeifyoucan/) and
[ChaosWest](https://twitter.com/__spq__/status/1552386564759687175). Well done
and hats off to both of them.

Thanks to the organisers of the [MCH2022 CTF](https://ctf.mch2022.org) for a
excellent challenge and a great CTF!

