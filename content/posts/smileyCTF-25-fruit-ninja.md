+++
date = '2025-06-19T13:39:15+02:00'
draft = false
title = 'smileyCTF 2025: Fruit Ninja'
+++

> my friend made a custom cpu, so of course i had to make a game for it. can you win? @unvariant REMEMBER TO GIVE THEM CPU
> 
> `rev`,  8 solves, created by flocto

*Fruit Ninja* was a fun challenge from last week's smileyCTF. It involved reverse engineering code written for a custom RISC-V 32 processor with a Harvard architecture, which could be relinked using a custom linker script to allow for easy static analysis. This revealed a straightforward flag checking scheme that could trivially be brute forced.

## 1. First steps

The challenge gives us the following files:

- `fruitninja/ram_file.mem`
- `fruitninja/rom_file.mem`
- `fruitninja/vcpu*`: a simulator for the custom CPU
- `fruitninja/src`: a directory containing files like `CPU.sv` and `RAM.sv`

A quick Google search reveals that `sv` stands for [SystemVerilog](https://en.wikipedia.org/wiki/SystemVerilog), a hardware description language useful for describing CPUs. So `src` contains the custom CPU's "source code".

We'll probably need to reverse the ROM to solve this challenge, so let's take a look inside `rom_file.mem` and `ram_file.mem`:

**rom_file.mem**
```
@00000000
00020137 00000097 254080e7 ff010113 00112623 00812423 [...]
```

**ram_file.mem**
```
@00000000
4e26d7c6 2f676fc6 3bec4bac 7806aa71 710fa7cf 655a0ef2 [...]
```

Clearly, these look like memory dumps with an address at the top and the actual data on the next line. However, we don't know how to decode this data until we know the CPU's instruction set.

## 2. Discovering the instruction set

Every CPU has a decoder that breaks down the zeroes and ones of a program into instructions it understands. If we can find the logic for the decoder, we know what operations our processor supports and how they are encoded.

Exploring `src/`, we find this intriguing enum in `CPU.h.sv`:

```SystemVerilog
package Opcode;
    typedef enum logic [6:0] {
        RegImm = 7'b00_100_11,
        RegReg = 7'b01_100_11,
        Load   = 7'b00_000_11,
        Store  = 7'b01_000_11,
        Branch = 7'b11_000_11,
        Jal    = 7'b11_011_11,
        Jalr   = 7'b11_001_11,
        Lui    = 7'b01_101_11,
        Auipc  = 7'b00_101_11
    } Opcode;
endpackage
```

If you know RISC-V, these opcodes will look familiar: they are identical to those used to encode RISC-V instructions. Also, in `Register.sv`  we find the line `logic [31:0] registers[31:0]`, so it seems we are dealing with a RISC-V 32 processor.

Now that we know the instruction set, we should be able to disassemble the ROM. We can do this with `capstone`:

```python
from capstone import *

def disasm():
    with open("rom_file.mem", "r") as f:
        words = f.read()[1:].split()

	addr = int(words[0], 16)
	instructions = [bytes.fromhex(instr) for instr in words[1:]]
	rom = b"".join(instructions)

    md = Cs(CS_ARCH_RISCV, CS_MODE_32)

    for i in md.disasm(rom, addr):
        print(f"{i.mnemonic} {i.op_str}")
```

Yet, the initial disassembly seems to be nonsensical:

```asm
c.addi4spn s0, sp, 0x100
c.jal -0x100
c.unimp
```

What if the memory dump is big-endian? Let's try reversing the byte order for each word:

```python
# convert instructions to little-endian by reversing the bytes in each word
instructions = [bytes.fromhex(instr)[::-1] for instr in words[1:]]
```

```asm
lui sp, 0x20
auipc ra, 0
jalr ra, ra, 0x254
addi sp, sp, -0x10
sw ra, 0xc(sp)
sw s0, 8(sp)
sw s1, 4(sp)
sw s2, 0(sp)
mv s0, a0
mv a0, zero
beqz a1, 0x1a4
beqz s0, 0x1a0
addi s1, zero, 0x20
addi s2, zero, 0x20
beqz a1, 0x90
srli a0, a1, 1
# [...]
```

Success! So, we're dealing with a RISC-V 32 CPU. Whew, that simplifies things: we can use standard RISC-V tools to analyse the ROM. Let's save the disassembly in `rom.S` and the RAM as raw little-endian bytes in `ram.bin`.

## 3. Discovering the memory architecture

There is something odd about `ram_file.mem` and `rom_file.mem`. They both start with `@00000000`, telling the CPU to load both RAM and ROM at the same address.

[![Harvard architecture - diagram by Nessa Ios](https://upload.wikimedia.org/wikipedia/commons/3/3f/Harvard_architecture.svg)](https://commons.wikimedia.org/wiki/File:Harvard_architecture.svg)

On a Von Neumann architecture (which most personal computers use), loading both the RAM and ROM to address `00000000` would cause them to overwrite each other. But on a Harvard architecture, the ROM will end up in instruction memory and the RAM in data memory, so both can be stored at `00000000`. This program seems like it was developed for a Harvard machine. Binary Ninja, our decompiler, expects a Von Neumann architecture, so we'll have to fix this.

Fortunately, we can use a custom linker script to decide where things get loaded. The assembly in our ROM contains only relative jumps, so it's position-independent and can theoretically be loaded anywhere. We just need to make sure the RAM is at address `000000`, because that's where our assembly expects it to be.

```ld
OUTPUT_FORMAT("elf32-littleriscv")
ENTRY(_start)

MEMORY
{
  RAM (rw) : ORIGIN = 0x00000000, LENGTH = 128K
  ROM (rx)  : ORIGIN = 0x00080000, LENGTH = 128K
}

SECTIONS
{
  .data : {
    *(.data)
  } > RAM

  .text : {
    *(.text)
  } > ROM
}
```

With linker script, we can assemble and relink the ROM and RAM into a single ELF file. We'll start by adding a few assembler directives to `rom.S` so the linker knows it belongs in the `.text` section and contains the entry point:

```asm
.section .text
.global _start

_start:
# [...]
```

Then we can assemble the ROM (I prefer `clang` as it maps more closely to the original assembly):
```
clang --target=riscv32 -march=rv32i rom.S -c -o rom.o
```

We also need to use `objcopy` to place the RAM in its own object file:

```
riscv64-unknown-elf-objcopy -I binary -O elf32-littleriscv -B riscv ram.bin ram.o
```

Finally, we use the linker script to combine the object files into a single ELF file:

```
riscv64-unknown-elf-ld rom.o ram.o -T linker.ld -o fruit.elf
```

## 4. Analysing the ROM

With a functional ELF file, we can load it up in Binary Ninja and analyse the pseudocode. Inside, we find several helper functions (including a manual `modulo(uint32_t dividend, uint32_t divisor)` implementation) and a function that looks like `main()`.

By looking at strings being loaded by the disassembly, we can infer what the `write(char*)` and `read(char*)` functions are.

![main() disassembly](main.png)

This gives us the following pseudocode for `main()`:

```c
int32_t main()
{
    write("cut my fruit in half: ");
    char buffer[0x25];
    
    if (read(&buffer) == 0x25)
    {
        int32_t j = 0;
        uint32_t tmp = 0;
        int32_t i = 0;
        char var_25_1 = 0;
        int32_t encoded[0x32];
        
        do
        {
            uint32_t c = ((uint32_t)buffer[i]);
            int32_t i_mod_3 = modulo((i & 0xff), 3);
            int32_t shift = (i_mod_3 << 1);
            int32_t j_1 = (j + 1);
            encoded[j] = (((c << shift) & 0x3f) | tmp);
            tmp = (c >> (shift ^ 6));
            
            if (i_mod_3 == 2)
            {
                encoded[j_1] = tmp;
                j_1 = (j + 2);
                tmp = 0;
            }
            
            i += 1;
            j = j_1;
        } while (i != 0x26);
        
        int32_t k = 0;
        int32_t* array_1 = &ARRAY;
        int32_t valid = 0x32;
        
        do
        {
            int32_t l = 0;
            int32_t acc = 0;
            int32_t* array_2 = array_1;
            
            do
            {
                int32_t val = *(uint32_t*)array_2;
                
                if (l >= encoded[k])
                    val = (0 - val);
                
                acc += val;
                l += 1;
                array_2 = &array_2[1];
            } while (l != 0x40);
            
            valid -= ((acc < 1) ? 1 : 0);
            k += 1;
            array_1 = &array_1[0x40];
        } while (k != 0x32);
        
        if (valid == 0)
        {
            write("yes\n");
            return 0;
        }
    }
    
    write("no\n");
    return 1;
}
```

The first part looks like it reads 37 input bytes and encodes them into 50 6-bit values using some kind of custom Base64 variant. The second part checks each of the 50 values against a separate array of 64 integers that are summed together. Only if the sum of these values is zero will the 6-bit value be seen as valid. The 6-bit value determines at what point all following array values will be treated as negative numbers, changing the final sum. Essentially, this is a simplified version of the [partition problem](https://en.wikipedia.org/wiki/Partition_problem).

Because each 6-bit value has only 64 possible values, and the correctness of one 6-bit value can be independently verified from the others, we can easily brute force the encoded flag.

```python
def retrieve_arr():
	"""Retrieve the int32_t ARRAY[50][64] from `ram_file.mem`"""
	
    with open("ram_file.mem", "r") as f:
        _, raw_mem = f.readlines()

	# read values into flat array
    vals = [int(word, 16) for word in raw_mem.strip().split(' ')][:0x32*0x40]

	# divide flat array into subarrays of 64 values each
    return [vals[i:i+0x40] for i in range(0, len(vals), 0x40)]

def guess(a: list[int], n: int) -> bool:
    acc = 0

	# sum all values in the array
    for i, val in enumerate(a):

		# once i exceeds our guess, treat subsequent values as negative
        if i >= n:
            val *= -1

        acc += val

    return acc & 0xffffffff == 0

def brute() -> bytes:
    A = retrieve_arr()

    flag64 = []

    for a in A:
        for n in range(2**6):
            if guess(a, n):
                flag64.append(n)
                break

    return flag64
```

Then, the flag can be decoded by inverting the original encoding:

```python
def decode(encoded_data: list[int]) -> bytes:
    decoded_bytes = bytearray()
    
    i = 0

    while i < len(encoded_data):
        chunk = encoded_data[i:i+4]
        
        e0 = chunk[0]

        if len(chunk) > 1:
            e1 = chunk[1]
            c0 = ((e1 & 0x03) << 6) | e0
            decoded_bytes.append(c0)
        
        if len(chunk) > 2:
            e2 = chunk[2]
            c1 = ((e2 & 0x0f) << 4) | (e1 >> 2)
            decoded_bytes.append(c1)

        if len(chunk) > 3:
            e3 = chunk[3]
            c2 = ((e3 & 0x3f) << 2) | (e2 >> 4)
            decoded_bytes.append(c2)
            
        i += 4
        
    return bytes(decoded_bytes)
```

This quickly yields our flag:

```python
>>> flag64 = brute()
>>> decode(flag64)
b'.;,;.{PPPerfect_pr3c15e_p4rT1Ti0ning}'
```

## Epilogue

The difficulty in most custom CPU challenges (including VM challenges) lies in understanding the instruction set. Once the instruction set is known, implementation details like endianness and memory architecture are easy to overcome. Luckily, RISC-V is supported by many compilers and static analysis tools, so it was easy to compile this into a working binary and obtain the pseudocode. If a truly custom instruction set had been used, we would have had to manually analyse the assembly, which would have taken significantly more effort.
