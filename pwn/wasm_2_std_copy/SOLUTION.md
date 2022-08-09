# Solution

## The patch

The patch I applied to WasmEdge disables running the Universal WASM binary
(compiled code section). However, it disables it after we already loaded the
binary, after the vulnerable code shown below. This was done on purpose to
disable executing the AOT compiled code but allowing it to be loaded.

## The vulnerability

WasmEdge has an arbitrary write exploit on [line 101 of
lib/loader/shared_library.cpp][stdcopy]:
```cpp
std::copy(Content.begin(), Content.end(), Binary + Offset);
```

The `Content` and `Offset` values can be manipulated by the user through the AOT
section in the WASM file. Although AOT (universal wasm execution) has been
turned off through the patch, it is still being loaded. The `Binary` is a large
heap chunk acquired through mmap. Therefore, it will have a consistent offset
from the other shared libraries.

You can find this vulnerability in several ways. Since I gave a
big hint in the title of the challenge, my intention was for it to be found
through manual code review. However, fuzzing would have also likely found the
issue in minimal time, as bad `Offset` values can easily cause a crash.

This vulnerability is the crux of the challenge. There are several different
ways to exploit it. I will outline one such way.

## One possible exploit

After searching on the internet, we find this [writeup][writeup] from hxp
CTF 2017. It details a very similar exploit and explains a solution. The
solution presented in the writeup is to overwrite `_IO_read_end` and
`_IO_write_base` in glibc to leak the mmap and stack address (there are plenty
of stack pointers in the glibc data segment). From there, you can run the
program again to write to the stack, using a ropchain or similar technique to
achieve code execution.

[stdcopy]: https://github.com/WasmEdge/WasmEdge/blob/312d7628a3dce72431abc39d88aa17745bdf612d/lib/loader/shared_library.cpp#L101
[writeup]: https://github.com/bennofs/docs/blob/9a0ef37d6037836d66e23288a8aa461b516c0fee/hxp-2017/impossible.md
