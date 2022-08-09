# Real World WASM 1 writeup

Real World WASM 1 was a pwn challenge in UIUCTF 2022. You are given the source
code for a C program which uses [WasmEdge][github] to execute WASM binaries.

A brief inspection of the source (chal.c) reveals that there isn't much
interesting. It takes the input WASM binary as hex and executes it, calling the
`main` function with a user-specified parameter.

## Investigating WasmEdge

Since there isn't much in chal.c, let's take a look at WasmEdge. What
webassembly features does it support? Are there any obvious security flaws? Is
the library being used properly?

A glance at the project's readme reveals that it supports "all standard
WebAssembly features and many proposed extensions". The link takes us to [this
page][extensions]. The WASI extensions look interesting, particularly the
sockets extension.

After futher digging, we find this [example][c-embed] for embedding WasmEdge in
C. This looks very familiar to chal.c, except it enables a WASI extension
through a `WasmEdge_ConfigureContext`. Unfortunately, the challenge does not
enable any extensions, so we can't use the sockets extension.

### Univeral WASM binary format

Eventually, we stumble upon the [universal binary format][universal] that
WasmEdge supports. The WasmEdge program can compile wasm binaries into host
instructions, inserting them into a separate section. Installing and running
`wasmedgec` ourselves, we find that we can change the host instructions section
and the `wasmedge` runner will execute it. There does not seem to be any
integrity checks of any sort.

In build.sh, we find the build flag `-DWASMEDGE_BUILD_AOT_RUNTIME=OFF`. So, this
implies that the universal wasm runtime is disabled, right? Confusingly enough,
this only disables the AOT compiler, not the runtime. Some testing with the
local challenge verifies this.

## Crafting a malicious universal WASM binary

In sample.wat, we create a simple WASM program. Then, we can compile this to
wasm with [wabt's][wabt] `wat2wasm` (or, use your favorite wasm assembler). The
output is sample.wasm.

To create a universal WASM binary, we use `wasmedgec`, the compiler tool for
WasmEdge. The output is in compiled.wasm. Using a disassembler, we can see that
the compiled native instructions are at the end of the file. We can replace
these instructions with our own (malicious.wasm).

## Sending the payload

Now, all that's left is to convert the malicious.wasm file to hex and send it
over the wire. You should get a shell!

[github]: https://github.com/wasmedge/WasmEdge/
[extensions]: https://wasmedge.org/book/en/intro/standard.html
[c-embed]: https://wasmedge.org/book/en/embed/c.html
[universal]: https://wasmedge.org/book/en/start/universal.html
[wabt]: https://github.com/WebAssembly/wabt
