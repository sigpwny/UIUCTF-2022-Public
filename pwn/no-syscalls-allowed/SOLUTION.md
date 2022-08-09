Solve steps:

* Each execution can leak one bit of data by spinning vs. immediately exiting
* Compile assembly to get pc inside main function with leave + pop (instead of ret)
* Use assembly to leak main function, bit by bit
* Disassemble main function
* Find relative address of flag via lea insn in main function
* Leak flag using relative reads, bit by bit
