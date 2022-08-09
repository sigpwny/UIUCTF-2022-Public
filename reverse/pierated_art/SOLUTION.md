# Pierated art solution

You are given several randomly generated piet programs that look like famous art
works. Each program checks a password and prints whether it is correct or not.

When you download the image and decode it, you will notice a block of color in
the top left. Piet programs start in the top left and move straight right until
the direction pointer is changed, by a black block or a "pointer" command.

The message is printed and N user input characters are received, due to the
number of ugly yellow squares.  Afterward, the program works as a very simple
flag checker: It takes your input character, adds an offset, and mods by 26 and
checks if it is zero. The program works in a clockwise spiral until it stops,
and outputs if your word was correct.

The challenge idea is to automate solving this spiral, you have to solve 10
images in a time limit. My solve script counts the size of the offset blocks,
and moves in a clockwise spiral, getting the correct character one by one.

See solve.py.
