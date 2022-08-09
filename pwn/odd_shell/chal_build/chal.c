#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("Display your oddities:");
    char *response = (char *)mmap((void *)0x123412340000, 0x1000, 7, 0x32, 0xffffffff, 0); // Reserving memory for our shellcode
    if (response != (char *)0x123412340000)
    {
        puts("I can't allocate memory!");
        exit(0xffffffff);
    }
    ssize_t rd = read(0, response, 0x800);

    if (*(response + rd - 1) == '\n')
    {
        *(response + rd - 1) = '\0';
        rd--;
    }

    for (ssize_t i = 0; i < rd; i++)
    {
        if (!((unsigned char)*(response + i) & 1))
        {
            puts("Invalid Character");
            exit(0xffffffff);
        }
    }

    (*(void (*)())response)();
}
