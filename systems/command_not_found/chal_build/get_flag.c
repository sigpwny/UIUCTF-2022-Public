// SPDX-License-Identifier: MIT
/*
 * Copyright 2022 Google LLC.
 */

#include <signal.h>
#include <stdio.h>
#include <sys/io.h>

#define PORT 0x2022

int main()
{
	if (ioperm(PORT, 1, 1)) {
		perror("ioperm");
		return 1;
	}

	for (;;) {
		unsigned char data = inb(PORT);

		if (!data)
			break;

		putchar(data);
	}

	return 0;
}
