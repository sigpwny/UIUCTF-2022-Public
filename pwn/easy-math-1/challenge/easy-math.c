#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define MATH_PROBLEMS 10000

int take_test() {
  int urand = open("/dev/urandom", O_RDONLY);
  if (!urand) return 1;
  unsigned char urand_byte;

  for (int i=0; i<MATH_PROBLEMS; i++) {
    if (read(urand, &urand_byte, 1) != 1) return 1;
    int a = urand_byte & 0xf;
    int b = urand_byte >> 4;
    printf("Question %d: %d * %d = ", i+1, a, b);

    int ans;
    if (scanf("%d", &ans) != 1) return 1;
    if (ans != a * b) return 1;
  }

  close(urand);
  return 0;
}

int check_id() {
  printf("Checking your student ID...\n\n");
  sleep(1);
  struct stat real, given;
  if (stat("/proc/1/fd/0", &real)) return 1;
  if (fstat(0, &given)) return 1;
  if (real.st_dev != given.st_dev) return 1;
  if (real.st_ino != given.st_ino) return 1;
  return 0;
}

int main() {
  setreuid(geteuid(), getuid());
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("Welcome to the MATH 101 final exam.\n");
  if (check_id()) {
    printf("The proctor kicks you out for pretending to be a student.\n");
    return 1;
  }

  printf("The test begins now. You have three hours.\n\n");
  alarm(3 * 60 * 60);
  if (take_test()) {
    printf("You have failed the test.\n");
    return 1;
  }

  setreuid(getuid(), getuid());
  system("cat /home/ctf/flag");
  return 0;
}
