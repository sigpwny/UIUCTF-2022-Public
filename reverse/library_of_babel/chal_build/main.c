#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "babel.h"

// max digits the user can enter
#define MAX_DIGITS 10000
// how many letters to show per row of page
#define ROW 80

// max length of a flag (read from file)
#define MAX_FLAG_LEN 256

#define TARGET1 "this page cannot be found."

void print_intro() {
    printf(
            "Welcome to the Library of Babel!\n"
            "We have every possible book in the world.\n"
            "You are using the online demo version, which only has every possible page.\n"
            "There are 3200 characters on each page.\n"
            "Each character can be a lowercase letter, a space, a period, or a comma.\n"
            "Feel free to browse around!\n"
            );
}

void clear_newlines() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

int is_valid_int(char* num) {
    // null pointer invalid
    if (num == NULL) {
        return 0;
    }
    // ignore single leading negative sign
    if (num[0] == '-') {
        num++;
    }
    // empty string not valid (or negative sign without number)
    if (num[0] == '\0') {
        return 0;
    }

    // check that all characters are digits
    for (unsigned i = 0; i < strlen(num); i++) {
        if (num[i] < '0' || num[i] > '9') {
            return 0;
        }
    }
    return 1;
}

// gets a bigint string
// returned pointer must be freed
char* get_big_int(char* prompt) {
    char* big_int = calloc(MAX_DIGITS, sizeof(char));
    while (1) {
        printf("%s: ", prompt);
        if (fgets(big_int, MAX_DIGITS, stdin) == NULL) {
            exit(1);
        }
        big_int[strcspn(big_int, "\n")] = '\0';
        if (!is_valid_int(big_int)) {
            printf("Invalid integer.\n");
        } else {
            return big_int;
        }
    }
}

// prompts for int between bounds
// repeats prompt until valid int is entered
unsigned long get_int(char* prompt, unsigned long lower, unsigned long upper) {
    unsigned long num;
    while (1) {
        printf("%s (%lu-%lu): ", prompt, lower, upper);
        if (scanf("%lu", &num) == EOF) {
            exit(1);
        }
        if (num >= lower && num <= upper) {
            return num;
        }
        printf("Please enter a number between %lu and %lu.\n", lower, upper);
    };
    return num;
}

void print_flag(char* fname) {
    FILE* fp = fopen(fname, "r");
    char buf[MAX_FLAG_LEN];
    if (fgets(buf, MAX_FLAG_LEN, fp) == NULL) {
        printf("Error: could not read flag. Please report this to an admin.\n");
        return;
    }
    fclose(fp);
    puts(buf);
}

void check_correct_page(char* page) {
    if (strncmp(page, TARGET1, strlen(TARGET1)) == 0) {
        // check that the rest of the page is all spaces
        for (unsigned i = strlen(TARGET1); i < strlen(page); i++) {
            if (page[i] != ' ') {
                return;
            }
        }
        printf("You have found a secret page!\n");
        printf("Flag: ");
        print_flag("flag.txt");
    }
}

void print_page(char* page) {
    for (unsigned i = 0; i < ROW + 4; i++) putchar('='); putchar('\n');
    for (unsigned i = 0; i < BABEL_PAGE_SIZE / ROW; i++) {
        printf("| ");
        for (unsigned j = 0; j < ROW; j++) {
            putchar(page[i * ROW + j]);
        }
        printf(" |\n");
    }
    for (unsigned i = 0; i < ROW + 4; i++) putchar('='); putchar('\n');
}

void get_input(struct query_t *query) {
    printf("\nWhich hexagon would you like to visit?\n");
    printf("Please enter the (w, x, y, z) coordinates of the hexagon.\n");
    query->w = get_big_int("w");
    query->x = get_big_int("x");
    query->y = get_big_int("y");
    query->z = get_big_int("z");

    printf("Finding the hexagon...\n");
    sleep(1);
    printf("Located!\n");

    printf("Which page would you like to see?\n");
    query->side = get_int("side", 1, 4);
    query->shelf = get_int("shelf", 1, 5);
    query->book = get_int("book", 1, 32);
    query->page = get_int("page", 1, 410);

    printf("\n");

    clear_newlines();
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    print_intro();

    struct query_t query;

    get_input(&query);

    printf("Searching...\n");

    char* page = babel_lookup(&query);

    printf("Here is your page:\n");
    print_page(page);

    check_correct_page(page);

    free(page);
    free(query.w);
    free(query.x);
    free(query.y);
    free(query.z);
}
