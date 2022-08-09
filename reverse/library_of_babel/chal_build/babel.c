#include "babel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>

#define NUM_CHARS 39

struct lcg_steps_t {
    mpz_t x; // LCG starting value
    mpz_t a; // LCG a
    mpz_t c; // LCG c
    mpz_t m; // LCG m
    mpz_t n; // num iterations of LCG
};

// Steps n times through the LCG
// note: modifies x
// source: https://www.nayuki.io/page/fast-skipping-in-a-linear-congruential-generator
static void lcg_skip(mpz_t a, mpz_t c, mpz_t m, mpz_t x, mpz_t n) {
    /* python pseudocode:
     * a1 = a - 1
     * ma = a1 * m
     * y = (pow(a, n, ma) - 1) // a1 * c
     * z = pow(a, n, m) * x
     * new_x = (y + z) % m
     */
    mpz_t a1, ma, y, z, new_x;
    mpz_inits(a1, ma, y, z, new_x, NULL);

    mpz_sub_ui(a1, a, 1);

    mpz_mul(ma, a1, m);

    mpz_powm(y, a, n, ma);
    mpz_sub_ui(y, y, 1);
    mpz_tdiv_q(y, y, a1);
    mpz_mul(y, y, c);

    mpz_powm(z, a, n, m);
    mpz_mul(z, z, x);

    mpz_add(new_x, y, z);
    mpz_mod(new_x, new_x, m);
    mpz_set(x, new_x);

    mpz_clears(a1, ma, y, z, new_x, NULL);
}

// convert mpz_t to base39 ([0-9a-z ,.]) string
static char* num_to_str(mpz_t x) {
    char* mpz_str = mpz_get_str(NULL, 39, x);
    size_t len = strlen(mpz_str);
    // copy to malloc chunk
    char* str = malloc(len + 1);
    memcpy(str, mpz_str, len + 1);

    for (int i = 0; str[i]; i++) {
        // convert to 39 in each byte
        if (str[i] >= '0' && str[i] <= '9') {
            str[i] = str[i] - '0';
        } else if (str[i] >= 'A' && str[i] < ('A' + 26)) {
            str[i] = str[i] - 'A' + 10;
        } else if (str[i] >= 'a' && str[i] < ('a' + (39 - 26 - 10))) {
            str[i] = str[i] - 'a' + 10 + 26;
        } else {
            printf("error: invalid base39 char '%c' in num_to_str\n", str[i]);
            exit(1);
        }

        // convert to custom base39
        if (str[i] == 0) {
            str[i] = ' ';
        } else if (str[i] == 1) {
            str[i] = '.';
        } else if (str[i] == 2) {
            str[i] = ',';
        } else if (str[i] < (10 + 3)) {
            str[i] = '0' + str[i] - 3;
        } else {
            str[i] = 'a' + str[i] - 10 - 3;
        }
    }

    return str;
}

// convert base39 ([0-9a-z ,.]) string to mpz_t
static void str_to_num(mpz_t ret, char* str) {
    for (int i = 0; str[i]; i++) {
        // convert to 39 in each byte
        if (str[i] == ' ') {
            str[i] = 0;
        } else if (str[i] == '.') {
            str[i] = 1;
        } else if (str[i] == ',') {
            str[i] = 2;
        } else if (str[i] >= '0' && str[i] <= '9') {
            str[i] = str[i] - '0' + 3;
        } else {
            str[i] = str[i] - 'a' + 10 + 3;
        }

        // convert to base39
        if (str[i] >= 0 && str[i] <= 9) {
            str[i] = str[i] + '0';
        } else if (str[i] >= 10 && str[i] < 10 + 26) {
            str[i] = str[i] - 10 + 'A';
        } else if (str[i] >= 10 + 26 && str[i] < 10 + 26 + (39 - 26 - 10)) {
            str[i] = str[i] - 10 - 26 + 'a';
        } else {
            printf("error: invalid base39 char '%c' in str_to_num\n", str[i]);
            exit(1);
        }
    }
    mpz_set_str(ret, str, 39);
}

// Parses query numbers into state for the LCG to step through
// lcg must be empty
// populates lcg with the correct values from query
static void parse_query(struct lcg_steps_t *lcg, struct query_t *query) {
    mpz_inits(lcg->x, lcg->n, lcg->a, lcg->c, lcg->m, NULL);

    // set LCG m to 39^3200
    mpz_ui_pow_ui(lcg->m, NUM_CHARS, BABEL_PAGE_SIZE);

    // set LCG n to 2^512
    mpz_ui_pow_ui(lcg->n, 2, 512);

    // set LCG a to (NUM_CHARS * shelf * side) + 1
    // a-1 should be a multiple of NUM_CHARS
    mpz_set_ui(lcg->a, NUM_CHARS * (query->shelf * query->side) + 1);

    // set LCG c to page * 32 + book
    mpz_set_ui(lcg->c, query->page * 32 + query->book);

    // Combined the w, x, y, z coordinates into one number
    mpz_t combined;
    mpz_init_set_ui(combined, 0);

    mpz_t shift_factor, w_, x_, y_, z_;
    mpz_inits(shift_factor, w_, x_, y_, z_, NULL);
    mpz_ui_pow_ui(shift_factor, NUM_CHARS, BABEL_PAGE_SIZE/4);

    mpz_set_str(w_, query->w, 10);
    mpz_set_str(x_, query->x, 10);
    mpz_set_str(y_, query->y, 10);
    mpz_set_str(z_, query->z, 10);

    mpz_mod(w_, w_, shift_factor);
    mpz_mod(x_, x_, shift_factor);
    mpz_mod(y_, y_, shift_factor);
    mpz_mod(z_, z_, shift_factor);

    // combine coords (think of this as conversion from 4 "digits" of base shift_factor)
    mpz_add(combined, combined, w_);
    mpz_mul(combined, combined, shift_factor);
    mpz_add(combined, combined, x_);
    mpz_mul(combined, combined, shift_factor);
    mpz_add(combined, combined, y_);
    mpz_mul(combined, combined, shift_factor);
    mpz_add(combined, combined, z_);

    mpz_set(lcg->x, combined);

    mpz_clears(combined, shift_factor, w_, x_, y_, z_, NULL);
}

// padded to BABEL_PAGE_SIZE
static char* num_to_str_padded(mpz_t num) {
    char* num_str = num_to_str(num);
    char* str = malloc(BABEL_PAGE_SIZE + 1);

    // left pad with spaces
    snprintf(str, BABEL_PAGE_SIZE+1, "%*s", BABEL_PAGE_SIZE, num_str);

    free(num_str);

    return str;
}

// queries a page of the library
// returned pointer must be freed
char* babel_lookup(struct query_t *query) {
    char* ret;
    struct lcg_steps_t lcg;

    parse_query(&lcg, query);

    lcg_skip(lcg.a, lcg.c, lcg.m, lcg.x, lcg.n);

    ret = num_to_str_padded(lcg.x);

    mpz_clears(lcg.x, lcg.n, lcg.a, lcg.c, lcg.m, NULL);

    return ret;
}
