#include <stdio.h>
#include <gmp.h>

// number of letters on a page
#define BABEL_PAGE_SIZE 3200

// w, x, y, z coordinates in base 10
// side: which side of the hexagon (1-4)
// shelf: which shelf (1-5)
// book: which book (1-32)
// page: which page (1-410)
struct query_t {
    char* w;
    char* x;
    char* y;
    char* z;
    unsigned long side;
    unsigned long shelf;
    unsigned long book;
    unsigned long page;
};

// Looks up the page for a query
// Returned string must be freed once done
char* babel_lookup(struct query_t *query);
