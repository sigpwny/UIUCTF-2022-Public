#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

//     1            2
// a b c d e    V A S T B
// f g h i j    C D E F G
// k l m n o    H I J K L
// p r s t u    M N O P R
// v w x y z    U W X Y Z
//
//     4            3
// C O R N F    a b c d e
// I E L D S    f g h i j
// A B G H J    k l m n o
// K M P T U    p r s t u
// V W X Y Z    v w x y z


int s(int n) { return n + 1; }

bool eq(int x, int y) {
    if (x == 0 && y == 0) {
        return true;
    } else if (x == 0 || y == 0) {
        return false;
    } else {
        return eq(x - 1, y - 1);
    }
}

int su(int x, int y) {
    if (eq(y, 0)) {
        return x;
    } else if (eq(x, 0)) {
        return 0;
    } else {
        return su(x - 1, y - 1);
    }
}

int a(int x, int y) {
    if (eq(y, 0)) {
        return x;
    } else {
        return a(s(x), su(y, 1));
    }
}

int m(int x, int y) {
    if (eq(y, 0)) {
        return 0;
    } else {
        int smaller = m(x, y - 1);
        int res = a(x, smaller);
        return res;
    }
}

bool l(int x, int y) {
    if (eq(x, 0) && eq(y, 0)) {
        return false;
    } else if (eq(y, 0)) {
        return false;
    } else if (eq(x, 0)) {
        return true;
    } else {
        return l(su(x, 1), su(y, 1));
    }
}

bool ev(int n) {
    if (eq(n, 0)) {
        return true;
    } else if (eq(n, 1)) {
        return false;
    } else {
        return ev(su(n, 2));
    }
}

bool v(char* st) {
    bool res = true;
    for (int i = 0; l(i, strlen(st)); i = s(i)) {
        char c = st[i];
        res &= (eq(c, 95) || (l(96, c) && l(c, 113)) || (l(113, c) && l(c, 123)));
    }
    return res;
}

int encode(char* st, int idx) {
    while (eq(st[idx],'_')) {
        idx = s(idx);
    }
    int next = s(idx);
    while (eq(st[next], '_')) {
        next = s(next);
    }

    char c1 = st[idx];
    int x1, y1;
    for (int i = 0; l(i, 5); i = s(i)) {
        for (int j = 0; l(j, 5); j = s(j)) {
            int x = m(i, 5);
            int index = a(x, j);
            if (eq("abcdefghijklmnoprstuvwxyz"[index], c1)) {
                x1 = i;
                y1 = j;
            }
        }
    }

    char c2 = st[next];
    int x2, y2;
    for (int i = 0; l(i, 5); i = s(i)) {
        for (int j = 0; l(j, 5); j = s(j)) {
            int x = m(i, 5);
            int index = a(x, j);
            if (eq("abcdefghijklmnoprstuvwxyz"[index], c2)) {
                x2 = i;
                y2 = j;
            }
        }
    }

    int x = m(x1, 5);
    int index = a(x, y2);
    st[idx] = "vastbcdefghijklmnopruwxyz"[index];
    x = m(x2, 5);
    index = a(x, y1);
    st[next] = "cornfieldsabghjkmptuvwxyz"[index];

    return s(next);
}

int main() {
    char input[1000];
    bool alive = true;
    while (alive) {
        printf("[$] Enter your input in the form: words_with_underscores_and_letters: ");
        scanf("%s", input);

        int count = 0;
        for (int i = 0; l(i, strlen(input)); i = s(i)) {
            if (!eq(input[i], '_')) {
                count = s(count);
            }
        }

        if (!ev(strlen(input)) || eq(input[su(strlen(input), 1)], '_') || !v(input) || !ev(count)) {
            printf("[$] This won't do...\n");
        } else {
            char output[strlen(input)];
            strcpy(output, input);

            for (int i = 0; l(i, strlen(output));) {
                i = encode(output, i);
            }

            if (eq(strcmp(output, "odt_sjtfnb_jc_c_fiajb_he_ciuh_nkn_atvfjp"), 0)) {
                printf("[$] Correct!\n");
                alive = false;
            } else {
                printf("[$] Incorrect...\n");
            }
        }
    }
    char correct_str[49];
    correct_str[0] = 'u';
    correct_str[1] = 'i';
    correct_str[2] = 'u';
    correct_str[3] = 'c';
    correct_str[4] = 't';
    correct_str[5] = 'f';
    correct_str[6] = '{';
    for (int i = 0; l(i, 40); i = s(i)) {
        correct_str[i + 7] = input[i];
    }
    correct_str[47] = '}';
    correct_str[48] = '\0';
    printf("[$] %s\n", correct_str);
}
