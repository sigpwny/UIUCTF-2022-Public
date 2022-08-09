#include "gen.h"

// Referenced from https://github.com/st98/my-ctf-challenges/blob/master/harekaze-ctf-2019/admins_product_key/src/product_key.c
char table_s[34]; // "JOTFQ3REH0XM2PIKN8497S5WG6VCAZUYL"
char padding = 'L';
unsigned char table[100]; 
DWORD brr[16];
int count;
int arr[16];
char flag[200] = "uiuctf{sorry_im_just_a_fake_flag}";

unsigned rol(unsigned x, unsigned y)
{
    return ((unsigned)(x) << (y) | (unsigned)(x) >> (64 - y)) & 0xffffffffffffffff;
}

unsigned ror(unsigned x, unsigned y)
{
    return ((unsigned)(x) >> (y) | (unsigned)(x) << (64 - y)) & 0xffffffffffffffff;
}

int usc() {
    unsigned int v1;
    unsigned int v2;
    int v3;

    v1 = brr[((BYTE)count + 5) & 0xf];
    v2 = brr[((BYTE)count + 12) & 0xf];
    v3 = (v2 << 9) ^ v2 ^ (brr[count] << 16) ^ brr[count];

    brr[count] = (v1 >> 10) ^ v1 ^ v3;
    count = ((BYTE)count + 11) & 0xf;
    brr[count] ^= (32 * ((v1 >> 10) ^ v1 ^ v3)) & 0xEB472E8D ^ (((v1 >> 10) ^ v1) << 25) ^ (v1 >> 10) ^ v1 ^ (v3 << 12) ^ (4 * brr[count]);

    return brr[count];
}

int ate(int* n) {
    int res;

    for (int i = 0; i < 4; i++) {
        brr[i] = (DWORD)n[4 * i];
        res = (unsigned int)(i + 1);
    }
    for (int i = 4; i < 16; i++) {
        brr[i] = (DWORD)0;
    }

    return res;
}

void obf(const char* f) {
    char crr[40];
    int i = 0;

    memset(arr, 0, sizeof(arr));

    for (; i < 16; i++)
    {
        arr[i] = ror(*(DWORD*)f, i);
    }

    ate(arr);

    for (i = 0; i < 0x64; i++)
    {
        usc();
    }

    *(DWORD*)&crr[0] = -1678030491;
    *(DWORD*)&crr[4] = 1213635701;
    *(DWORD*)&crr[8] = 865493747;
    *(DWORD*)&crr[12] = -1002882818;
    *(DWORD*)&crr[16] = 52570913;
    *(DWORD*)&crr[20] = 15408472;
    *(DWORD*)&crr[24] = -277531332;
    *(DWORD*)&crr[28] = 1883894447;
    *(DWORD*)&crr[32] = 2049029407;
    *(DWORD*)&crr[36] = -595920156;

    for (i = 0; i < 0xa; i++)
    {

        *(DWORD*)&crr[i * 4] ^= usc();
    }

    snprintf(table_s, sizeof(table_s), "%s", crr);

}



void init_t(char* t) {
    int len = strlen(t);
    for (int i = 0; i < len; i++) {
        table[t[i]] = i;
    }
}

void decode(char* input, unsigned char* output) {

    obf(flag);

    init_t(table_s);

    int len_i = strlen(input);
    int len_o = len_i * 5 / 8;
    int i;
    char* in = input;

    for (i = 0; i < len_i; i++) {
        if (input[i] == padding) {
            input[i] = table_s[0];
        }
    }

    for (i = 0; i < len_o; i++) {
        switch (i % 5) {
        case 0:
            output[i] = (table[*in] << 3) | (table[*(in + 1)] >> 2);
            in++;
            break;
        case 1:
            output[i] = ((table[*in] & 3) << 6) | (table[*(in + 1)] << 1) | (table[*(in + 2)] >> 4);
            in += 2;
            break;
        case 2:
            output[i] = ((table[*in] & 0xf) << 4) | (table[*(in + 1)] >> 1);
            in++;
            break;
        case 3:
            output[i] = ((table[*in] & 1) << 7) | (table[*(in + 1)] << 2) | (table[*(in + 2)] >> 3);
            in += 2;
            break;
        case 4:
            output[i] = ((table[*in] & 7) << 5) | table[*(in + 1)];
            in += 2;
            break;
        }
    }

    output[len_o] = '\0';
}




