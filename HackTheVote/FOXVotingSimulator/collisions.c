#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

uint32_t hash(char * data, size_t length);

int     main(void)
{
    uint32_t    val;

    val = hash("Trump", strlen("Trump"));
    printf("Trump: %u - %u\n", val, val % 100);
    val = hash("Cruz", strlen("Cruz"));
    printf("Cruz: %u - %u\n", val, val % 100);
    val = hash("Rubio", strlen("Rubio"));
    printf("Rubio: %u - %u\n", val, val % 100);
    val = hash("Jeb!", strlen("Jeb!"));
    printf("Jeb!: %u - %u\n", val, val % 100);

    FILE        *file = fopen("words.txt", "r"); // use any wordlist there
    char        buf[64];
    char        **arr;
    int         count = 0;
    arr = malloc(100 * sizeof(char *));
    while (count < 100)
    {
        fgets(buf, 64, file);
        buf[strlen(buf) - 1] = '\0';
        val = hash(buf, strlen(buf)) % 100;
        if (arr[val] == NULL)
        {
            arr[val] = strdup(buf);
            count++;
        }
    }
    for (count = 0; count < 100; count++)
    {
        printf("[%d]%s\n", count, arr[count]);
    }
    return 0;
}

uint32_t hash(char * data, size_t length) {
    uint32_t val = 0;
    int i;
    for (i=0; i<length; i++) {
        val += data[i];
        val += (val << 10);
        val ^= (val >> 6);
    }

    val += (val<<3);
    val ^= (val>>11);
    val += (val<<15);
    return val;
}
