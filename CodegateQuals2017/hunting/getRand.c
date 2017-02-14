#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int     main(void)
{
    int i;
    srand(time(NULL) - 1);
    for (i = 0; i < 1000; i++)
        printf("%d\n", rand());
    return 0;
}
