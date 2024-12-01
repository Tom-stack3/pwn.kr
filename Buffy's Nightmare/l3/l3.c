#include <stdio.h>

int get_secret_int() {
    // Read random value from /dev/urandom
    FILE *f = fopen("/dev/urandom", "r");
    int secret_int;
    fread(&secret_int, sizeof(secret_int), 1, f);
    fclose(f);
    return secret_int;
}

int main() {
    int secret_int = get_secret_int();
    int guess = 0;
    int index = 0;
    int value = 0;
    int array[10] = {0};

    printf("Index: ");
    scanf("%d", &index);
    printf("Value: ");
    scanf("%d", &value);
    array[index] = value;
    printf("Array[%d] = %d\n", index, array[index]);
    printf("Guess the secret: ");
    scanf("%d", &guess);
    if (guess == secret_int) {
        printf("You won!\n");
    }
    else {
        printf("You lost!\n");
    }
}
