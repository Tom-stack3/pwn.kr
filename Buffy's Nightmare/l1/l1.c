#include <stdio.h>

int main() {
    int are_you_winning = 0;
    int index = 0;
    int value = 0;
    int array[10] = {0};
    while (are_you_winning != 1) {
        printf("Index: ");
        scanf("%d", &index);
        printf("Value: ");
        scanf("%d", &value);
        array[index] = value;
        printf("Array[%d] = %d\n", index, array[index]);
        printf("Are you winning son? %d\n", are_you_winning);
    }
    printf("You won!\n");
}
