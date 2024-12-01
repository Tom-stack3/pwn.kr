# [Buffy's Nightmare] - Level 2 - Writeup

## Problem

Pretty similar to Level 1, we have a program that asks for an index and a value. The program writes the value to the array at the given index. The program then prints the value at the index and the value of `secret_int` which is a random int from `/dev/urandom`. The program continues to ask for an index and a value until `secret_int` is 0.

## Solution

Again, we need to exit the infinite loop to win. We still have the same out-of-bounds write primitive, just that this time we change a random value instead of a fixed value. It doesn't matter to us though.

To solve this challenge, we'll give the program the following input:

```bash
Index: 12 # Out-of-bounds write to overwrite secret_int
Value: 0
```

Shortly:

```bash
echo -e "12\n0" | ./l2.out
```
