# [Buffy's Nightmare] - Level 3 - Writeup

## Problem

Here we don't have an infinite loop anymore. The program reads a random value from `/dev/urandom` and stores it in `secret_int`. The program then asks for an index and a value. The program writes the value to the array at the given index. Then we are asked for a guess. If the guess is equal to `secret_int`, we win the challange, otherwise we lose.

## Solution

We need to cause the equation `guess == secret_int` to be true. Think about how we can do this without knowing the value of `secret_int`.

We can try and guess the randomness of the value read from `/dev/urandom`. But we'll need to be very lucky to guess the correct value. (Or brute force it, or play with the randomness of `/dev/urandom`, but I'll leave that to you.)

We can acheive what we want by changing the value of `secret_int` in memory!
Again, we have an out-of-bounds write in the array `array`. We can write to any index in the array, including indexes greater than 9. We can use this to change the value of `secret_int`!

```bash
Index: 13 # Out-of-bounds write to overwrite secret_int
Value: 100 # New value for secret_int
Guess the secret: 100 # We win!
```

Shortly:

```bash
echo -e "13\n100\n100" | ./l3.out
```
