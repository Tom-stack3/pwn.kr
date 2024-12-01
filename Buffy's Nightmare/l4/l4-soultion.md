# [Buffy's Nightmare] - Level 4 - Writeup

## Problem

Same as before with a little change. We are not allowed to overwrite `secret_int` anymore.

## Solution

We need to cause the equation `guess == secret_int` to be true. This time, without the ability to change the value of `secret_int`. Which means we need to get the value of `secret_int`, in order to make the right guess.

How can we do this? We have the regular out-of-bounds write, but this time what we want is a relative-read, and not write. How can we leverage the write to read the value of `secret_int`? Think about it, and try to get creative :wink:


Spoilers ahead! :warning: :warning: :warning:

Ok, let's think aboout it. Where we can get the read from memory we want? The only place might be interesting to us is the line:
```c
printf("Array[%d] = %d\n", index, array[index]);
```

What if we make `array[index]` point to `secret_int`?

If we try it the naive way like we did before (`index = 13`), we'll get the error message saying we are not allowed to overwrite `secret_int`.

But we can be more creative!

Spoilers ahead! :warning: :warning: :warning:

How about we overwrite the index itself? :exploding_head: :exploding_head:

We can overwrite `index` with the value of the index we want to read from memory. This way, we can read the value of `secret_int`. Confused? Let's see it in action:

Input:
```bash
Index: 11 # Out-of-bounds write to overwrite index itself
```

Now, `index` is 11. Which means that `array[index]` is `array[11]`, which points to `index` itself.
The next thing that will happen is that we'll be able to choose `value`. After that, the program will run:

```c
array[index] = value; // Set array[index] to value
```

Because we've said that `array[11]` is `index`, the above line will set `index` to `value`. So in reality, we are able to set `index` to the new value we'll input. Why is this useful? Because the thing after that is:

```c
printf("Array[%d] = %d\n", index, array[index]); // Print value of array[index] and index
```

So, we control the value of `index`, which means we control where `array[index]` points to! This is what's read from memory and printed to us. So, we can make `array[index]` point to `secret_int` and read its value!

To do that, we want to set `index` to 13, so that `array[index]` points to `secret_int`. Let's see it in action:

```bash
Value: 13 # New value for index, which will point array[index] to secret_int (array[13] = secret_int)
```

Now, `array[13]` which is `secret_int` will be printed to us. We can then guess the value of `secret_int` and win the challenge!

```bash
Array[13] = <secret_int will be printed>
Guess the secret: <secret_int> # We win!
```

Shortly:

```bash
Index: 11
Value: 13
Array[13] = <secret_int>
Guess the secret: <secret_int>
```
