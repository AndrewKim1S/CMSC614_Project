
Compile
Download optipng https://sourceforge.net/projects/optipng/files/OptiPNG/optipng-0.7.5/
export CFLAGS="-g -O0 -fno-pie -fsanitize=address"
export LDFLAGS="-no-pie -fsanitize=address"
./configure
make - this might require make clean, make and then make again...?

Add this to gifread.c:372
```
if (last_byte == 0) {
    printf("[*] Conditions for HEAP buffer overflow met\n");
    abort();
}
```

Run
```
./optipng POC
```

