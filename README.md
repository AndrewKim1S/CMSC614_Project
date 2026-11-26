

CVE-2017-12067 mkbitmap
The afl-clang-fast binary is under afl/ directory. Confirmed CVE still triggers under new compiler
```
git clone https://github.com/skyrpex/potrace.git
cd potrace
git checkout b3fce824046abcc0465deb5596d4556b132c77aa
autoreconf -fi
mkdir build
cd build
CC="<path to afl-clang-fast>" ../configure \ CFLAGS="-g -O0 -fno-pie -fno-omit-frame-pointer -fsanitize=address" \ LDFLAGS="-no-pie -fsanitize=address"
make
```

- sipdump
- pngdetail
- sq
- mruby

