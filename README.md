

All these binaries were tested with the following
```
AFL_SKIP_CPUFREQ=1 ./afl_fuzz.sh
```

CVE-2017-12067 mkbitmap
The afl-clang-fast binary is under afl/ directory. Confirmed CVE still triggers under new compiler
```
Original compile instructions 
CC="<path to afl-clang-fast>" ../configure \ CFLAGS="-g -O0 -fno-pie -fno-omit-frame-pointer -fsanitize=address" \ LDFLAGS="-no-pie -fsanitize=address"
make
```

CVE-2017-11654 sipdump
```
Original compile instructions 
make CC=<path to afl-clang-fast>
```

CVE-2022-44081 pngdetail
```
Original compile instructions 
make pngdetail CXX=<path to afl-clang-fast++>
```

CVE-2026-3389 sq
```
Original compile instructions 
AFLCXX="/home/sheehyun/dev/umd/CMSC614_Project/AFLplusplus/afl-clang-fast++"
sed -i "s|g++|$AFLCXX|g" sq/Makefile
make CC="$AFLCXX" CC_EXTRA_FLAGS="-O0 -g"
```

CVE-2021-46023 mruby
```
Original compile instructions 
make CC=<path to afl-clang-fast>
```

