

wget https://sourceforge.net/projects/lame/files/lame/3.99/lame-3.99.5.tar.gz
tar -xf lame-3.99.5.tar.gz
cd lame-3.99.5
mkdir build
cd build
../configure CC="gcc" \                      
             CXX="g++" \
             CFLAGS="-g -O0 -fno-pie -fsanitize=address" \
             LDFLAGS="-no-pie"

Add to get_audio.c:1178
```
if (samples_to_read > 2304 || samples_to_read < 0) {
    printf("[*] Condition for CVE\n");
    abort(); 
}
```

./lame -f -V 9 POC
