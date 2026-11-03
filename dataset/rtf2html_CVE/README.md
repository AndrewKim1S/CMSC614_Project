
git clone https://github.com/lvu/rtf2html.git
git checkout 4b0e5a3cca2d0c81ee50dcfaa7e3d3dd0a89e59b
cd 
mkir build
cd build
../configure CC="gcc" \         
             CXX="g++" \
             CFLAGS="-g -O0 -fno-pie -Wno-error" \
             LDFLAGS="-no-pie"
make

