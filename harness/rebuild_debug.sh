#!/bin/bash
# Rebuild the two dataset binaries that shipped fully stripped, keeping their
# README build flags but not stripping, so white-box tools get symbols/DWARF.
# Output: rebuilt/<entry>/ = the dataset entry (PoC, README) + the new binary.
# Runs inside build.sif:
#   srun -p mc2 --account=mc2 --qos=default -c 4 --mem=8G -t 00:30:00 apptainer exec \
#       --containall --cleanenv --bind $PWD:/work --pwd /work \
#       /fs/nexus-scratch/$USER/cmsc614/images/build.sif bash harness/rebuild_debug.sh [variant]
# variant (mujs only): o2 (default: the release build the dataset binary came
# from, plus -g) or o0 (the README's stated intent, -g -O0)
#
# Faithfulness check: strip a copy of each rebuilt binary and compare its size
# with the dataset binary (printed at the end).
set -euo pipefail
VARIANT=${1:-o2}
B=/tmp/rebuild
rm -rf "$B" && mkdir -p "$B"

stage() {   # entry binary built_path
    local entry=$1 bin=$2 built=$3
    rm -rf "rebuilt/$entry" && mkdir -p "rebuilt/$entry"
    find "dataset/$entry" -maxdepth 1 -type f ! -name "$bin" -exec cp {} "rebuilt/$entry/" \;
    cp "$built" "rebuilt/$entry/$bin"
    file "rebuilt/$entry/$bin" | sed 's/, BuildID[^,]*//'
}

# --- sam2p (CVE-2020-19491): follow the README (prepend its flags; the
# Makefile runs ./configure --enable-gif --enable-lzw itself). The configure
# output overrides the prepended CXXFLAGS, so the effective build is the
# default -O2 with -s; keep -O2 but replace -s with -g.
cp -r sources/CVE-2020-19491 "$B/sam2p"
cd "$B/sam2p"
printf 'CFLAGS = -g -O0 -no-pie\nCXXFLAGS = -g -O0 -no-pie\nLDFLAGS = -no-pie\n' | cat - Makefile > Makefile.new
mv Makefile.new Makefile
sed -i 's/^LDALL=$(LDXX) -s /LDALL=$(LDXX) /; s/^\(CXD_[a-z]* *=$(CXX)\) -s /\1 -g /' Makefile
make sam2p >/tmp/sam2p.build.log 2>&1 || { tail -30 /tmp/sam2p.build.log; exit 1; }
grep -m1 -E "^g\+\+.* -c appliers.cpp" /tmp/sam2p.build.log || true
cd /work
stage CVE-2020-19491 sam2p "$B/sam2p/sam2p"
printf 'Rebuilt with symbols by harness/rebuild_debug.sh: README steps, gcc-14, effective flags\n-O2 -g -no-pie (the dataset binary: -O2 -s, i.e. the same build but stripped).\n' \
    > rebuilt/CVE-2020-19491/REBUILT.md

# --- mujs-pp (CVE-2022-30975): the dataset binary looks like the default
# release build (-O2, -Wl,-s). o0 = README intent; o2 = release optimization
# with debug info. Command-line LDFLAGS overrides the Makefile's -Wl,-s.
cp -r sources/CVE-2022-30975 "$B/mujs"
cd "$B/mujs"
if [ "$VARIANT" = o2 ]; then
    make build=release XCFLAGS="-g -no-pie" LDFLAGS="-no-pie" CC=gcc-14 build/release/mujs-pp \
        >/tmp/mujs.build.log 2>&1 || { tail -30 /tmp/mujs.build.log; exit 1; }
    built=build/release/mujs-pp; flags="-O2 -g -no-pie (release optimization, not stripped)"
else
    make build=debug XCFLAGS="-O0 -no-pie" LDFLAGS="-no-pie" CC=gcc-14 build/debug/mujs-pp \
        >/tmp/mujs.build.log 2>&1 || { tail -30 /tmp/mujs.build.log; exit 1; }
    built=build/debug/mujs-pp; flags="-g -O0 -no-pie (README intent)"
fi
cd /work
stage CVE-2022-30975 mujs-pp "$B/mujs/$built"
printf 'Rebuilt with symbols by harness/rebuild_debug.sh: %s, gcc-14.\nThe dataset binary was a stripped release build.\n' "$flags" \
    > rebuilt/CVE-2022-30975/REBUILT.md

echo "--- faithfulness: stripped size of the rebuild vs the dataset binary"
for eb in CVE-2020-19491/sam2p CVE-2022-30975/mujs-pp; do
    strip -o "$B/stripped" "rebuilt/$eb"
    echo "$eb: rebuilt+stripped $(stat -c %s "$B/stripped") B, dataset $(stat -c %s "dataset/$eb") B"
done
