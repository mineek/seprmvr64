rm kernelcache.img4 kcache.patched kc.bpatch ../../seprmvr64/seprmvr64 || true
gcc ../../seprmvr64/seprmvr64.c -o ../../seprmvr64/seprmvr64
../../seprmvr64/seprmvr64 kcache.raw kcache.patched
kerneldiff kcache.raw kcache.patched kc.bpatch
img4 -i ../ipsw/kernelcache.release.n71 -o kernelcache.img4 -M IM4M -T rkrn -P kc.bpatch
