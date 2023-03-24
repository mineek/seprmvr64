gaster pwn && gaster reset
irecovery -f iBSS.img4
irecovery -f iBEC.img4
irecovery -f devicetree.img4
irecovery -c devicetree
if [ -f "trustcache.img4" ]; then
    irecovery -f trustcache.img4
    irecovery -c firmware
fi
irecovery -f kernelcache.img4
irecovery -c bootx
