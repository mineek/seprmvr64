# seprmvr64
dual-boot iOS 10.3.3-14.x with latest SEP.

## What is this?
This is a tool that will patch the kernel to make the latest SEP "compatible" with lower versions, all SEP related things like passcode, TouchID, FaceID, etc. are broken, and there are other caveats, read below. This is a proof of concept, and I'm sure a lot of these patches are unnecessary, but I'm just publishing what I used to get it working.

## Warning
I am not responsible for any damage caused to anything, use at your own risk, this is not meant to be end-user friendly, and I'm not going to provide support for this.

## Caveats
* Does NOT work on 16 GB devices, because we are dual-booting iOS, and 2 iOS installations take up around 16 GB of space, which makes both iOS installations impossible to use. Unless you're already on iOS 12 for example, which uses lower storage.
* Encrypted WiFi networks will always say "incorrect password" when trying to connect, use a open network.
* TouchID / Passcode / FaceID are all broken, you can't use them.
* You have a NULL passcode, every time you're asked for a passcode, any input should be accepted.
* ~~First boot ( the one with progress bar ) can take upto 1 hour on some versions, subsequent boots are normal.~~ ( this has since been fixed, ymmv )
* For some reason, your mainOS has a VERY high chance of bootlooping, please only use this on a test device you're comfortable losing data off. ( Also, ymmv, it may or may not bootloop. )

## Guide
1. Begin with downloading a IPSW for your desired iOS version, and extract it.
2. Run `asr -source "ipsw/$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."OS"."Info"."Path" xml1 -o - ipsw/BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)" -target out.dmg --embed -erase -noprompt --chunkchecksum --puppetstrings` to create a asr image.
3. Clone [sshrd_script](https://github.com/verygenericname/sshrd_script) and boot into the SSH ramdisk, make sure you create the ssh ramdisk with the version you're currently on.
4. Run `/usr/bin/mount_filesystems` in the SSH ramdisk to mount the filesystems.
5. Create new partitions for dual-booted iOS:
    * `/sbin/newfs_apfs -o role=i -A -v SystemX /dev/disk0s1`
    * `/sbin/newfs_apfs -o role=0 -A -v DataX /dev/disk0s1`

6. Mount the new partitions, you may need to replace disk0s1s8 and disk0s1s9 if you don't have a baseband partition:
    * `/sbin/mount_apfs /dev/disk0s1s8 /mnt8/`
    * `/sbin/mount_apfs /dev/disk0s1s9 /mnt9/`

7. Copy the keybags: `cp -av /mnt2/keybags /mnt9/`
8. On your mac, in another terminal, SCP over the asr image you created earlier: `scp -P2222 -r out.dmg root@localhost:/mnt8/`
9. Reboot your device
    * `/usr/sbin/nvram auto-boot=false`
    * `/sbin/reboot`
10. Boot into the SSH ramdisk again, and run `/System/Library/Filesystems/apfs.fs/apfs_invert -d /dev/disk0s1 -s 8 -n out.dmg` to apply the asr image to the new partition.
11. Mount the filesystems again:
    * `/usr/bin/mount_filesystems`
    * `/sbin/mount_apfs /dev/disk0s1s8 /mnt8/`
    * `/sbin/mount_apfs /dev/disk0s1s9 /mnt9/`
12. Move over `/var` from the rootfs partition to the var partition: `mv -v /mnt8/private/var/* /mnt9/`
13. Copy over preboot: `cp -av /mnt6/$(cat /mnt6/active)/* /mnt8/`
14. Create some folders required for booting:
    * `mkdir -p /mnt8/private/xarts`
    * `mkdir -p /mnt8/private/preboot`
15. Remove AOP firmware: `rm -v /mnt8/usr/standalone/firmware/FUD/AOP.img4`
16. Copy over preboot again: `cp -av /mnt6/* /mnt8/private/preboot/`
17. Replace the factorydata with the factorydata from the main OS:
    * `rm -rv /mnt8/System/Library/Caches/com.apple.factorydata`
    * `/sbin/mount_apfs /dev/disk0s1s5 /mnt5/`
    * `cp -av /mnt5/FactoryData/* /mnt8/`
18. Change fstab to point to the new partition, and change `hfs` to `apfs`: `nano /mnt8/etc/fstab`
19. We're almost done installing! At this point, you'll boot into the Setup screen and are unable to activate, to get SpringBoard you'll need a way to skip Setup, I won't be linking to any of these methods, so figure it out yourself.
20. Finally, reboot:
    * `/usr/sbin/nvram auto-boot=false`
    * `/sbin/reboot`

### Boot files
1. Extract your IM4M file from your shsh blob using `img4tool -e -s blob -m IM4M`
2. Create a img4 from your trustcache and devicetree using:
    * `img4 -i trustcache -o trustcache.img4 -M IM4M -T rtsc`
    * `img4 -i devicetree -o devicetree.img4 -M IM4M -T rdtr`
3. Decrypt your iBSS and iBEC using `gaster decrypt iBSS.im4p iBSS.dec` and `gaster decrypt iBEC.im4p iBEC.dec`
4. Patch your iBSS using `iBoot64Patcher iBSS.dec iBSS.patched`
5. Patch your iBEC, change the `rd=` argument to point to your new partition, and you can replace `serial=3` with `-v` if you don't have a serial cable: `iBoot64Patcher iBEC.dec iBEC.patched -b "rd=disk0s1s8 debug=0x2014e wdt=-1 serial=3"`
6. Create img4s from your patched iBSS and iBEC using:
    * `img4 -i iBSS.patched -o iBSS.img4 -M IM4M -A -T ibss`
    * `img4 -i iBEC.patched -o iBEC.img4 -M IM4M -A -T ibec`
7. Extract your kernelcache using `img4 -i kernelcache -o kcache.raw`
8. Now, use seprmvr64:
    * `gcc seprmvr64/seprmvr64.c -o seprmvr64`
    * `./seprmvr64 kcache.raw kcache.patched -s <ios ver>` i.e. `./seprmvr64 kcache.raw kcache.patched -s 10`
9. Create a kc.bpatch using `kerneldiff kcache.raw kcache.patched kc.bpatch`
10. Create a img4 from your kernelcache using `img4 -i kernelcache -o kernelcache.img4 -M IM4M -T rkrn -P kc.bpatch`

### Booting
1. Use `gaster` to pwn your device:
    * `gaster pwn`
    * `gaster reset`
2. Send over your iBSS and iBEC using `irecovery -f iBSS.img4` and `irecovery -f iBEC.img4`
3. Send over your devicetree using `irecovery -f devicetree.img4`, then use `irecovery -c devicetree` to load it.
4. If you have a trustcache, send it over using `irecovery -f trustcache.img4`, then use `irecovery -c firmware` to load it.
5. Finally, send over your kernelcache using `irecovery -f kernelcache.img4`, then use `irecovery -c bootx` to boot, reminder that first boot with progress bar can take upto 1 hour, so be patient.

### Scripts
I've provided some scripts in the `scripts` folder to help automate the booting and development process.

### Credits
* [Ralph0045](https://github.com/Ralph0045/Kernel64Patcher/blob/master/Kernel64Patcher.c) for the AMFI patch and base of Kernel64Patcher
