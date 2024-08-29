# seprmvr64 ( v2 method )
downgrade to older iOS versions with latest SEP on 64 bit checkm8 iOS devices

## Warning
I am not responsible for any damage caused to anything, use at your own risk, this is not meant to be end-user friendly, and I'm not going to provide support for this.

## Compatibility
iPhone 6s, iPhone 7 and iPhone X have been tested and work, if you have a different device, you might need to do some modifications.

## Caveats
* Encrypted WiFi networks will always say "incorrect password" when trying to connect, use a open network.
* TouchID / Passcode / FaceID are all broken, you can't use them.
* You have a NULL passcode, every time you're asked for a passcode, any input should be accepted.

## Guide
This guide will be split into 3 parts, first we should backup some files, then we need to restore the device, the last part is to make it bootable.

### Part 0: Preparation work.
1. To make Finder on macOS temporarily shut up about iOS devices, you can run this.
 - `killall -STOP AMPDevicesAgent AMPDeviceDiscoveryAgent MobileDeviceUpdater`
 - To revert: `killall -CONT AMPDevicesAgent AMPDeviceDiscoveryAgent MobileDeviceUpdater`
 - This is not necessary, but it can be useful.
2. Restore the device to latest, and then enter a SSH ramdisk.
3. Back-up the `/mnt6/active/usr/standalone/firmware/sep-firmware.img4` file.
4. Reboot out of the ssh ramdisk, and proceed to the next part.

### Part 1: Restoring the device
1. Begin with downloading a IPSW for your desired iOS version, and extract it.
2. Create a folder named `ipswcfw` or something similar, and re-extract the IPSW into that folder. So you now have 2 folders, `ipsw` and `ipswcfw`.
3. Look in the `BuildManifest.plist` for the RestoreRamdisk path, then run `img4 -i ipsw/<...>.dmg -o ramdisk.dmg`
4. Open restored_external in any disassembler you're comfortable with, and now we have to do a few patches.
 - The first is to force _ramrod_device_has_sep to return 0.
 - The second is to force _ramrod_device_has_baseband to return 0.
   - If you're going to iOS 10 or earlier, you can also just modify the restore options plist instead of this patch.
 - The third is to force fdr step to always succeed.
   - so first find the xref to "RestoredFDRRecover", then go into the function.
   - At the end, just make it return 0, but don't impact any other functionality.
5. Resign restored_external with ldid, make sure to keep the entitlements, and copy it back.
6. Now patch asr with [asr64_patcher](https://github.com/exploit3dguy/asr64_patcher), resign it, and copy it back.
7. Now we need to patch the devicetree, so extract the raw payload using img4. (`img4 -i ipsw/Firmware/all_flash/... -o dtree.raw`)
8. Open it in any hex editor and then find the string `content-protect` and change it to any other string, as long as it's the same length.
9. Wrap the dtree.raw back into a im4p ( fourcc = `dtre` ), and copy it back in the ipswcfw folder to its original location.
10. Extract the kernel, and patch it with KPlooshFinder and Kernel64Patcher, they can both be found in Semaphorin's binaries.
 - KPlooshFinder has the arguments: kcache.raw kcache.patched
 - For Kernel64Patcher you should find the arguments for your desired version and device combination in Semaphorin's source.
11. Use kerneldiff to create a diff file
 - `kerneldiff kcache.raw kcache.patched2 kc.bpatch`
12. Wrap the kernel back into a im4p
 - `img4 -i ./ipsw/kernelcache.release.iphone9 -o kernelcache.im4p -T rkrn -P kc.bpatch`
13. Now make the restore ramdisk into a im4p.
 - `img4 -i ./ramdisk.dmg -o ramdisk.im4p -A -T rdsk`
14. Rebuild a ipsw from our ipswcfw folder.
 - `zip -0 -r ../ipswcfw.ipsw *` - Assuming you're in the ipswcfw folder.
15. Now you can restore the device with futurerestore, blobs don't matter.
 - `futurerestore -t shsh.shsh2 --use-pwndfu --skip-blob --serial --rdsk ramdisk.im4p --rkrn kernelcache.im4p --latest-sep --latest-baseband ./ipswcfw.ipsw`

### Part 2: Making the device bootable
1. After futurerestore has finished, you will be stuck in DFU, but because this DFU is entered a different way, we should reboot into DFU with the button combination first to be able to exploit it with gaster.
 - Use the key combination for your device
 - This part might be a bit tricky on certain devices, but you should be able to do it with the right timing and some trial and error.
2. Now boot a ssh ramdisk made with your new version.
3. Once in the ramdisk, rename the snapshot if restored to iOS 11.3(?)+
 - `/usr/bin/snaputil -n $(/usr/bin/snaputil -l /mnt1) orig-fs /mnt1`
 - You can safely skip this step on iOS 10-.
4. Restore the sep-firmware we backed up.
 - `scp -P2222 -r sep-firmware.img4 root@localhost:/mnt1/usr/standalone/firmware/sep-firmware.img4`
5. Now from here on, you can choose how much you want to mess with the file system.
 - If you want a more useable system, follow what Semaphorin does to the file system.
 - If you want it to be vanilla, you can just reboot out of the ramdisk.
 - Note that the device will be stuck on Setup.app, to combat this you can either restore activation tickets like Semaphorin does or bypass it in some way, which I won't get into.
6. Reboot out of the ramdisk, and create boot files.
 - Again, I'm not gonna explain this again, you can follow what Semaphorin does or just do it yourself.
7. If everything went well, you should be able to boot your desired iOS version.
