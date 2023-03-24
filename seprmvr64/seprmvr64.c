#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "patchfinder64.c"

#define GET_OFFSET(klen, x) (x - (uintptr_t)kbuf) // Thanks to @Ralph0045 for this

addr_t xref_stuff;
void *str_stuff;
addr_t beg_func;

int get_amfi_out_of_my_way_patch(void* kbuf,size_t klen) {
    
    printf("%s: Entering ...\n",__FUNCTION__);
    
    void* xnu = memmem(kbuf,klen,"root:xnu-",9);
    int kernel_vers = atoi(xnu+9);
    printf("%s: Kernel-%d inputted\n",__FUNCTION__, kernel_vers);
    char amfiString[33] = "entitlements too small";
    int stringLen = 22;
    if (kernel_vers >= 7938) { // Using "entitlements too small" fails on iOS 15 Kernels
        strncpy(amfiString, "Internal Error: No cdhash found.", 33);
        stringLen = 32;
    }
    void* ent_loc = memmem(kbuf,klen,amfiString,stringLen);
    if(!ent_loc) {
        printf("%s: Could not find %s string\n",__FUNCTION__, amfiString);
        return -1;
    }
    printf("%s: Found %s str loc at %p\n",__FUNCTION__,amfiString,GET_OFFSET(klen,ent_loc));
    addr_t ent_ref = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, ent_loc));
    if(!ent_ref) {
        printf("%s: Could not find %s xref\n",__FUNCTION__,amfiString);
        return -1;
    }
    printf("%s: Found %s str ref at %p\n",__FUNCTION__,amfiString,(void*)ent_ref);
    addr_t next_bl = step64(kbuf, ent_ref, 100, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find next bl\n",__FUNCTION__);
        return -1;
    }
    next_bl = step64(kbuf, next_bl+0x4, 200, INSN_CALL);
    if(!next_bl) {
        printf("%s: Could not find next bl\n",__FUNCTION__);
        return -1;
    }
    if(kernel_vers>3789) { 
        next_bl = step64(kbuf, next_bl+0x4, 200, INSN_CALL);
        if(!next_bl) {
            printf("%s: Could not find next bl\n",__FUNCTION__);
            return -1;
        }
    }
    addr_t function = follow_call64(kbuf, next_bl);
    if(!function) {
        printf("%s: Could not find function bl\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching AMFI at %p\n",__FUNCTION__,(void*)function);
    *(uint32_t *)(kbuf + function) = 0x320003E0;
    *(uint32_t *)(kbuf + function + 0x4) = 0xD65F03C0;
    return 0;
}

int get_funny_patches(void *kbuf, size_t klen)
{
    printf("%s: Starting...\n", __FUNCTION__);

    void* xnu = memmem(kbuf,klen,"root:xnu-",9);
    int kernel_vers = atoi(xnu+9);

    printf("[*] Patching sks timeout strike\n");
    str_stuff = memmem(kbuf, klen, "AppleKeyStore: sks timeout strike %d", 36);
    if (!str_stuff)
    {
        printf("[-] Failed to find sks timeout strike\n");
        return -1;
    }
    xref_stuff = xref64(kbuf, 0, klen, (addr_t)GET_OFFSET(klen, str_stuff));
    beg_func = bof64(kbuf, 0, xref_stuff);
    *(uint32_t *)(kbuf + beg_func) = 0x52800000;
    *(uint32_t *)(kbuf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched sks timeout strike\n");

    //\x1b[35m ***** SEP Panicked! dumping log. *****\x1b[0m
    printf("[*] Patching SEP Panicked\n");
    str_stuff = memmem(kbuf, klen, "\x1b[35m ***** SEP Panicked! dumping log. *****\x1b[0m", 36);
    if (!str_stuff)
    {
        printf("[-] Failed to find SEP Panicked\n");
        return -1;
    }
    xref_stuff = xref64(kbuf, 0, klen, (addr_t)GET_OFFSET(klen, str_stuff));
    beg_func = bof64(kbuf, 0, xref_stuff);
    *(uint32_t *)(kbuf + beg_func) = 0x52800000;
    *(uint32_t *)(kbuf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched SEP Panicked\n");

    printf("[*] Patching AppleKeyStore: operation failed\n");
    str_stuff = memmem(kbuf, klen, "AppleKeyStore: operation %s(pid: %d se", 38);
    if (!str_stuff)
    {
        printf("[-] Failed to find AppleKeyStore: operation failed\n");
        return -1;
    }
    xref_stuff = xref64(kbuf, 0, klen, (addr_t)GET_OFFSET(klen, str_stuff));
    while (*(uint32_t *)(kbuf + xref_stuff) != 0xD63F0100)
    {
        xref_stuff -= 0x4;
    }
    *(uint32_t *)(kbuf + xref_stuff) = 0xD2800000;
    printf("[+] Patched AppleKeyStore: operation failed\n");

    if (kernel_vers == 4903) {
        // did everything needed already for iOS 12
        printf("%s: quitting...\n", __FUNCTION__);
        return 0;
    }

    printf("[*] Patching AppleMesaSEPDriver\n");
    str_stuff = memmem(kbuf, klen, "ERROR: %s: AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d", 66);
    if (!str_stuff)
    {
        printf("[-] Failed to find AppleMesaSEPDriver\n");
        return -1;
    }
    xref_stuff = xref64(kbuf, 0, klen, (addr_t)GET_OFFSET(klen, str_stuff));
    beg_func = bof64(kbuf, 0, xref_stuff);
    *(uint32_t *)(kbuf + beg_func) = 0x52800000;
    *(uint32_t *)(kbuf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched AppleMesaSEPDriver\n");

    //AppleSEP:WARNING: EP0 received unsolicited message
    printf("[*] Patching AppleSEP:WARNING: EP0 received unsolicited message\n");
    str_stuff = memmem(kbuf, klen, "AppleSEP:WARNING: EP0 received unsolicited message", 48);
    if (!str_stuff)
    {
        printf("[-] Failed to find AppleSEP:WARNING: EP0 received unsolicited message\n");
        return -1;
    }
    xref_stuff = xref64(kbuf, 0, klen, (addr_t)GET_OFFSET(klen, str_stuff));
    beg_func = bof64(kbuf, 0, xref_stuff);
    *(uint32_t *)(kbuf + beg_func) = 0x52800000;
    *(uint32_t *)(kbuf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched AppleSEP:WARNING: EP0 received unsolicited message\n");

    //SEP/OS failed to boot at stage
    printf("[*] Patching SEP/OS failed to boot at stage\n");
    str_stuff = memmem(kbuf, klen, "\"SEP/OS failed to boot at stage %d\\nFirmware type: %s\"@/BuildRoot/Library/Caches/com.apple.xbs/Sources/AppleSEPManager", 96);
    if (!str_stuff)
    {
        printf("[-] Failed to find SEP/OS failed to boot at stage\n");
        return -1;
    }
    xref_stuff = xref64(kbuf, 0, klen, (addr_t)GET_OFFSET(klen, str_stuff));
    beg_func = bof64(kbuf, 0, xref_stuff);
    *(uint32_t *)(kbuf + beg_func) = 0x52800000;
    *(uint32_t *)(kbuf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched SEP/OS failed to boot at stage\n");

    //AppleBiometricSensor: RECOVERY: Reason %d, Last command 0x%x
    printf("[*] Patching AppleBiometricSensor: RECOVERY\n");
    str_stuff = memmem(kbuf, klen, "AppleBiometricSensor: RECOVERY: Reason %d, Last command 0x%x", 57);
    if (!str_stuff)
    {
        printf("[-] Failed to find AppleBiometricSensor: RECOVERY\n");
        return -1;
    }
    xref_stuff = xref64(kbuf, 0, klen, (addr_t)GET_OFFSET(klen, str_stuff));
    beg_func = bof64(kbuf, 0, xref_stuff);
    *(uint32_t *)(kbuf + beg_func) = 0x52800000;
    *(uint32_t *)(kbuf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched AppleBiometricSensor: RECOVERY\n");

    //ERROR: %s: _sensorErrorCounter:%u --> reset\n
    printf("[*] Patching _sensorErrorCounter: --> reset\n");
    str_stuff = memmem(kbuf, klen, "ERROR: %s: _sensorErrorCounter:%u --> reset\\n", 41);
    if (!str_stuff)
    {
        printf("[-] Failed to find _sensorErrorCounter: --> reset\n");
        return -1;
    }
    xref_stuff = xref64(kbuf, 0, klen, (addr_t)GET_OFFSET(klen, str_stuff));
    beg_func = bof64(kbuf, 0, xref_stuff);
    *(uint32_t *)(kbuf + beg_func) = 0x52800000;
    *(uint32_t *)(kbuf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched _sensorErrorCounter: --> reset\n");
    
    //ERROR: %s: AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d\n\n
    printf("[*] Patching ERROR: AssertMacros\n");
    str_stuff = memmem(kbuf, klen, "ERROR: %s: AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d", 66);
    if (!str_stuff)
    {
        printf("[-] Failed to find ERROR: AssertMacros\n");
        return -1;
    }
    int done = 0;
    while (!done)
    {
        xref_stuff = xref64(kbuf, xref_stuff + 1, klen, (addr_t)GET_OFFSET(klen, str_stuff));
        if (xref_stuff == 0)
        {
            done = 1;
            break;
        }
        beg_func = bof64(kbuf, 0, xref_stuff);
        if (*(uint32_t *)(kbuf + beg_func + 0x18) == 0xb4000293)
        {
            printf("[+] Skipped ERROR: AssertMacros at 0x%llx\n", beg_func);
            continue;
        }
        *(uint32_t *)(kbuf + beg_func) = 0x52800000;
        *(uint32_t *)(kbuf + beg_func + 0x4) = 0xD65F03C0;
        printf("[+] Patched ERROR: AssertMacros at 0x%llx\n", beg_func);
    }
    printf("[+] Patched ERROR: AssertMacros\n");

    printf("%s: quitting...\n", __FUNCTION__);

    return 0;
}

int main(int argc, char *argv[])
{

    if (argc < 3)
    {
        printf("seprmvr64\n");
        printf("by mineek\n");
        printf("Usage: kcache.raw kcache.patched [--skip-amfi]\n");
        return 0;
    }

    printf("%s: Starting...\n", __FUNCTION__);

    char *in = argv[1];
    char *out = argv[2];

    void *kbuf;
    size_t klen;

    FILE *fp = fopen(in, "rb");
    if (!fp)
    {
        printf("[-] Failed to open kernel\n");
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    klen = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    kbuf = (void *)malloc(klen);
    if (!kbuf)
    {
        printf("[-] Out of memory\n");
        fclose(fp);
        return -1;
    }

    fread(kbuf, 1, klen, fp);
    fclose(fp);

    // CREDITS: https://github.com/Ralph0045/Kernel64Patcher/blob/master/Kernel64Patcher.c
    if (argc == 4 && !strcmp(argv[3], "--skip-amfi"))
    {
        printf("[*] Skipping AMFI patch\n");
    }
    else
    {
        printf("[*] Patching AMFI\n");
        get_amfi_out_of_my_way_patch(kbuf, klen);
        printf("[+] Patched AMFI\n");
    }

    get_funny_patches(kbuf, klen);

    fp = fopen(out, "wb+");

    fwrite(kbuf, 1, klen, fp);
    fflush(fp);
    fclose(fp);

    free(kbuf);

    printf("[*] Writing out patched file to %s\n", out);

    printf("%s: Quitting...\n", __FUNCTION__);

    return 0;
}
