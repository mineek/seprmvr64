#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "plooshfinder.h"
#include "plooshfinder32.h"
#include "macho.h"

void *xref_stuff;
void *str_stuff;
void *beg_func;

void *kbuf;
size_t klen;

/*int get_amfi_out_of_my_way_patch(void* kbuf,size_t klen) {
    
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
    printf("%s: Found %s str loc at %p\n",__FUNCTION__,amfiString,GET_OffSET(klen,ent_loc));
    void *ent_ref = pf_follow_xref(kbuf,0,klen,(void *)GET_OffSET(klen, ent_loc));
    if(!ent_ref) {
        printf("%s: Could not find %s xref\n",__FUNCTION__,amfiString);
        return -1;
    }
    printf("%s: Found %s str ref at %p\n",__FUNCTION__,amfiString,(void*)ent_ref);
    void *next_bl = step64(kbuf, ent_ref, 100, INSN_CALL);
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
    void *function = follow_call64(kbuf, next_bl);
    if(!function) {
        printf("%s: Could not find function bl\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Patching AMFI at %p\n",__FUNCTION__,(void*)function);
    *(uint32_t *)(kbuf + function) = 0x320003e0;
    *(uint32_t *)(kbuf + function + 0x4) = 0xD65F03C0;
    return 0;
}

int patch_simple(void* kbuf, size_t klen, char* string, int len) {
    str_stuff = memmem(kbuf, klen, string, len);
    if (!str_stuff)
    {
        printf("[-] Failed to find the patch string\n");
        return -1;
    }
    int done = 0;
    int initial = 0;
    while (!done)
    {
        if (initial == 0)
        {
            xref_stuff = pf_follow_xref(kbuf, 0, klen, (void *)GET_OffSET(klen, str_stuff));
            initial = 1;
        }
        else {
            xref_stuff = pf_follow_xref(kbuf, xref_stuff + 0x4, klen, (void *)GET_OffSET(klen, str_stuff));
        }
        if (!xref_stuff)
        {
            done = 1;
            break;
        }
        *(uint32_t *)(kbuf + xref_stuff) = 0x52800000;
        *(uint32_t *)(kbuf + xref_stuff + 0x4) = 0xD65F03C0;
        printf("[+] Patched at %p\n", (void*)xref_stuff);
    }
    return 0;
}

int patch_sep(void *kbuf, size_t klen)
{
    printf("%s: Starting...\n", __FUNCTION__);

    printf("[*] Patching sks timeout strike\n");
    str_stuff = memmem(kbuf, klen, "AppleKeyStore: sks timeout strike %d", 36);
    if (!str_stuff)
    {
        printf("[-] Failed to find sks timeout strike\n");
        return -1;
    }
    xref_stuff = pf_follow_xref(kbuf, 0, klen, (void *)GET_OffSET(klen, str_stuff));
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
    xref_stuff = pf_follow_xref(kbuf, 0, klen, (void *)GET_OffSET(klen, str_stuff));
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
    xref_stuff = pf_follow_xref(kbuf, 0, klen, (void *)GET_OffSET(klen, str_stuff));
    while (*(uint32_t *)(kbuf + xref_stuff) != 0xD63F0100)
    {
        xref_stuff -= 0x4;
    }
    *(uint32_t *)(kbuf + xref_stuff) = 0xD2800000;
    printf("[+] Patched AppleKeyStore: operation failed\n");

    printf("[*] Patching AppleMesaSEPDriver\n");
    str_stuff = memmem(kbuf, klen, "ERROR: %s: AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d", 66);
    if (!str_stuff)
    {
        str_stuff = memmem(kbuf, klen, "AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d", 55);
        if (!str_stuff)
        {
            printf("[-] Failed to find AppleMesaSEPDriver\n");
            return -1;
        }
    }
    xref_stuff = pf_follow_xref(kbuf, 0, klen, (void *)GET_OffSET(klen, str_stuff));
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
    xref_stuff = pf_follow_xref(kbuf, 0, klen, (void *)GET_OffSET(klen, str_stuff));
    beg_func = bof64(kbuf, 0, xref_stuff);
    *(uint32_t *)(kbuf + beg_func) = 0x52800000;
    *(uint32_t *)(kbuf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched AppleSEP:WARNING: EP0 received unsolicited message\n");

    //SEP/OS failed to boot at stage
    printf("[*] Patching SEP/OS failed to boot at stage\n");
    str_stuff = memmem(kbuf, klen, "\"SEP/OS failed to boot at stage %d\\nFirmware type: %s\"@/BuildRoot/Library/Caches/com.apple.xbs/Sources/AppleSEPManager/AppleSEPManager-302.70.5/AppleSEPManagerARM.cpp:1646", 96);
    if (!str_stuff)
    {
        str_stuff = memmem(kbuf, klen, "\"SEP/OS failed to boot\"@/BuildRoot/Library/Caches/com.apple.xbs/Sources/AppleSEPManager/AppleSEPManager", 92);
        if (!str_stuff)
        {
            printf("[-] Failed to find SEP/OS failed to boot at stage\n");
            return -1;
        }
    }
    xref_stuff = pf_follow_xref(kbuf, 0, klen, (void *)GET_OffSET(klen, str_stuff));
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
    xref_stuff = pf_follow_xref(kbuf, 0, klen, (void *)GET_OffSET(klen, str_stuff));
    beg_func = bof64(kbuf, 0, xref_stuff);
    *(uint32_t *)(kbuf + beg_func) = 0x52800000;
    *(uint32_t *)(kbuf + beg_func + 0x4) = 0xD65F03C0;
    printf("[+] Patched AppleBiometricSensor: RECOVERY\n");
    
    //ERROR: %s: AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d\n\n
    printf("[*] Patching ERROR: AssertMacros\n");
    str_stuff = memmem(kbuf, klen, "ERROR: %s: AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d", 66);
    if (!str_stuff)
    {
        str_stuff = memmem(kbuf, klen, "AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d", 55);
        if (!str_stuff)
        {
            printf("[-] Failed to find ERROR: AssertMacros\n");
            return -1;
        }
    }
    int done = 0;
    while (!done)
    {
        xref_stuff = pf_follow_xref(kbuf, xref_stuff + 1, klen, (void *)GET_OffSET(klen, str_stuff));
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

    ///BuildRoot/Library/Caches/com.apple.xbs/Sources/AppleCredentialManager/AppleCredentialManager-195.70.8/AppleCredentialManager/AppleCredentialManager.cpp
    printf("[*] Patching AppleCredentialManager\n");
    str_stuff = memmem(kbuf, klen, "/BuildRoot/Library/Caches/com.apple.xbs/Sources/AppleCredentialManager/AppleCredentialManager-195/AppleCredentialManager/AppleCredentialManager.cpp", 147);
    if (!str_stuff)
    {
        printf("[-] Failed to find AppleCredentialManager\n");
        return -1;
    }
    done = 0;
    while (!done)
    {
        xref_stuff = pf_follow_xref(kbuf, xref_stuff + 1, klen, (void *)GET_OffSET(klen, str_stuff));
        if (xref_stuff == 0)
        {
            done = 1;
            break;
        }
        beg_func = bof64(kbuf, 0, xref_stuff);
        *(uint32_t *)(kbuf + beg_func) = 0x52800000;
        *(uint32_t *)(kbuf + beg_func + 0x4) = 0xD65F03C0;
        printf("[+] Patched AppleCredentialManager at 0x%llx\n", beg_func);
    }
    printf("[+] Patched AppleCredentialManager\n");

    printf("%s: quitting...\n", __FUNCTION__);

    return 0;
}*/

void *bof64(void *ptr) {
    for (; ptr >= 0; ptr -= 4) {
        uint32_t op = *(uint32_t *) ptr;
        if ((op & 0xffc003ff) == 0x910003FD) {
            unsigned delta = (op >> 10) & 0xfff;
            //printf("%x: ADD X29, SP, #0x%x\n", ptr, delta);
            if ((delta & 0xf) == 0) {
                void *prev = ptr - ((delta >> 4) + 1) * 4;
                uint32_t au = *(uint32_t *)(prev);
                if ((au & 0xffc003e0) == 0xa98003e0) {
                    //printf("%x: STP x, y, [SP,#-imm]!\n", prev);
                    return prev;
                }
                // try something else
                while (ptr > 0) {
                    ptr -= 4;
                    au = *(uint32_t *) ptr;
                    // SUB SP, SP, #imm
                    if ((au & 0xffc003ff) == 0xD10003ff && ((au >> 10) & 0xfff) == delta + 0x10) {
                        return ptr;
                    }
                    // STP x, y, [SP,#imm]
                    if ((au & 0xffc003e0) != 0xa90003e0) {
                        ptr += 4;
                        break;
                    }
                }
            }
        }
    }
    return 0;
}

bool patch_sks(struct pf_patch32_t patch, uint32_t *stream) {
    char *str = pf_follow_xref(kbuf, stream);

    if (strcmp(str, "AppleKeyStore: sks timeout strike %d\n") == 0) {
        uint32_t *begin = bof64(stream);

        begin[0] = 0x52800000;
        begin[1] = ret;

        printf("[+] Patched sks timeout strike at 0x%lx\n", macho_ptr_to_va(kbuf, begin));
        return true;
    } else if (strcmp(str, "AppleKeyStore: operation %s(pid: %d sel: %d ret: %x '%d'%s)\n") == 0) {
        uint32_t *blr = pf_find_prev(stream, 0x1000, 0xd63f0100, 0xffffffff);
        if (!blr) {
            printf("[-] Failed to find blr in AppleKeyStore\n");
            return false;
        }

        blr[0] = 0xd2800000;
        printf("[+] Patched AppleKeyStore: operation failed at 0x%lx\n", macho_ptr_to_va(kbuf, blr));
        return true;
    }

    return false;
}

bool patch_smgr(struct pf_patch32_t patch, uint32_t *stream) {
    char *str = pf_follow_xref(kbuf, stream);

    if (strncmp(str, "\"SEP Panic:", 11) == 0) {
        uint32_t *begin = bof64(stream);

        begin[0] = 0x52800000;
        begin[1] = ret;

        printf("[+] Patched SEP Panicked at 0x%lx\n", macho_ptr_to_va(kbuf, begin));
        return true;
    } else if (strcmp(str, "AppleSEP:WARNING: EP0 received unsolicited message 0x%016llx\n") == 0) {
        uint32_t *begin = bof64(stream);

        begin[0] = 0x52800000;
        begin[1] = ret;

        printf("[+] Patched EP0 received unsolicited message at 0x%lx\n", macho_ptr_to_va(kbuf, begin));
        return true;
    } else if (strncmp(str, "\"SEP/OS failed to boot", 22) == 0) {
        uint32_t *begin = bof64(stream);

        begin[0] = 0x52800000;
        begin[1] = ret;

        printf("[+] Patched SEP/OS failed to boot at 0x%lx\n", macho_ptr_to_va(kbuf, begin));
        return true;
    }

    return false;
}

bool patch_abs(struct pf_patch32_t patch, uint32_t *stream) {
    char *str = pf_follow_xref(kbuf, stream);

    if (strcmp(str, "AppleBiometricSensor: RECOVERY: Reason %d, Last command 0x%x\n") == 0) {
        uint32_t *begin = bof64(stream);

        begin[0] = 0x52800000;
        begin[1] = ret;

        printf("[+] Patched AppleBiometricSensor at 0x%lx\n", macho_ptr_to_va(kbuf, begin));
        return true;
    }

    return false;
}

bool patch_mesa(struct pf_patch32_t patch, uint32_t *stream) {
    char *str = pf_follow_xref(kbuf, stream);

    if ((strcmp(str, "ERROR: %s: AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d\n\n\n") == 0) ||
        (strcmp(str, "AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d\n") == 0)) {
        uint32_t *begin = bof64(stream);

        if (begin[6] == 0xb4000293) {
            printf("[+] Skipping AssertMacros at 0x%lx\n", macho_ptr_to_va(kbuf, begin));

            return false;
        }

        begin[0] = 0x52800000;
        begin[1] = ret;

        printf("[+] Patched AssertMacros at 0x%lx\n", macho_ptr_to_va(kbuf, begin));
        return true;
    }

    return false;
}

bool patch_acm(struct pf_patch32_t patch, uint32_t *stream) {
    char *str = pf_follow_xref(kbuf, stream);

    if (strncmp(str, "/BuildRoot/Library/Caches/com.apple.xbs/Sources/AppleCredentialManager/AppleCredentialManager-", 94) == 0) {
        str += 94;
        while (str[-1] != '/') str++;
        
        if (strcmp(str, "AppleCredentialManager/AppleCredentialManager.cpp") == 0) {
            uint32_t *begin = bof64(stream);

            begin[0] = 0x52800000;
            begin[1] = ret;

            printf("[+] Patched ACM at 0x%lx\n", macho_ptr_to_va(kbuf, begin));
        }
    }

    return false;
}

void patch_sep() {
    struct mach_header_64 *sks_kext = macho_find_kext(kbuf, "com.apple.driver.AppleSEPKeyStore");
    if (!sks_kext) return;
    struct section_64 *sks_text = macho_find_section(sks_kext, "__TEXT_EXEC", "__text");
    if (!sks_text) return;

    void *sks_text_buf = (void *) sks_kext + sks_text->offset;
    uint64_t sks_text_len = sks_text->size;

    uint32_t str_matches[] = {
        0x90000000, // adrp
        0x91000000  // add
    };

    uint32_t str_masks[] = {
        0x9f000000,
        0xff800000
    };

    struct pf_patch32_t sks_patch = pf_construct_patch32(str_matches, str_masks, sizeof(str_matches) / sizeof(uint32_t), (void *) patch_sks);

    struct pf_patch32_t sks_patches[] = {
        sks_patch
    };

    struct pf_patchset32_t sks_patchset = pf_construct_patchset32(sks_patches, sizeof(sks_patches) / sizeof(struct pf_patch32_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit32(sks_text_buf, sks_text_len, sks_patchset);

    struct mach_header_64 *smgr_kext = macho_find_kext(kbuf, "com.apple.driver.AppleSEPManager");
    if (!smgr_kext) return;
    struct section_64 *smgr_text = macho_find_section(smgr_kext, "__TEXT_EXEC", "__text");
    if (!smgr_text) return;

    void *smgr_text_buf = (void *) smgr_kext + smgr_text->offset;
    uint64_t smgr_text_len = smgr_text->size;


    struct pf_patch32_t smgr_patch = pf_construct_patch32(str_matches, str_masks, sizeof(str_matches) / sizeof(uint32_t), (void *) patch_smgr);

    struct pf_patch32_t smgr_patches[] = {
        smgr_patch
    };

    struct pf_patchset32_t smgr_patchset = pf_construct_patchset32(smgr_patches, sizeof(smgr_patches) / sizeof(struct pf_patch32_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit32(smgr_text_buf, smgr_text_len, smgr_patchset);

    struct mach_header_64 *abs_kext = macho_find_kext(kbuf, "com.apple.driver.AppleBiometricSensor");
    if (!abs_kext) return;
    struct section_64 *abs_text = macho_find_section(abs_kext, "__TEXT_EXEC", "__text");
    if (!abs_text) return;

    void *abs_text_buf = (void *) abs_kext + abs_text->offset;
    uint64_t abs_text_len = abs_text->size;


    struct pf_patch32_t abs_patch = pf_construct_patch32(str_matches, str_masks, sizeof(str_matches) / sizeof(uint32_t), (void *) patch_abs);

    struct pf_patch32_t abs_patches[] = {
        abs_patch
    };

    struct pf_patchset32_t abs_patchset = pf_construct_patchset32(abs_patches, sizeof(abs_patches) / sizeof(struct pf_patch32_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit32(abs_text_buf, abs_text_len, abs_patchset);

    struct mach_header_64 *mesa_kext = macho_find_kext(kbuf, "com.apple.driver.AppleMesaSEPDriver");
    if (!mesa_kext) return;
    struct section_64 *mesa_text = macho_find_section(mesa_kext, "__TEXT_EXEC", "__text");
    if (!mesa_text) return;

    void *mesa_text_buf = (void *) mesa_kext + mesa_text->offset;
    uint64_t mesa_text_len = mesa_text->size;


    struct pf_patch32_t mesa_patch = pf_construct_patch32(str_matches, str_masks, sizeof(str_matches) / sizeof(uint32_t), (void *) patch_mesa);

    struct pf_patch32_t mesa_patches[] = {
        mesa_patch
    };

    struct pf_patchset32_t mesa_patchset = pf_construct_patchset32(mesa_patches, sizeof(mesa_patches) / sizeof(struct pf_patch32_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit32(mesa_text_buf, mesa_text_len, mesa_patchset);

    struct mach_header_64 *acm_kext = macho_find_kext(kbuf, "com.apple.driver.AppleSEPCredentialManager");
    if (!acm_kext) return;
    struct section_64 *acm_text = macho_find_section(acm_kext, "__TEXT_EXEC", "__text");
    if (!acm_text) return;

    void *acm_text_buf = (void *) acm_kext + acm_text->offset;
    uint64_t acm_text_len = acm_text->size;


    struct pf_patch32_t acm_patch = pf_construct_patch32(str_matches, str_masks, sizeof(str_matches) / sizeof(uint32_t), (void *) patch_acm);

    struct pf_patch32_t acm_patches[] = {
        acm_patch
    };

    struct pf_patchset32_t acm_patchset = pf_construct_patchset32(acm_patches, sizeof(acm_patches) / sizeof(struct pf_patch32_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit32(acm_text_buf, acm_text_len, acm_patchset);
}

bool patch_amfi_old(struct pf_patch32_t patch, uint32_t *stream) {
    char *str = pf_follow_xref(kbuf, stream);

    if (strcmp(str, "entitlements too small") == 0) {
        uint32_t *tbnz = pf_find_next(stream, 0x64, 0x37000000, 0x7f00001f);
        
        if (!tbnz) {
            printf("[-] AMFI: Unable to find tbnz\n");
            return false;
        } else if (!pf_maskmatch32(tbnz[-1], 0x94000000, 0xfc000000)) {
            printf("[-] AMFI: Not a bl?\n");
            return false;
        }
        
        // now that we're sure we have the right thing, patch it
        uint32_t *check = pf_follow_branch(kbuf, tbnz - 1);

        check[0] = 0x320003e0; // orr w0, wzr, 0x1
        check[1] = ret;


        printf("[+] Patched AMFI at 0x%lx\n", macho_ptr_to_va(kbuf, check));
        return true;
    }

    return false;
}


void patch_amfi() {
    struct nlist_64 *trustcache = macho_find_symbol(kbuf, "_pmap_lookup_in_static_trust_cache");
    if (!trustcache) {
        struct mach_header_64 *amfi_kext = macho_find_kext(kbuf, "com.apple.driver.AppleMobileFileIntegrity");
        if (!amfi_kext) return;
        struct section_64 *amfi_text = macho_find_section(amfi_kext, "__TEXT_EXEC", "__text");
        if (!amfi_text) return;

        void *amfi_text_buf = (void *) amfi_kext + amfi_text->offset;
        uint64_t amfi_text_len = amfi_text->size;

        uint32_t str_matches[] = {
            0x90000000, // adrp
            0x91000000  // add
        };

        uint32_t str_masks[] = {
            0x9f000000,
            0xff800000
        };

        struct pf_patch32_t amfi_patch = pf_construct_patch32(str_matches, str_masks, sizeof(str_matches) / sizeof(uint32_t), (void *) patch_amfi_old);

        struct pf_patch32_t amfi_patches[] = {
            amfi_patch
        };

        struct pf_patchset32_t amfi_patchset = pf_construct_patchset32(amfi_patches, sizeof(amfi_patches) / sizeof(struct pf_patch32_t), (void *) pf_find_maskmatch32);

        pf_patchset_emit32(amfi_text_buf, amfi_text_len, amfi_patchset);

        return;
    }

    uint32_t *trustcache_stream = macho_va_to_ptr(kbuf, trustcache->offset);

    trustcache_stream[0] = 0x320003e0;
    trustcache_stream[1] = ret;
    printf("[+] Patched AMFI at 0x%lx\n", trustcache->offset);
}

int main(int argc, char *argv[])
{
    printf("Starting seprmvr64 by Mineek\n");
    if (argc < 3)
    {
        printf("Usage: kcache.raw kcache.patched [--skip-amfi]\n");
        return 0;
    }

    char *in = argv[1];
    char *out = argv[2];

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

    uint32_t magic = macho_get_magic(kbuf);

    if (!magic) {
        free(kbuf);
        return 1;
    }

    void *orig_dyld_buf = kbuf;
    if (magic == 0xbebafeca) {
        kbuf = macho_find_arch(kbuf, CPU_TYPE_ARM64);
        if (!kbuf) {
            free(kbuf);
            return 1;
        }
    }

    patch_sep();

    if (argc == 4 && !strcmp(argv[3], "--skip-amfi")) {
        printf("[*] Skipping AMFI patch\n");
    } else {
        patch_amfi();
    }

    fp = fopen(out, "wb+");

    fwrite(kbuf, 1, klen, fp);
    fflush(fp);
    fclose(fp);

    free(kbuf);

    printf("[*] Wrote patched file to %s\n", out);

    return 0;
}
