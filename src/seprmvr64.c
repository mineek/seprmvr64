#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "plooshfinder.h"
#include "plooshfinder32.h"
#include "formats/macho.h"

void *kbuf;
size_t klen;

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

bool patch_sks(struct pf_patch_t *patch, uint32_t *stream) {
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
    } else if (strncmp(str, "AppleKeyStore: operation failed (pid: %d sel: %d ret: %x \'%d\')", 62) == 0) {
        uint32_t *begin = bof64(stream);

        begin[0] = 0x52800000;
        begin[1] = ret;

        printf("[+] Patched AppleKeyStore: operation failed at 0x%lx\n", macho_ptr_to_va(kbuf, begin));
        return true;
    }
    return false;
}

bool patch_smgr(struct pf_patch_t *patch, uint32_t *stream) {
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

bool patch_abs(struct pf_patch_t *patch, uint32_t *stream) {
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

bool patch_mesa(struct pf_patch_t *patch, uint32_t *stream) {
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

bool patch_acm(struct pf_patch_t *patch, uint32_t *stream) {
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

    struct pf_patch_t sks_patch = pf_construct_patch(str_matches, str_masks, sizeof(str_matches) / sizeof(uint32_t), (void *) patch_sks);

    struct pf_patch_t sks_patches[] = {
        sks_patch
    };

    struct pf_patchset_t sks_patchset = pf_construct_patchset(sks_patches, sizeof(sks_patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(sks_text_buf, sks_text_len, sks_patchset);

    struct mach_header_64 *smgr_kext = macho_find_kext(kbuf, "com.apple.driver.AppleSEPManager");
    if (!smgr_kext) return;
    struct section_64 *smgr_text = macho_find_section(smgr_kext, "__TEXT_EXEC", "__text");
    if (!smgr_text) return;

    void *smgr_text_buf = (void *) smgr_kext + smgr_text->offset;
    uint64_t smgr_text_len = smgr_text->size;


    struct pf_patch_t smgr_patch = pf_construct_patch(str_matches, str_masks, sizeof(str_matches) / sizeof(uint32_t), (void *) patch_smgr);

    struct pf_patch_t smgr_patches[] = {
        smgr_patch
    };

    struct pf_patchset_t smgr_patchset = pf_construct_patchset(smgr_patches, sizeof(smgr_patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(smgr_text_buf, smgr_text_len, smgr_patchset);

    struct mach_header_64 *abs_kext = macho_find_kext(kbuf, "com.apple.driver.AppleBiometricSensor");
    if (!abs_kext) return;
    struct section_64 *abs_text = macho_find_section(abs_kext, "__TEXT_EXEC", "__text");
    if (!abs_text) return;

    void *abs_text_buf = (void *) abs_kext + abs_text->offset;
    uint64_t abs_text_len = abs_text->size;


    struct pf_patch_t abs_patch = pf_construct_patch(str_matches, str_masks, sizeof(str_matches) / sizeof(uint32_t), (void *) patch_abs);

    struct pf_patch_t abs_patches[] = {
        abs_patch
    };

    struct pf_patchset_t abs_patchset = pf_construct_patchset(abs_patches, sizeof(abs_patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(abs_text_buf, abs_text_len, abs_patchset);

    struct mach_header_64 *mesa_kext = macho_find_kext(kbuf, "com.apple.driver.AppleMesaSEPDriver");
    if (!mesa_kext) return;
    struct section_64 *mesa_text = macho_find_section(mesa_kext, "__TEXT_EXEC", "__text");
    if (!mesa_text) return;

    void *mesa_text_buf = (void *) mesa_kext + mesa_text->offset;
    uint64_t mesa_text_len = mesa_text->size;


    struct pf_patch_t mesa_patch = pf_construct_patch(str_matches, str_masks, sizeof(str_matches) / sizeof(uint32_t), (void *) patch_mesa);

    struct pf_patch_t mesa_patches[] = {
        mesa_patch
    };

    struct pf_patchset_t mesa_patchset = pf_construct_patchset(mesa_patches, sizeof(mesa_patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(mesa_text_buf, mesa_text_len, mesa_patchset);

    struct mach_header_64 *acm_kext = macho_find_kext(kbuf, "com.apple.driver.AppleSEPCredentialManager");
    if (!acm_kext) return;
    struct section_64 *acm_text = macho_find_section(acm_kext, "__TEXT_EXEC", "__text");
    if (!acm_text) return;

    void *acm_text_buf = (void *) acm_kext + acm_text->offset;
    uint64_t acm_text_len = acm_text->size;


    struct pf_patch_t acm_patch = pf_construct_patch(str_matches, str_masks, sizeof(str_matches) / sizeof(uint32_t), (void *) patch_acm);

    struct pf_patch_t acm_patches[] = {
        acm_patch
    };

    struct pf_patchset_t acm_patchset = pf_construct_patchset(acm_patches, sizeof(acm_patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(acm_text_buf, acm_text_len, acm_patchset);
}

bool patch_amfi_old(struct pf_patch_t *patch, uint32_t *stream) {
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

        struct pf_patch_t amfi_patch = pf_construct_patch(str_matches, str_masks, sizeof(str_matches) / sizeof(uint32_t), (void *) patch_amfi_old);

        struct pf_patch_t amfi_patches[] = {
            amfi_patch
        };

        struct pf_patchset_t amfi_patchset = pf_construct_patchset(amfi_patches, sizeof(amfi_patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

        pf_patchset_emit(amfi_text_buf, amfi_text_len, amfi_patchset);

        return;
    }

    uint32_t *trustcache_stream = macho_va_to_ptr(kbuf, trustcache->offset);

    trustcache_stream[0] = 0x320003e0; // orr w0, wzr, 0x1
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

    void *orig_kbuf = kbuf;
    if (magic == 0xbebafeca) {
        kbuf = macho_find_arch(kbuf, CPU_TYPE_ARM64);
        if (!kbuf) {
            free(orig_kbuf);
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

    fwrite(orig_kbuf, 1, klen, fp);
    fflush(fp);
    fclose(fp);

    free(orig_kbuf);

    printf("[*] Wrote patched file to %s\n", out);

    return 0;
}
