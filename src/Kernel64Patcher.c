/*
* Copyright 2020, @Ralph0045
* gcc Kernel64Patcher.c -o Kernel64Patcher
*/

#if defined(__linux__) || defined(__gnu_linux__)
    #define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "patchfinder64.c"

#define GET_OFFSET(kernel_len, x) (x - (uintptr_t) kernel_buf)

#define LSL0 0
#define LSL16 16
#define LSL32 32

#define _PAGEOFF(x) ((x) & 0xFFFFF000)

#define _ADRP(r, o) (0x90000000 | ((((o) >> 12) & 0x3) << 29) | ((((o) >> 12) & 0x1FFFFC) << 3) | ((r) & 0x1F))
#define _BL(a, o) (0x94000000 | ((((o) - (a)) >> 2) & 0x3FFFFFF))
#define _B(a, o) (0x14000000 | ((((o) - (a)) >> 2) & 0x3FFFFFF))
#define _MOVKX(r, i, s) (0xF2800000 | (((s) & 0x30) << 17) | (((i) & 0xFFFF) << 5) | ((r) & 0x1F))
#define _MOVZX(r, i, s) (0xD2800000 | (((s) & 0x30) << 17) | (((i) & 0xFFFF) << 5) | ((r) & 0x1F))
#define _MOVZW(r, i, s) (0x52800000 | (((s) & 0x30) << 17) | (((i) & 0xFFFF) << 5) | ((r) & 0x1F))
#define _NOP() 0xD503201F

// tested on an ipad 6 on ios 13.7, this was done to avoid wait like 2 or 10 minutes when it is booting
int get__sepTransactResponse_patch_ios13(void* kernel_buf, size_t kernel_len) {
    printf("%s: Entering ...\n",__FUNCTION__);
    void* ent_loc = memmem(kernel_buf, kernel_len, "_sepTransactResponse", 21);
    if(!ent_loc) {
        printf("%s: Could not find \"_sepTransactResponse\" string\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"_sepTransactResponse\" str loc at %p\n",__FUNCTION__,GET_OFFSET(kernel_len,ent_loc));
    addr_t ent_ref = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, ent_loc));
    if(!ent_ref) {
        printf("%s: Could not find \"_sepTransactResponse\" xref\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"_sepTransactResponse\" xref at %p\n",__FUNCTION__,(void*)ent_ref);
    addr_t beg_func = bof64_patchfinder64(kernel_buf, 0, ent_ref);
    if(!beg_func) {
        printf("%s: Could not find \"_sepTransactResponse\" beg_func\n",__FUNCTION__);
        return -1;
    }
    printf("%s: Found \"_sepTransactResponse\" beg_func at %p\n",__FUNCTION__,(void*)beg_func);
    printf("%s: Patching \"_sepTransactResponse\" at %p\n", __FUNCTION__,(void*)(beg_func));
    *(uint32_t *)(kernel_buf + beg_func) = 0x52800000;
    printf("%s: Patching \"_sepTransactResponse\" at %p\n", __FUNCTION__,(void*)(beg_func + 0x4));
    *(uint32_t *)(kernel_buf + beg_func + 0x4) = 0xD65F03C0;
    return 0;
}

int findandpatch(void* kernel_buf, size_t kernel_len, void* string) {
    //printf("klen: %zu\nkbuf: %p\ncurrent str: %s\nsearch term: %s\n", klen, kbuf, (char *)string, (char *)searchstr);
    void* str_stuff = memmem(kernel_buf, kernel_len, string, strlen(string) - 1);
    if (!str_stuff) {
        printf("[-] Failed to find %s string\n", string);
        return -1;
    }
    
    addr_t xref_stuff = xref64(kernel_buf,0,kernel_len,(addr_t)GET_OFFSET(kernel_len, str_stuff));
    addr_t beg_func = bof64_patchfinder64(kernel_buf,0,xref_stuff);

    *(uint32_t *) (kernel_buf + beg_func) = 0x52800000;
    *(uint32_t *) (kernel_buf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched %s\n", string);
    return 0;
}

extern int seprmvr64(int argc, char *argv[], char* ver);

int main(int argc, char **argv) {    
    printf("%s: Starting...\n", __FUNCTION__);
    
    for(int i=0;i<argc;i++) {
        if(strcmp(argv[i], "-s") == 0) {
            printf("Kernel: Adding seprmvr64 patch...\n");
            if (strcmp(argv[i+1], "10") == 0 || strcmp(argv[i+1], "11") == 0 || strcmp(argv[i+1], "12") == 0 || strcmp(argv[i+1], "13") == 0 || strcmp(argv[i+1], "14") == 0) {
                char* oldname = argv[2];
                const char* str1 = oldname;
                const char* str2 = ".seprmvr64";
                char *res;
                res = malloc(strlen(str1) + strlen(str2) + 1);
                if (!res) {
                    fprintf(stderr, "malloc() failed: insufficient memory!\n");
                    return EXIT_FAILURE;
                }
                strcpy(res, str1);
                strcat(res, str2);
                argv[2] = res;
                seprmvr64(argc, argv, argv[i+1]);
                argv[2] = oldname;
                argv[1] = res;
            }
        }
    }

    FILE* fp = NULL;
    
    if(argc < 4){
        printf("Usage: %s <kernel_in> <kernel_out> <args>\n",argv[0]);
        printf("\t-s\t\tPatch seprmvr64 (iOS 7, 8, 9, 10, 11, 12, 13& 14 Only)\n");
        printf("\t-t\t\tPatch _sepTransactResponse (iOS 13 Only)\n");
        return 0;
    }
    
    
    char *filename = argv[1];
    
    fp = fopen(argv[1], "rb");
    if(!fp) {
        printf("%s: Error opening %s!\n", __FUNCTION__, argv[1]);
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    size_t kernel_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    void* kernel_buf = (void*)malloc(kernel_len);
    if(!kernel_buf) {
        printf("%s: Out of memory!\n", __FUNCTION__);
        fclose(fp);
        return -1;
    }
    
    fread(kernel_buf, 1, kernel_len, fp);
    fclose(fp);

    if(memmem(kernel_buf,kernel_len,"KernelCacheBuilder",18)) {
        printf("%s: Detected IMG4/IM4P, you have to unpack and decompress it!\n",__FUNCTION__);
        return -1;
    }
    
    if (*(uint32_t*)kernel_buf == 0xbebafeca) {
        printf("%s: Detected fat macho kernel\n",__FUNCTION__);
        memmove(kernel_buf,kernel_buf+28,kernel_len);
    }

    init_kernel(0, filename);
    
    for(int i=0;i<argc;i++) {
        if(strcmp(argv[i], "-s") == 0) {
            if(strcmp(argv[i+1], "7") == 0) {
                void* strings[] = {
                    "\x1b[35m ***** SEP Panicked! dumping log. *****\x1b[0m",
                    "\"sks request timeout\"",
                    "AppleKeyStore: operation failed (pid: %d sel: %d ret: %x)",
                    "AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d",
                    "AppleSEP:WARNING: EP0 received unsolicited message",
                    //"/SourceCache/AppleCredentialManager/AppleCredentialManager-30/AppleCredentialManager/AppleCredentialManager.cpp",
                    "\"SEP/OS failed to boot\"",
                    "AppleSEP:WARNING: EP0 received unsolicited message 0x%016llx",
                    //"failed to notify system keybag updation %d",
                    //"failed to notify %d",
                    "\"REQUIRE fail: %s @ %s:%u:%s: \"",
                    //"AppleKeyStore starting (BUILT: %s %s)",
                    //"AppleKeyStore:Sending category unlock status with %d",
                    //"AppleKeyStore:Sending lock change %d"
                };
                for(int i = 0; i < sizeof(strings)/sizeof(strings[0]); i++) {
                    if(findandpatch(kernel_buf, kernel_len, strings[i]) != 0) {
                        printf("[-] Failed to patch %s\n", strings[i]);
                    }
                }
            } else if (strcmp(argv[i+1], "8") == 0) {
                void* strings[] = {
                    "\x1b[35m ***** SEP Panicked! dumping log. *****\x1b[0m",
                    "\"sks request timeout\"",
                    "AppleKeyStore: operation failed (pid: %d sel: %d ret: %x)",
                    "AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d",
                    "AppleSEP:WARNING: EP0 received unsolicited message",
                    //"/SourceCache/AppleCredentialManager/AppleCredentialManager-30/AppleCredentialManager/AppleCredentialManager.cpp",
                    "\"SEP/OS failed to boot\"",
                    "AppleSEP:WARNING: EP0 received unsolicited message 0x%016llx",
                    //"failed to notify system keybag updation %d",
                    //"failed to notify %d",
                    "\"REQUIRE fail: %s @ %s:%u:%s: \"",
                    //"AppleKeyStore starting (BUILT: %s %s)",
                    //"AppleKeyStore:Sending category unlock status with %d",
                    //"AppleKeyStore:Sending lock change %d"
                    "\"Content Protection: uninitialized cnode %p\"",
                    "cp_vnode_setclass"
                };
                for(int i = 0; i < sizeof(strings)/sizeof(strings[0]); i++) {
                    if(findandpatch(kernel_buf, kernel_len, strings[i]) != 0) {
                        printf("[-] Failed to patch %s\n", strings[i]);
                    }
                }
            } else if (strcmp(argv[i+1], "9") == 0) {
                void* strings[] = {
                    "\x1b[35m ***** SEP Panicked! dumping log. *****\x1b[0m",
                    "\"sks request timeout\"",
                    "AppleKeyStore: operation failed (pid: %d sel: %d ret: %x)",
                    "AssertMacros: %s (value = 0x%lx), %s file: %s, line: %d",
                    //"AppleSEP:WARNING: EP0 received unsolicited message",
                    //"/SourceCache/AppleCredentialManager/AppleCredentialManager-30/AppleCredentialManager/AppleCredentialManager.cpp",
                    "\"SEP/OS failed to boot\"",
                    //"AppleSEP:WARNING: EP0 received unsolicited message 0x%016llx",
                    //"failed to notify system keybag updation %d",
                    //"failed to notify %d",
                    "\"REQUIRE fail: %s @ %s:%u:%s: \"",
                    //"AppleKeyStore starting (BUILT: %s %s)",
                    //"AppleKeyStore:Sending category unlock status with %d",
                    //"AppleKeyStore:Sending lock change %d"
                    "\"Content Protection: uninitialized cnode %p\"",
                    "cp_vnode_setclass"
                };
                for(int i = 0; i < sizeof(strings)/sizeof(strings[0]); i++) {
                    if(findandpatch(kernel_buf, kernel_len, strings[i]) != 0) {
                        printf("[-] Failed to patch %s\n", strings[i]);
                    }
                }
            } else if (strcmp(argv[i+1], "10") == 0) {
                void* strings[] = {
                    "\"SEP Panic\"",
                    "AppleKeyStore: operation failed (pid: %d sel: %d ret: %x)",
                    "\"Content Protection: uninitialized cnode %p\"",
                    "cp_vnode_setclass"
                };
                for(int i = 0; i < sizeof(strings)/sizeof(strings[0]); i++) {
                    if(findandpatch(kernel_buf, kernel_len, strings[i]) != 0) {
                        printf("[-] Failed to patch %s\n", strings[i]);
                    }
                }
            } else if (strcmp(argv[i+1], "11") == 0) {
                void* strings[] = {
                    "AppleKeyStore: operation %s(pid: %d sel: %d ret: %x '%d'%s)"
                };
                for(int i = 0; i < sizeof(strings)/sizeof(strings[0]); i++) {
                    if(findandpatch(kernel_buf, kernel_len, strings[i]) != 0) {
                        printf("[-] Failed to patch %s\n", strings[i]);
                    }
                }
            } else if (strcmp(argv[i+1], "12") == 0) {
                void* strings[] = {
                    "AppleKeyStore: operation %s(pid: %d sel: %d ret: %x '%d'%s)",
                    "\"Content Protection: uninitialized cnode %p\"",
                    "cp_vnode_setclass"
                };
                for(int i = 0; i < sizeof(strings)/sizeof(strings[0]); i++) {
                    if(findandpatch(kernel_buf, kernel_len, strings[i]) != 0) {
                        printf("[-] Failed to patch %s\n", strings[i]);
                    }
                }
            } else if (strcmp(argv[i+1], "13") == 0) {
                void* strings[] = {
                    "AppleKeyStore: operation %s(pid: %d sel: %d ret: %x '%d'%s)",
                    "\"Content Protection: uninitialized cnode %p\"",
                    "cp_vnode_setclass"
                };
                for(int i = 0; i < sizeof(strings)/sizeof(strings[0]); i++) {
                    if(findandpatch(kernel_buf, kernel_len, strings[i]) != 0) {
                        printf("[-] Failed to patch %s\n", strings[i]);
                    }
                }
            } else if (strcmp(argv[i+1], "14") == 0) {
                void* strings[] = {
                    "%s%s:%s%s%s%s%u:%s%u:%s operation %s(sel: %d ret: %x%s)%s",
                    "%s%s:%s%s%s%s%u:%s%u:%s sks timeout strike %d%s",
                    "\"Content Protection: uninitialized cnode %p\"",
                    "cp_vnode_setclass"
                };
                for(int i = 0; i < sizeof(strings)/sizeof(strings[0]); i++) {
                    if(findandpatch(kernel_buf, kernel_len, strings[i]) != 0) {
                        printf("[-] Failed to patch %s\n", strings[i]);
                    }
                }
            }
        }
        if(strcmp(argv[i], "-t") == 0) {
            printf("Kernel: Adding _sepTransactResponse patch...\n");
            get__sepTransactResponse_patch_ios13(kernel_buf,kernel_len);
        }
    }
    
    term_kernel();
    
    /* Write patched kernel */
    printf("%s: Writing out patched file to %s...\n", __FUNCTION__, argv[2]);
    
    fp = fopen(argv[2], "wb+");
    if(!fp) {
        printf("%s: Unable to open %s!\n", __FUNCTION__, argv[2]);
        free(kernel_buf);
        return -1;
    }
    
    fwrite(kernel_buf, 1, kernel_len, fp);
    fflush(fp);
    fclose(fp);
    
    free(kernel_buf);
    
    printf("%s: Quitting...\n", __FUNCTION__);
    
    return 0;
}