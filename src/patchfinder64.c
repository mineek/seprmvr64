//
//  patchfinder64.c
//  extra_recipe
//
//  Created by xerub on 06/06/2017.
//  Copyright © 2017 xerub. All rights reserved.
//

#if defined(__linux__) || defined(__gnu_linux__)
    #define _GNU_SOURCE
#endif

#include <assert.h>
#include <stdint.h>
#include <string.h>

typedef unsigned long long addr_t;

#define IS64(image) (*(uint8_t *)(image) & 1)

#define MACHO(p) ((*(unsigned int *)(p) & ~1) == 0xfeedface)

/* generic stuff *************************************************************/

#define UCHAR_MAX 255

static unsigned char *
boyermoore_horspool_memmem(const unsigned char* haystack, size_t hlen,
                           const unsigned char* needle,   size_t nlen)
{
    size_t last, scan = 0;
    size_t bad_char_skip[UCHAR_MAX + 1]; /* Officially called:
                                          * bad character shift */

    /* Sanity checks on the parameters */
    if (nlen <= 0 || !haystack || !needle)
        return NULL;

    /* ---- Preprocess ---- */
    /* Initialize the table to default value */
    /* When a character is encountered that does not occur
     * in the needle, we can safely skip ahead for the whole
     * length of the needle.
     */
    for (scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
        bad_char_skip[scan] = nlen;

    /* C arrays have the first byte at [0], therefore:
     * [nlen - 1] is the last byte of the array. */
    last = nlen - 1;

    /* Then populate it with the analysis of the needle */
    for (scan = 0; scan < last; scan = scan + 1)
        bad_char_skip[needle[scan]] = last - scan;

    /* ---- Do the matching ---- */

    /* Search the haystack, while the needle can still be within it. */
    while (hlen >= nlen)
    {
        /* scan from the end of the needle */
        for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
            if (scan == 0) /* If the first byte matches, we've found it. */
                return (void *)haystack;

        /* otherwise, we need to skip some bytes and start again.
           Note that here we are getting the skip value based on the last byte
           of needle, no matter where we didn't match. So if needle is: "abcd"
           then we are skipping based on 'd' and that value will be 4, and
           for "abcdd" we again skip on 'd' but the value will be only 1.
           The alternative of pretending that the mismatched character was
           the last character is slower in the normal case (E.g. finding
           "abcd" in "...azcd..." gives 4 by using 'd' but only
           4-2==2 using 'z'. */
        hlen     -= bad_char_skip[haystack[last]];
        haystack += bad_char_skip[haystack[last]];
    }

    return NULL;
}

/* disassembler **************************************************************/

static int HighestSetBit(int N, uint32_t imm)
{
	int i;
	for (i = N - 1; i >= 0; i--) {
		if (imm & (1 << i)) {
			return i;
		}
	}
	return -1;
}

static uint64_t ZeroExtendOnes(unsigned M, unsigned N)	// zero extend M ones to N width
{
	(void)N;
	return ((uint64_t)1 << M) - 1;
}

static uint64_t RORZeroExtendOnes(unsigned M, unsigned N, unsigned R)
{
	uint64_t val = ZeroExtendOnes(M, N);
	if (R == 0) {
		return val;
	}
	return ((val >> R) & (((uint64_t)1 << (N - R)) - 1)) | ((val & (((uint64_t)1 << R) - 1)) << (N - R));
}

static uint64_t Replicate(uint64_t val, unsigned bits)
{
	uint64_t ret = val;
	unsigned shift;
	for (shift = bits; shift < 64; shift += bits) {	// XXX actually, it is either 32 or 64
		ret |= (val << shift);
	}
	return ret;
}

static int DecodeBitMasks(unsigned immN, unsigned imms, unsigned immr, int immediate, uint64_t *newval)
{
	unsigned levels, S, R, esize;
	int len = HighestSetBit(7, (immN << 6) | (~imms & 0x3F));
	if (len < 1) {
		return -1;
	}
	levels = ZeroExtendOnes(len, 6);
	if (immediate && (imms & levels) == levels) {
		return -1;
	}
	S = imms & levels;
	R = immr & levels;
	esize = 1 << len;
	*newval = Replicate(RORZeroExtendOnes(S + 1, esize, R), esize);
	return 0;
}

static int DecodeMov(uint32_t opcode, uint64_t total, int first, uint64_t *newval)
{
	unsigned o = (opcode >> 29) & 3;
	unsigned k = (opcode >> 23) & 0x3F;
	unsigned rn, rd;
	uint64_t i;

	if (k == 0x24 && o == 1) {			// MOV (bitmask imm) <=> ORR (immediate)
		unsigned s = (opcode >> 31) & 1;
		unsigned N = (opcode >> 22) & 1;
		if (s == 0 && N != 0) {
			return -1;
		}
		rn = (opcode >> 5) & 0x1F;
		if (rn == 31) {
			unsigned imms = (opcode >> 10) & 0x3F;
			unsigned immr = (opcode >> 16) & 0x3F;
			return DecodeBitMasks(N, imms, immr, 1, newval);
		}
	} else if (k == 0x25) {				// MOVN/MOVZ/MOVK
		unsigned s = (opcode >> 31) & 1;
		unsigned h = (opcode >> 21) & 3;
		if (s == 0 && h > 1) {
			return -1;
		}
		i = (opcode >> 5) & 0xFFFF;
		h *= 16;
		i <<= h;
		if (o == 0) {				// MOVN
			*newval = ~i;
			return 0;
		} else if (o == 2) {			// MOVZ
			*newval = i;
			return 0;
		} else if (o == 3 && !first) {		// MOVK
			*newval = (total & ~((uint64_t)0xFFFF << h)) | i;
			return 0;
		}
	} else if ((k | 1) == 0x23 && !first) {		// ADD (immediate)
		unsigned h = (opcode >> 22) & 3;
		if (h > 1) {
			return -1;
		}
		rd = opcode & 0x1F;
		rn = (opcode >> 5) & 0x1F;
		if (rd != rn) {
			return -1;
		}
		i = (opcode >> 10) & 0xFFF;
		h *= 12;
		i <<= h;
		if (o & 2) {				// SUB
			*newval = total - i;
			return 0;
		} else {				// ADD
			*newval = total + i;
			return 0;
		}
	}

	return -1;
}

/* patchfinder ***************************************************************/

static addr_t
step64(const uint8_t *buf, addr_t start, size_t length, uint32_t what, uint32_t mask)
{
    addr_t end = start + length;
    while (start < end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start += 4;
    }
    return 0;
}

static addr_t
step64_back(const uint8_t *buf, addr_t start, size_t length, uint32_t what, uint32_t mask)
{
    addr_t end = start - length;
    while (start >= end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start -= 4;
    }
    return 0;
}

static addr_t
bof64_patchfinder64(const uint8_t *buf, addr_t start, addr_t where)
{
    for (; where >= start; where -= 4) {
        uint32_t op = *(uint32_t *)(buf + where);
        if ((op & 0xFFC003FF) == 0x910003FD) {
            unsigned delta = (op >> 10) & 0xFFF;
            //printf("%x: ADD X29, SP, #0x%x\n", where, delta);
            if ((delta & 0xF) == 0) {
                addr_t prev = where - ((delta >> 4) + 1) * 4;
                uint32_t au = *(uint32_t *)(buf + prev);
                if ((au & 0xFFC003E0) == 0xA98003E0) {
                    //printf("%x: STP x, y, [SP,#-imm]!\n", prev);
                    return prev;
                }
                // try something else
                while (where > start) {
                    where -= 4;
                    au = *(uint32_t *)(buf + where);
                    // SUB SP, SP, #imm
                    if ((au & 0xFFC003FF) == 0xD10003FF && ((au >> 10) & 0xFFF) == delta + 0x10) {
                        return where;
                    }
                    // STP x, y, [SP,#imm]
                    if ((au & 0xFFC003E0) != 0xA90003E0) {
                        where += 4;
                        break;
                    }
                }
            }
        }
    }
    return 0;
}

static addr_t
xref64(const uint8_t *buf, addr_t start, addr_t end, addr_t what)
{
    addr_t i;
    uint64_t value[32];

    memset(value, 0, sizeof(value));

    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        if ((op & 0x9F000000) == 0x90000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
            continue;				// XXX should not XREF on its own?
        /*} else if ((op & 0xFFE0FFE0) == 0xAA0003E0) {
            unsigned rd = op & 0x1F;
            unsigned rm = (op >> 16) & 0x1F;
            //printf("%llx: MOV X%d, X%d\n", i, rd, rm);
            value[rd] = value[rm];*/
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) {
                imm <<= 12;
            } else {
                //assert(shift == 0);
                if (shift > 1) continue;
            }
            //printf("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[reg] = value[rn] + imm;	// XXX address, not actual value
        /*} else if ((op & 0xF9C00000) == 0xF9000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: STR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[rn] = value[rn] + imm;	// XXX address, not actual value*/
        } else if ((op & 0x9F000000) == 0x10000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, ((long long)adr >> 11) + i);
            value[reg] = ((long long)adr >> 11) + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;		// XXX address, not actual value
        }
        if (value[reg] == what) {
            return i;
        }
    }
    return 0;
}

static addr_t
calc64(const uint8_t *buf, addr_t start, addr_t end, int which)
{
    addr_t i;
    uint64_t value[32];

    memset(value, 0, sizeof(value));

    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        if ((op & 0x9F000000) == 0x90000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
        /*} else if ((op & 0xFFE0FFE0) == 0xAA0003E0) {
            unsigned rd = op & 0x1F;
            unsigned rm = (op >> 16) & 0x1F;
            //printf("%llx: MOV X%d, X%d\n", i, rd, rm);
            value[rd] = value[rm];*/
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) {
                imm <<= 12;
            } else {
                //assert(shift == 0);
                if (shift > 1) continue;
            }
            //printf("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[reg] = value[rn] + imm;	// XXX address, not actual value
        } else if ((op & 0xF9C00000) == 0xF9000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: STR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[rn] = value[rn] + imm;	// XXX address, not actual value
        } else if ((op & 0x9F000000) == 0x10000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, ((long long)adr >> 11) + i);
            value[reg] = ((long long)adr >> 11) + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;		// XXX address, not actual value
        }
    }
    return value[which];
}

static addr_t
calc64mov(const uint8_t *buf, addr_t start, addr_t end, int which)
{
    addr_t i;
    uint64_t value[32];

    memset(value, 0, sizeof(value));

    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        uint64_t newval;
        int rv = DecodeMov(op, value[reg], 0, &newval);
        if (rv == 0) {
            if (((op >> 31) & 1) == 0) {
                newval &= 0xFFFFFFFF;
            }
            value[reg] = newval;
        }
    }
    return value[which];
}

static addr_t
find_call64(const uint8_t *buf, addr_t start, size_t length)
{
    return step64(buf, start, length, 0x94000000, 0xFC000000);
}

static addr_t
follow_call64(const uint8_t *buf, addr_t call)
{
    long long w;
    w = *(uint32_t *)(buf + call) & 0x3FFFFFF;
    w <<= 64 - 26;
    w >>= 64 - 26 - 2;
    return call + w;
}

static addr_t
follow_cbz(const uint8_t *buf, addr_t cbz)
{
    return cbz + ((*(int *)(buf + cbz) & 0x3FFFFE0) << 10 >> 13);
}

static addr_t
xref64code(const uint8_t *buf, addr_t start, addr_t end, addr_t what)
{
    addr_t i;

    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        if ((op & 0x7C000000) == 0x14000000) {
            addr_t where = follow_call64(buf, i);
            //printf("%llx: B[L] 0x%llx\n", i + kerndumpbase, kerndumpbase + where);
            if (where == what) {
                return i;
            }
        }
    }
    return 0;
}

/* kernel iOS10 **************************************************************/

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach-o/loader.h>
//#include "vfs.h" // img4lib

#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
#include <mach/mach.h>
size_t kread(uint64_t where, void *p, size_t size);
#endif

#ifdef VFS_H_included
#define INVALID_HANDLE NULL
static FHANDLE
OPEN(const char *filename, int oflag)
{
    ssize_t rv;
    char buf[28];
    FHANDLE fd = file_open(filename, oflag);
    if (!fd) {
        return NULL;
    }
    rv = fd->read(fd, buf, 4);
    fd->lseek(fd, 0, SEEK_SET);
    if (rv == 4 && !MACHO(buf)) {
        fd = img4_reopen(fd, NULL, 0);
        if (!fd) {
            return NULL;
        }
        rv = fd->read(fd, buf, sizeof(buf));
        if (rv == sizeof(buf) && *(uint32_t *)buf == 0xBEBAFECA && __builtin_bswap32(*(uint32_t *)(buf + 4)) > 0) {
            return sub_reopen(fd, __builtin_bswap32(*(uint32_t *)(buf + 16)), __builtin_bswap32(*(uint32_t *)(buf + 20)));
        }
        fd->lseek(fd, 0, SEEK_SET);
    }
    return fd;
}
#define CLOSE(fd) (fd)->close(fd)
#define READ(fd, buf, sz) (fd)->read(fd, buf, sz)
static ssize_t
PREAD(FHANDLE fd, void *buf, size_t count, off_t offset)
{
    ssize_t rv;
    //off_t pos = fd->lseek(FHANDLE fd, 0, SEEK_CUR);
    fd->lseek(fd, offset, SEEK_SET);
    rv = fd->read(fd, buf, count);
    //fd->lseek(FHANDLE fd, pos, SEEK_SET);
    return rv;
}
#else
#define FHANDLE int
#define INVALID_HANDLE -1
#define OPEN open
#define CLOSE close
#define READ read
#define PREAD pread
#endif

static uint8_t *kernel = NULL;
static int kernel_version = 0;
static size_t kernel_size = 0;

static addr_t xnucore_base = 0;
static addr_t xnucore_size = 0;
static addr_t prelink_base = 0;
static addr_t prelink_size = 0;
static addr_t pplcode_base = 0;
static addr_t pplcode_size = 0;
static addr_t cstring_base = 0;
static addr_t cstring_size = 0;
static addr_t pstring_base = 0;
static addr_t pstring_size = 0;
static addr_t kerndumpbase = -1;
static addr_t kernel_entry = 0;
static void *kernel_mh = 0;
static addr_t kernel_delta = 0;

int
init_kernel(addr_t base, const char *filename)
{
    size_t rv;
    uint8_t buf[0x4000];
    uint8_t *vstr;
    unsigned i, j;
    const struct mach_header *hdr = (struct mach_header *)buf;
    FHANDLE fd = INVALID_HANDLE;
    const uint8_t *q;
    addr_t min = -1;
    addr_t max = 0;
    int is64 = 0;

    if (filename == NULL) {
#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
        rv = kread(base, buf, sizeof(buf));
        if (rv != sizeof(buf) || !MACHO(buf)) {
            return -1;
        }
#else
        (void)base;
        return -1;
#endif
    } else {
        fd = OPEN(filename, O_RDONLY);
        if (fd == INVALID_HANDLE) {
            return -1;
        }
        rv = READ(fd, buf, sizeof(buf));
        if (rv != sizeof(buf) || !MACHO(buf)) {
            CLOSE(fd);
            return -1;
        }
    }

    if (IS64(buf)) {
        is64 = 4;
    }

    q = buf + sizeof(struct mach_header) + is64;
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT_64 && ((struct segment_command_64 *)q)->vmsize) {
            const struct segment_command_64 *seg = (struct segment_command_64 *)q;
            if (min > seg->vmaddr) {
                min = seg->vmaddr;
            }
            if (max < seg->vmaddr + seg->vmsize) {
                max = seg->vmaddr + seg->vmsize;
            }
            if (!strcmp(seg->segname, "__TEXT_EXEC")) {
                xnucore_base = seg->vmaddr;
                xnucore_size = seg->filesize;
            }
            if (!strcmp(seg->segname, "__PLK_TEXT_EXEC")) {
                prelink_base = seg->vmaddr;
                prelink_size = seg->filesize;
            }
            if (!strcmp(seg->segname, "__PPLTEXT")) {
                pplcode_base = seg->vmaddr;
                pplcode_size = seg->filesize;
            }
            if (!strcmp(seg->segname, "__TEXT")) {
                const struct section_64 *sec = (struct section_64 *)(seg + 1);
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__cstring")) {
                        cstring_base = sec[j].addr;
                        cstring_size = sec[j].size;
                    }
                }
            }
            if (!strcmp(seg->segname, "__PRELINK_TEXT")) {
                const struct section_64 *sec = (struct section_64 *)(seg + 1);
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__text")) {
                        pstring_base = sec[j].addr;
                        pstring_size = sec[j].size;
                    }
                }
            }
        }
        if (cmd->cmd == LC_UNIXTHREAD) {
            uint32_t *ptr = (uint32_t *)(cmd + 1);
            uint32_t flavor = ptr[0];
            struct {
                uint64_t x[29];	/* General purpose registers x0-x28 */
                uint64_t fp;	/* Frame pointer x29 */
                uint64_t lr;	/* Link register x30 */
                uint64_t sp;	/* Stack pointer x31 */
                uint64_t pc; 	/* Program counter */
                uint32_t cpsr;	/* Current program status register */
            } *thread = (void *)(ptr + 2);
            if (flavor == 6) {
                kernel_entry = thread->pc;
            }
        }
        q = q + cmd->cmdsize;
    }

    if (pstring_base == 0 && pstring_size == 0) {
        pstring_base = cstring_base;
        pstring_size = cstring_size;
    }
    if (prelink_base == 0 && prelink_size == 0) {
        prelink_base = xnucore_base;
        prelink_size = xnucore_size;
    }

    kerndumpbase = min;
    xnucore_base -= kerndumpbase;
    prelink_base -= kerndumpbase;
    pplcode_base -= kerndumpbase;
    cstring_base -= kerndumpbase;
    pstring_base -= kerndumpbase;
    kernel_size = max - min;

    if (filename == NULL) {
#ifdef __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__
        kernel = malloc(kernel_size);
        if (!kernel) {
            return -1;
        }
        rv = kread(kerndumpbase, kernel, kernel_size);
        if (rv != kernel_size) {
            free(kernel);
            kernel = NULL;
            return -1;
        }

        kernel_mh = kernel + base - min;
#endif
    } else {
        kernel = calloc(1, kernel_size);
        if (!kernel) {
            CLOSE(fd);
            return -1;
        }

        q = buf + sizeof(struct mach_header) + is64;
        for (i = 0; i < hdr->ncmds; i++) {
            const struct load_command *cmd = (struct load_command *)q;
            if (cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (struct segment_command_64 *)q;
                size_t sz = PREAD(fd, kernel + seg->vmaddr - min, seg->filesize, seg->fileoff);
                if (sz != seg->filesize) {
                    CLOSE(fd);
                    free(kernel);
                    kernel = NULL;
                    return -1;
                }
                if (!kernel_mh) {
                    kernel_mh = kernel + seg->vmaddr - min;
                }
                if (!strcmp(seg->segname, "__LINKEDIT")) {
                    kernel_delta = seg->vmaddr - min - seg->fileoff;
                }
            }
            q = q + cmd->cmdsize;
        }

        CLOSE(fd);
    }

    vstr = boyermoore_horspool_memmem(kernel, kernel_size, (uint8_t *)"Darwin Kernel Version", sizeof("Darwin Kernel Version") - 1);
    if (vstr) {
        kernel_version = atoi((const char *)vstr + sizeof("Darwin Kernel Version"));
    }

    return 0;
}

void
term_kernel(void)
{
    free(kernel);
}

/* these operate on VA ******************************************************/

#define INSN_RETAB  0xD65F0FFF, 0xFFFFFFFF
#define INSN_RET    0xD65F03C0, 0xFFFFFFFF
#define INSN_CALL   0x94000000, 0xFC000000
#define INSN_B      0x14000000, 0xFC000000
#define INSN_CBZ    0x34000000, 0xFC000000
#define INSN_BLR    0xD63F0000, 0xFFFFFC1F

addr_t
find_register_value(addr_t where, int reg)
{
    addr_t val;
    addr_t bof = 0;
    where -= kerndumpbase;
    if (where > xnucore_base) {
        bof = bof64_patchfinder64(kernel, xnucore_base, where);
        if (!bof) {
            bof = xnucore_base;
        }
    } else if (where > prelink_base) {
        bof = bof64_patchfinder64(kernel, prelink_base, where);
        if (!bof) {
            bof = prelink_base;
        }
    }
    val = calc64(kernel, bof, where, reg);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

addr_t
find_reference(addr_t to, int n, int where)
{
    addr_t ref, end;
    addr_t base = xnucore_base;
    addr_t size = xnucore_size;
    switch (where) {
        case 1:
            base = prelink_base;
            size = prelink_size;
            break;
        case 2:
            base = pplcode_base;
            size = pplcode_size;
            break;
    }
    if (n <= 0) {
        n = 1;
    }
    end = base + size;
    to -= kerndumpbase;
    do {
        ref = xref64(kernel, base, end, to);
        if (!ref) {
            return 0;
        }
        base = ref + 4;
    } while (--n > 0);
    return ref + kerndumpbase;
}

addr_t
find_strref(const char *string, int n, int where)
{
    uint8_t *str;
    addr_t base = cstring_base;
    addr_t size = cstring_size;
    switch (where) {
        case 1:
            base = pstring_base;
            size = pstring_size;
            break;
    }
    str = boyermoore_horspool_memmem(kernel + base, size, (uint8_t *)string, strlen(string));
    if (!str) {
        return 0;
    }
    return find_reference(str - kernel + kerndumpbase, n, where);
}

addr_t
find_gPhysBase(void)
{
    addr_t ret, val;
    addr_t ref = find_strref("pmap_alloc_page_for_kern", 1, 0);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    if (kernel_version >= 18) {
        // A12
        ret = step64(kernel, ref, 384, INSN_RETAB);
        if (!ret) {
            ret = step64(kernel, ref, 384, INSN_RET);
        }
    } else {
        ret = step64(kernel, ref, 64, INSN_RET);
    }
    if (!ret) {
        // iOS 11
        ref = step64(kernel, ref, 1024, INSN_RET);
        if (!ref) {
            return 0;
        }
        ret = step64(kernel, ref + 4, 64, INSN_RET);
        if (!ret) {
            return 0;
        }
    }
    if (kernel_version >= 18) {
        val = calc64(kernel, ref, ret, 9);
    } else {
        val = calc64(kernel, ref, ret, 8);
    }
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

addr_t
find_ptov_table(void)
{
    addr_t bof, val;
    addr_t ref = find_strref("\"ml_static_vtop(): illegal VA:", 1, 0);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    bof = bof64_patchfinder64(kernel, xnucore_base, ref);
    if (!bof) {
        return 0;
    }
    val = calc64(kernel, bof, bof + 48, 8);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

addr_t
find_kernel_pmap(void)
{
    addr_t call, bof, val;
    addr_t ref = find_strref("\"pmap_map_bd\"", 1, 0);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    call = step64_back(kernel, ref, 64, INSN_CALL);
    if (!call) {
        return 0;
    }
    bof = bof64_patchfinder64(kernel, xnucore_base, call);
    if (!bof) {
        return 0;
    }
    if (kernel_version == 18) {
        // iOS 12
        val = calc64(kernel, bof, call, 8);
    } else {
        val = calc64(kernel, bof, call, 2);
    }
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

addr_t
find_amfiret(void)
{
    addr_t ret;
    addr_t ref = find_strref("AMFI: hook..execve() killing pid %u: %s\n", 1, 1);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    ret = step64(kernel, ref, 512, INSN_RET);
    if (!ret) {
        return 0;
    }
    return ret + kerndumpbase;
}

addr_t
find_ret_0(void)
{
    addr_t off;
    uint32_t *k;
    k = (uint32_t *)(kernel + xnucore_base);
    for (off = 0; off < xnucore_size - 4; off += 4, k++) {
        if (k[0] == 0xAA1F03E0 && k[1] == 0xD65F03C0) {
            return off + xnucore_base + kerndumpbase;
        }
    }
    k = (uint32_t *)(kernel + prelink_base);
    for (off = 0; off < prelink_size - 4; off += 4, k++) {
        if (k[0] == 0xAA1F03E0 && k[1] == 0xD65F03C0) {
            return off + prelink_base + kerndumpbase;
        }
    }
    return 0;
}

addr_t
find_amfi_memcmpstub(void)
{
    addr_t call, dest, reg;
    addr_t ref = find_strref("%s: Possible race detected. Rejecting.", 1, 1);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    call = step64_back(kernel, ref, 64, INSN_CALL);
    if (!call) {
        return 0;
    }
    dest = follow_call64(kernel, call);
    if (!dest) {
        return 0;
    }
    reg = calc64(kernel, dest, dest + 8, 16);
    if (!reg) {
        return 0;
    }
    return reg + kerndumpbase;
}

addr_t
find_sbops(void)
{
    addr_t off, what;
    uint8_t *str = boyermoore_horspool_memmem(kernel + pstring_base, pstring_size, (uint8_t *)"Seatbelt sandbox policy", sizeof("Seatbelt sandbox policy") - 1);
    if (!str) {
        return 0;
    }
    what = str - kernel + kerndumpbase;
    for (off = 0; off < kernel_size - prelink_base; off += 8) {
        if (*(uint64_t *)(kernel + prelink_base + off) == what) {
            return *(uint64_t *)(kernel + prelink_base + off + 24);
        }
    }
    return 0;
}

addr_t
find_lwvm_mapio_patch(void)
{
    addr_t call, dest, reg;
    addr_t ref = find_strref("_mapForIO", 1, 1);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    call = step64(kernel, ref, 64, INSN_CALL);
    if (!call) {
        return 0;
    }
    call = step64(kernel, call + 4, 64, INSN_CALL);
    if (!call) {
        return 0;
    }
    dest = follow_call64(kernel, call);
    if (!dest) {
        return 0;
    }
    reg = calc64(kernel, dest, dest + 8, 16);
    if (!reg) {
        return 0;
    }
    return reg + kerndumpbase;
}

addr_t
find_lwvm_mapio_newj(void)
{
    addr_t call;
    addr_t ref = find_strref("_mapForIO", 1, 1);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    call = step64(kernel, ref, 64, INSN_CALL);
    if (!call) {
        return 0;
    }
    call = step64(kernel, call + 4, 64, INSN_CALL);
    if (!call) {
        return 0;
    }
    call = step64(kernel, call + 4, 64, INSN_CALL);
    if (!call) {
        return 0;
    }
    call = step64_back(kernel, call, 64, INSN_B);
    if (!call) {
        return 0;
    }
    return call + 4 + kerndumpbase;
}

addr_t
find_cpacr_write(void)
{
    addr_t off;
    uint32_t *k;
    k = (uint32_t *)(kernel + xnucore_base);
    for (off = 0; off < xnucore_size - 4; off += 4, k++) {
        if (k[0] == 0xd5181040) {
            return off + xnucore_base + kerndumpbase;
        }
    }
    return 0;
}

addr_t
find_str(const char *string)
{
    uint8_t *str = boyermoore_horspool_memmem(kernel, kernel_size, (uint8_t *)string, strlen(string));
    if (!str) {
        return 0;
    }
    return str - kernel + kerndumpbase;
}

addr_t
find_entry(void)
{
    /* XXX returns an unslid address */
    return kernel_entry;
}

const unsigned char *
find_mh(void)
{
    return kernel_mh;
}

addr_t
find_amfiops(void)
{
    addr_t off, what;
    uint8_t *str = boyermoore_horspool_memmem(kernel + pstring_base, pstring_size, (uint8_t *)"Apple Mobile File Integrity", sizeof("Apple Mobile File Integrity") - 1);
    if (!str) {
        return 0;
    }
    what = str - kernel + kerndumpbase;
    /* XXX will only work on a dumped kernel */
    for (off = 0; off < kernel_size - prelink_base; off += 8) {
        if (*(uint64_t *)(kernel + prelink_base + off) == what) {
            return *(uint64_t *)(kernel + prelink_base + off + 0x18);
        }
    }
    return 0;
}

addr_t
find_sysbootnonce(void)
{
    addr_t off, what;
    uint8_t *str = boyermoore_horspool_memmem(kernel + cstring_base, cstring_size, (uint8_t *)"com.apple.System.boot-nonce", sizeof("com.apple.System.boot-nonce") - 1);
    if (!str) {
        return 0;
    }
    what = str - kernel + kerndumpbase;
    for (off = 0; off < kernel_size - xnucore_base; off += 8) {
        if (*(uint64_t *)(kernel + xnucore_base + off) == what) {
            return xnucore_base + off + 8 + 4 + kerndumpbase;
        }
    }
    return 0;
}

addr_t
find_trustcache(void)
{
    addr_t cbz, call, func, val;
    addr_t ref = find_strref("amfi_prevent_old_entitled_platform_binaries", 1, 1);
    if (!ref) {
        // iOS 11
        ref = find_strref("com.apple.MobileFileIntegrity", 0, 1);
        if (!ref) {
            return 0;
        }
        ref -= kerndumpbase;
        call = step64(kernel, ref, 64, INSN_CALL);
        if (!call) {
            return 0;
        }
        call = step64(kernel, call + 4, 64, INSN_CALL);
        goto okay;
    }
    ref -= kerndumpbase;
    cbz = step64(kernel, ref, 32, INSN_CBZ);
    if (!cbz) {
        return 0;
    }
    call = step64(kernel, follow_cbz(kernel, cbz), 4, INSN_CALL);
  okay:
    if (!call) {
        return 0;
    }
    func = follow_call64(kernel, call);
    if (!func) {
        return 0;
    }
    val = calc64(kernel, func, func + 16, 8);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

addr_t
find_amficache(void)
{
    addr_t cbz, call, func, bof, val;
    addr_t ref = find_strref("amfi_prevent_old_entitled_platform_binaries", 1, 1);
    if (!ref) {
        // iOS 11
        ref = find_strref("com.apple.MobileFileIntegrity", 0, 1);
        if (!ref) {
            return 0;
        }
        ref -= kerndumpbase;
        call = step64(kernel, ref, 64, INSN_CALL);
        if (!call) {
            return 0;
        }
        call = step64(kernel, call + 4, 64, INSN_CALL);
        goto okay;
    }
    ref -= kerndumpbase;
    cbz = step64(kernel, ref, 32, INSN_CBZ);
    if (!cbz) {
        return 0;
    }
    call = step64(kernel, follow_cbz(kernel, cbz), 4, INSN_CALL);
  okay:
    if (!call) {
        return 0;
    }
    func = follow_call64(kernel, call);
    if (!func) {
        return 0;
    }
    bof = bof64_patchfinder64(kernel, func - 256, func);
    if (!bof) {
        return 0;
    }
    val = calc64(kernel, bof, func, 9);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

addr_t
find_cache(int dynamic)
{
    addr_t call;
    addr_t func;
    addr_t val;
    addr_t amfiUC_inTrustCache = find_strref("%s: only allowed process can check the trust cache", 1, 1); // Trying to find AppleMobileFileIntegrityUserClient::isCdhashInTrustCache
    if (!amfiUC_inTrustCache) {
        return 0;
    }
    amfiUC_inTrustCache -= kerndumpbase;

    call = step64_back(kernel, amfiUC_inTrustCache, 11 * 4, INSN_CALL);
    if (!call) {
        return 0;
    }
    func = follow_call64(kernel, call);

    call = step64(kernel, func, 8 * 4, INSN_CALL);
    if (!call) {
        return 0;
    }
    func = follow_call64(kernel, call);

    call = step64(kernel, func, 8 * 4, INSN_CALL);
    if (!call) {
        return 0;
    }
    if (dynamic) {
        // We ignore the above call, as we are looking for the dynamic cache
        call = step64(kernel, call + 4, 8 * 4, INSN_CALL);
        if (!call) {
            return 0;
        }
        func = follow_call64(kernel, call);
        val = calc64(kernel, func, func + 16 * 4, 21);
    } else {
        func = follow_call64(kernel, call);
        val = calc64(kernel, func, func + 12 * 4, 9);
    }
    if (!val) {
        return 0;
    }

    return val + kerndumpbase;
}

addr_t
find_add_x0_x0_0x40_ret(void)
{
    // csblob_get_cdhash()
    static const uint8_t insn[] = { 0x00, 0x00, 0x01, 0x91, 0xc0, 0x03, 0x5f, 0xd6 }; // 0x91010000, 0xD65F03C0

    uint8_t *str;
    str = boyermoore_horspool_memmem(kernel + xnucore_base, xnucore_size, insn, sizeof(insn));
    if (str) {
        return str - kernel + kerndumpbase;
    }
    str = boyermoore_horspool_memmem(kernel + prelink_base, prelink_size, insn, sizeof(insn));
    if (str) {
        return str - kernel + kerndumpbase;
    }
    return 0;
}

addr_t
find_vfs_context_current(void)
{
    addr_t bof, call;
    addr_t ref = find_strref("\"vnode_put(%p): iocount < 1\"", 1, 0);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    bof = bof64_patchfinder64(kernel, xnucore_base, ref);
    if (!bof) {
        return 0;
    }
    call = find_call64(kernel, bof, 100);
    if (!call) {
        return 0;
    }
    call = follow_call64(kernel, call);
    if (!call) {
        return 0;
    }
    return call + kerndumpbase;
}

addr_t
find_vnode_lookup(void)
{
    addr_t call;
    addr_t ref = find_strref("/private/var/mobile", 1, 0);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    call = find_call64(kernel, ref, 100);
    if (!call) {
        return 0;
    }
    call = find_call64(kernel, call + 4, 100);
    if (!call) {
        return 0;
    }
    call = find_call64(kernel, call + 4, 100);
    if (!call) {
        return 0;
    }
    call = follow_call64(kernel, call);
    if (!call) {
        return 0;
    }
    return call + kerndumpbase;
}

addr_t
find_vnode_put(void)
{
    addr_t call, stub, val;
    addr_t ref = find_strref("hfs: set VeryLowDisk: vol:%s, backingstore b_avail:%lld, tag:%d\n", 1, 1);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    call = find_call64(kernel, ref, 32);
    if (!call) {
        return 0;
    }
    call = find_call64(kernel, call + 4, 32);
    if (!call) {
        return 0;
    }
    stub = follow_call64(kernel, call);
    val = calc64(kernel, stub, stub + 12, 16);
    if (!val) {
        return 0;
    }
    return *(uint64_t *)(kernel + val);
}

addr_t
find_rootvnode(void)
{
    addr_t blr, val;
    addr_t ref = find_strref("\"bsd_init: cannot find root vnode: %s\"", 1, 0);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    blr = step64_back(kernel, ref, 100, INSN_BLR);
    if (!blr) {
        return 0;
    }
    val = calc64(kernel, blr - 16, blr, 1);
    if (!val) {
        return 0;
    }
#if 0
    assert(calc64(kernel, ref, ref + 16, 0) == val);
#endif
    return val + kerndumpbase;
}

addr_t
find_zone_map_ref(void)
{
    addr_t bof, val;
    addr_t ref = find_strref("\"Nothing being freed to the zone_map. start = end = %p\\n\"", 1, 0);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    bof = bof64_patchfinder64(kernel, xnucore_base, ref);
    if (!bof) {
        return 0;
    }
#if 0
#define INSN_ADRP 0x90000000, 0x9F000000
    addr_t pos;
    int r = -1, reg = *(uint32_t *)(kernel + ref) & 0x1F;
    for (pos = ref; pos > bof; pos -= 4) {
        pos = step64_back(kernel, pos, pos - bof, INSN_ADRP);
        if (!pos) {
            break;
        }
        r = *(uint32_t *)(kernel + pos) & 0x1F;
        if (r != reg) {
            printf("\t0x%llx\n", pos + kerndumpbase);
            break;
        }
    }
    assert(r != reg && r == 9);
#endif
    val = calc64(kernel, bof, ref, 9);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

addr_t
find_pmap_initialize_legacy_static_trust_cache_ppl(void)
{
    addr_t i = 0;
    for (;;) {
        addr_t site, jump, call;
        site = step64(kernel, xnucore_base + i, xnucore_size - i, 0xD28004AF, 0xFFFFFFFF); // MOV X15, #0x25
        if (!site) {
            return 0;
        }
        jump = step64(kernel, site + 4, 4, INSN_B);
        if (jump) {
            call = xref64code(kernel, xnucore_base, xnucore_base + xnucore_size, site);
            if (call) {
                return call + kerndumpbase;
            }
            return site + kerndumpbase;
        }
        i = site - xnucore_base + 4;
    }
    return 0;
}

addr_t
find_trust_cache_ppl(void)
{
    addr_t str, bof, val;
    str = find_strref("\"loadable trust cache buffer too small (%ld) for entries claimed (%d)\"", 1, 2);
    if (!str) {
        return 0;
    }
    str -= kerndumpbase;
    bof = bof64_patchfinder64(kernel, pplcode_base, str);
    if (!bof) {
        return 0;
    }
    val = calc64(kernel, bof, str, 8);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

/* extra_recipe **************************************************************/

#define INSN_STR8 0xF9000000 | 8, 0xFFC00000 | 0x1F
#define INSN_POPS 0xA9407BFD, 0xFFC07FFF

addr_t
find_AGXCommandQueue_vtable(void)
{
    addr_t val, str8;
    addr_t ref = find_strref("AGXCommandQueue", 1, 1);
    if (!ref) {
        return 0;
    }
    val = find_register_value(ref, 0);
    if (!val) {
        return 0;
    }
    ref = find_reference(val, 1, 1);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    str8 = step64(kernel, ref, 32, INSN_STR8);
    if (!str8) {
        return 0;
    }
    val = calc64(kernel, ref, str8, 8);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

addr_t
find_allproc(void)
{
    addr_t val;
    addr_t ref = find_strref("shutdownwait", 1, 0);
    if (!ref) {
        return 0;
    }
    ref -= kerndumpbase;
    val = calc64(kernel, ref, ref + 32, 8);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

addr_t
find_call5(void)
{
    addr_t bof;
    uint8_t gadget[] = { 0x95, 0x5A, 0x40, 0xF9, 0x68, 0x02, 0x40, 0xF9, 0x88, 0x5A, 0x00, 0xF9, 0x60, 0xA2, 0x40, 0xA9 };
    uint8_t *str = boyermoore_horspool_memmem(kernel + prelink_base, prelink_size, gadget, sizeof(gadget));
    if (!str) {
        return 0;
    }
    bof = bof64_patchfinder64(kernel, prelink_base, str - kernel);
    if (!bof) {
        return 0;
    }
    return bof + kerndumpbase;
}

addr_t
find_realhost(addr_t priv)
{
    addr_t val;
    if (!priv) {
        return 0;
    }
    priv -= kerndumpbase;
    val = calc64(kernel, priv, priv + 12, 0);
    if (!val) {
        return 0;
    }
    return val + kerndumpbase;
}

#ifdef HAVE_MAIN
#include <mach-o/nlist.h>

addr_t
find_symbol(const char *symbol)
{
    unsigned i;
    const struct mach_header *hdr = kernel_mh;
    const uint8_t *q;
    int is64 = 0;

    if (IS64(hdr)) {
        is64 = 4;
    }

    /* XXX will only work on a decrypted kernel */
    if (!kernel_delta) {
        return 0;
    }

    /* XXX I should cache these.  ohwell... */
    q = (uint8_t *)(hdr + 1) + is64;
    for (i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SYMTAB) {
            const struct symtab_command *sym = (struct symtab_command *)q;
            const char *stroff = (const char *)kernel + sym->stroff + kernel_delta;
            if (is64) {
                uint32_t k;
                const struct nlist_64 *s = (struct nlist_64 *)(kernel + sym->symoff + kernel_delta);
                for (k = 0; k < sym->nsyms; k++) {
                    if (s[k].n_type & N_STAB) {
                        continue;
                    }
                    if (s[k].n_value && (s[k].n_type & N_TYPE) != N_INDR) {
                        if (!strcmp(symbol, stroff + s[k].n_un.n_strx)) {
                            /* XXX this is an unslid address */
                            return s[k].n_value;
                        }
                    }
                }
            }
        }
        q = q + cmd->cmdsize;
    }
    return 0;
}

/* test **********************************************************************/

int
main(int argc, char **argv)
{
    int rv;
    addr_t base = 0;
    const addr_t vm_kernel_slide = 0;
    rv = init_kernel(base, (argc > 1) ? argv[1] : "krnl");
    assert(rv == 0);

    addr_t allproc = find_allproc();
    printf("allproc = 0x%llx\n", allproc);
    addr_t realhost = find_realhost(find_symbol("_host_priv_self") + vm_kernel_slide);
    printf("realhost = 0x%llx\n", realhost - vm_kernel_slide);

    addr_t trustcache = find_trustcache();
    if (!trustcache) {
        trustcache = find_cache(1);
    }
    printf("trustcache = 0x%llx\n", trustcache);
    addr_t amficache = find_amficache();
    if (!amficache) {
        amficache = find_cache(0);
    }
    printf("amficache = 0x%llx\n", amficache);

    printf("trustcache_ppl = func:0x%llx, data:0x%llx\n", find_pmap_initialize_legacy_static_trust_cache_ppl(), find_trust_cache_ppl());

    term_kernel();
    return 0;
}

#endif	/* HAVE_MAIN */