/* ARM COFF support for BFD.
   Copyright (C) 2017 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.

   Written by Peter Jones, Red Hat, Inc. */

#define L_LNNO_SIZE 2
#define INCLUDE_COMDAT_FIELDS_IN_AUXENT

#include "coff/external.h"

#define COFF_PAGE_SIZE	0x1000

#define AA64PEMAGIC	0xaa64

#define AA64BADMAG(x)	((x).f_magic != AA64PEMAGIC)
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b

#define OMAGIC          0404    /* Object files, eg as output.  */
#define ZMAGIC          IMAGE_NT_OPTIONAL_HDR64_MAGIC    /* Demand load format, eg normal ld output 0x10b.  */
#define STMAGIC		0401	/* Target shlib.  */
#define SHMAGIC		0443	/* Host   shlib.  */

/* Define some NT default values.  */
/*  #define NT_IMAGE_BASE        0x400000 moved to internal.h.  */
#define NT_SECTION_ALIGNMENT 0x1000
#define NT_FILE_ALIGNMENT    0x200
#define NT_DEF_RESERVE       0x100000
#define NT_DEF_COMMIT        0x1000

/* Relocation directives.  */

struct external_reloc
{
  char r_vaddr[4];
  char r_symndx[4];
  char r_type[2];
};

#define RELOC struct external_reloc
#define RELSZ 10

// PE-COFF relocation types for AARCH64, which are mostly a subset of the ELF
// types, but with different numbers.

enum {
  IMAGE_REL_ARM64_ABSOLUTE = 0,	      // 64-bit VA	    R_AARCH64_NONE		A
  IMAGE_REL_ARM64_ADDR32 = 1,	      // 32-bit VA	    R_AARCH64_ABS32		S + A
  IMAGE_REL_ARM64_ADDR32NB = 2,	      // 32-bit RVA	    R_AARCH64_PREL32		S + A - P
  IMAGE_REL_ARM64_BRANCH26 = 3,	      // 26-bit VA B/BL	    R_AARCH64_JUMP26		S + A - P
  IMAGE_REL_ARM64_PAGEBASE_REL21 = 4, // 21-bit	pg ADRP	    R_AARCH64_ADR_PREL_PG_HI21	Page(S+A)-Page(P)
  IMAGE_REL_ARM64_REL21 = 5,	      // 21-bit pgoff ADR				S + A
  IMAGE_REL_ARM64_PAGEOFFSET_12A = 6, // 12-bit	pgoff ADD(S)  R_AARCH64_ADD_ABS_LO12_NC	Delta(P) + A
  IMAGE_REL_ARM64_PAGEOFFSE_12L = 7,  // 12-bit	pgoff LDST  R_AARCH64_LDST8_ABS_LO12_NC	Delta(P) + A
  IMAGE_REL_ARM64_SECREL = 8,	      // 32-bit offset	    R_AARCH64_RELATIVE		Delta(S) + A
  IMAGE_REL_ARM64_SECREL_LO12A = 9,   // 12-bit [11:0] secoff ADD(S)			Delta(S) + A
  IMAGE_REL_ARM64_SECREL_HI12A = 10,  // 12-bit [23:12] secoff ADD(S)			Delta(S) + A
  IMAGE_REL_ARM64_SECREL_LO12L = 11,  // 12-bit [11:0] secoff LDR			Delta(S) + A
  IMAGE_REL_ARM64_TOKEN = 12,	      // 32-bit CLR token				N
  IMAGE_REL_ARM64_SECTION = 13,	      // 16-bit section table index			N
  IMAGE_REL_ARM64_ADDR64 = 14,	      // 64-bit VA	    R_AARCH64_ABS64		S + A
  IMAGE_REL_ARM64_BRANCH19 = 15,      // 19-bit VA cond B				S + A
  IMAGE_REL_ARM64_BRANCH14 = 16,      // 14-bit VA TBZ/TBNZ				S + A
  IMAGE_REL_ARM64_REL32 = 17,	      // 32-bit RVA of the next byte			S + A + 4
};
