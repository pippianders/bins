/* ARM COFF support for BFD.
   Copyright (C) 2021 Free Software Foundation, Inc.

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

#define AA64PEMAGIC	0x5064

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

// PE-COFF relocation types for RISCV64, which are mostly a subset of the ELF
// types, but with different numbers.

enum {
  IMAGE_REL_RISCV64_ABSOLUTE = 0,	      // 64-bit VA	    R_RISCV64_NONE		A
};
