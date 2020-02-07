#ifndef EPEP_ARCH_H
#define EPEP_ARCH_H

#define TARGET_IS_aarch64pep

#if defined TARGET_IS_aarch64pep
# define COFF_WITH_peaa64
# define pe_use_aa64
#elif defined TARGET_IS_i386pep
# define COFF_WITH_pex64
# define pe_use_x86_64
#else
# error unknown target
#endif

#endif /* EPEP_ARCH_H */
