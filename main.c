// #ifdef CONFIG_HOTPLUG_CPU error!!!
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
//#include <linux/build_bug.h>
#include <asm/tlbflush.h>
#include <asm/mmu_context.h> /* __get_current_cr3_fast() */
#include <asm/segment.h>
#include <asm/fsgsbase.h>

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define BIT_llu(n) (((unsigned long long)1) << (n))
#define BIT_lu(n) (((unsigned long)1) << (n))
#define BIT_u(n) (((unsigned int)1) << (n))

/* Align a value down to the nearest page boundary */
#define PAGEALIGNDOWN(val) ((val) & ~(PAGE_SIZE-1))
/* Align a value up to the nearest page boundary */
#define PAGEALIGNUP(val) (PAGEALIGNDOWN((val) + (PAGE_SIZE-1)))
/* Get the number of pages in a value (round up) */
#define PAGESUP(val) (PAGEALIGNUP(val) >> PAGE_SHIFT)
/* log2 of the number of pages in a value (round up), to be used  with
   __get_free_pages() and friends */
#define ORDER(val) (order_base_2(PAGESUP(val)))


/* VMCS Field encodings [SDM 3D Appx. B] */

/* Host control registers */
#define VMCS_ENC_HOSTCR0 0x00006c00
#define VMCS_ENC_HOSTCR3 0x00006c02
#define VMCS_ENC_HOSTCR4 0x00006c04

/* Host segment selector fields */
#define VMCS_ENC_HOSTES  0x00000c00
#define VMCS_ENC_HOSTCS  0x00000c02
#define VMCS_ENC_HOSTSS  0x00000c04
#define VMCS_ENC_HOSTDS  0x00000c06
#define VMCS_ENC_HOSTFS  0x00000c08
#define VMCS_ENC_HOSTGS  0x00000c0a
#define VMCS_ENC_HOSTTR  0x00000c0c

/* Host base address fields */
#define VMCS_ENC_HOSTFSBASE     0x00006c06
#define VMCS_ENC_HOSTGSBASE     0x00006c08
#define VMCS_ENC_HOSTTRBASE     0x00006c0a
#define VMCS_ENC_HOSTGDTRBASE   0x00006c0c
#define VMCS_ENC_HOSTIDTRBASE   0x00006c0e

/* Host `flow control` */
#define VMCS_ENC_HOSTRSP    0x00006c14
#define VMCS_ENC_HOSTRIP    0x00006c16

/* Host fast syscall control MSRs */
#define VMCS_ENC_HOSTIA32SYSENTERESP 0x00006c10
#define VMCS_ENC_HOSTIA32SYSENTEREIP 0x00006c12
#define VMCS_ENC_HOSTIA32SYSENTERCS  0x00004c00

/* VMX controls */
#define VMCS_ENC_PINCTLS   0x00004000
#define VMCS_ENC_PROCTLS   0x00004002
#define VMCS_ENC_EXITCTLS  0x0000400C
#define VMCS_ENC_ENTRYCTLS 0x00004012

/* Guest state area */
#define VMCS_ENC_GUESTCR0           0x00006800
#define VMCS_ENC_GUESTCR3           0x00006802
#define VMCS_ENC_GUESTCR4           0x00006804
#define VMCS_ENC_GUESTDR7           0x0000681A
#define VMCS_ENC_GUESTRSP           0x0000681c
#define VMCS_ENC_GUESTRIP           0x0000681e
#define VMCS_ENC_GUESTRFLAGS        0x00006820

#define VMCS_ENC_GUESTESBASE        0x00006806
#define VMCS_ENC_GUESTCSBASE        0x00006808
#define VMCS_ENC_GUESTSSBASE        0x0000680a
#define VMCS_ENC_GUESTDSBASE        0x0000680c
#define VMCS_ENC_GUESTFSBASE        0x0000680e
#define VMCS_ENC_GUESTGSBASE        0x00006810
#define VMCS_ENC_GUESTLDTRBASE      0x00006812
#define VMCS_ENC_GUESTTRBASE        0x00006814
#define VMCS_ENC_GUESTGDTRBASE      0x00006816
#define VMCS_ENC_GUESTIDTRBASE      0x00006818

#define VMCS_ENC_GUESTESSEL         0x00000800
#define VMCS_ENC_GUESTCSSEL         0x00000802
#define VMCS_ENC_GUESTSSSEL         0x00000804
#define VMCS_ENC_GUESTDSSEL         0x00000806
#define VMCS_ENC_GUESTFSSEL         0x00000808
#define VMCS_ENC_GUESTGSSEL         0x0000080a
#define VMCS_ENC_GUESTLDTRSEL       0x0000080c
#define VMCS_ENC_GUESTTRSEL         0x0000080e

#define VMCS_ENC_GUESTESLIM         0x00004800
#define VMCS_ENC_GUESTCSLIM         0x00004802
#define VMCS_ENC_GUESTSSLIM         0x00004804
#define VMCS_ENC_GUESTDSLIM         0x00004806
#define VMCS_ENC_GUESTFSLIM         0x00004808
#define VMCS_ENC_GUESTGSLIM         0x0000480a
#define VMCS_ENC_GUESTLDTRLIM      0x0000480c
#define VMCS_ENC_GUESTTRLIM        0x0000480e
#define VMCS_ENC_GUESTGDTRLIM       0x00004810
#define VMCS_ENC_GUESTIDTRLIM       0x00004812

#define VMCS_ENC_GUESTESACR         0x00004814
#define VMCS_ENC_GUESTCSACR         0x00004816
#define VMCS_ENC_GUESTSSACR         0x00004818
#define VMCS_ENC_GUESTDSACR         0x0000481a
#define VMCS_ENC_GUESTFSACR         0x0000481c
#define VMCS_ENC_GUESTGSACR         0x0000481e
#define VMCS_ENC_GUESTLDTRSACR      0x00004820
#define VMCS_ENC_GUESTTRSACR        0x00004822

#define VMCS_ENC_VMINSTRERR 0x00004400 /* 32bit ro / VM-instruction error */

struct msrs {
    unsigned long long vmx_basic;

    unsigned long long vmx_cr0_fixed0;
    unsigned long long vmx_cr0_fixed1;
    unsigned long long vmx_cr4_fixed0;
    unsigned long long vmx_cr4_fixed1;

    /* capability msrs */
    unsigned long long vmx_pinbased_ctls;
    unsigned long long vmx_procbased_ctls;
    unsigned long long vmx_exit_ctls;
    unsigned long long vmx_entry_ctls;

    /* The following *_true_* capability msrs will only be read if bit 55
       of vmx_basic is set, as specified in the SDM. Otherwise the values here
       will be undefined. */
    unsigned long long vmx_true_pinbased_ctls;
    unsigned long long vmx_true_procbased_ctls;
    unsigned long long vmx_true_exit_ctls;
    unsigned long long vmx_true_entry_ctls;
};


/* BEGIN GLOBALS */
struct msrs g_msrs;
unsigned long long g_vmxon_sz; /* Size in bytes of the vmxon regin */
struct page *g_vmxon_pgs, *g_vmcs_pgs, *g_guestpg;
phys_addr_t g_vmxon_paddr, g_vmcs_paddr, g_guestpg_paddr;

/* END GLOBALS   */

/* Courtesy of KVM. We could have read the msr but the kernel already checks
   cpu features during boot. */
static int vmx_disabled_by_bios(void) {
    return !boot_cpu_has(X86_FEATURE_MSR_IA32_FEAT_CTL) ||
           !boot_cpu_has(X86_FEATURE_VMX);
}

/* Execute a VMXON instruction given the physical address of the vmxon regions
   as a parameters.
   Returns 0 on success, -1 if vmxon faults and -2 if vmxon fails.
   Please see [SDM 3C 31.5 & 3C 30.3 VMXON]
   <https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html>
*/
static noinline int __cpu_vmxon(phys_addr_t vmxon_pointer) {
    asm_volatile_goto("1: vmxon     %[vmxon_pointer]\n\t"
                      "   .byte 0x2e\n\t"            /* branch not taken hint*/
                      "   jc        %l[vmfail_invalid]\n\t"
                      _ASM_EXTABLE(1b, %l[fault])
              :                                      /* no output operands  */
              : [vmxon_pointer] "m"(vmxon_pointer)  /* input operands      */
              : "cc"                                 /* clobbers carry flag */
              : fault, vmfail_invalid);              /* goto labels         */
    return 0; /* VMSucceed, we are in VMX root operation, yay! */

fault: /* VMXON faulted, the kernel takes us here by virtue of dark magic */
    pr_info("VMXON faulted!\n");
    return -1;
vmfail_invalid: /* Carry flag was 1 after VMXON */
    pr_info("VMXON VMfailInvalid\n");
    return -2;
}

/* Executes a VMXOFF instruction.
   Returns 0 on success, -1 if vmxoff faults and -2 if vmxoff fails.
   Please see [SDM 3C 31.5 & 3C 30.3 VMXOFF]
*/
static noinline int __cpu_vmxoff(void) {
    asm_volatile_goto("1: vmxoff\n\t"
                      "   .byte 0x2e\n\t"           /* branch not taken hint*/
                      "   jna   %l[vmfail]\n\t"     /* CF=1 or ZF=1        */
                      _ASM_EXTABLE(1b, %l[fault])
              :                                     /* no output operands  */
              :                                     /* no input operands   */
              : "cc"                                /* clobbers carry flag */
              : fault, vmfail);                     /* goto labels         */
    return 0; /* VMSucceed, we are outisde VMX operation, yay! */

fault: /* VMXOFF faulted */
    pr_info("VMXOFF faulted!\n");
    return -1;
vmfail: /* either CF or ZF were 1 */
    pr_info("VMXOFF VMfail\n");
    return -2;
}

/* Execute a VMCLEAR instruction given the physical address of the vmcss as a
   parameter.
   Returns 0 on success, -1 if vmclear faults and -2 if vmclear fails.
   Please see [SDM 3C 31.6 & 3C 30.3 VMCLEAR]
*/
static noinline int __cpu_vmclear(phys_addr_t vmcs_pointer) {
    asm_volatile_goto("1: vmclear   %[vmcs_pointer]\n\t"
                      "   .byte 0x2e\n\t"            /* branch not taken hint*/
                      "   jna       %l[vmfail]\n\t"  /* CF=1 or ZF=1        */
                      _ASM_EXTABLE(1b, %l[fault])
              :                                      /* no output operands  */
              : [vmcs_pointer] "m"(vmcs_pointer)    /* input operands      */
              : "cc"                                 /* clobbers carry flag */
              : fault, vmfail);                      /* goto labels         */
    return 0; /* VMSucceed */

fault:
    pr_info("VMCLEAR faulted!\n");
    return -1;
vmfail:
    pr_info("VMCLEAR VMfail\n");
    return -2;
}

/* Execute a VMPTRLD instruction given the physical address of the vmcss as a
   parameter.
   Returns 0 on success, -1 if vmptrld faults and -2 if vmptrld fails.
   Please see [SDM 3C 31.6 & 3C 30.3 VMPTRLD]
*/
static noinline int __cpu_vmptrld(phys_addr_t vmcs_pointer) {
    asm_volatile_goto("1: vmptrld   %[vmcs_pointer]\n\t"
                      "   .byte 0x2e\n\t"            /* branch not taken hint*/
                      "   jna       %l[vmfail]\n\t"  /* CF=1 or ZF=1        */
                      _ASM_EXTABLE(1b, %l[fault])
              :                                      /* no output operands  */
              : [vmcs_pointer] "m"(vmcs_pointer)    /* input operands      */
              : "cc"                                 /* clobbers carry flag */
              : fault, vmfail);                      /* goto labels         */
    return 0; /* VMSucceed */

fault:
    pr_info("VMPTRLD faulted!\n");
    return -1;
vmfail:
    pr_info("VMPTRLD VMfail\n");
    return -2;
}



/* Executes a VMREAD instruction given the VMCS field encoding in `field`
   and returns the read value. *retval is an output parameter, it returns
   0 on success, -1 when VMREAD faults and -2 when it fails. If *retval
   is non-zero, the returned value is undefined.

   For some reason it gives a compile error if we use OutputOperands together
   with goto labels in the inline asm block, so we have to write this a bit
   differently than the wrappers above. kvm does something simillar,
   see arch/x86/kvm/vmx/vmx_ops.h:__vmcs_readl()

   Thanks to Andrew Haley for pointing out that _retval should be "+*" and not
   "=*", otherwise the compiler would optimize-away its initialization to 0.
   <https://gcc.gnu.org/pipermail/gcc-help/2022-January/141096.html>
*/
static __always_inline  unsigned long __cpu_vmread(unsigned long field, int *retval) {
    unsigned long val;
    int _retval = 0;

    asm volatile(
        "1:    vmread %[field], %[val]\n\t"
        "      .byte 0x3e\n\t"              /* branch taken hint */
        "      ja 3f\n\t"                   /* success! jump out of asm block */
        /* VMfail, set ret to -2 and get out of asm  */
        "      mov $-2, %[_retval]\n\t"
        "      jmp 3f\n\t"
        /* fault, set ret to -1 and fall out of asm */
        "2:    mov $-1, %[_retval]\n\t"
        "3:\n\t"

        _ASM_EXTABLE(1b, 2b)
        : [val] "=rm" (val), [_retval] "+rm" (_retval)
        : [field] "r" (field)
        : "cc"
    );

    *retval = _retval;
    return val;
}

/*
   Execute a VMWRITE instruction. Writes a value `val` to a field given by the
   VMCS field encoding `field` [SDM 3D Appx. B.1]. Don't confuse field encoding
   with field index.

   Return 0 on success, -1 if vmwrite faults and -2 if vmwrite fails;

   USAGE NOTES ON different field sizes:
   `field` is the secondary source operand (the target VMCS field) and `val` is
   the primary source operand.
   Quote from [SDM 3C 30.3 VMWRITE instr reference]:
    "(...In 64-bit mode) If the VMCS field specified by the secondary source
    operand is shorter than this effective operand size, the high bits of the
    primary source operand are ignored. If the VMCS field is longer, then the
    high bits of the field are cleared to 0"

    Meaning we ca use this for all field sizes.
    If we write a small val into a big field we'll default the remaining bits
    to 0.
    If we write a big val into a small field we'll default ignore the remainign
    bits.
*/
static __always_inline int __cpu_vmwrite(unsigned long field, unsigned long val) {
    #ifdef DEBUG
    pr_info("\tAbout to VMWRITE(%08lx, 0x%016lx)\n", field, val);
    #endif

    asm_volatile_goto("1: vmwrite %[val], %[field]\n\t"
                      "   .byte 0x2e\n\t"             /* branch not taken hint*/
                      "   jna     %l[vmfail]\n\t"     /* CF=1 or ZF=1         */
                      _ASM_EXTABLE(1b, %l[fault])
              :                                       /* no output operands  */
              : [field] "r" (field), [val] "rm" (val) /* input operands      */
              : "cc"                                  /* clobbers carry flag */
              : fault, vmfail);                       /* goto labels         */
    return 0;

fault:
    pr_info("VMWRITE faulted!\n");
    return -1;
vmfail:
    pr_info("VMWRITE VMfail field (enc) = 0x%016lx val = 0x%016lx\n", field, val);
    #ifdef DEBUG
    {
        int retval; unsigned long val;
        val = __cpu_vmread(VMCS_ENC_VMINSTRERR, &retval);
        pr_info("\t\tVMREAD(VMCS_ENC_VMINSTRERR) = %lu (vmread retval=%d)\n",
            val, retval); /* See [SDM 3C 30.4] for VM Instruction Error nums */
    }
    #endif
    return -2;
}

static __always_inline int vmcs_write16(unsigned long field, unsigned short val) {
    BUILD_BUG_ON_MSG(!__builtin_constant_p(field) || ((field & 0x6001) != 0),
        "vmcs_write16: Invalid field encoding");

    return __cpu_vmwrite(field, (unsigned long) val);
}

static __always_inline int vmcs_write32(unsigned long field, unsigned int val) {
    BUILD_BUG_ON_MSG(!__builtin_constant_p(field) || ((field & 0x6001) != 0x4000),
        "vmcs_write32: Invalid field encoding");

    return __cpu_vmwrite(field, (unsigned long) val);
}

static __always_inline int vmcs_write64(unsigned long field, unsigned long val) {
    BUILD_BUG_ON_MSG(!__builtin_constant_p(field) ||
        ( (field & 0x6001) != 0x6000 && (field & 0x6001) != 0x2001 ) ,
        "vmcs_write64: Invalid field encoding");

    return __cpu_vmwrite(field, val);
}


#if 0
// TODO: MAKE THIS DEBUG_VMWRITE
#ifdef DEBUG
#define vmcs_write64(field, val) do {                   \
    pr_info(__stringify(field) ": %08lx\n", field);     \
    vmcs_write64(field, val);                           \
} while(0)
#endif
#endif /* 0 */

static noinline int vmlaunch(void) {
    asm_volatile_goto("   nop\n\t" /* To avoid a mov ss / pop ss */
                      "1: vmlaunch\n\t"
                      "   .byte 0x2e\n\t"    /* branch not taken hint*/
                      "   jz     %l[vmfail_valid]\n\t"
                      "   .byte 0x2e\n\t"
                      "   jc     %l[vmfail_invalid]\n\t"
                      _ASM_EXTABLE(1b, %l[fault])
              :
              :
              : "cc"
              : fault, vmfail_valid, vmfail_invalid);
    return 0;

fault:
    pr_info("VMLAUNCH faulted!\n");
    return -1;
vmfail_invalid:
    pr_info("VMLAUNCH VMfailInvalid\n");
    return -2;
vmfail_valid:
    pr_info("VMLAUNCH VMfailValid\n");
    #ifdef DEBUG
    {
        int retval; unsigned long val;
        val = __cpu_vmread(VMCS_ENC_VMINSTRERR, &retval);
        pr_info("\t\tVMREAD(VMCS_ENC_VMINSTRERR) = %lu (vmread retval=%d)\n",
            val, retval); /* See [SDM 3C 30.4] for VM Instruction Error nums */
    }
    #endif
    return -2;
}


/* Returns 0 on success, != 0 on error */
static int setup_vmcs_guest_area(void) {
    int retval = 0;
    unsigned int segacr;

    /* CR0 CR3 CR4
       <https://en.wikipedia.org/wiki/Control_register> (or the manual)

     By putting a breakpoint with the gdbstub kernel debugger in a userspace
     program on a x86_64 Linux 5.10.7 qemu vm we broke into a thread in
     userspace and got the following values:
cr0            0x80050033          [ PG AM WP NE ET MP PE ]
cr3            0x37d7805           [ PDBR=1 PCID=0 ]
cr4            0x370ef0            [ SMAP SMEP OSXSAVE PCIDE FSGSBASE UMIP
                                     OSXMMEXCPT OSFXSR PGE MCE PAE PSE ]

    We're gonna use those values with some modifications:
        - We disable paging in cr0 and set cr3 to 0

    With this, our guest will acces the physical address space of the host
    directly (if we properly set flat segmentation later).
    In this initial version of the hypervisor we don't do any effort to emulate
    guest memory, neither EPT nor shadow page tables (Intel SDM calls that
    virtual-TLB).
     */
    retval |= vmcs_write64(VMCS_ENC_GUESTCR0, 0x00050033);
    retval |= vmcs_write64(VMCS_ENC_GUESTCR3, 0);
    retval |= vmcs_write64(VMCS_ENC_GUESTCR4, 0x370ef0);

    /* DR7 - Debug control register. We disable hw breakpoints (hopefully) */
    retval |= vmcs_write64(VMCS_ENC_GUESTDR7, 0);

    /* RSP, RIP, RFLAGS */
    retval |= vmcs_write64(VMCS_ENC_GUESTRSP,
        ((unsigned long)g_guestpg_paddr)+0x1000-32);
    retval |= vmcs_write64(VMCS_ENC_GUESTRIP,(unsigned long)g_guestpg_paddr);
    /* RFLAGS (kvm-hello-world.c: bit 1 always set, check if necessary)
       See [SDM 3.4.3] for documentation on EFLAGS */
    retval |= vmcs_write64(VMCS_ENC_GUESTRFLAGS, 2);

    /* segment selectors, we set them all to 0 and we'll let the
       processor use the descriptor caches directly, this way we don't
       have to build segment tables. TODO: kvm-hello-world sets a bit*/

    /* XXX: Do we need bit 2?*/
    retval |= vmcs_write16(VMCS_ENC_GUESTESSEL, 0);
    retval |= vmcs_write16(VMCS_ENC_GUESTCSSEL, 0);
    retval |= vmcs_write16(VMCS_ENC_GUESTSSSEL, 0);
    retval |= vmcs_write16(VMCS_ENC_GUESTDSSEL, 0);
    retval |= vmcs_write16(VMCS_ENC_GUESTFSSEL, 0);
    retval |= vmcs_write16(VMCS_ENC_GUESTGSSEL, 0);
    retval |= vmcs_write16(VMCS_ENC_GUESTLDTRSEL, 0);
    retval |= vmcs_write16(VMCS_ENC_GUESTTRSEL, 0);

    /* segment descriptor caches (base and limit) */
    /* In 64-bit mode: CS, DS, ES, SS are treated as if each segment
       base is 0, regardless of the value of the associated Segment
       descriptor base. [SDM 3.4.2.1] */
/*  retval |= vmcs_write64(VMCS_ENC_GUESTESBASE, 0);
    retval |= vmcs_write64(VMCS_ENC_GUESTCSBASE, 0);
    retval |= vmcs_write64(VMCS_ENC_GUESTSSBASE, 0);
    retval |= vmcs_write64(VMCS_ENC_GUESTDSBASE, 0); */

    retval |= vmcs_write64(VMCS_ENC_GUESTFSBASE, 0);
    retval |= vmcs_write64(VMCS_ENC_GUESTGSBASE, 0);
    retval |= vmcs_write64(VMCS_ENC_GUESTLDTRBASE, 0);
    retval |= vmcs_write64(VMCS_ENC_GUESTTRBASE, 0);
    retval |= vmcs_write64(VMCS_ENC_GUESTGDTRBASE, 0);
    retval |= vmcs_write64(VMCS_ENC_GUESTIDTRBASE, 0);

    /* Limit checks for CS, DS, ES, SS, FS, and GS are disabled in
       64-bit mode [SDM 3.4.2.1] */
/*  retval |= vmcs_write64(VMCS_ENC_GUESTESLIM, -1);
    retval |= vmcs_write64(VMCS_ENC_GUESTCSLIM, -1);
    retval |= vmcs_write64(VMCS_ENC_GUESTSSLIM, -1);
    retval |= vmcs_write64(VMCS_ENC_GUESTDSLIM, -1);
    retval |= vmcs_write64(VMCS_ENC_GUESTFSLIM, -1);
    retval |= vmcs_write64(VMCS_ENC_GUESTGSLIM, -1); */

    // XXX: Maybe remove these.
    retval |= vmcs_write32(VMCS_ENC_GUESTLDTRLIM, -1); // xxx: page gran?
    retval |= vmcs_write32(VMCS_ENC_GUESTTRLIM, -1);
    retval |= vmcs_write32(VMCS_ENC_GUESTGDTRLIM, -1);
    retval |= vmcs_write32(VMCS_ENC_GUESTIDTRLIM, -1);


    /* segment descriptor caches (access rights)
       See [SDM 3.4.5 Segment Descriptors] and [SDM 3C 24.4.1]
    */

    /* CS descriptor */
    segacr =  11 /* Segment type = 11 (Code: execute, read, accessed) */
            | BIT_u(4)   /* S (Descriptor type) = 1 (code or data) */
            | (3 << 5)   /* DPL = 3 (ring 3 segment) */
            | BIT_u(7)   /* P (Present) = 1 */
            | BIT_u(13)  /* L (64-bit mode, for cs only) = 1 */
            | BIT_u(14); /* D/B (Default operation size) = 1 (32-bit)
                           maybe ignored on 64-bit mode, please check */
           /* BIT 15 cleared (G Granularity) interpret segment limits
              in byte units as opposed to 4-KiB units */
           /* BIT 16 cleared (0 = segment usable)     */
           /* Remaining bits are cleared              */

    retval |= vmcs_write32(VMCS_ENC_GUESTCSACR, segacr);
    /* descriptors for DS, SS, ES, GS, FS */
    segacr &= 0xfffffff8; /* clear 3 lowes bits (Segment Type) */
    segacr |= 3;          /* segment type Data: read/write, accessed */
    retval |= vmcs_write32(VMCS_ENC_GUESTDSACR, segacr);
    retval |= vmcs_write32(VMCS_ENC_GUESTSSACR, segacr);
    retval |= vmcs_write32(VMCS_ENC_GUESTESACR, segacr);
    retval |= vmcs_write32(VMCS_ENC_GUESTFSACR, segacr);
    retval |= vmcs_write32(VMCS_ENC_GUESTGSACR, segacr);
    // TODO: LDTR, TR, GDTR, IDTR
    // We leave them at 0, see what happens

    /* XXX: EFER? */


    /* TODO: See FreeBSD VMM */

    return retval;
}

static noinline void temporary_vmexit_hdlr_panic(void) {
    int i;
    for (i = 0; i < 16; i++) {
        printk("EXIT! ( TODO: SEE EXIT REASON)\n\n");
    }
    for (i=0; i < 16; i++) {
        int retval; unsigned long val;
        val = __cpu_vmread(VMCS_ENC_VMINSTRERR, &retval);
        pr_info("\t\tVMREAD(VMCS_ENC_VMINSTRERR) = %lu (vmread retval=%d)\n",
            val, retval); /* See [SDM 3C 30.4] for VM Instruction Error nums */
        val = __cpu_vmread(0x00004402, &retval); 
        pr_info("\t\texit reason = %p (vmread retval=%d)\n",
            (void *)val, retval); /* See [SDM 3C 30.4] for VM Instruction Error nums */
    }

    panic("SUCCESS!");
}

static __always_inline unsigned long __read_rsp(void) {
    unsigned long _rsp;
    asm volatile("mov %%rsp, %[_rsp]\n\t" : [_rsp] "=rm" (_rsp) );
    return _rsp;
}

// XXX: synchronization concerns?
/* Returns 0 on success, != 0 on error */
static noinline int setup_vmcs_host_area(void) {
    unsigned long cr, base, sysenter, tr;
    unsigned short segsel;
    struct cpu_entry_area *cpu_area;
    struct desc_ptr dt;
    int retval = 0;

    cpu_area = get_cpu_entry_area(smp_processor_id());

    /* control registers */
    cr = read_cr0();
    retval |= vmcs_write64(VMCS_ENC_HOSTCR0, cr);
    cr = __read_cr3(); // __get_current_cr3_fast();
    retval |= vmcs_write64(VMCS_ENC_HOSTCR3, cr);
    cr = cr4_read_shadow();
    retval |= vmcs_write64(VMCS_ENC_HOSTCR4, cr);

    /* segment selectors and base address fields */
    /* You can find them in arch/x86/include/asm/segment.h (__KERNEL_DS ...)
       They are defined twice, once for CONFIG_X86_32 and once for
       CONFIG_X86_64 (ours), however, some of them can change at runtime.

       kvm (arch/x86/kvm/vmx/vmx.c:vmx_prepare_switch_to_guest()) does a lot of
       stuff probably to not fail guest entry restrictions and to optimize stuff
       by using insight into how the kernel uses segments and selectors.
       Since I don't have that wisdom we are gonna  get them dynamically,
       the idea is we wanna be conservative and not break the host kernel, at
       the cost of setup performance and maybe having to debug guest entry failures
       later.
    */

    savesegment(cs, segsel);
    retval |= vmcs_write16(VMCS_ENC_HOSTCS, segsel);
    savesegment(ds, segsel);
    retval |= vmcs_write16(VMCS_ENC_HOSTDS, segsel);
    savesegment(es, segsel);
    retval |= vmcs_write16(VMCS_ENC_HOSTES, segsel);
    savesegment(ss, segsel);
    retval |= vmcs_write16(VMCS_ENC_HOSTSS, segsel);
    savesegment(fs, segsel);
    retval |= vmcs_write16(VMCS_ENC_HOSTFS, segsel);
    savesegment(gs, segsel);
    retval |= vmcs_write16(VMCS_ENC_HOSTGS, segsel);
    store_tr(tr);
    retval |= vmcs_write16(VMCS_ENC_HOSTTR, tr);

    /* kvm seems to call curent_save_fsgs() which caches the fs/gs bases in
       current->thread.(fs/gs)base (done with irqs disabled). Then it
       uses those values. We prefer to get them directly, again, we don't
       wanna mess with the host. I hope and pray this doesn't break the host
       on a vm exit. */
    base = x86_fsbase_read_cpu();
    retval |= vmcs_write64(VMCS_ENC_HOSTFSBASE, base);
    base = rdgsbase(); // ro review
    retval |= vmcs_write64(VMCS_ENC_HOSTGSBASE, base);
    /* Linux uses per-cpu TSS and GDT
       <https://en.wikipedia.org/wiki/Task_state_segment#Use_of_TSS_in_Linux> */
    // ?
    base = (unsigned long)&cpu_area->tss.x86_tss;
    retval |= vmcs_write64(VMCS_ENC_HOSTTRBASE, base);
    base = (unsigned long)get_current_gdt_ro();
    retval |= vmcs_write64(VMCS_ENC_HOSTGDTRBASE, base);
    store_idt(&dt);
    retval |= vmcs_write64(VMCS_ENC_HOSTIDTRBASE, (unsigned long)dt.address);

    // TODO: Remember to set HOSTRSP and HOSTRIP right before vmenter!!!!!!!
    retval |= vmcs_write64(VMCS_ENC_HOSTRSP, __read_rsp());
    retval |= vmcs_write64(VMCS_ENC_HOSTRIP, temporary_vmexit_hdlr_panic);

    /* Host fast syscall control MSRs */
    // ?
    rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter);
    retval |= vmcs_write64(VMCS_ENC_HOSTIA32SYSENTERESP, sysenter);
    rdmsrl(MSR_IA32_SYSENTER_EIP, sysenter);
    retval |= vmcs_write64(VMCS_ENC_HOSTIA32SYSENTEREIP, sysenter);
    rdmsrl(MSR_IA32_SYSENTER_CS, sysenter);
    retval |= vmcs_write32(VMCS_ENC_HOSTIA32SYSENTERCS,
        (unsigned int)sysenter); /* low 32 bits */

    return retval;
}



/*
   TODO
*/
static noinline unsigned int make_vmcs_ctl(
    unsigned long long vmx_basic_msr,
    unsigned long long msr_cap, unsigned long long msr_true_cap,
    unsigned int desired_set, unsigned int desired_clear) {

    unsigned int setting, fixed0, fixed1, old_fixed1;

#ifdef DEBUG
    pr_info("\tmake_vmcs_ctl(): set 0x%08x clear 0x%08x (neg 0x%08x)\n",
        desired_set, desired_clear, ~desired_clear);
    if (unlikely((desired_set & ~desired_clear) != 0))
        panic("Overlaping set and clear vmcs ctl settings");
#endif /* DEBUG */

    /* clearing takes precedence in overlaping desires (if not debug) */
    desired_set &= desired_clear;

    if (unlikely(!((vmx_basic_msr >> 55) & 1)) ) {
        fixed1 = (unsigned int)msr_cap;
        fixed0 = (unsigned int)(msr_cap >> 32);
        setting = (desired_set & fixed0) | fixed1;
    } else {
        fixed1 = (unsigned int)msr_true_cap;
        fixed0 = (unsigned int)(msr_true_cap >> 32);
        setting = (desired_set & fixed0) | fixed1;
        old_fixed1 = (unsigned int)msr_cap;
        /* we have to set to 1 the free bits that were previously fixed1
           but haven't been neither expressly set nor cleared. */
        setting |= (~fixed1 & old_fixed1) & (~desired_set | desired_clear);
    }

#ifdef DEBUG
        if (unlikely((~desired_clear & fixed1) != 0))
            panic("Tryng to clear a fixed1 vmcs ctl");
        if (unlikely((desired_set & ~fixed0) != 0))
            panic("Trying to set a fixed0 vmcs ctl");
        if (unlikely((~fixed0 & fixed1) != 0))
            panic("Conflicting vmcs ctl bitfix requirements");
        if (unlikely((~(fixed0 | desired_clear)) != 0)) {
            pr_info("\t[INFO] overclearing 0x%08x (neg 0x%08x) OK!\n",
                fixed0 | desired_clear, ~(fixed0 | desired_clear));
        }
        if (unlikely((desired_set & fixed1) != 0)) {
            pr_info("\t[INFO] oversetting 0x%08x OK!\n",
                fixed1 & desired_set);
        }
#endif /* DEBUG */

    return setting;
}

static int setup_vmcs_control_fields(void) {
    int retval = 0;
    unsigned int ctls;

    /* [SDM 23.6] VM-Execution controls                                  */
    /* Pin-Based Execution controls (Table 23-5 & chapter 26) */
    ctls = make_vmcs_ctl(g_msrs.vmx_basic,
        g_msrs.vmx_pinbased_ctls, g_msrs.vmx_true_pinbased_ctls,
            /*set*/
              BIT_u(0)    /* External-interrupt exiting */
            | BIT_u(3)    /* NMI exiting */
            | BIT_u(5), // ???????????????/
            /*clear*/
         ~(   BIT_u(6)    /* Activate VMX-preemption timer */
            | BIT_u(7)    /* Process posted interrupts (no) ????????? */
                      )
          );
        pr_info("pinctls= 0x%08x\n", ctls);
    retval |= vmcs_write32(VMCS_ENC_PINCTLS, ctls);

    /*            Proc-Based Execution controls (Table 24-6 & chapter 24) */
    ctls = make_vmcs_ctl(g_msrs.vmx_basic,
        g_msrs.vmx_procbased_ctls, g_msrs.vmx_true_procbased_ctls,
            /*set*/
              BIT_u(7)   /* HLT exiting */
            | BIT_u(9)   /* INVLPG exiting */
            | BIT_u(15)  /* CR3-load exiting (*) */
            | BIT_u(16)  /* CR3-store exiting (*) */
            | BIT_u(19)  /* CR8-load exiting */
            | BIT_u(20)  /* CR8-store exiting */
            | BIT_u(23)  /* MOV-DR exiting */
            | BIT_u(24), /* Unconditional I/O exiting */

           /*clear*/
         ~(   BIT_u(12) /* RDTSC exiting */
            | BIT_u(25) /* Use I/O bitmaps (clear so as not to ignore bit 24) */
            | BIT_u(28) /* Use MSR bitmaps */
            | BIT_u(31) /* Activate secondary controls (we let them all 0) */
                     )
          );
        pr_info("procctls= 0x%08x\n", ctls);
    retval |= vmcs_write32(VMCS_ENC_PROCTLS, ctls);

    /* VM-Exit controls (Table 24-10 & chapter 24) */
    ctls = make_vmcs_ctl(g_msrs.vmx_basic,
        g_msrs.vmx_exit_ctls, g_msrs.vmx_true_exit_ctls,
            /*set*/
              BIT_u(9)      /* Host address-space size (IA64 only) */
            //| BIT_u(12)  /* Load IA32_PERF_GLOBAL_CTRL ???? */
            | BIT_u(15),  /*  Acknowledge interrupt on exit ????????? */
           /*clear*/
         ~(   0
                     )
          );
    /* VM-Exit controls for MSRs. This can be used to specify which and where
       in memory guest MSRs will be stored on a vm exit and which and where
       in memory host msrs can be found to replace the guest ones on a vmexit.
       We do not set any of this controls for our first tests.

       Similarly, there are a set of symmetric VM-Entry Controls for MSRs,
       we do not touch them either.
     */

        pr_info("exitctls= 0x%08x\n", ctls);
    retval |= vmcs_write32(VMCS_ENC_EXITCTLS, ctls);

        /* VM-Entry control fields */
    ctls = make_vmcs_ctl(g_msrs.vmx_basic,
        g_msrs.vmx_entry_ctls, g_msrs.vmx_true_entry_ctls,
            /*set*/
              BIT_u(9)   /* IA-32e mode guest */
            | BIT_u(15), /*  Acknowledge interrupt on exit ????????? */
            //| BIT_u(13) /* Load IA32_PERF_GLOBAL_CTRL ??????? */
           /*clear*/
         ~(   0
                     )
          );
     pr_info("entryctls= 0x%08x\n", ctls);
    retval |= vmcs_write32(VMCS_ENC_ENTRYCTLS, ctls);

    return retval;
}

/* [SDM 3C 31.5]
   Returns 0 on success, !=0 on error */
static int noinline setup_vmcs(void) {
    int retval;

    retval = setup_vmcs_host_area();
    if (retval) {
        pr_info("Failure to setup vmcs host area\n");
        return retval;
    }

    retval = setup_vmcs_control_fields();
    if (retval) {
        pr_info("Failure to setup vmcs control fields\n");
        return retval;
    }

    retval = setup_vmcs_guest_area();
    if (retval) {
        pr_info("Failure to setup vmcs guest area\n");
        return retval;
    }

    return 0;
}

void read_vmx_capability_msrs(void) {
    unsigned long long basic_bit55 = g_msrs.vmx_basic & BIT_llu(55);

    rdmsrl(MSR_IA32_VMX_PINBASED_CTLS, g_msrs.vmx_pinbased_ctls);
    pr_info("MSR_IA32_VMX_PINBASED_CTLS: 0x%016llx\n", g_msrs.vmx_pinbased_ctls);
    rdmsrl(MSR_IA32_VMX_PROCBASED_CTLS, g_msrs.vmx_procbased_ctls);
    pr_info("MSR_IA32_VMX_PROCBASED_CTLS: 0x%016llx\n", g_msrs.vmx_procbased_ctls);
    rdmsrl(MSR_IA32_VMX_EXIT_CTLS, g_msrs.vmx_exit_ctls);
    pr_info("MSR_IA32_VMX_EXIT_CTLS: 0x%016llx\n", g_msrs.vmx_exit_ctls);
    rdmsrl(MSR_IA32_VMX_ENTRY_CTLS, g_msrs.vmx_entry_ctls);
    pr_info("MSR_IA32_VMX_ENTRY_CTLS: 0x%016llx\n", g_msrs.vmx_entry_ctls);
    rdmsrl(MSR_IA32_VMX_EXIT_CTLS, g_msrs.vmx_exit_ctls);
    pr_info("MSR_IA32_VMX_EXIT_CTLS: 0x%016llx\n", g_msrs.vmx_exit_ctls);



    if (basic_bit55) {
        rdmsrl(MSR_IA32_VMX_TRUE_PINBASED_CTLS, g_msrs.vmx_true_pinbased_ctls);
        pr_info("MSR_IA32_VMX_TRUE_PINBASED_CTLS: 0x%016llx\n", g_msrs.vmx_true_pinbased_ctls);
        rdmsrl(MSR_IA32_VMX_TRUE_PROCBASED_CTLS, g_msrs.vmx_true_procbased_ctls);
        pr_info("MSR_IA32_VMX_TRUE_PROCBASED_CTLS: 0x%016llx\n", g_msrs.vmx_true_procbased_ctls);
        rdmsrl(MSR_IA32_VMX_TRUE_EXIT_CTLS, g_msrs.vmx_true_exit_ctls);
        pr_info("MSR_IA32_VMX_TRUE_EXIT_CTLS: 0x%016llx\n", g_msrs.vmx_true_exit_ctls);  
        rdmsrl(MSR_IA32_VMX_TRUE_ENTRY_CTLS, g_msrs.vmx_true_entry_ctls);
        pr_info("MSR_IA32_VMX_TRUE_ENTRY_CTLS: 0x%016llx\n", g_msrs.vmx_true_entry_ctls); 
        rdmsrl(MSR_IA32_VMX_TRUE_EXIT_CTLS, g_msrs.vmx_true_exit_ctls);
        pr_info("MSR_IA32_VMX_TRUE_EXIT_CTLS: 0x%016llx\n", g_msrs.vmx_true_exit_ctls); 
    }
}

int init_module(void) {
	unsigned int vmxon_order;
    void *vmxon_vaddr, *vmcs_vaddr;
    unsigned long host_cr0, host_cr4;
    unsigned long tmp1, tmp2;

    pr_info("Ahoy-hoy!\n");

    if (num_possible_cpus() > 1) { /* we don't protect against cpu hotplugging*/
        pr_info("This demo only works on uniprocessor hosts!\n");
        pr_info("num_possible_cpus() = %u\n", num_possible_cpus());
        return -1;
    }

    /* [SDM 23.6] Check VMX support */
    if (!(cpuid_ecx(1) & BIT_llu(5))) {
        pr_info("VMX not supported (CPUID.1:ECX.VMX[bit 5] = 0)\n");
        return -1;
    }

    host_cr0 = read_cr0();
    /* NOTE on reading and writting host cr4:
       looking at arch/x86/kvm/vmx/vmx.c:hardware_enable() and kvm_cpu_vmxon(),
       reads and writes to cr4 are done with cr4_read_shadow(), cr4_set_bits()
       and cr4_clear_bits() instead of __read_cr4() and __write_cr4(), the latter
       not even being exported by the kernel (I suspect for a reason).
       Internally the cr4_* functions seem to cache the values, and the wirte
       ones update both the cache and issue the mov cr4.
    */
    host_cr4 = cr4_read_shadow();
    pr_info("host_cr0 = 0x%016lx\n", host_cr0);
    pr_info("host_cr4 = 0x%016lx\n", host_cr4);

    /* Fail if VMX is already enabled */
    if (host_cr4 & BIT_lu(13)) {
        pr_info("Failing because VMX is busy (running another hypervisor?)\n");
        return -1;
    }

    /* Check if VMX is disabled by BIOS. [SDM 3C 31.5] tells us to do it right
       before executing VMXON but kvm does it earlier
       (see arch/x86/kvm/x86.c:kvm_arch_init()). It seems ok to do it now. */

    if (vmx_disabled_by_bios()) {
        pr_info("VMX disabled by BIOS, please enable VMX\n");
        return -1;
    }

    rdmsrl(MSR_IA32_VMX_BASIC, g_msrs.vmx_basic);
    rdmsrl(MSR_IA32_VMX_CR0_FIXED0, g_msrs.vmx_cr0_fixed0);
    rdmsrl(MSR_IA32_VMX_CR0_FIXED1, g_msrs.vmx_cr0_fixed1);
    rdmsrl(MSR_IA32_VMX_CR4_FIXED0, g_msrs.vmx_cr4_fixed0);
    rdmsrl(MSR_IA32_VMX_CR4_FIXED1, g_msrs.vmx_cr4_fixed1);
    pr_info("MSR_IA32_VMX_BASIC: 0x%016llx\n", g_msrs.vmx_basic);
    pr_info("MSR_IA32_VMX_CR0_FIXED0: 0x%016llx\n", g_msrs.vmx_cr0_fixed0);
    pr_info("MSR_IA32_VMX_CR0_FIXED1: 0x%016llx\n", g_msrs.vmx_cr0_fixed1);
    pr_info("MSR_IA32_VMX_CR4_FIXED0: 0x%016llx\n", g_msrs.vmx_cr4_fixed0);
    pr_info("MSR_IA32_VMX_CR4_FIXED1: 0x%016llx\n", g_msrs.vmx_cr4_fixed1);

    read_vmx_capability_msrs();


    /* [SDM 3D Appendix A.1 ] On Intel 64 this bit has to be 0 */
    if (g_msrs.vmx_basic & BIT_llu(48)) {
        pr_info("Phys addr width as reported by MSR VMX_BASIC.48 is invalid\n");
        return -1;
    }

    /* [SDM 3D Appendix A.1] Assert that the reported memory type for VMCS
       and others is of write-back type. XXX: Do we really need this? */
    if (((g_msrs.vmx_basic >> 50) & 0xf) != 6) {
        pr_info("Reported mem type for VMCS is not write-back (WB)");
        return -1;
    }

    // TODO: Determine vmx capabilities? (31.5)

    /* [SDM 3C 31.5] Create VMXON region XXX: Hosted in cache coherent mem?
       XXX: We reserve the mem closer to the local cpu node XXX: non pageable?*/
    g_vmxon_sz = (g_msrs.vmx_basic >> 32) & 0x1fff;
    vmxon_order = ORDER(g_vmxon_sz);
    pr_info("g_vmxon_sz = %llu\n", g_vmxon_sz);

    g_vmxon_pgs = alloc_pages(GFP_KERNEL, vmxon_order);
    if (!g_vmxon_pgs) {
        pr_info("alloc_pages() failed when allocating VMXON region "
                "order = %u\n", vmxon_order);
        return -1;
    }

    vmxon_vaddr = page_address(g_vmxon_pgs);
    g_vmxon_paddr = __pa(vmxon_vaddr);
    pr_info("Allocated VMXON region: order = %u vmxon_vaddr = 0x%p "
            "g_vmxon_paddr = 0x%p\n", vmxon_order, vmxon_vaddr,
            (void *) g_vmxon_paddr);

    /* [SDM 3C 31.5 & Appx. 3D A.1] Initialize version id in VMXON region
       XXX: Should we make this volatile? */
    *((unsigned int *)vmxon_vaddr) =
        (unsigned int)(g_msrs.vmx_basic & 0x7fffffff);

    /* [SDM 3C 31.5] Ensure host cr0 has the necessary fixed to 1 bits set
       and the necessary fixed to 0 bits cleared. We don't change cr0 to
       not mess with the kernel, we just fail if the conditions are not met.
       This will guarantee host is in protected mode with paging enabled.
       This is just a sanity check, it is probably not necessary.

       NOTE: When a bit is 1 in both msrs, it has to be 1 in cr*.
             When a bit is 0 in both msrs, it has to be 0 in cr*
             [SDM Appx. 3D A.7]
    */
    tmp1 = (unsigned long) (g_msrs.vmx_cr0_fixed0 & g_msrs.vmx_cr0_fixed1);
    tmp2 = (unsigned long) (g_msrs.vmx_cr0_fixed0 | g_msrs.vmx_cr0_fixed1);
    if ((tmp1 != (tmp1 & host_cr0)) || (tmp2 != (tmp2 | host_cr0))) {
        pr_info("Failed host cr0 fixed bits check\n");
        goto fail_free_vmxon_pgs;
    }

    /* [SDM 3C 31.5] Enable VMX by setting CR4.VMXE[bit 13] and do the fixed
       bits check on cr4 just like we did with cr0 above.
       We also check again if VMX is busy to minimize the risk of a race */
    host_cr4 = cr4_read_shadow();
    if (host_cr4 & BIT_lu(13)) goto fail_free_vmxon_pgs;
    cr4_set_bits(BIT_lu(13));
    host_cr4 = cr4_read_shadow();
    pr_info("host_cr4 after setting VMXE[bit 13] = %016lx\n", host_cr4);

    tmp1 = (unsigned long) (g_msrs.vmx_cr4_fixed0 & g_msrs.vmx_cr4_fixed1);
    tmp2 = (unsigned long) (g_msrs.vmx_cr4_fixed0 | g_msrs.vmx_cr4_fixed1);
    if ((tmp1 != (tmp1 & host_cr4)) || (tmp2 != (tmp2 | host_cr4))) {
        pr_info("Failed host cr4 fixed bits check\n");
        goto fail_cr4fixed;
    }

    if (__cpu_vmxon(g_vmxon_paddr) < 0) goto fail_cr4fixed;
    pr_info("Successfully entered VMX root operation!\n");


    /* Allocate a page of memory where the guest is gonna have its code and
       and data. In this intial version, the guest is gonna have paging disabled
       and will access host physical memory directly (yes, dangerous) */
    g_guestpg = alloc_page(GFP_KERNEL);
    if (!g_guestpg) {
        pr_info("allog_page() failed when allocating guest page.");
        goto fail_alloc_guestpg;
    }

    /* fill guest page with HLT instruction */
    memset(page_address(g_guestpg), 0xf4, 4096);

    /* [SDM 3C 31.6] Create VMCS region */
    g_vmcs_pgs = alloc_pages(GFP_KERNEL, vmxon_order);
    if (!g_vmcs_pgs) {
        pr_info("alloc_pages() failed when allocating VMCS "
                "order = %u\n", vmxon_order);
        goto fail_alloc_vmcs;
    }

    vmcs_vaddr = page_address(g_vmcs_pgs);
    memset(vmcs_vaddr, 0, g_vmxon_sz);
    g_vmcs_paddr = __pa(vmcs_vaddr);
    pr_info("Allocated VMXCS region: order = %u vmxon_vaddr = 0x%p "
            "g_vmxon_paddr = 0x%p\n", vmxon_order, vmcs_vaddr,
            (void *) g_vmcs_paddr);

    /* [SDM 3C 31.6 & Appx. 3D A.1] Initialize version id in VMCS region
       XXX: Should we make this volatile? */
    *((unsigned int *)vmcs_vaddr) =
        (unsigned int)(g_msrs.vmx_basic & 0x7fffffff);

    if (__cpu_vmclear(g_vmcs_paddr) < 0) goto fail_free_vmcs_pgs;
    if (__cpu_vmptrld(g_vmcs_paddr) < 0) goto fail_free_vmcs_pgs; /* TODO */
    if (setup_vmcs()) goto fail_free_vmcs_pgs;                    /* TODO */
    vmlaunch();

    /* Exit VMX root operation and disable vmx before returning */
    __cpu_vmclear(g_vmcs_paddr);
    __free_pages(g_vmcs_pgs, vmxon_order);
    if (__cpu_vmxoff() < 0) panic("VMXOFF failed\n");
    pr_info("Successfully exited VMX root operation!\n");
    cr4_clear_bits(BIT_lu(13));
    host_cr4 = cr4_read_shadow();
    pr_info("cr4 after vmxoff = %016lx (bt 13 = %lu)\n",
        host_cr4, (host_cr4 & BIT_lu(13)) >> 13);
   __free_pages(g_vmxon_pgs, vmxon_order);

    return 0; /* success */

fail_free_vmcs_pgs:
    __free_pages(g_vmcs_pgs, vmxon_order);
fail_alloc_vmcs:
    if (__cpu_vmxoff() < 0) panic("VMXOFF failed\n");
fail_alloc_guestpg:
fail_cr4fixed:
   cr4_clear_bits(BIT_lu(13));
fail_free_vmxon_pgs:
   __free_pages(g_vmxon_pgs, vmxon_order);

    return -1; /* fail */
}

void cleanup_module(void) {
	pr_info("Bye!\n");
}

/* module_init(init_module);
   module_exit(cleanup_module); */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("hMihaiDavid");
MODULE_DESCRIPTION("WIP hypervisor for Linux x86_64 (Intel VMX)");
MODULE_VERSION("0.01");
