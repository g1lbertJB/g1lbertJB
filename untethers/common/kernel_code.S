.globl _kernel_code_start
.globl _kernel_code_end

.thumb

#define LoadRegister(_Data, _Reg) \
    adr     _Reg, _Data     ;     \
    ldr     _Reg, [_Reg]

#define CallFunction(_Data)           \
    LoadRegister(_Data, r12)     ;    \
    blx     r12

#define Patch(_Offset, _Patch)        \
    LoadRegister(_Offset, r0)    ;    \
    LoadRegister(_Patch, r1)     ;    \
    str     r1, [r0]

.align 4
_kernel_code_start:
    push    {lr}

    /* Print hello string. */
    adr     r0, _helloString
    CallFunction(_ioLogPtr)

    /* Kernel patch */
    Patch(_csEnforcementPtr, _csEnforcementPatch)
    Patch(_vmEnterPtr, _vmEnterPatch)
    Patch(_taskForPid0, _taskForPid0Patch)
    Patch(_PE_Debugger, _PE_Debugger_Patch)

    /* Fix up nx */
    LoadRegister(_nxEnabled, r0)
    movs    r1, #1
    strb    r1, [r0]
    subs    r0, #1
    movs    r1, #0
    strb    r1, [r0]

    /* Fix up sysent */
    Patch(_sysentCall0, _nosys)

    /* Flush and clear cache */
    movs    r0, #0
    CallFunction(_flushIcache)
    CallFunction(_clearDcache)

    /* We're done. */
    adr     r0, _hello2
    CallFunction(_ioLogPtr)

    /* Success */
    mov     r0, #0
    pop     {pc}

.align 4
_helloString:
    .asciz "WE R NOT #FAKR, UNTHREADEDJB IS REEL\n"
    .align 4
_hello2:
    .asciz "tanks 2 @planetbeing n @posixninja n @chronicdev for #explot code in rkcy raccon :) :) :)\nkrnl patchs from #opensn0w ))\n"
    .align 4
_ioLogPtr:
    .long (KERNEL_IOLOG)

/* kernel patches */
_csEnforcementPtr:
    .long KERNEL_CS_ENFORCEMENT    // offset
_csEnforcementPatch:
    .long 0x23016aa2    // mov r3, #1

_vmEnterPtr:
    .long KERNEL_VM_ENTER    // offset
_vmEnterPatch:
    .long 0xbf0428ff    // cmp r0, #0xff

_taskForPid0:
    .long KERNEL_TASK_FOR_PID0    // offset
_taskForPid0Patch:
    .long 0xe0069101    // branch

_PE_Debugger:
    .long KERNEL_PE_DEBUGGER    // offset
_PE_Debugger_Patch:
    .long 0x47702001    // movs r0, #1

_nxEnabled:
    .long   KERNEL_NX_ENABLE
_sysentCall0:
    .long   KERNEL_SYSCALL0
_nosys:
    .long   KERNEL_SYSCALL0_VALUE
_flushIcache:
    .long   KERNEL_FLUSH_DCACHE
_clearDcache:
    .long   KERNEL_FLUSH_DCACHE


.align 2
_kernel_code_end:
    nop

