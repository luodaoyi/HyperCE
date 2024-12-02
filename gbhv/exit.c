#include "exit.h"
#include "ept.h"
#include "vmcs_encodings.h"

/*
 * Intialize fields of the exit context based on values read from the VMCS.
 */
VOID VmxInitializeExitContext(PVMEXIT_CONTEXT ExitContext, PGPREGISTER_CONTEXT GuestRegisters)
{
	VMX_ERROR VmError;

	VmError = 0;

	OsZeroMemory(ExitContext, sizeof(VMEXIT_CONTEXT));

	/*
	 * Store pointer of the guest register context on the stack to the context for later access.
	 */
	ExitContext->GuestContext = GuestRegisters;

	/* By default, we increment RIP unless we're handling an EPT violation. */
	ExitContext->ShouldIncrementRIP = TRUE;

	/* By default, we continue execution. */
	ExitContext->ShouldStopExecution = FALSE;

	// Guest RSP at the time of exit
	VmxVmreadFieldToImmediate(VMCS_GUEST_RSP, &ExitContext->GuestContext->GuestRSP);

	// Guest RIP at the time of exit
	VmxVmreadFieldToImmediate(VMCS_GUEST_RIP, &ExitContext->GuestRIP);

	// Guest RFLAGS at the time of exit
	VmxVmreadFieldToImmediate(VMCS_GUEST_RFLAGS, &ExitContext->GuestFlags.RFLAGS);

	// The type of exit
	VmxVmreadFieldToRegister(VMCS_EXIT_REASON, &ExitContext->ExitReason);

	// Additional information about specific types of exits
	VmxVmreadFieldToImmediate(VMCS_EXIT_QUALIFICATION, &ExitContext->ExitQualification);

	// Length of the exiting instruction
	VmxVmreadFieldToImmediate(VMCS_VMEXIT_INSTRUCTION_LENGTH, &ExitContext->InstructionLength);

	// Information about the faulting instruction
	VmxVmreadFieldToImmediate(VMCS_VMEXIT_INSTRUCTION_INFO, &ExitContext->InstructionInformation);

	// Guest physical address during EPT exits
	VmxVmreadFieldToImmediate(VMCS_GUEST_PHYSICAL_ADDRESS, &ExitContext->GuestPhysicalAddress);
}


VOID HvExitHandleCpuid(PVMM_PROCESSOR_CONTEXT ProcessorContext, PVMEXIT_CONTEXT ExitContext)
{
	INT32 CPUInfo[4];

	UNREFERENCED_PARAMETER(ProcessorContext);

	// Perform actual CPUID
	__cpuidex(CPUInfo, (int)ExitContext->GuestContext->GuestRAX, (int)ExitContext->GuestContext->GuestRCX);

	// If guest is requesting version information
	if(ExitContext->GuestContext->GuestRAX == CPUID_VERSION_INFORMATION)
	{
		// Tell them that VMX is not a supported feature of our virtual processor.
		CPUInfo[2] = (INT32)HvUtilBitClearBit(CPUInfo[2], CPUID_VMX_ENABLED_BIT);
	}

	/*
	 * Give guest the results of the CPUID call.
	 */
	ExitContext->GuestContext->GuestRAX = CPUInfo[0];
	ExitContext->GuestContext->GuestRBX = CPUInfo[1];
	ExitContext->GuestContext->GuestRCX = CPUInfo[2];
	ExitContext->GuestContext->GuestRDX = CPUInfo[3];
}

VOID HvExitHandleEptMisconfiguration(PVMM_PROCESSOR_CONTEXT ProcessorContext, PVMEXIT_CONTEXT ExitContext)
{
	UNREFERENCED_PARAMETER(ProcessorContext);

	HvUtilLogError("EPT Misconfiguration! A field in the EPT paging structure was invalid. Faulting guest address: 0x%llX\n", ExitContext->GuestPhysicalAddress);

	ExitContext->ShouldIncrementRIP = FALSE;
	ExitContext->ShouldStopExecution = TRUE;

	// We can't continue now. EPT misconfiguration is a fatal exception that will probably crash the OS if we don't get out *now*.
}

VOID HvExitHandleUnknownExit(PVMM_PROCESSOR_CONTEXT ProcessorContext, PVMEXIT_CONTEXT ExitContext)
{
	UNREFERENCED_PARAMETER(ProcessorContext);

	__debugbreak();
	HvUtilLogError("Unknown exit reason! An exit was made but no handler was configured to handle it. Reason: 0x%llX\n", ExitContext->ExitReason.BasicExitReason);

	// Try to keep executing, despite the unknown exit.
	ExitContext->ShouldIncrementRIP = TRUE;
	
}

VOID HvExitHandleReadMsrExit(PVMM_PROCESSOR_CONTEXT ProcessorContext, PVMEXIT_CONTEXT ExitContext)
{
	UNREFERENCED_PARAMETER(ProcessorContext);

	union __msr msr;
	unsigned __int64 msr_index = ExitContext->GuestContext->GuestRCX;
	switch (msr_index)
	{
	case IA32_INTERRUPT_SSP_TABLE_ADDR:
		msr.all = HvUtilVmRead(GUEST_INTERRUPT_SSP_TABLE_ADDR);
		break;

	case IA32_SYSENTER_CS:
		msr.all = HvUtilVmRead(GUEST_SYSENTER_CS);
		break;

	case IA32_SYSENTER_EIP:
		msr.all = HvUtilVmRead(GUEST_SYSENTER_EIP);
		break;

	case IA32_SYSENTER_ESP:
		msr.all = HvUtilVmRead(GUEST_SYSENTER_ESP);
		break;

	case IA32_S_CET:
		msr.all = HvUtilVmRead(GUEST_S_CET);
		break;

	case IA32_PERF_GLOBAL_CTRL:
		msr.all = HvUtilVmRead(GUEST_PERF_GLOBAL_CONTROL);
		break;

	case IA32_PKRS:
		msr.all = HvUtilVmRead(GUEST_PKRS);
		break;

	case IA32_RTIT_CTL:
		msr.all = HvUtilVmRead(GUEST_RTIT_CTL);
		break;

	case IA32_BNDCFGS:
		msr.all = HvUtilVmRead(GUEST_BNDCFGS);
		break;

	case IA32_PAT:
		msr.all = HvUtilVmRead(GUEST_PAT);
		break;

	case IA32_EFER:
		msr.all = HvUtilVmRead(GUEST_EFER);
		break;

	case IA32_GS_BASE:
		msr.all = HvUtilVmRead(GUEST_GS_BASE);
		break;

	case IA32_FS_BASE:
		msr.all = HvUtilVmRead(GUEST_FS_BASE);
		break;

	default:
		msr.all = __readmsr(msr_index);
		break;
	}


	ExitContext->GuestContext->GuestRDX = msr.high;
	ExitContext->GuestContext->GuestRCX = msr.low;
	ExitContext->ShouldIncrementRIP = TRUE;
}


VOID HvExitHandleWriteMsrExit(PVMM_PROCESSOR_CONTEXT ProcessorContext, PVMEXIT_CONTEXT ExitContext)
{
	UNREFERENCED_PARAMETER(ProcessorContext);

	unsigned __int64 msr_index = ExitContext->GuestContext->GuestRCX;
	union __msr msr;
	msr.high = ExitContext->GuestContext->GuestRDX;
	msr.low = ExitContext->GuestContext->GuestRAX;

	switch (msr_index)
	{
	case IA32_INTERRUPT_SSP_TABLE_ADDR:
		 HvUtilVmWrite(GUEST_INTERRUPT_SSP_TABLE_ADDR, msr.all);
		break;

	case IA32_SYSENTER_CS:
		 HvUtilVmWrite(GUEST_SYSENTER_CS, msr.all);
		break;

	case IA32_SYSENTER_EIP:
		 HvUtilVmWrite(GUEST_SYSENTER_EIP, msr.all);
		break;

	case IA32_SYSENTER_ESP:
		 HvUtilVmWrite(GUEST_SYSENTER_ESP, msr.all);
		break;

	case IA32_S_CET:
		 HvUtilVmWrite(GUEST_S_CET, msr.all);
		break;

	case IA32_PERF_GLOBAL_CTRL:
		 HvUtilVmWrite(GUEST_PERF_GLOBAL_CONTROL, msr.all);
		break;

	case IA32_PKRS:
		 HvUtilVmWrite(GUEST_PKRS, msr.all);
		break;

	case IA32_RTIT_CTL:
		 HvUtilVmWrite(GUEST_RTIT_CTL, msr.all);
		break;

	case IA32_BNDCFGS:
		 HvUtilVmWrite(GUEST_BNDCFGS, msr.all);
		break;

	case IA32_PAT:
		 HvUtilVmWrite(GUEST_PAT, msr.all);
		break;

	case IA32_EFER:
		 HvUtilVmWrite(GUEST_EFER, msr.all);
		break;

	case IA32_GS_BASE:
		 HvUtilVmWrite(GUEST_GS_BASE, msr.all);
		break;

	case IA32_FS_BASE:
		 HvUtilVmWrite(GUEST_FS_BASE, msr.all);
		break;

	default:
		__writemsr(msr_index, msr.all);
		break;
	}

	ExitContext->ShouldIncrementRIP = TRUE;
}


/**
 * Dispatch to the correct handler function given the exit code.
 */
BOOL HvExitDispatchFunction(PVMM_PROCESSOR_CONTEXT ProcessorContext, PVMEXIT_CONTEXT ExitContext)
{
	VMX_ERROR VmError;
	SIZE_T GuestInstructionLength;

	VmError = 0;

	/*
	 * Choose an appropriate function to handle our exit.
	 */
	switch (ExitContext->ExitReason.BasicExitReason)
	{
		/*
		 * The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,1
		 * INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
		 * VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
		 *
		 * GETSEC will never exit because we will never run in SMX mode.
		 */
	case VMX_EXIT_REASON_EXECUTE_CPUID:
		HvExitHandleCpuid(ProcessorContext, ExitContext);
		break;
	case VMX_EXIT_REASON_EXECUTE_INVD:
		__wbinvd();
		break;
	case VMX_EXIT_REASON_EXECUTE_XSETBV:
		_xsetbv((UINT32)ExitContext->GuestContext->GuestRCX,
			ExitContext->GuestContext->GuestRDX << 32 |
			ExitContext->GuestContext->GuestRAX);
		break;
	case VMX_EXIT_REASON_EPT_MISCONFIGURATION:
		HvExitHandleEptMisconfiguration(ProcessorContext, ExitContext);
		break;
	case VMX_EXIT_REASON_EPT_VIOLATION:
		HvExitHandleEptViolation(ProcessorContext, ExitContext);
		break;
	case VMX_EXIT_REASON_EXECUTE_RDMSR:
		HvExitHandleReadMsrExit(ProcessorContext, ExitContext);
		break;
	case VMX_EXIT_REASON_EXECUTE_WRMSR:
		HvExitHandleWriteMsrExit(ProcessorContext, ExitContext);
		break;
	default:
		HvExitHandleUnknownExit(ProcessorContext, ExitContext);
		break;
	}

	if (ExitContext->ShouldStopExecution)
	{
		HvUtilLogError("HvExitDispatchFunction: Leaving VMX mode.\n");
		return FALSE;
	}

	/* If we're an 'instruction' exit, we need to act like a fault handler and move the instruction pointer forward. */
	if(ExitContext->ShouldIncrementRIP)
	{
		VmxVmreadFieldToImmediate(VMCS_VMEXIT_INSTRUCTION_LENGTH, &GuestInstructionLength);

		ExitContext->GuestRIP += GuestInstructionLength;

		VmxVmwriteFieldFromImmediate(VMCS_GUEST_RIP, ExitContext->GuestRIP);
	}

	return TRUE;
}
