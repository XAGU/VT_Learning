#include "exithandler.h"
#include "vtsystem.h"
#include "vtasm.h"


GUEST_REGS g_GuestRegs;

static void VMMEntryPointEbd()
{
	ULONG ExitReason;
	ULONG ExitInstructionLength;
	ULONG GuestResumeEIP;
	ExitReason					= Vmx_VmRead(VM_EXIT_REASON);
	ExitInstructionLength		= Vmx_VmRead(VM_EXIT_INSTRUCTION_LEN);
	g_GuestRegs.eip				= Vmx_VmRead(GUEST_RIP);
	g_GuestRegs.eflags			= Vmx_VmRead(GUEST_RFLAGS);
	g_GuestRegs.esp				= Vmx_VmRead(GUEST_RSP);
	Log("g_GuestRegs.eip", g_GuestRegs.eip);
	__asm int 3


}



void __declspec(naked) VMMEntryPoint(void)
{
	__asm
	{
		mov ax,fs
		mov fs,ax
		mov ax,gs
		mov gs,ax
	}
	VMMEntryPointEbd();
}