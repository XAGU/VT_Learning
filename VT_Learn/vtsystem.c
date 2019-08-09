#include "vtsystem.h"
#include "vtasm.h"
#include "exithandler.h"

VMX_CPU g_VMXCPU;

static ULONG VmxAdjustControls(ULONG Ctl, ULONG Msr)
{
	LARGE_INTEGER MsrValue;
	MsrValue.QuadPart = Asm_ReadMsr(Msr);
	Ctl &= MsrValue.HighPart;
	Ctl |= MsrValue.LowPart;
	return Ctl;
}

void SetupVMCS()
{
	ULONG GdtBase, IdtBase;
	GdtBase = Asm_GetGdtBase();
	IdtBase = Asm_GetIdtBase();
//1.Guest state fields
//2.host state fields
	Vmx_VmWrite(HOST_CR0, Asm_GetCr0());
	Vmx_VmWrite(HOST_CR3, Asm_GetCr3());
	Vmx_VmWrite(HOST_CR4, Asm_GetCr4());

	Vmx_VmWrite(HOST_ES_SELECTOR, Asm_GetEs() & 0xFFF8);
	Vmx_VmWrite(HOST_CS_SELECTOR, Asm_GetCs() & 0xFFF8);
	Vmx_VmWrite(HOST_DS_SELECTOR, Asm_GetDs() & 0xFFF8);
	Vmx_VmWrite(HOST_FS_SELECTOR, Asm_GetFs() & 0xFFF8);
	Vmx_VmWrite(HOST_GS_SELECTOR, Asm_GetGs() & 0xFFF8);
	Vmx_VmWrite(HOST_SS_SELECTOR, Asm_GetSs() & 0xFFF8);
	Vmx_VmWrite(HOST_TR_SELECTOR, Asm_GetTr() & 0xFFF8);

	Vmx_VmWrite(HOST_TR_BASE, 0x801E3000);


	Vmx_VmWrite(HOST_GDTR_BASE, GdtBase);
	Vmx_VmWrite(HOST_IDTR_BASE, IdtBase);

	Vmx_VmWrite(HOST_IA32_SYSENTER_CS, Asm_ReadMsr(MSR_IA32_SYSENTER_CS) & 0xFFFFFFFF);
	Vmx_VmWrite(HOST_IA32_SYSENTER_ESP, Asm_ReadMsr(MSR_IA32_SYSENTER_ESP) & 0xFFFFFFFF);
	Vmx_VmWrite(HOST_IA32_SYSENTER_EIP, Asm_ReadMsr(MSR_IA32_SYSENTER_EIP) & 0xFFFFFFFF); // KiFastCallEntry

	Vmx_VmWrite(HOST_RSP, ((ULONG)g_VMXCPU.pStack) + 0x1000);     //Host 临时栈
	Vmx_VmWrite(HOST_RIP, (ULONG)VMMEntryPoint);                  //这里定义我们的VMM处理程序入口
//3.vm-control fields
	//3.1. vm execution contro
	Vmx_VmWrite(PIN_BASED_VM_EXEC_CONTROL, VmxAdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
	Vmx_VmWrite(CPU_BASED_VM_EXEC_CONTROL, VmxAdjustControls(0, MSR_IA32_VMX_PROCBASED_CTLS));
	//3.2. vm entry control
	Vmx_VmWrite(VM_ENTRY_CONTROLS, VmxAdjustControls(0, MSR_IA32_VMX_ENTRY_CTLS));
	//3.3. vm exit control
	Vmx_VmWrite(VM_EXIT_CONTROLS, VmxAdjustControls(0, MSR_IA32_VMX_EXIT_CTLS));
	

}

NTSTATUS StartVirtualTechnology()
{
	_CR4 uCr4;
	_EFLAGS uEflags;
	//判断及其是否开启VT
	if (!IsVTEnabled())
	{
		return STATUS_UNSUCCESSFUL;
	}

	//设置CR4第14位为1
	*((ULONG*)&uCr4) = Asm_GetCr4();
	uCr4.VMXE = 1;
	Asm_SetCr4(*((ULONG*)&uCr4));

	//分配一个4k内存，将其物理地址作为Vmx_VmxOn参数
	g_VMXCPU.pVMXONRegion = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'vmx');
	RtlZeroMemory(g_VMXCPU.pVMXONRegion, 0x1000);
	*(ULONG*)g_VMXCPU.pVMXONRegion = 1;
	g_VMXCPU.pVMXONRegion_PA = MmGetPhysicalAddress(g_VMXCPU.pVMXONRegion);

	//开启VMX
	Vmx_VmxOn(g_VMXCPU.pVMXONRegion_PA.LowPart, g_VMXCPU.pVMXONRegion_PA.HighPart);
	//判断开启是否成功
	*((ULONG*)&uEflags) = Asm_GetEflags();
	if (uEflags.CF != 0)
	{
		Log("ERROR:VMXON指令调用失败！", 0);
		ExFreePool(g_VMXCPU.pVMXONRegion);
		return STATUS_UNSUCCESSFUL;
	}
	Log("SUCCESS:VMXON指令调用成功！", 1);

	//分配一个4k内存，将其物理地址作为Vmx_clear参数
	g_VMXCPU.pVMCSRegion = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'vmcs');
	RtlZeroMemory(g_VMXCPU.pVMCSRegion, 0x1000);
	*(ULONG*)g_VMXCPU.pVMCSRegion = 1;
	g_VMXCPU.pVMCSRegion_PA = MmGetPhysicalAddress(g_VMXCPU.pVMCSRegion);
	//分配栈空间
	g_VMXCPU.pStack = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'stck');
	RtlZeroMemory(g_VMXCPU.pStack, 0x1000);

	Vmx_VmClear(g_VMXCPU.pVMCSRegion_PA.LowPart, g_VMXCPU.pVMCSRegion_PA.HighPart);
	Log("SUCCESS:VMCLEAR指令调用成功!", 0)
	//选择机器
	Vmx_VmPtrld(g_VMXCPU.pVMCSRegion_PA.LowPart, g_VMXCPU.pVMCSRegion_PA.HighPart);



	void SetupVMCS();

	Vmx_VmLaunch();
	//=======================================================
	Log("ERROR:Vmx_VmLaunch指令调用失败!", Vmx_VmRead(VM_INSTRUCTION_ERROR));
	return STATUS_SUCCESS;
}

NTSTATUS StopVirtualTechnology()
{
	_CR4 uCr4;
	//关闭VMX
	Vmx_VmxOff();
	//置Cr4 VMXE位为0
	*((ULONG*)&uCr4) = Asm_GetCr4();
	uCr4.VMXE = 0;
	Asm_SetCr4(*((ULONG*)&uCr4));
	//释放内存
	ExFreePool(g_VMXCPU.pVMXONRegion);
	ExFreePool(g_VMXCPU.pVMCSRegion);
	Log("SUCCESS:VMXOFF指令调用成功！", 1);
	return STATUS_SUCCESS;
}

static BOOLEAN IsVTEnabled()
{
	ULONG       uRet_EAX, uRet_ECX, uRet_EDX, uRet_EBX;
	_CPUID_ECX  uCPUID;
	_CR0        uCr0;
	_CR4    uCr4;
	IA32_FEATURE_CONTROL_MSR msr;
	//1. CPUID
	Asm_CPUID(1, &uRet_EAX, &uRet_EBX, &uRet_ECX, &uRet_EDX);
	*((PULONG)&uCPUID) = uRet_ECX;

	if (uCPUID.VMX != 1)
	{
		Log("ERROR: 这个CPU不支持VT!", 0);
		return FALSE;
	}

	// 2. MSR
	*((PULONG)&msr) = (ULONG)Asm_ReadMsr(MSR_IA32_FEATURE_CONTROL);
	if (msr.Lock != 1)
	{
		Log("ERROR:VT指令未被锁定!", 0);
		return FALSE;
	}

	// 3. CR0 CR4
	*((PULONG)&uCr0) = Asm_GetCr0();
	*((PULONG)&uCr4) = Asm_GetCr4();

	if (uCr0.PE != 1 || uCr0.PG != 1 || uCr0.NE != 1)
	{
		Log("ERROR:这个CPU没有开启VT!", 0);
		return FALSE;
	}

	if (uCr4.VMXE == 1)
	{
		Log("ERROR:这个CPU已经开启了VT!", 0);
		Log("可能是别的驱动已经占用了VT，你必须关闭它后才能开启。", 0);
		return FALSE;
	}


	Log("SUCCESS:这个CPU支持VT!", 0);
	return TRUE;
}