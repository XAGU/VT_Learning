#include <ntifs.h>
#include "vtasm.h"
#include "vtsystem.h"

void DriverUnLoad(PDRIVER_OBJECT pDriverObj)
{
	StopVirtualTechnology();
	KdPrint(("驱动卸载成功！"));
}

//global

ULONG g_ret_eip;
ULONG g_ret_esp;

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING usRegPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	pDriverObj->DriverUnload = DriverUnLoad;
	KdPrint(("驱动安装成功！"));
	__asm
	{
		pushad
		pushfd
		mov g_ret_eip, offset RET_EIP
		mov g_ret_esp, esp
	}
	Status = StartVirtualTechnology();
	__asm
	{
	RET_EIP:
		popfd
		popad
	}

	//=====================================

	Log("DriverEntry Return !", 0);
	return Status;
}