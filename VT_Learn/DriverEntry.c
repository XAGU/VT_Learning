#include <ntifs.h>
#include "vtasm.h"
#include "vtsystem.h"

void DriverUnLoad(PDRIVER_OBJECT pDriverObj)
{
	StopVirtualTechnology();
	KdPrint(("驱动卸载成功！"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING usRegPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	pDriverObj->DriverUnload = DriverUnLoad;
	KdPrint(("驱动安装成功！"));
	Status = StartVirtualTechnology();
	return Status;
}