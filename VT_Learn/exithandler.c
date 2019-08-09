#include "exithandler.h"
#include "vtsystem.h"
#include "vtasm.h"

void __declspec(naked) VMMEntryPoint(void)
{
	__asm
	{
		int 3
	}
}