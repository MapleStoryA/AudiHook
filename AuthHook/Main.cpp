#include "WinsockHax.h"
#include "MemoryEdit.h"
#include <stdio.h>
#include <intrin.h>


struct Packet {
	short len;
	byte type;
	byte subtype;
	byte data[];
};

Packet *packetEcx;


void DumpPacket(Packet *packet) {
	int i;
	unsigned char *p = (unsigned char *)packet;
	printf("Received packet: [%x][%x] Lentgh: %d\n", packet->type, packet->subtype, packet->len);
	for (i = 0; i<128; i++) {
		printf("0x%02x ", p[i]);
		if ((i % 16 == 0) && i)
			printf("\n");
	}
	printf("\n");
}

void PrintPacket(Packet *packet) {
	DumpPacket(packet);
}

void hooked() {

	PrintPacket(packetEcx);
	
}

void __declspec(naked) hook_recv() {
	__asm {
		mov packetEcx, ecx
		pushad 
		call hooked
		popad
		push 0x931BF0
		ret
	}
}


void HookPacket_OnReceive() {
    DWORD *addr = (DWORD*)0x00930EE4;
	MemoryEdit::hookCall((BYTE*)addr, (DWORD)&hook_recv);
}


DWORD dwOld;
SYSTEM_INFO sSysInfo;
DWORD dwJmpBack;
DWORD dwHook = 0x00930EE4;


BOOL WINAPI DllMain(HINSTANCE hinstDLL,  DWORD fdwReason, LPVOID lpvReserved)
{
	DisableThreadLibraryCalls(hinstDLL);
	if(fdwReason == DLL_PROCESS_ATTACH)
	{
		
		/*AllocConsole();
		freopen("CONIN$", "r", stdin);
		freopen("CONOUT$", "w", stdout);
		freopen("CONOUT$", "w", stderr);
		AllocConsole();*/

		const BOOL winsockRet = true;//HaxWinsock();
	
		if (winsockRet == FALSE)
		{
			MessageBox(0, "Internal Hooks Failed", 0, 0);
		}
		HookPacket_OnReceive();
		

		return winsockRet;
	}

	return FALSE;
}