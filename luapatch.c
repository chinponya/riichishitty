// awful

#include <direct.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>

#define _AMD64_
#include "detours.h"
#undef _AMD64_

#define OUTPUT_DIRECTORY "luapatch"
#define XLUA_DLL_NAME "tolua.dll"
#define XLUA_LOADBUFFER_NAME "tolua_loadbuffer"

#define SEPARATOR '/'

#pragma comment (lib, "detours")
#pragma comment (lib, "user32")

typedef int (*xluaL_loadbuffer_func)(void *, const char *, int, const char *);
static xluaL_loadbuffer_func impl_xluaL_loadbuffer_func = NULL;

int hkxluaL_loadbuffer(void *L, const char *buff, int size, const char *name)
{
	printf("%s: loading %s...\n", __FUNCTION__, name);
	char path[MAX_PATH] = { '\0' };
	snprintf(path, MAX_PATH, "%s/%s.lua", OUTPUT_DIRECTORY, name);
	FILE *fp;
	fopen_s(&fp, name, "rb");
	if(fp) {
		printf("loading %s from %s instead\n", name, path);
		fseek(fp, 0, SEEK_END);
		size_t fz = ftell(fp);
		rewind(fp);

		if(fz > size) {
			// XXX: is this safe?
			realloc((void *)buff, fz);
		}
		memset((void *)buff, 0, fz > size ? fz : size);
		fread((void *)buff, sizeof(unsigned char), fz, fp);
		fclose(fp);
	}

	return impl_xluaL_loadbuffer_func(L, buff, size, name);
}

void entrypoint()
{
	if(_mkdir(OUTPUT_DIRECTORY) == -1 && errno != EEXIST) {
		printf("Failed to create %s (%d)! Spinning.\n", OUTPUT_DIRECTORY, errno);
		while(1) { }
	}
	while(!GetModuleHandle(XLUA_DLL_NAME)) {
		printf("Failed to get handle to %s... sleeping (1s)\n", XLUA_DLL_NAME);
		Sleep(1000);
	}
	impl_xluaL_loadbuffer_func = (xluaL_loadbuffer_func)GetProcAddress(GetModuleHandle(XLUA_DLL_NAME), XLUA_LOADBUFFER_NAME);
	if(!impl_xluaL_loadbuffer_func) {
		printf("Failed to get %s! Spinning.\n", XLUA_LOADBUFFER_NAME);
		while(1) { };
	}
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	LONG ret = DetourAttach((void **)&impl_xluaL_loadbuffer_func, (void **)hkxluaL_loadbuffer);
	if(ret) {
		printf("Failed to hook %s: %ld! Spinning.\n", XLUA_LOADBUFFER_NAME, ret);
		while(1) { };
	}
	DetourTransactionCommit();
	printf("Hooked %s. Goodbye.\n", XLUA_LOADBUFFER_NAME);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	if(fdwReason == DLL_PROCESS_ATTACH) {
		bool headless = false;
		if(!AttachConsole(ATTACH_PARENT_PROCESS)) {
			if(!AllocConsole()) {
				MessageBox(NULL, "Failed to allocate a new console!\nContinuing anyway, but we're going to be headless for the rest of this!", "luadump", MB_ICONERROR | MB_OK);
				bool headless = true;
			}
		}
		if(!headless) {
			freopen_s((FILE **)stdin, "CONIN$", "r", stdin);
			freopen_s((FILE **)stdout, "CONOUT$", "w", stdout);
		}
		DisableThreadLibraryCalls(hinstDLL);
		CreateThread(NULL, 0x1000, (LPTHREAD_START_ROUTINE)entrypoint, NULL, 0, NULL);
	}
	return TRUE;
}