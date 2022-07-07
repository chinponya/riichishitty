// clang luadump.c -o luadump.dll -shared
// Inject into GF2_Exilium.
// An alternative to this is decrypting assets-config-lua.ab, and extracting the files from there.
// This alternative is recommended for more "pure" dumps, but for quick 'n' dirty ones, this DLL should suffice.

#include <direct.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <Windows.h>

#define _AMD64_
#include "detours.h"
#undef _AMD64_

#define OUTPUT_DIRECTORY "luachunks"
#define XLUA_DLL_NAME "tolua.dll"
#define XLUA_LOADBUFFER_NAME "tolua_loadbuffer"

#define SEPARATOR '/'

#pragma comment (lib, "detours")
#pragma comment (lib, "user32")

typedef int (*xluaL_loadbuffer_func)(void *, const char *, int, const char *);
static xluaL_loadbuffer_func impl_xluaL_loadbuffer_func = NULL;

void create_directories(const char *path)
{
	char dir[MAX_PATH] = { '\0' };
	char tmp[MAX_PATH] = { '\0' };
	char *sep = strchr(path, SEPARATOR);
	while(sep) {
		int len = sep - path;
		memcpy(tmp, path, len);
		tmp[len] = '\0';
		snprintf(dir, MAX_PATH, "%s/%s", OUTPUT_DIRECTORY, tmp);
		_mkdir(dir);
		printf("%s: created %s.\n", __FUNCTION__, dir);
		sep = strchr(sep + 1, SEPARATOR);
	}
}

int hkxluaL_loadbuffer(void *L, const char *buff, int size, const char *name)
{
	char path[MAX_PATH] = { '\0' };
	snprintf(path, MAX_PATH, "%s/%s.lua", OUTPUT_DIRECTORY, name);
	printf("%s: loading %s...\n", __FUNCTION__, name);
	create_directories(name);
	FILE *file;
	int retries = 0;
	while(true) {
		fopen_s(&file, path, "wb");
		if(!file) {
			if(retries >= 5) {
				printf("Failed to open %s for writing! Bye!\n", path);
				TerminateProcess(GetCurrentProcess(), 0);
			}
			printf("Failed to open %s for writing! Sleeping (1s)\n", path);
			Sleep(1000);
			retries++;
		} else {
			break;
		}
	}
	fwrite(buff, sizeof(unsigned char), size, file);
	fclose(file);
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