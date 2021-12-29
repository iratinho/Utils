/*
*MIT License
Copyright (c) 2021 iratinho
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#pragma once
#include "Windows.h"
#include <TlHelp32.h>
#include <functional>
#include <tchar.h>

namespace WindowsUtils
{
#ifdef UNICODE
#define _strlen_(x) wcslen(x)
#define _strcmp_(x, y) wcscmp(x, y)
#else
#define _strlen_(x) strlen(x)
#define _strcmp_(x, y) strcmp(x, y)
#endif
    
    inline DWORD FindProcessID(const TCHAR* ProcessName)
    {
        PROCESSENTRY32 ProcessEntry;
        ZeroMemory(&ProcessEntry, sizeof ProcessEntry);
        ProcessEntry.dwSize = sizeof ProcessEntry;

        // Traverse process's to find the process id for our target process name
        const HANDLE ProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (Process32First(ProcessSnapshot, &ProcessEntry))
        {
            do
            {
                if (!_strcmp_(ProcessEntry.szExeFile, ProcessName))
                {
                    CloseHandle(ProcessSnapshot);
                    return ProcessEntry.th32ProcessID;
                }
            }while (Process32Next(ProcessSnapshot, &ProcessEntry));
        }

        return {};
    }

    inline BYTE* FindModuleBaseAddress(DWORD ProcessID, const TCHAR* ModuleName)
    {
        MODULEENTRY32 ModuleEntry;
        ZeroMemory(&ModuleEntry, sizeof ModuleEntry);
        ModuleEntry.dwSize = sizeof ModuleEntry;

        // Traverse modules in this process to find our target module
        const HANDLE ModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessID);
        if (Module32First(ModuleSnapshot, &ModuleEntry))
        {
            do
            {
                if (!_strcmp_(ModuleEntry.szModule, ModuleName))
                {
                    CloseHandle(ModuleSnapshot);
                    return ModuleEntry.modBaseAddr;
                }
            }while (Module32Next(ModuleSnapshot, &ModuleEntry));
        }

        return {};
    }

    // JMP instruction length
    #define JMP_LENGTH 5
    #define DEFINE_TRAMPOLINE_FUNC(Ret, Call_Convention, ...) typedef Ret(Call_Convention* TrampolineFuncPtr)(__VA_ARGS__)

    inline void ScopedVirtualProtect(_In_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flNewProtect, std::function<void()> Data)
    {
        DWORD OldProtection;
        VirtualProtect(lpAddress, dwSize, flNewProtect, &OldProtection);

        Data();

        DWORD Temp;
        VirtualProtect(lpAddress, dwSize, OldProtection, &Temp);
    }

    inline void InstallDetour32(BYTE* Src, BYTE* Dest, size_t Length, size_t MangledBytes)
    {
        ScopedVirtualProtect(Src, Length, PAGE_EXECUTE_READWRITE, [&]()
        {
            memset(Src, 0x90, Length + MangledBytes);
            *Src = 0xE9;
            *(uintptr_t*)((uintptr_t)Src + 1) = (uintptr_t)Dest - (uintptr_t)Src - JMP_LENGTH;
        });
    }

    template <typename Ret>
    Ret InstallTrampoline32(BYTE* Dest, size_t Length, size_t MangledBytes)
    {
        void* TrampolinePtr = VirtualAlloc(nullptr, Length + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        memcpy(TrampolinePtr, Dest, Length);

        *(BYTE*)((uintptr_t)TrampolinePtr + Length + MangledBytes) = 0xE9; // jmp
        *(uintptr_t*)((uintptr_t)TrampolinePtr + Length + MangledBytes + 1) = (uintptr_t)Dest + Length - ((uintptr_t)TrampolinePtr + Length + JMP_LENGTH);

        return static_cast<Ret>(TrampolinePtr);
    }

    inline bool InjectDll(const TCHAR* ProcessName, const TCHAR* DllPath)
    {
        const DWORD  ProcessID = FindProcessID(ProcessName);
        const HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessID);

        if (ProcessHandle == nullptr)
            return false;

        void* AllocMemory = VirtualAlloc(ProcessHandle, _strlen_(DllPath) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (AllocMemory == nullptr)
            return false;

        if (WriteProcessMemory(ProcessHandle, AllocMemory, DllPath, _strlen_(DllPath) + 1, nullptr) == false)
            return false;

        const LPTHREAD_START_ROUTINE ThreadStartRoutinePtr = (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibrary(TEXT("kernel32")), "LoadLibraryA");

        DWORD ThreadID;
        const HANDLE ThreadHandle = CreateRemoteThread(ProcessHandle, nullptr, 0, ThreadStartRoutinePtr, AllocMemory, 0, &ThreadID);

        if (ThreadHandle == nullptr)
            return false;

        return true;
    }
}