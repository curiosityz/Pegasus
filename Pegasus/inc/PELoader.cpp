/*
    PELoader.cpp
    PE loader x32/x64, direct mapping, for simple dlls only
*/

#include <windows.h>
#include <stdexcept>
#include <vector>
#include <string>

#ifndef SHELLCODE_MODE
    #pragma message("usual mode")
    #include "dbg.h"

    // define apis usually
    #define VirtualAlloc_ VirtualAlloc    
    #define VirtualFree_ VirtualFree
    #define GetProcAddress_ GetProcAddress
    #define LoadLibraryA_ LoadLibraryA

    //#define OutputDebugStringA_ OutputDebugStringA

    #define _stop

#else
    #pragma message("SHELLCODE mode")
    #define DbgPrint(args, ...)

    // define apis using shellcode context
    #define VirtualAlloc_ pAPIs->p_VirtualAlloc    
    #define VirtualFree_ pAPIs->p_VirtualFree
    #define GetProcAddress_ pAPIs->p_GetProcAddress
    #define LoadLibraryA_ pAPIs->p_LoadLibraryA

    //#define OutputDebugStringA_ pAPIs->p_OutputDebugStringA

    // sleep stop at errors
    //#define _stop while(true) {}
    #define _stop

#endif

#include "PELoader.h"

void* my_memcpy(void* dst, const void* src, size_t n)
{
    return std::memcpy(dst, src, n);
}

// simple lstrcpy() replacement
void my_lstrcpy(PCHAR pDest, PCHAR pSrc)
{
    while (*pSrc) { *pDest++ = *pSrc++; }
}

SIZE_T PeSupAlign(SIZE_T Size, SIZE_T Alignment)
{
    return (Size + Alignment - 1) & ~(Alignment - 1);
}

BOOL LoaderProcessRelocs(LPVOID NewBase, PIMAGE_NT_HEADERS Pe)
{
    try {
        DWORD i;
        PIMAGE_DATA_DIRECTORY DataDir = PeSupGetDirectoryEntryPtr(Pe, IMAGE_DIRECTORY_ENTRY_BASERELOC);
        if (DataDir->VirtualAddress && DataDir->Size) {
            ULONG_PTR BaseDelta = ((ULONG_PTR)NewBase - (ULONG_PTR)PeSupGetOptionalField(Pe, ImageBase));
            PIMAGE_BASE_RELOCATION_EX Reloc = (PIMAGE_BASE_RELOCATION_EX)((SIZE_T)NewBase + DataDir->VirtualAddress);

            while (DataDir->Size > IMAGE_SIZEOF_BASE_RELOCATION) {
                ULONG NumberRelocs = (Reloc->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / sizeof(WORD);
                PCHAR PageVa = (PCHAR)((SIZE_T)NewBase + Reloc->VirtualAddress);

                if (DataDir->Size >= (LONG)Reloc->SizeOfBlock) {
                    for (i = 0; i < NumberRelocs; i++) {
                        USHORT RelocType = (Reloc->TypeOffset[i] >> IMAGE_REL_BASED_SHIFT);

                        switch (RelocType) {
                        case IMAGE_REL_BASED_ABSOLUTE:
                            // Do nothing. This one is used just for alignment.
                            break;
                        case IMAGE_REL_BASED_HIGHLOW:
                            *(PULONG)(PageVa + (Reloc->TypeOffset[i] & IMAGE_REL_BASED_MASK)) += (ULONG)BaseDelta;
                            break;
#ifdef _M_AMD64
                        case IMAGE_REL_BASED_DIR64:
                            *(PULONG_PTR)(PageVa + (Reloc->TypeOffset[i] & IMAGE_REL_BASED_MASK)) += BaseDelta;
                            break;
#endif
                        default:
                            throw std::runtime_error("Unsupported relocation type");
                        }
                    }
                }
                DataDir->Size -= (LONG)Reloc->SizeOfBlock;
                Reloc = (PIMAGE_BASE_RELOCATION_EX)((PCHAR)Reloc + Reloc->SizeOfBlock);
            }
        }
        return TRUE;
    } catch (const std::exception& e) {
        DbgPrint("ERR: %s", e.what());
        return FALSE;
    }
}

#if (!defined(_M_X64))
    #define PIMAGE_THUNK_DATA_XXX PIMAGE_THUNK_DATA32
    #define IMAGE_ORDINAL_FLAGXX IMAGE_ORDINAL_FLAG32
#else
    #define PIMAGE_THUNK_DATA_XXX PIMAGE_THUNK_DATA64
    #define IMAGE_ORDINAL_FLAGXX IMAGE_ORDINAL_FLAG64
#endif

#ifndef SHELLCODE_MODE
BOOL LoaderProcessImports(LPVOID NewBase, PIMAGE_NT_HEADERS Pe)
#else
BOOL LoaderProcessImports(SHELLCODE_APIS *pAPIs, LPVOID NewBase, PIMAGE_NT_HEADERS Pe)
#endif
{
    try {
        PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((SIZE_T)PeSupGetDirectoryEntryPtr(Pe, IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress);
        if (pImportDescriptor != NULL) {
            pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((SIZE_T)NewBase + (SIZE_T)pImportDescriptor);
            while (pImportDescriptor->Name != 0) {
                PCHAR ModuleName = (PCHAR)((SIZE_T)NewBase + (SIZE_T)pImportDescriptor->Name);
                PVOID ModuleBase = LoadLibraryA_(ModuleName);
                if (ModuleBase == NULL) {
                    throw std::runtime_error("Required module not loaded");
                }

                PIMAGE_THUNK_DATA_XXX pFirstThunkData = (PIMAGE_THUNK_DATA_XXX)((SIZE_T)NewBase + (SIZE_T)(pImportDescriptor->FirstThunk));
                PIMAGE_THUNK_DATA_XXX pOriginalThunkData = (PIMAGE_THUNK_DATA_XXX)((SIZE_T)NewBase + (SIZE_T)(pImportDescriptor->OriginalFirstThunk));

                while (pOriginalThunkData->u1.Ordinal != 0) {
                    PCHAR FuncName;
                    if (!(pOriginalThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAGXX)) {
                        PIMAGE_IMPORT_BY_NAME pImageImportByName = (PIMAGE_IMPORT_BY_NAME)RVATOVA(NewBase, pOriginalThunkData->u1.AddressOfData);
                        FuncName = (PCHAR)(&pImageImportByName->Name);
                    } else {
                        FuncName = (PCHAR)((SIZE_T)pOriginalThunkData->u1.Ordinal & 0x0000FFFF);
                    }

                    LPVOID FuncAddr = GetProcAddress_((HMODULE)ModuleBase, FuncName);
                    if (FuncAddr == 0) {
                        throw std::runtime_error("Required function not found");
                    }

                    *(LPVOID *)pFirstThunkData = FuncAddr;
                    pOriginalThunkData++;
                    pFirstThunkData++;
                }
                pImportDescriptor++;
            }
        }
        return TRUE;
    } catch (const std::exception& e) {
        DbgPrint("ERR: %s", e.what());
        return FALSE;
    }
}

/*
    Simple PE loader wrapper function
    pPE - ptr to buffer with dll to be loaded (it's size is calculated from PE header)
    pImage & lImageSize - ptrs to resulting virtual HMODULE (dll imagebase) and it's size
    pDllMainParam - value to be specified to dllmain as lpvReserved param
    pEntryPoint - ptr to receive entry point (dllmain)
    NB: it is up to caller to execute module's entrypoint with essential params!
*/
#ifndef SHELLCODE_MODE
BOOL PELoad(LPVOID pPE, LPVOID *pImage, SIZE_T *lImageSize, LPVOID *pEntryPoint )
#else
BOOL PELoad(SHELLCODE_APIS *pAPIs, LPVOID pPE, LPVOID *pImage, SIZE_T *lImageSize, LPVOID *pEntryPoint )
#endif
{
    try {
        if (!pPE || !pImage || !lImageSize || !pEntryPoint) {
            throw std::invalid_argument("Invalid input parameters");
        }

        PIMAGE_NT_HEADERS Pe = (PIMAGE_NT_HEADERS)PeSupGetImagePeHeader((SIZE_T)pPE);
        *lImageSize = PeSupGetOptionalField(Pe, SizeOfImage);
        *pImage = (PCHAR)VirtualAlloc_(0, *lImageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        SIZE_T NumberSections = Pe->FileHeader.NumberOfSections;
        SIZE_T FileAlign = PeSupGetOptionalField(Pe, FileAlignment);
        PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(Pe);

        my_memcpy(*pImage, pPE, PeSupGetOptionalField(Pe, SizeOfHeaders));

        // Copying sections
        for (SIZE_T i = 0; i < NumberSections; i++) {
            SIZE_T bSize = PeSupAlign(Section->SizeOfRawData, FileAlign);
            if (bSize) {
                my_memcpy((LPVOID)((SIZE_T)*pImage + Section->VirtualAddress), (LPVOID)((SIZE_T)pPE + Section->PointerToRawData), bSize);
            }
            Section += 1;
        }

        // Processing relocs and imports
#ifndef SHELLCODE_MODE
        if (!LoaderProcessRelocs(*pImage, Pe) || !LoaderProcessImports(*pImage, Pe)) {
#else
        if (!LoaderProcessRelocs(*pImage, Pe) || !LoaderProcessImports(pAPIs, *pImage, Pe)) {
#endif
            throw std::runtime_error("Failure during relocs or imports processing");
        }

        *pEntryPoint = (LPVOID)((SIZE_T)*pImage + PeSupGetOptionalField(Pe, AddressOfEntryPoint));
        DbgPrint("EP is found at %04Xh", *pEntryPoint);
        return TRUE;
    } catch (const std::exception& e) {
        DbgPrint("ERR: %s", e.what());
        if (*pImage) {
            VirtualFree_(*pImage, 0, MEM_RELEASE);
        }
        return FALSE;
    }
}
