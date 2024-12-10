/*
    DomainListMachines.h
    Header file for the Domain List Machines module.
    Provides API to enumerate visible machines in the current or any specified domain.
*/

#pragma once

#include <windows.h>
#include <winnetwk.h>

// Callback function for enumerating network items
typedef BOOL(CALLBACK* WNETENUMITEMSFUNC)(LPNETRESOURCE, LPWSTR, LPVOID);

// Define functions for import-export, used in both compilation modes
typedef struct _DomainListMachines_ptrs {
    BOOL(*fndlmEnumV1)(LPWSTR wszDomain);
    BOOL(*fndlmEnumV2)(BOOL bEnumShares, BOOL bEnumAllNetworks, WNETENUMITEMSFUNC efnEnumFunc, LPVOID pCallbackParam);
} DomainListMachines_ptrs, *PDomainListMachines_ptrs;

#ifdef ROUTINES_BY_PTR

#pragma message(__FILE__": ROUTINES_BY_PTR compilation mode")

// Global variable definition for transparent code replacements
extern DomainListMachines_ptrs DomainListMachines_apis;

// Transparent code replacements
#define dlmEnumV1 DomainListMachines_apis.fndlmEnumV1
#define dlmEnumV2 DomainListMachines_apis.fndlmEnumV2

// Function to resolve pointers to the API functions
VOID DomainListMachines_resolve(DomainListMachines_ptrs *apis);

#else

// Function declarations
BOOL dlmEnumV1(LPWSTR wszDomain);
BOOL dlmEnumV2(BOOL bEnumShares, BOOL bEnumAllNetworks, WNETENUMITEMSFUNC efnEnumFunc, LPVOID pCallbackParam);

// Function to import pointers to the API functions
VOID DomainListMachines_imports(DomainListMachines_ptrs *apis);

#endif
