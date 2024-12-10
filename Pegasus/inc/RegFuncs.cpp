/*
    RegFuncs.cpp
    Misc simple registry-related function
*/

#include <windows.h>
#include <stdexcept>
#include <string>

#include "mem.h"
#include "dbg.h"
#include "MyStringRoutines.h"

#include "RegFuncs.h"

#pragma comment (lib, "crypt32.lib")

/*
    Checks/creates a full reg path, assuming more than 1 subkey may be missed in
    a standard query
    hRootKey - usually HKEY_CURRENT_USER
    wszRegPath - registry path to check/create (NB: 32 is max deep)
    Returns:
    ERROR_SUCCESS if creation was ok, or some error code from last RegCreateKeyEx call
*/
LSTATUS RegCreatePath(HKEY hRootKey, LPCWSTR wszRegPath)
{
    HKEY hPrevKey, hCurrentKey;    // handle of reg subkeys being opened
    std::wstring wszRegPathLocal;  // local buffer for reg path
    std::wstring wszTmpStr;        // tmp string to hold every chunk of input string
    LSTATUS lRes = ERROR_SUCCESS;  // RegCreateKeyEx result, func's initial result

    try {
        // create local copy of input data
        wszRegPathLocal = wszRegPath;

        // replace all '\' with null terminator
        std::replace(wszRegPathLocal.begin(), wszRegPathLocal.end(), L'\\', L'\0');

        // init pos ptr
        LPCWSTR wszRPL_Pos = wszRegPathLocal.c_str();

        // init hPrevKey
        hPrevKey = hRootKey;

        // perform loop
        while (lstrlen(wszRPL_Pos)) {
            DbgPrint("checking [%ws]", wszRPL_Pos);

            // try to open first. This is essential due to OS restriction on creating some root subkeys
            if (ERROR_SUCCESS != RegOpenKeyExW(hPrevKey, wszRPL_Pos, 0, KEY_READ | KEY_WRITE, &hCurrentKey)) {
                // read+write open failed, attempt read only
                if (ERROR_SUCCESS != RegOpenKeyExW(hPrevKey, wszRPL_Pos, 0, KEY_READ, &hCurrentKey)) {
                    // even read failed, attempt to create this time
                    lRes = RegCreateKeyExW(hPrevKey, wszRPL_Pos, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &hCurrentKey, NULL);
                    if (ERROR_SUCCESS != lRes) {
                        DbgPrint("failed at [%ws] with code %04Xh(%u)", wszRPL_Pos, lRes, lRes);
                        break;  // exit while loop to allow cleanup routines
                    }
                }
            }

            // close unneeded handle
            if (hPrevKey != hRootKey) {
                RegCloseKey(hPrevKey);
            }

            // exchange handles
            hPrevKey = hCurrentKey;

            // move to next position using dirty pointer manipulation trick
            wszRPL_Pos += lstrlen(wszRPL_Pos) + 1;
        }
    }
    catch (const std::exception& e) {
        DbgPrint("Exception: %s", e.what());
        lRes = ERROR_EXCEPTION_IN_SERVICE;
    }

    return lRes;
}

/*
    Attempts to set reg DWORD value at HKEY_CURRENT_USER
*/
BOOL RegWriteDWORD(LPCWSTR wszRegPath, LPCWSTR wszKeyName, DWORD dwValueToSet)
{
    BOOL bRes = FALSE;  // function's result
    HKEY hKey;

    DbgPrint("wszRegPath=[%ws] wszKeyName=[%ws] dwValueToSet=%u", wszRegPath, wszKeyName, dwValueToSet);

    try {
        if (ERROR_SUCCESS == RegCreateKeyExW(HKEY_CURRENT_USER, wszRegPath, 0, NULL, 0, KEY_READ | KEY_WRITE, NULL, &hKey, NULL)) {
            if (ERROR_SUCCESS == RegSetValueExW(hKey, wszKeyName, 0, REG_DWORD, (PBYTE)&dwValueToSet, sizeof(dwValueToSet))) {
                bRes = TRUE;
            }
            RegFlushKey(hKey);
            RegCloseKey(hKey);
        }
    }
    catch (const std::exception& e) {
        DbgPrint("Exception: %s", e.what());
    }

    DbgPrint("func res %u", bRes);
    return bRes;
}

/*
    Removes specified value
*/
BOOL RegRemoveValue(HKEY hRootKey, LPCWSTR wszRegPath, LPCWSTR wszRegKeyname)
{
    BOOL bResult = FALSE;  // function's result
    HKEY hKey;  // internal reg handle

    try {
        // try to open registry at specified path
        if (ERROR_SUCCESS != RegOpenKeyExW(hRootKey, wszRegPath, 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &hKey)) {
            DbgPrint("RegOpenKeyEx failed");
            return bResult;
        }

        // query param to determine needed buffer's len
        if (ERROR_SUCCESS != RegDeleteValueW(hKey, wszRegKeyname)) {
            return bResult;
        }

        // essential to keep changes in case of sudden reboot
        RegFlushKey(hKey);
        RegCloseKey(hKey);

        // assign result
        bResult = TRUE;
    }
    catch (const std::exception& e) {
        DbgPrint("Exception: %s", e.what());
    }

    return bResult;
}

/*
    Removes specified key
*/
BOOL RegRemoveKey(HKEY hRootKey, LPCWSTR wszRegPath)
{
    BOOL bResult = FALSE;  // function's result

    try {
        if (ERROR_SUCCESS != RegDeleteKey(hRootKey, wszRegPath)) {
            DbgPrint("RegDeleteKey failed, le %p", GetLastError());
            return bResult;
        }

        bResult = TRUE;
    }
    catch (const std::exception& e) {
        DbgPrint("Exception: %s", e.what());
    }

    return bResult;
}
