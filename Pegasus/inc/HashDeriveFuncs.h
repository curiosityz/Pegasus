/*
    HashDeriveFuncs.h
*/

#pragma once

#include <windows.h>

// Function to calculate the hash of the target machine name
UINT64 i64CalcTargetMachineHash(LPWSTR wszTargetMachineName);
