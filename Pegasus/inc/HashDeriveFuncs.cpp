/*
	HashDeriveFuncs.cpp
	Routines to generate target hash from some source
	Used to init rnd pseudo-random number generators from constant source
*/

#include <Windows.h>
#include <string>
#include <vector>
#include <stdexcept>

#include "dbg.h"
#include "mem.h"
#include "HashedStrings.h"
#include "CryptoStrings.h"

#include "HashDeriveFuncs.h"

LPWSTR g_wszLocalMachineName = NULL;

/*
	Calculates a CONSTANT hash from target machine name (without ^ HASHSTR_RND_XOR)
	wszTargetMachineName may be NULL to indicate local machine (a name will be queried internally and stored)
	or some other machine in format '\\WS-NAME'. Also supported '\\*' format if needed by caller
*/
UINT64 i64CalcTargetMachineHash(LPWSTR wszTargetMachineName)
{
	DWORD dwLen;	// tmp len var
	std::wstring wszResBuff;
	UINT64 i64Res = 0;	// func result

	try {
		// directly hash if used passed param
		if (wszTargetMachineName) { 
			i64Res = HashStringW_const(wszTargetMachineName); 
			return i64Res; 
		}

		// need to query local machine's name
		if (!g_wszLocalMachineName) {
			g_wszLocalMachineName = (LPWSTR)my_alloc(1024);
			dwLen = MAX_COMPUTERNAME_LENGTH + 1;
			if (!GetComputerName(g_wszLocalMachineName, &dwLen)) {
				throw std::runtime_error("Failed to get computer name");
			}
		}

		// form resulting buffer
		wszResBuff = L"\\\\";
		wszResBuff += g_wszLocalMachineName;

		// calc hash
		i64Res = HashStringW_const(wszResBuff.c_str());
		DbgPrint("formatted local machine name [%ws], hash %08X%08X", wszResBuff.c_str(), (DWORD)(i64Res << 32), (DWORD)i64Res);

	} catch (const std::exception& e) {
		DbgPrint("Exception: %s", e.what());
		throw;
	}

	return i64Res;
}
