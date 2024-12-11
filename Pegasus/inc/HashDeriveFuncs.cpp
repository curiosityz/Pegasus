/*
	HashDeriveFuncs.cpp
	Routines to generate target hash from some source
	Used to init rnd pseudo-random number generators from constant source
*/

#include <Windows.h>
#include <stdexcept> // for std::runtime_error

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
	LPWSTR wszResBuff, wszS;
	UINT64 i64Res = 0;	// func result

	try {	// not a loop

		// directly hash if used passed param
		if (wszTargetMachineName) { 
			i64Res = HashStringW_const(wszTargetMachineName); 
		} else {
			// need to query local machine's name
			if (!g_wszLocalMachineName) {
				g_wszLocalMachineName = (LPWSTR)my_alloc(1024);
				if (!g_wszLocalMachineName) {
					throw std::runtime_error("Memory allocation failed for g_wszLocalMachineName");
				}
				dwLen = MAX_COMPUTERNAME_LENGTH + 1;
				if (!GetComputerName(g_wszLocalMachineName, &dwLen)) {
					throw std::runtime_error("Failed to get computer name");
				}
			} // !g_wszLocalMachineName

			// form resulting buffer
			wszResBuff = (LPWSTR)my_alloc(1024);
			if (!wszResBuff) {
				throw std::runtime_error("Memory allocation failed for wszResBuff");
			}
			wszS = CRSTRW("\\\\", "\x00\x20\xdc\x0d\x02\x20\xe0\x39\xd8\xa4\xd2");
			lstrcat(wszResBuff, wszS);
			lstrcat(wszResBuff, g_wszLocalMachineName);
			my_free(wszS);

			// calc hash
			i64Res = HashStringW_const(wszResBuff);
			DbgPrint("formatted local machine name [%ws], hash %08X%08X", wszResBuff, (DWORD)(i64Res << 32), (DWORD)i64Res);
			my_free(wszResBuff);
		}

	} catch (const std::exception& e) {
		DbgPrint("Exception: %s", e.what());
		i64Res = 0; // or some other error value
	}

	return i64Res;
}
