/*
	NetMessageEnvelope.cpp
	Function to encoding and decoding messages circulating in local network via different transports (pipes, mailslots, etc)
*/

#include <windows.h>
#include <stdexcept>
#include <vector>

#include "mem.h"
#include "dbg.h"
#include "RandomGen.h"
#include "CryptRoutines.h"
#include "NetMessageEnvelope.h"

/*
	Performs xor with key shift over passed buffer
*/
void nmeXorBuffer(LPVOID pBuffer, DWORD dwBufferLen, DWORD dwKeyIn)
{
	BYTE *pb = static_cast<BYTE *>(pBuffer);
	DWORD dwCounter = dwBufferLen;
	DWORD dwKey = dwKeyIn;

	while (dwCounter) {
		*pb ^= static_cast<BYTE>(dwKey);
		dwKey = (dwKey >> 5) | (dwKey << (32 - 5));
		pb++;
		dwCounter--;
	}
}

/*
	Adds a special envelope over binary data.
	It is used to check message integrity and transfer id (class) of message
*/
void nmeMakeEnvelope(LPVOID pBuffer, DWORD dwBufferLen, BYTE bMessageId, LPVOID *pEnveloped, DWORD *dwEnvelopedLen)
{
	NET_MESSAGE_ENVELOPE *pmEnvelope;	// to cast ptr to newly allocated buffer
	RndClass rg = { 0 };
	std::vector<BYTE> bHash(20);	// buffer to hold hash results
	ULONG ulBufferLen = 20;	// len of ^ buffer

	// *pEnveloped except first DWORD with random key
	LPVOID pVolatilePart;
	DWORD dwVolatilePartLen;

	// calc target buffer len
	*dwEnvelopedLen = sizeof(NET_MESSAGE_ENVELOPE) + dwBufferLen;
	*pEnveloped = my_alloc(*dwEnvelopedLen);

	// append original data
	memcpy(static_cast<BYTE *>(*pEnveloped) + sizeof(NET_MESSAGE_ENVELOPE), pBuffer, dwBufferLen);

	// cast ptr to fill values
	pmEnvelope = static_cast<NET_MESSAGE_ENVELOPE *>(*pEnveloped);
	pmEnvelope->bMessageId = bMessageId;

	// fill random encode value
	rgNew(&rg);
	pmEnvelope->dwRandomKey = rg.rgGetRndDWORD(&rg);

	// prepare shifted ptrs
	pVolatilePart = static_cast<BYTE *>(*pEnveloped) + sizeof(DWORD);
	dwVolatilePartLen = *dwEnvelopedLen - sizeof(DWORD);

	// calc sha hash into temporary buffer
	if (!cryptCalcHashSHA(pVolatilePart, dwVolatilePartLen, bHash.data(), &ulBufferLen)) {
		throw std::runtime_error("Failed to calculate hash, packet will be unusable");
	}

	// copy hash to resulting buffer
	memcpy(pmEnvelope->bMessageHash, bHash.data(), 20);

	// make overall packet mangling using pmEnvelope->dwRandomKey
	nmeXorBuffer(pVolatilePart, dwVolatilePartLen, pmEnvelope->dwRandomKey);
}

/*
	Verify and decode network message. Returns TRUE on success.
	Modify original buffer, returns offset to real data start, caller should adjust buffer's len if needed
	Until all checks are done ok, no data modification performed
	NB: source buffer is not touched until full verification done ok
*/
bool nmeCheckRemoveEnvelope(LPVOID pBufferIn, DWORD *dwBufferLen, BYTE *bMessageId)
{
	bool bRes = false;	// function result

	std::vector<BYTE> bufferLocal(*dwBufferLen);	// local copy of input buffer

	NET_MESSAGE_ENVELOPE *pmEnvelope; // casted copy of input buffer

	LPVOID pVolative;
	DWORD dwVolatileLen = *dwBufferLen - sizeof(DWORD);

	std::vector<BYTE> bHash(20);	// buffer to hold hash from decoded input
	std::vector<BYTE> bHashCalculated(20);	// calculated hash value of source data with hash field nulled
	ULONG ulBufferLen = 20;	// len of ^ buffer

	try {
		// check for sane len
		if (*dwBufferLen < sizeof(NET_MESSAGE_ENVELOPE) + 1) {
			throw std::runtime_error("Too small message received");
		}

		// copy into local buffer
		memcpy(bufferLocal.data(), pBufferIn, *dwBufferLen);

		// assign local ptrs
		pmEnvelope = reinterpret_cast<NET_MESSAGE_ENVELOPE *>(bufferLocal.data());
		pVolative = static_cast<BYTE *>(bufferLocal.data()) + sizeof(DWORD);

		// decode buffer
		nmeXorBuffer(pVolative, dwVolatileLen, pmEnvelope->dwRandomKey);

		// save hash to local
		memcpy(bHash.data(), pmEnvelope->bMessageHash, 20);

		// wipe hash from input for proper calculation
		memset(pmEnvelope->bMessageHash, 0, 20);

		// calc hash into tmp buffer
		if (!cryptCalcHashSHA(pVolative, dwVolatileLen, bHashCalculated.data(), &ulBufferLen)) {
			throw std::runtime_error("Failed to calculate hash, check failed");
		}

		// compare hashes
		if (memcmp(bHash.data(), bHashCalculated.data(), 20) != 0) {
			throw std::runtime_error("Hash check failed, invalid packet");
		}

		// save results
		*dwBufferLen = *dwBufferLen - sizeof(NET_MESSAGE_ENVELOPE);
		*bMessageId = pmEnvelope->bMessageId;

		// overwrite mem contents via tmp buffer
		memcpy(pBufferIn, static_cast<BYTE *>(bufferLocal.data()) + sizeof(NET_MESSAGE_ENVELOPE), *dwBufferLen);
		memset(static_cast<BYTE *>(pBufferIn) + *dwBufferLen, 0, sizeof(NET_MESSAGE_ENVELOPE));	// wipe original contents

		// done ok
		bRes = true;
	} catch (const std::exception& e) {
		DbgPrint("ERR: %s", e.what());
	}

	return bRes;
}
