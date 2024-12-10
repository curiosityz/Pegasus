/*
	LocalStorage.cpp
	Routines for storing some information chunks locally, to be processed later
*/

#include <windows.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <mutex>

#include "mem.h"
#include "dbg.h"
#include "CryptoStrings.h"
#include "RandomGen.h"

#include "LocalStorage.h"

// Global mutex for thread safety
std::mutex g_localStorageMutex;

// Vector to store local storage items
std::vector<LOCAL_STORAGE_ITEM> g_localStorageItems;

/*
	Performs initialization of persistent local storage
*/
VOID lsInitLocalStorage()
{
	DbgPrint("entered");

	try {
		// Initialization code here
	}
	catch (const std::exception& e) {
		DbgPrint("Exception: %s", e.what());
		throw;
	}
}

/*
	Adds an item to the local storage
*/
VOID lsAddItem(StorageItemSourceEnum siSource, DWORD dwItemUniqId, LPVOID pData, SIZE_T lDataLen)
{
	std::lock_guard<std::mutex> lock(g_localStorageMutex);

	try {
		LOCAL_STORAGE_ITEM newItem;
		newItem.siSource = siSource;
		newItem.dwItemUniqId = dwItemUniqId;
		newItem.pData = my_alloc(lDataLen);
		memcpy(newItem.pData, pData, lDataLen);
		newItem.lDataLen = lDataLen;

		g_localStorageItems.push_back(newItem);
	}
	catch (const std::exception& e) {
		DbgPrint("Exception: %s", e.what());
		throw;
	}
}

/*
	Removes an item from the local storage by unique ID
*/
VOID lsRemoveItem(DWORD dwItemUniqId)
{
	std::lock_guard<std::mutex> lock(g_localStorageMutex);

	try {
		auto it = std::remove_if(g_localStorageItems.begin(), g_localStorageItems.end(),
			[dwItemUniqId](const LOCAL_STORAGE_ITEM& item) {
				return item.dwItemUniqId == dwItemUniqId;
			});

		if (it != g_localStorageItems.end()) {
			my_free(it->pData);
			g_localStorageItems.erase(it, g_localStorageItems.end());
		}
	}
	catch (const std::exception& e) {
		DbgPrint("Exception: %s", e.what());
		throw;
	}
}

/*
	Gets an item from the local storage by unique ID
*/
LOCAL_STORAGE_ITEM* lsGetItem(DWORD dwItemUniqId)
{
	std::lock_guard<std::mutex> lock(g_localStorageMutex);

	try {
		for (auto& item : g_localStorageItems) {
			if (item.dwItemUniqId == dwItemUniqId) {
				return &item;
			}
		}
	}
	catch (const std::exception& e) {
		DbgPrint("Exception: %s", e.what());
		throw;
	}

	return nullptr;
}
