/*
	LocalStorage.cpp
	Routines for storing some information chunks locally, to be processed later
*/

#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>

#include "mem.h"
#include "dbg.h"
#include "CryptoStrings.h"
#include "RandomGen.h"

#include "LocalStorage.h"

std::vector<std::string> localStorage;

/*
	Performs initialization of persistent local storage
*/
VOID lsInitLocalStorage()
{
	DbgPrint("entered");

	// Initialize local storage
	localStorage.clear();
}

/*
	Adds a chunk of information to the local storage
*/
VOID lsAddToLocalStorage(const std::string& data)
{
	DbgPrint("entered");

	try {
		localStorage.push_back(data);
	}
	catch (const std::exception& e) {
		DbgPrint("Exception: %s", e.what());
	}
}

/*
	Saves the local storage to a file
*/
VOID lsSaveLocalStorageToFile(const std::string& fileName)
{
	DbgPrint("entered");

	try {
		std::ofstream outFile(fileName, std::ios::out | std::ios::binary);
		if (!outFile) {
			throw std::ios_base::failure("Failed to open file for writing");
		}

		for (const auto& data : localStorage) {
			outFile.write(data.c_str(), data.size());
			outFile.put('\n');
		}

		outFile.close();
	}
	catch (const std::exception& e) {
		DbgPrint("Exception: %s", e.what());
	}
}

/*
	Loads the local storage from a file
*/
VOID lsLoadLocalStorageFromFile(const std::string& fileName)
{
	DbgPrint("entered");

	try {
		std::ifstream inFile(fileName, std::ios::in | std::ios::binary);
		if (!inFile) {
			throw std::ios_base::failure("Failed to open file for reading");
		}

		localStorage.clear();
		std::string line;
		while (std::getline(inFile, line)) {
			localStorage.push_back(line);
		}

		inFile.close();
	}
	catch (const std::exception& e) {
		DbgPrint("Exception: %s", e.what());
	}
}
