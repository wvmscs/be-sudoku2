 // antisudoku.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
/*******************
 * Ce programme procède à la remédiation d'un compte 
 * utilisateur infecté par le ramsomware SUDOKU.
 * (c) 2019 William VITAL 
 * Pulic domain (03/03/2019)
 *
 * AntiSudoku réalise:  
 *  - la supression de la persistance et supression/mise en quarantaine des programes SUDOKU malveillants
 *  - le déchiffrement des fichiers chiffrés par le programme Sudoku 
 *  - la suppression des notes de demande de rançon après vérification de leur hash (sauvegarde d'une de ces notes pour chaque hash trouvé)
 *  - la production d'un rappoprt sur le travail effectué, le nombre de fichiers récupéré, la liste des fichiers dont le déchiffrement n'a pas été possible.
 *  - la génération des IOCs (md5 des .exe et .txt)
 * 
 */


#include "pch.h"
#include <iostream>
#include <Windows.h>
//#include <strsafe.h>
//#include "blowfish2.h"
#include "blowfish3.h"

using namespace std;

class KEYARRAYA {
private:
	static const int MAXKEY_CACHE = 100;
	ULARGE_INTEGER uli[MAXKEY_CACHE + 1];
	int maxkey = -1, currentKey = -1;
public:
	KEYARRAYA();
	ULARGE_INTEGER * getKey();
	ULARGE_INTEGER * getNextKey();
	void appendKey(ULARGE_INTEGER *lpKey);
};

const int MYMAXLEN = 150;
const char *LPMIMES[]= {".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".rtf", 
                        ".pdf", ".jpg", ".jpeg", ".html", ".htm", ".png", ".gif", NULL} ;
const char *LPMAGIC[] = {
			"PK\x03\x04", "PK\x05\x06", "PK\x07\x08",	// docx pptx xlsx
			"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",			// doc ppt xls
			"%PDF",									// pdf
			"GIF8",							// gif
			"\x89PNG","RIFF",					// png
			"\xff\xd8\xff",  // jpg jpeg
			"{\rtf1",									// rtf
			NULL };

// indique si le bloc mémoire peut être assimilé à un décodage réussi
inline BOOL isKnownMagic(const byte *lp, const unsigned len) {
	const char **l = LPMAGIC;
	BOOL retval = FALSE;
	while (*l && !retval) {
		if (!strncmp((const char *)lp, *l, strlen(*l))) { 
			retval = TRUE; }
		l++;
	}
	if (!retval) {
		// tenter une reconaissance de caractères ascii ou utf8
		BOOL b = TRUE;
		for (int i = 0; i < 10 && b; i++) {
			b = b && (isascii(*(lp + i)) || iswascii(*(lp + i)));
		}
		retval = b;
	}
	return retval;
}

void parcoursRepertoires(LPCSTR currentDirectory, void (*fn_callback)(void *, LPCSTR,  LPWIN32_FIND_DATAA), 
	void *lpcontext) {
	
	WIN32_FIND_DATAA wfd_context;
	CHAR curSearch[MYMAXLEN];

	snprintf(curSearch, MYMAXLEN - 1, "%s\\*", currentDirectory);
	//cout << "searching " << curSearch << "\n";

	

	HANDLE hfind = FindFirstFileA(curSearch, &wfd_context);
	if (hfind) {
		do {
			DWORD att = wfd_context.dwFileAttributes;
			if (!(att & 0x10)) {
				// le fichier n'est pas un répertoire
				fn_callback(lpcontext, currentDirectory, &wfd_context);
			}
			else {
				if (!(att & 0x400) && strcmp(wfd_context.cFileName, ".") 
					&& strcmp(wfd_context.cFileName,"..") ) {
					// le répertoire n'est pas un lien 
					CHAR newSearchDir[MYMAXLEN];
					snprintf(newSearchDir, MYMAXLEN - 1, "%s\\%s", currentDirectory,
						wfd_context.cFileName);
					parcoursRepertoires(newSearchDir, fn_callback, lpcontext);
				}
			}
		} while (FindNextFileA(hfind, &wfd_context));
		FindClose(hfind);
	}
	//cout << "end of search  " <<  curSearch << "\n";
}




void printFileTimes(LPWIN32_FIND_DATAA lpFileDesc)
{
	SYSTEMTIME ftCreate, ftAccess, ftWrite;
	LPSYSTEMTIME lptimes[] = { &ftCreate, &ftAccess, &ftWrite, NULL };
	const int MYLLEN = 256;
	char printstring[MYLLEN];

	//DWORD dwRet;

	// Convert the last-file times to system time (UTC).
	FileTimeToSystemTime(&(lpFileDesc->ftCreationTime), &ftCreate);
	FileTimeToSystemTime(&(lpFileDesc->ftLastAccessTime), &ftAccess);
	FileTimeToSystemTime(&(lpFileDesc->ftLastWriteTime), &ftWrite);

	LPSYSTEMTIME *lp = lptimes;
	while (*lp) {
		// Build a string showing the date and time.

		snprintf(printstring, MYLLEN,
			" %02d/%02d/%d--%02d:%02d:%0d:%d",
			 (*lp)->wDay, (*lp)->wMonth, (*lp)->wYear,
			(*lp)->wHour, (*lp)->wMinute, (*lp)->wSecond, (*lp)->wMilliseconds);
		cout << printstring;
		lp++;
	}
}



BOOL uncipherFile(const char *lpFilePath, KEYARRAYA *lpKeyCache);

//KEYARRAYA Ka;

void fn_action_show(void* context, LPCSTR currentDir, LPWIN32_FIND_DATAA lpFileDesc) {
	 

	char FILEPATH[256];
	snprintf(FILEPATH, 256, "%s\\%s", currentDir, lpFileDesc->cFileName);

	/*cout << "Found: " << FILEPATH;
	printFileTimes(lpFileDesc);
	cout << "\n";
	*/
	uncipherFile(FILEPATH, (KEYARRAYA *)context);
}

void fn_listdir(void *context, LPCSTR currentDir, LPWIN32_FIND_DATAA lpFileDesc) {
	char *lpext = strstr(lpFileDesc->cFileName, ".");
	const char **lplistexts = LPMIMES;

	while (lpext && *lplistexts) {
		if (strcmp(lpext, *lplistexts) == 0) {
			
			fn_action_show(context, currentDir, lpFileDesc);
			lpext = NULL;
		}
		lplistexts++;
	}

	
}




void printSystemTime(LPSYSTEMTIME lpst) {
	const int MYLLEN = 256;
	char printstring[MYLLEN];
	LPSYSTEMTIME *lp = &lpst;

	snprintf(printstring, MYLLEN,
		" %02d/%02d/%d--%02d:%02d:%0d:%d",
		(*lp)->wDay, (*lp)->wMonth, (*lp)->wYear,
		(*lp)->wHour, (*lp)->wMinute, (*lp)->wSecond, (*lp)->wMilliseconds);
	cout << printstring;

}

class BLOWFISH {
private:
	struct blf_cbc_ctx cbcCTX;
	byte* cipherKey;
	int keylength;
	unsigned char IV[8];

	static void fn_result(unsigned char byte, void *user_data);
	byte *current;
	int bytecount;

public:
	BLOWFISH( byte* cipherKey, int keylength);
	void setIV(const unsigned char *iv);
	int Decrypt_CBC(byte* inoutdata, int length, int* newlength);
};

BLOWFISH::BLOWFISH(byte* cipherKey, int keylength) {
	this->cipherKey = cipherKey;
	this->keylength = keylength;
	memset(&cbcCTX, 0, sizeof(cbcCTX));
}
void BLOWFISH::fn_result(unsigned char u, void *user_data) {
	BLOWFISH *that = (BLOWFISH *)user_data;
	that->bytecount++;
	*(that->current) = u;
	that->current++;
}

void BLOWFISH::setIV(const unsigned char *iv) {
	//printf("0x%lx 0x%lx\n", c->ll, c->lr);
	for (int i = 0; i < 8; i++)
		IV[i] = *iv++;
}


int BLOWFISH::Decrypt_CBC(byte* inoutdata, int length, int * newlength) {

	this->current = inoutdata;
	this->bytecount = 0;

	Blowfish_cbc_start(&this->cbcCTX, 0,
		this->cipherKey, this->keylength,
		this->fn_result,
		this);

	cbcCTX.ll = cbcCTX.lr = 0;
	for (int i = 0; i < 4; i++) {
		this->cbcCTX.ll = (this->cbcCTX.ll << 8) | IV[i]; // ((((((*iv++) << 8) | (*iv++)) << 8) | (*iv++)) << 8) | (*iv++);
		this->cbcCTX.lr = (this->cbcCTX.lr << 8) | IV[i+4]; ; // ((((((*iv++) << 8) | (*iv++)) << 8) | (*iv++)) << 8) | (*iv++);
	}

	byte * lp = inoutdata;
	for ( int i = 0; i<length; i++) {
		Blowfish_cbc_feed(&this->cbcCTX, *lp);
		lp++;
	}

	Blowfish_cbc_stop(&this->cbcCTX);

	*newlength = this->bytecount;

	return TRUE;
}


KEYARRAYA::KEYARRAYA() { 
	maxkey = 0;  // ajoute une clé à 0000000000000000 
	currentKey = -1; 
	memset(uli, 0, sizeof(uli));
}
ULARGE_INTEGER * KEYARRAYA::getKey(void) {
	currentKey = -1;
	return getNextKey();
}
ULARGE_INTEGER * KEYARRAYA::getNextKey(void) {
	if (currentKey < maxkey ) {
		currentKey++;
		return &uli[currentKey];
	}
	return NULL;
}

void KEYARRAYA::appendKey(ULARGE_INTEGER *lpKey) {
	if (maxkey < MAXKEY_CACHE) {
		maxkey++;		
	} else {
		cout << "L'espace des clés pourrait être agrandi...\n";
	}
	uli[maxkey].QuadPart = lpKey->QuadPart;
}

const unsigned char *lpIV = (unsigned char *)"@GPCODE";
const char *lpMagicCryptor = "GPGcryptor";

BOOL tryDecypherFile(const char *lpFilePath, byte *lpBuffer, DWORD fileLen, DWORD trueSize, ULARGE_INTEGER *ulargeptr) {
	FILETIME ft_var;
	//tester une clé
	SYSTEMTIME thisKey;
	int decryptlen = 0;

	BOOL retval = FALSE;

	ft_var.dwHighDateTime = ulargeptr->HighPart;
	ft_var.dwLowDateTime = ulargeptr->LowPart;
	FileTimeToSystemTime(&ft_var, &thisKey);

	BLOWFISH bf((byte *)&thisKey, 0x10);
	bf.setIV(lpIV);
	bf.Decrypt_CBC(lpBuffer, fileLen, &decryptlen);

	// vérification du décodage 
	if (isKnownMagic(lpBuffer, decryptlen) == TRUE) {

		cout << " TROUVE\nkey=";
		printSystemTime(&thisKey);
		cout  << "\n";

		HANDLE hFile = CreateFileA(lpFilePath, GENERIC_WRITE, 0, NULL,
			OPEN_EXISTING, 0, NULL);
		DWORD effectiveWritedbytes = 0;
		if (hFile) {
			WriteFile(hFile, lpBuffer, trueSize, &effectiveWritedbytes, NULL);
			if (trueSize != effectiveWritedbytes) {
				cout << "write patially failed, " << effectiveWritedbytes << " of " << trueSize << " bytes written.\n";
			}
			CloseHandle(hFile);
			retval = TRUE;
		}
		else {
			cout << "write failde for " << lpFilePath;
		}
	}
	return retval;
}

BOOL uncipherFile(const char *lpFilePath, KEYARRAYA *lpKeyCache) {
	FILETIME ftCreate, ftAccess, ftWrite , ft_var;
	SYSTEMTIME  stWrite, stWrite_min;
	ULARGE_INTEGER ularge, ularge_ftWrite, ularge_ftWrite_min;
	unsigned long timeWindows = 10000000;  //(1000 milisec)

	// Provisoire
	//if (!strstr(lpFilePath, ".png"))
	//	return FALSE;

	HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ , 0, NULL,
		OPEN_EXISTING, 0, NULL);
	//byte *lpIV = (byte *)"@GPCODE";
	//const char *lpMagicCryptor = "GPGcryptor";

	if (hFile) {
		DWORD fileSize, fileSizeHight=0;

		GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite);
		
		// Convert the file times to system time (UTC).
		FileTimeToSystemTime(&ftWrite, &stWrite);
		ularge.LowPart = ftWrite.dwLowDateTime;
		ularge.HighPart = ftWrite.dwHighDateTime;
		ularge.QuadPart = ularge.QuadPart - timeWindows;
		ft_var.dwHighDateTime = ularge.HighPart;
		ft_var.dwLowDateTime = ularge.LowPart;
		FileTimeToSystemTime(&ft_var, &stWrite_min);


		// Read the file data
		if ((fileSize = GetFileSize(hFile, NULL)) ) {
			DWORD bytesRead = 0;
			DWORD trueSize = 0;

			byte *fileData = (byte *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
			byte *lpBuffer = (byte *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);

			if (ReadFile(hFile, fileData, fileSize, &bytesRead, NULL)) {
				CloseHandle(hFile); hFile = NULL;
				if (strstr((char*)fileData, lpMagicCryptor) == (char *)fileData) {
					int magiclen = strlen(lpMagicCryptor);
					trueSize = *(DWORD *)((char *)fileData + magiclen);

					cout << "Cyphered: " << lpFilePath  << " ("  << trueSize << ")\n";

					BOOL fileOK = FALSE;

					// on regarde si on ne possède pas déjà la clé
					ULARGE_INTEGER *ulargeptr = lpKeyCache->getKey();
					while (ulargeptr && !fileOK) {
						cout << "*";
						memcpy(lpBuffer, (byte *)fileData + magiclen + 4, bytesRead - (magiclen + 4));

						fileOK = tryDecypherFile(lpFilePath, lpBuffer, bytesRead - (magiclen + 4), trueSize, ulargeptr);
					
						ulargeptr = lpKeyCache->getNextKey();
					}

					if (!fileOK) {
						// brut force: on commence avec une clée de l'age du fichier
						// puis on remonte le temps
						ularge_ftWrite.LowPart = ftWrite.dwLowDateTime;
						ularge_ftWrite.HighPart = ftWrite.dwHighDateTime;
						ularge_ftWrite_min.QuadPart = ularge_ftWrite.QuadPart - timeWindows;

						int count = 0;
						while (!fileOK && ularge_ftWrite.QuadPart >= ularge_ftWrite_min.QuadPart) {
							
							cout << ".";

							memcpy(lpBuffer, (byte *)fileData + magiclen + 4, bytesRead - (magiclen + 4));
							fileOK = tryDecypherFile(lpFilePath, lpBuffer, bytesRead - (magiclen + 4), trueSize, &ularge_ftWrite);

							if(fileOK) lpKeyCache->appendKey(&ularge_ftWrite); // enregistrer la clé trouvée

							ularge_ftWrite.QuadPart -= 10000; //1ms
						}

					}
					if (!fileOK) cout << " No key found!";
					cout << "\n";
				}

			}
			HeapFree(GetProcessHeap(), NULL, fileData);
			HeapFree(GetProcessHeap(), NULL, lpBuffer);
		}
		else {
			cout << "Echec lecture taille de: " << lpFilePath << "\n";
		}

		if (hFile) CloseHandle(hFile);
	}
	return FALSE;
}


int main()
{
	const char var1[] = "HOMEDRIVE", var2[] = "HOMEPATH";
	KEYARRAYA Ka;  // Container de stockage des clés touvées pendant le parcours des répertoires
	
	/** Homepath de l'utilisateur */
	LPSTR homepath = (LPSTR)malloc(MYMAXLEN);

	int len = GetEnvironmentVariableA(var1, homepath, MYMAXLEN);
	if (len && len < MYMAXLEN - 1) {
		len += GetEnvironmentVariableA(var2, homepath + len, MYMAXLEN - len);
	}

    std::cout << "HOMEPATH: " << homepath <<"\n";

	/* *** TODO: automatiser la supression des clés et binaires servant à la persistance
	 *     du malware
	 */

	/* *** RECUPERATION des fichiers chiffrés
	 */
	// Deux parcours des répertoires suffisent pour récupérer tous les fichiers.
	// - Windows ne garantie pas l'ordre d'exploration des fichiers et répertoires 
	// - la date de modification des fichiers qui ont été chiffré est plus ou moins proche de 
	// la date utilisée comme clé de chifrement en fonction du nombre et de la taille des 
	// fichiers chiffré avec une même  clé.
	// 
	// Il n'y a donc pas de garantie de retrouver la clé de chiffrement d'un ensemble de fichiers
	// dès le premier fichier rencontré. Par contre on est certain d'avoir retrouvé toutes les 
	// clés de chiffrement à l'issu d'une première exploration complète. En effet le délai entre le 
	// le choix de la clé de chiffrement (date de lancement du malware Sudoku) et le
	// chiffrement des premiers fichies d'une série est inférieur à 100ms.
	// Pour mémoire: la résolution de l'heure système (SYSTEMTIME utilisée comme clé de chiffrement)
	// est de 1ms; la résolution de la date de modification des fichiers peut aller 
	// jusqu'à 0,1 microsecondes (dépend du système de fichiers).

	parcoursRepertoires(homepath, fn_listdir, &Ka);
	parcoursRepertoires(homepath, fn_listdir, &Ka);

	
}

