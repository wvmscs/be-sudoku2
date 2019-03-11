/*
  Copyright (C) 2019 WVConsultants (FR).  All rights reserved.

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
	 claim that you wrote the original software. If you use this software
	 in a product, an acknowledgment in the product documentation would be
	 appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
	 misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

 William VITAL
 consultants@william-vital.fr

 */
// antisudoku.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
/*******************
 * Ce programme procède à la remédiation d'un compte 
 * utilisateur infecté par le ransomware SUDOKU.
 * (c) 2019 William VITAL 
 * Pulic domain (03/03/2019)
 *
 * Utilise la bibliothèque MD5 de  L. Peter Deutsch, Aladdin Enterprises (2002) 
 * Utilise la bibliothèque BLOWFISH de David Madore <david.madore@ens.fr> (1999)
 *
 * AntiSudoku réalise:  
 *  - la supression de la persistance et supression/mise en quarantaine des programes SUDOKU malveillants
 *  - le déchiffrement des fichiers chiffrés par le programme Sudoku 
 *  - la suppression des notes de demande de rançon après vérification de leur hash (sauvegarde d'une de ces notes pour chaque hash trouvé)
 *  - la production d'un rappoprt sur le travail effectué, le nombre de fichiers récupéré, la liste des fichiers dont le déchiffrement n'a pas été possible.
 *  - la génération des IOCs (md5 des .exe et .txt)
 * 
 */


//#include "pch.h"
#include <iostream>
#include <fstream>
#include <Windows.h>



//#include <strsafe.h>
//#include "blowfish2.h"
#include "blowfish3.h"
#include "md5.h"

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

typedef struct tag_savestates {
	KEYARRAYA Ka;  // Container de stockage des clés touvées pendant le parcours des répertoires
	unsigned int nbFichiersChiffres, nbFichiersDechiffres, nbRepertoireTrouve, 
		nbFichierReadmeSupprime, nbEchecLectureFichier, nbFichierExeSupprime;
	BOOL bCountRep;
	HANDLE hlogfile;
	std::ostream *log;
	char * pbasePath;
	const char *listOfDirectoryToSkip[10] = {
		"AppData\\Local",
		NULL
	};

} savestates, *psavestates;

const int MYMAXLEN = 1024;
const int FILEPATH_LEN = 1024;
const int FILEBUFFER_LEN = 1024;

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

// méthode de vérification du critère d'arrêt moins laxiste!
BOOL isKnownMagic(const char *pPath, byte *lpbuff, int len) {
	static const char *magic_docx[] = { "PK\x03\x04", "PK\x05\x06", "PK\x07\x08", NULL };
	static const char *magic_doc[] =  { "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", NULL };
	static const char *magic_pdf[] = { "%PDF", NULL };
	static const char *magic_gif[] = { "GIF8", NULL };
	static const char *magic_png[] = { "\x89PNG", "RIFF", NULL };
	static const char *magic_jpg[] = { "\xff\xd8\xff", NULL };
	static const char *magic_rtf[] = { "{\rtf1", NULL };
	BOOL retval = FALSE;
	const char *extension = strrchr(pPath, '.');
	const char ** evid = NULL;
	if (extension) {
		extension += 1;
		if (_stricmp(extension, "docx") == 0 || _stricmp(extension, "pptx") == 0 || _stricmp(extension, "xlsx") == 0) {
			evid = magic_docx;
		} 
		if (!evid) if (_stricmp(extension, "doc") == 0 || _stricmp(extension, "ppt") == 0 || _stricmp(extension, "xls") == 0) {
			evid = magic_doc;
		}
		if (!evid) if (_stricmp(extension, "pdf") == 0) {
			evid = magic_pdf;
		}
		if (!evid) if (_stricmp(extension, "gif") == 0) {
			evid = magic_gif;
		}
		if (!evid) if (_stricmp(extension, "png") == 0) {
			evid = magic_png;
		}
		if (!evid) if (_stricmp(extension, "jpg") == 0 || _stricmp(extension, "jepg") == 0) {
			evid = magic_jpg;
		}
		if (!evid) if (_stricmp(extension, "rtf") == 0) {
			evid = magic_rtf;
		}
		if (evid) {
			for (const char **p = evid; *p != NULL; p++) {
				int max = strlen(*p);
				if (len >= max) {
					if (memcmp(lpbuff, *p, max) == 0) retval = TRUE;
				}
			}
		}
		if (!retval) if (_stricmp(extension, "htm") == 0 || _stricmp(extension, "html") == 0) {
			// tenter une reconaissance de caractères ascii ou utf8 (une trentaire ...
			BOOL b = TRUE;
			int mlen = 30; if (len < 30) mlen = len;
			if (mlen) {
				for (int i = 0; i < mlen && b; i++) {
					b = b && (isascii(*(lpbuff + i)) || iswascii(*(lpbuff + i)));
				}
				retval = b;
			}
		}

	}
	return retval;
}


const unsigned char *lpIV = (unsigned char *)"@GPCODE";
const char *lpMagicCryptor = "GPGcryptor";
const char *lpIOCmd5_exe = "\x52\xfb\x8b\xa7\x0f\xbc\x1b\xa8\xf9\xd6\x65\xf2\x19\x29\xbb\x50";
const char *lpIOCmd5_readme = "\x94\x89\x9f\x98\x3b\x85\x47\xca\xbb\xcf\x3b\xe4\x9d\xd9\xd5\xd5";
const char *lpRegKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

/* DANGEREUX! _ voir l'implémentation alternative ci-dessus moins laxiste
// indique si le bloc mémoire peut être assimilé à un décodage réussi
inline BOOL isKnownMagic_old(const byte *lp, const unsigned len) {
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
		int mlen = 10; if (len < 10) mlen=len;
		for (int i = 0; i < mlen && b; i++) {
			b = b && (isascii(*(lp + i)) || iswascii(*(lp + i)));
		}
		retval = b;
	}
	return retval;
}
*/

unsigned int revoveFileByMd5(const LPCSTR pcurrentDirectory, const LPCSTR pextend, const LPCSTR pmd5, psavestates lpcontext, BOOL report_supress, BOOL useextend=TRUE) {
	WIN32_FIND_DATAA wfd_context;
	CHAR curSearch[MYMAXLEN];
	unsigned int count = 0;

	if (useextend)
		snprintf(curSearch, MYMAXLEN - 1, "%s\\%s", pcurrentDirectory, pextend);
	else
		snprintf(curSearch, MYMAXLEN - 1, "%s", pcurrentDirectory);

	HANDLE hfind = FindFirstFileA(curSearch, &wfd_context);
	if (hfind != INVALID_HANDLE_VALUE) {
		do {
			char filePath[FILEPATH_LEN];
			unsigned char fileBuffer[FILEPATH_LEN];
			md5_state_t md5st;

			if (!(wfd_context.dwFileAttributes & 0x10)) {
				if (useextend)
					snprintf(filePath, FILEPATH_LEN, "%s\\%s", pcurrentDirectory, &wfd_context.cFileName);
				else
					snprintf(filePath, FILEPATH_LEN, "%s", pcurrentDirectory);
				// cout << " ... Etude de la suppression de " << filePath;
				md5_init(&md5st);
				FILE *fd;
				if (fopen_s(&fd, filePath, "rb") == 0) {
					md5_byte_t digest[16];
					unsigned int len_r = 1;
					while (len_r) {
						len_r = fread(fileBuffer, 1, FILEPATH_LEN, fd);
						md5_append(&md5st, fileBuffer, len_r);
					}
					fclose(fd);

					md5_finish(&md5st, digest);
					if (memcmp(digest, pmd5, 16) == 0) {

						if ( _unlink(filePath) == 0 ) {
							count++;
							// cout << "    *** Supprimé ";
							if (report_supress) *lpcontext->log << pextend << ": suppression de "<< filePath << "\n";
						}
						else {
							cout << filePath <<"    *** Echec suppression (ERREUR)\n";
						}

					}

				}
				else {
					cout << filePath << "   *** ERREUR\n";
				}
				
			}
		} while (FindNextFileA(hfind, &wfd_context));
		FindClose(hfind);
	}
	return count;
}
unsigned int removeReadMeFile(const LPCSTR currentDirectory, psavestates lpcontext) {
	return revoveFileByMd5(currentDirectory, "README.txt", lpIOCmd5_readme, lpcontext, FALSE);
}
unsigned int removeSudokuFile(const LPCSTR currentDirectory, psavestates lpcontext) {
	return revoveFileByMd5(currentDirectory, "*.exe", lpIOCmd5_exe, lpcontext, TRUE);
}
unsigned int removeFileIfIOC(const LPCSTR currentDirectory, psavestates lpcontext) {
	return revoveFileByMd5(currentDirectory, "*.exe", lpIOCmd5_exe, lpcontext, TRUE, FALSE);
}


BOOL isDirectoryToSkip(LPCSTR psearchDir, psavestates lpcontext) {
	BOOL retval = FALSE;
	int l = strlen(lpcontext->pbasePath) + 1;
	for (const char **p = lpcontext->listOfDirectoryToSkip; *p; p++) {
		if (strstr(psearchDir, *p) == (psearchDir + l))
			retval = TRUE;
	}
	return retval;
}

void parcoursRepertoires(LPCSTR currentDirectory, void (*fn_callback)(void *, LPCSTR,  LPWIN32_FIND_DATAA), 
	psavestates lpcontext) {
	
	WIN32_FIND_DATAA wfd_context;
	CHAR curSearch[MYMAXLEN];

	snprintf(curSearch, MYMAXLEN - 1, "%s\\*", currentDirectory);
	//cout << "searching " << curSearch << "\n";

	if (lpcontext->bCountRep) {
		lpcontext->nbRepertoireTrouve++;
		// suppression des fichiers README.txt
		lpcontext->nbFichierReadmeSupprime += removeReadMeFile(currentDirectory, lpcontext);
		// supression des fichiers Sudoku.exe et de ses clones
		lpcontext->nbFichierExeSupprime += removeSudokuFile(currentDirectory, lpcontext);		
	}


	HANDLE hfind = FindFirstFileA(curSearch, &wfd_context);
	if (hfind != INVALID_HANDLE_VALUE) {
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
					if (!isDirectoryToSkip(newSearchDir, lpcontext))
						parcoursRepertoires(newSearchDir, fn_callback, lpcontext);
					else {
						// on n'effectura pas de recovery des sous répertoires à partir de ce point
						*lpcontext->log << "Skipped: le répertoire " << newSearchDir << "ne sera pas analysé\n";
						cout << "Skipped: le répertoire " << newSearchDir << "ne sera pas analysé\n";
					}
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



BOOL uncipherFile(const char *lpFilePath, psavestates lpKeyCache);

//KEYARRAYA Ka;

void fn_action_show(void* context, LPCSTR currentDir, LPWIN32_FIND_DATAA lpFileDesc) {
	 

	char FILEPATH[256];
	snprintf(FILEPATH, 256, "%s\\%s", currentDir, lpFileDesc->cFileName);

	/*cout << "Found: " << FILEPATH;
	printFileTimes(lpFileDesc);
	cout << "\n";
	*/
	
	uncipherFile(FILEPATH, (psavestates)context);
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

#define MYLLEN 256
char __printstring[MYLLEN];
char * stringSystemTime(LPSYSTEMTIME lp) {
	snprintf(__printstring, MYLLEN,
		" %02d/%02d/%d-%02d:%02d:%0d:%d",
		(lp)->wDay, (lp)->wMonth, (lp)->wYear,
		(lp)->wHour, (lp)->wMinute, (lp)->wSecond, (lp)->wMilliseconds);
	return __printstring;
}

void printSystemTime(LPSYSTEMTIME lpst) {
	cout << stringSystemTime(lpst);
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


BOOL tryDecypherFile(const char *lpFilePath, byte *lpBuffer, DWORD fileLen, DWORD trueSize, ULARGE_INTEGER *ulargeptr, psavestates lpKeyCache) {
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
	if (isKnownMagic(lpFilePath, lpBuffer, decryptlen) == TRUE) {

		cout << " TROUVE key=";
		printSystemTime(&thisKey);
		cout  << "\n";

		*lpKeyCache->log << " TROUVE key=" << stringSystemTime(&thisKey) << "\n";

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
			cout << "write failed for " << lpFilePath;
		}
	}
	return retval;
}

BOOL uncipherFile(const char *lpFilePath, psavestates lpKeyCache) {
	FILETIME ftCreate, ftAccess, ftWrite , ft_var;
	SYSTEMTIME  stWrite, stWrite_min;
	ULARGE_INTEGER ularge, ularge_ftWrite, ularge_ftWrite_min;
	unsigned long timeWindows = 10000000;  //(1000 milisec)
	BOOL retval = FALSE;

	// Provisoire
	//if (!strstr(lpFilePath, ".png"))
	//	return FALSE;

	HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ , 0, NULL,
		OPEN_EXISTING, 0, NULL);
	//byte *lpIV = (byte *)"@GPCODE";
	//const char *lpMagicCryptor = "GPGcryptor";

	if (hFile != INVALID_HANDLE_VALUE) {
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
					*lpKeyCache->log << "Cyphered: " << lpFilePath << " (" << trueSize << ")   ";
					lpKeyCache->nbFichiersChiffres++ ;

					BOOL fileOK = FALSE;

					// on regarde si on ne possède pas déjà la clé
					ULARGE_INTEGER *ulargeptr = lpKeyCache->Ka.getKey();
					while (ulargeptr && !fileOK) {
						cout << "*";
						//*lpKeyCache->log << "*";
						memcpy(lpBuffer, (byte *)fileData + magiclen + 4, bytesRead - (magiclen + 4));

						fileOK = tryDecypherFile(lpFilePath, lpBuffer, bytesRead - (magiclen + 4), trueSize, ulargeptr, lpKeyCache);
					
						ulargeptr = lpKeyCache->Ka.getNextKey();
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
							//*lpKeyCache->log << ".";

							memcpy(lpBuffer, (byte *)fileData + magiclen + 4, bytesRead - (magiclen + 4));
							fileOK = tryDecypherFile(lpFilePath, lpBuffer, bytesRead - (magiclen + 4), trueSize, &ularge_ftWrite, lpKeyCache);

							if(fileOK) lpKeyCache->Ka.appendKey(&ularge_ftWrite); // enregistrer la clé trouvée

							ularge_ftWrite.QuadPart -= 10000; //1ms
						}

					}
					if (!fileOK) { cout << " No key found!"; *lpKeyCache->log << " No key found!\n"; }
					cout << "\n"; //*lpKeyCache->log << "\n";
					if (fileOK) {
						retval = TRUE;
						lpKeyCache->nbFichiersDechiffres++;
					}
					else if (!lpKeyCache->bCountRep) {
						*lpKeyCache->log << "ECHEC: clé non trouvée, déchiffrement de " << lpFilePath <<"\n";
					}
				}

			}
			HeapFree(GetProcessHeap(), NULL, fileData);
			HeapFree(GetProcessHeap(), NULL, lpBuffer);
		}

		if (hFile) CloseHandle(hFile);
	}
	else if (!lpKeyCache->bCountRep) {
		lpKeyCache->nbEchecLectureFichier++;
		*lpKeyCache->log << "ECHEC: lors de l'ouverture du fichier " << lpFilePath << "\n";

	}
	return retval;
}


int main()
{
	const char var1[] = "HOMEDRIVE", var2[] = "HOMEPATH";
	const char forensic_name[] = "antiSudoku";
	savestates svsts;
	
	KEYARRAYA Ka;  // Container de stockage des clés touvées pendant le parcours des répertoires
	
	svsts.nbFichiersChiffres = svsts.nbFichiersDechiffres = svsts.nbRepertoireTrouve = 0;
	svsts.nbFichierReadmeSupprime = svsts.nbEchecLectureFichier = svsts.nbFichierExeSupprime = 0;
	svsts.bCountRep = FALSE;
	svsts.hlogfile = NULL;

	std:filebuf fb;
	

	/** Homepath de l'utilisateur */
	LPSTR homepath = (LPSTR)malloc(MYMAXLEN);
	LPSTR forensicpath = (LPSTR)malloc(MYMAXLEN);

	int len = GetEnvironmentVariableA(var1, homepath, MYMAXLEN);
	if (len && len < MYMAXLEN - 1) {
		len += GetEnvironmentVariableA(var2, homepath + len, MYMAXLEN - len);
	}

    std::cout << "HOMEPATH: " << homepath <<"\n";
	svsts.pbasePath = homepath;

	/* *** TODO: automatiser la supression des clés et binaires servant à la persistance
	 *     du malware
	 */
	// Etape forensic: sauvegarder les élements de preuve et traces
	
	snprintf(forensicpath, MYMAXLEN, "%s\\%s.log", homepath, forensic_name);
	//svsts.hlogfile = CreateFileA(forensicpath, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
	fb.open(forensicpath, std::ios::out);
	svsts.log = new std::ostream(&fb);
	*svsts.log << "ANTISUDOKU: Restauration des fichiers chiffrés par le malware Sudoku.exe\n";
	*svsts.log << " (identifié par Windows Defender comme Trojan:Win32/Sprisky.U!cl)\n\n";
	*svsts.log << "Actions exécutées:\n";
	*svsts.log << "    - suppression de la valeur _SuDOkU_ de la clé de registre HKEY_CURRENT_USER\\" << lpRegKey << "\n";
	*svsts.log << "    - suppression de toutes les copies du programme Sudoku.exe et de ses clones\n";
	*svsts.log << "    - suppression des fichiers texte de demande de rançon\n";
	*svsts.log << "    - déchiffrement des fichiers personnels\n\n";
	*svsts.log << "Point de départ pour le parcours des répertoires: " << homepath << "\n";
	*svsts.log << "_________________ log d'exécution ___________________\n";

	/*if (svsts.hlogfile) {
		std::cout << "forensic: " << forensicpath << "\n";
	} else {
		cout << "open failed for: " << forensicpath << "\n";
	}*/

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
	// chiffrement des premiers fichies d'une série est inférieur à 1000ms.
	// Pour mémoire: la résolution de l'heure système (SYSTEMTIME utilisée comme clé de chiffrement)
	// est de 1ms; la résolution de la date de modification des fichiers peut aller 
	// jusqu'à 0,1 microsecondes (dépend du système de fichiers).

	//parcoursRepertoires(homepath, fn_listdir, &Ka);
	//parcoursRepertoires(homepath, fn_listdir, &Ka);

	// supression de la clé de registre
	HKEY tpKey =  NULL;
	LPSTR lpSudokuPath = (LPSTR)malloc(MYMAXLEN);
	DWORD lenSudokuPath = MYMAXLEN;
	LSTATUS retval = RegOpenKeyExA(HKEY_CURRENT_USER, lpRegKey, NULL, KEY_READ|KEY_SET_VALUE, &tpKey);
	if (retval == ERROR_SUCCESS) {
		retval = RegQueryValueExA(tpKey, "_SuDOkU_", NULL, NULL, (LPBYTE)lpSudokuPath, &lenSudokuPath);
		if (retval == ERROR_SUCCESS) {
			*(lpSudokuPath + lenSudokuPath) = '\x00';
			svsts.nbFichierExeSupprime += removeFileIfIOC(lpSudokuPath, &svsts); // supression du fichier (!si IOC ... parano!)			
		}
		retval = RegDeleteValueA(tpKey, "_SuDOkU_"); // , /*KEY_WOW64_32KEY*/  KEY_WOW64_64KEY, NULL);
		RegCloseKey(tpKey);
		if (retval != ERROR_SUCCESS && retval != ERROR_FILE_NOT_FOUND) {
			*svsts.log << "REG: Echec de supression de la clé _SuDOkU_\n";
		} else if(retval == ERROR_SUCCESS) *svsts.log << "REG: clé _SuDOkU_ supprimée\n";
		else  *svsts.log << "REG: la clé _SuDOkU_ était déjà abscente\n";
	}
	else {
		*svsts.log << "REG: Impossible d'ouvrir la clé " << lpRegKey << "\n";
	}

	//Vérification du répertoire startup et purge des clones de SUDOKU qui pourraient s'y trouver
	const char *lpstartupkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
	LPSTR lpstartupPath = (LPSTR)malloc(MYMAXLEN);
	DWORD lenStartupPath = MYMAXLEN;
	retval = RegOpenKeyExA(HKEY_CURRENT_USER, lpstartupkey, NULL, KEY_READ, &tpKey);
	if (retval == ERROR_SUCCESS) {
		retval = RegQueryValueExA(tpKey, "Startup", NULL, NULL, (LPBYTE)lpstartupPath, &lenStartupPath);
		if (retval == ERROR_SUCCESS) {
			*(lpstartupPath + lenStartupPath) = '\x00';
			svsts.nbFichierExeSupprime += removeSudokuFile(lpstartupPath, &svsts); //suppression des clones	
		}
		RegCloseKey(tpKey);
	}
	free(lpstartupPath); lpstartupPath=NULL;

	svsts.bCountRep = TRUE;
	parcoursRepertoires(homepath, fn_listdir, &svsts); //Tour 1

	svsts.bCountRep = FALSE;
	parcoursRepertoires(homepath, fn_listdir, &svsts); //Tour 2 ... pour être sûr 

	*svsts.log << "\n_________________  Statistiques   ___________________\n";
	{
		char statsBuffer[FILEBUFFER_LEN];
		snprintf(statsBuffer, FILEBUFFER_LEN,
			"Nombre de fichiers trouvés chiffrés\t\t\t\t%u\nNombre de fichiers déchiffrés avec succès\t\t\t%u\nNombre de répertoires parcourus\t\t\t\t\t%u\n",
			svsts.nbFichiersChiffres,
			svsts.nbFichiersDechiffres,
			svsts.nbRepertoireTrouve
		);
		cout << statsBuffer;
		*svsts.log << statsBuffer;

		snprintf(statsBuffer, FILEBUFFER_LEN,
			"Nombre de fichiers README.txt supprimés\t\t\t\t%u\nNombre de copies du programme SUDOKU.exe supprimées\t\t%u\nNombre de fichiers qui n'ont pût être côntrolés (Erreurs)\t%u\n",
			svsts.nbFichierReadmeSupprime ,
			svsts.nbFichierExeSupprime ,
			svsts.nbEchecLectureFichier

			);
		cout << statsBuffer;
		*svsts.log << statsBuffer;

	}
	
	cout << "\n Un log d'exécution à été produit dans " << homepath << "\\" << forensic_name << ".log\n";

	//CloseHandle(svsts.hlogfile);
	fb.close();
	return 0;
}

