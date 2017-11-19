// LotsOfHashes.cpp : Defines the initialization routines for the DLL.
//

#include "stdafx.h"
#include "time.h"
#include "contentplug.h"
#include "Hashes.h"
#include "Cache.h"
#include "FileHash.h"
#include <share.h>

// field indexes
typedef enum _field_index
{
	FDX_CRC32 = 0,
	FDX_CRC32b,
	FDX_eD2k_eMule,
	FDX_GOST,
	FDX_HAVAL_128_3,
	FDX_HAVAL_128_4,
	FDX_HAVAL_128_5,
	FDX_HAVAL_160_3,
	FDX_HAVAL_160_4,
	FDX_HAVAL_160_5,
	FDX_HAVAL_192_3,
	FDX_HAVAL_192_4,
	FDX_HAVAL_192_5,
	FDX_HAVAL_224_3,
	FDX_HAVAL_224_4,
	FDX_HAVAL_224_5,
	FDX_HAVAL_256_3,
	FDX_HAVAL_256_4,
	FDX_HAVAL_256_5,
	FDX_MD4,
	FDX_MD5,
	FDX_MURMUR_32,
	FDX_MURMUR_128,
	FDX_RIPEMD_128,
	FDX_RIPEMD_160,
	FDX_RIPEMD_256,
	FDX_RIPEMD_320,
	FDX_SALSA10,
	FDX_SALSA20,
	FDX_SHA1_160,
	FDX_SHA2_224,
	FDX_SHA2_256,
	FDX_SHA2_384,
	FDX_SHA2_512,
	FDX_SHA3_224,
	FDX_SHA3_256,
	FDX_SHA3_384,
	FDX_SHA3_512,
	FDX_Snefru_128,
	FDX_Snefru_256,
	FDX_Tiger_128_3,
	FDX_Tiger_128_4,
	FDX_Tiger_160_3,
	FDX_Tiger_160_4,
	FDX_Tiger_192_3,
	FDX_Tiger_192_4,
	FDX_Whirlpool,
	// FDX_Field_Count - MUST BE LAST
	FDX_Field_Count
} field_index;


#define _detectstring ""
#define fieldcount FDX_Field_Count

char* fieldnames[fieldcount] = 
{
	"CRC32", "CRC32b", "eD2k/eMule", "GOST", "HAVAL 128,3",
	"HAVAL 128,4", "HAVAL 128,5", "HAVAL 160,3", "HAVAL 160,4", "HAVAL 160,5",
	"HAVAL 192,3", "HAVAL 192,4", "HAVAL 192,5", "HAVAL 224,3", "HAVAL 224,4",
	"HAVAL 224,5", "HAVAL 256,3", "HAVAL 256,4", "HAVAL 256,5", "MD4",
	"MD5", "Murmur 32", "Murmur 128", "RIPEMD 128", "RIPEMD 160",
	"RIPEMD 256", "RIPEMD 320", "Salsa10", "Salsa20", "SHA1 160",
	"SHA2 224", "SHA2 256", "SHA2 384", "SHA2 512", "SHA3 224",
	"SHA3 256", "SHA3 384", "SHA3 512", "Snefru 128", "Snefru 256",
	"Tiger 128,3", "Tiger 128,4", "Tiger 160,3", "Tiger 160,4", "Tiger 192,3",
	"Tiger 192,4", "Whirlpool"
};

#define field_choices "Uppercase|Lowercase|Delimited uppercase|Delimited lowercase"
//#define field_choices "HEX|hex|H:E:X|h:e:x"		total commander handle units as case insensitive (HEX==hex)


/******************************************************************
// All fields are of the same type.
int fieldtypes[fieldcount] =
{
	ft_stringw, ft_stringw, ft_stri...
};

// All fields have the same units/choices
char* fieldunits_and_multiplechoicestrings[fieldcount] =	
{
	field_choices, field_choices, field_choi...
};

// Not Needed
int fieldflags[fieldcount] =
	{0, 0, 0, 0, 0};

// Not Needed
int sortorders[fieldcount] =
	{1, 1, 1, 1, 1};

// Not Needed
char* multiplechoicevalues[2] =
	{"", ""};

// Not Needed
BOOL GetValueAborted=false; 
******************************************************************/

#define HASH_CODE_BUFF_BYTE_SIZE 64		/* 64 is the longer output byte code size of all supported algorithms.
													 The output code of SHA-512 & Whirlpool is 512 bits, ergo 64 bytes */

#define HASH_CODE_BUFF_SIZE 129			/* 128 is the longer output hex code size of all supported algorithms.
														The output code of SHA-512 & Whirlpool is 512 bits
														which means 128 hex digits in displayable string + 0 terminating */

void HashByFieldIndex(int FieldIndex, CMMFileBytes& mmFile, BYTE** ppbHash, DWORD& dwHashLen, PROGRESSCALLBACKPROC progressCallback);

CHashes			g_hashes;
HMODULE			g_hModule = NULL;


//////////////////////////////////////////////////////////////////////////////////////////
//
BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch(ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		g_hModule = (HMODULE)hModule;		
		break;
		//#########################################

	case DLL_PROCESS_DETACH:		
		break;
		//#########################################
	}

    return TRUE;
}

//////////////////////////////////////////////////////////////////////////////////////////
//
void __stdcall ContentPluginUnloading(void)
{
	Write2Log(L"E ContentPluginUnloading");
#ifdef USE_CACHE
	CCache::Release();
#endif
	CConfiguration::Release();
}

//////////////////////////////////////////////////////////////////////////////////////////
//
int __stdcall ContentGetDetectString(char* DetectString, int maxlen)
{
	strlcpy(DetectString, _detectstring, maxlen);
	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////
//
int __stdcall ContentGetSupportedField(int FieldIndex, char* FieldName, char* Units, int maxlen)
{
	// for compare
	if(FieldIndex >= 10000)
	{
		// if in range of the field count
		if(FieldIndex < (10000+fieldcount))
		{
			char szFieldNameFmt[] = {"Compare %s "};

			_snprintf_s(FieldName, maxlen-1, _TRUNCATE, szFieldNameFmt, fieldnames[FieldIndex-10000]);

			Units[0]=0;
			return ft_comparecontent;
		}
		else
			return ft_nomorefields;
	}

	if( (FieldIndex < 0) || (FieldIndex >= fieldcount) )
		return ft_nomorefields;

	strlcpy(FieldName, fieldnames[FieldIndex], maxlen-1);
	strlcpy(Units, field_choices, maxlen-1);	// All fields have the same units/choices; fieldunits_and_multiplechoicestrings[FieldIndex]	

	return ft_stringw;		// All fields are of the same type; fieldtypes[FieldIndex];
}

//////////////////////////////////////////////////////////////////////////////////////////
//
void __stdcall ContentStopGetValue(char* FileName)
{
	Write2Log(L"E ContentStopGetValue");
	g_hashes.Abort();
}

//////////////////////////////////////////////////////////////////////////////////////////
//
void __stdcall ContentStopGetValueW(WCHAR* FileName)
{
	Write2Log(L"E ContentStopGetValueW");
	g_hashes.Abort();
}

//////////////////////////////////////////////////////////////////////////////////////////
//
int __stdcall ContentGetValue(char* FileName, int FieldIndex, int UnitIndex, void* FieldValue, int maxlen, int flags)
{
	Write2Log(L"E ContentGetValue");

	WCHAR FileNameW[MAX_FILE_PATH_NAME];
	WCHAR FieldValueW[HASH_CODE_BUFF_SIZE];

	int	nRet = ContentGetValueW(awlcpy(FileNameW, FileName, _countof(FileNameW)), FieldIndex, UnitIndex, FieldValueW, maxlen, flags);

	walcpy((char*)FieldValue, FieldValueW, maxlen);

	return nRet;
}

//////////////////////////////////////////////////////////////////////////////////////////
//
int __stdcall ContentGetValueW(WCHAR* FileName, int FieldIndex, int UnitIndex, void* FieldValue, int maxlen, int flags)
{
	// check field range
	if( (FieldIndex < 0) || (FieldIndex >= fieldcount) )
		return ft_nosuchfield;

	if(flags & CONTENT_DELAYIFSLOW)
		return ft_delayed;

	WIN32_FILE_ATTRIBUTE_DATA		fa;	

	// Get file type (directory or file)
	// Also the cache needs to know the file size and file LastWrite time
	if( !::GetFileAttributesEx(FileName, GetFileExInfoStandard, &fa) )
		return ft_fileerror;

	// if its a directory or its an empty file then exit with empty field
	if( (fa.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (fa.nFileSizeHigh==0 && fa.nFileSizeLow==0) )
		return ft_fieldempty;

	Write2Log(L"E ContentGetValueW %d ? %s", FieldIndex, FileName);

	try
	{
		BYTE*			pbHash = NULL;
		DWORD			dwHashLen = 0;

#ifdef USE_CACHE
		CFileHash*	pfh = NULL;
		
		// check in cache
		CCache::insertOrFind_t		iof = CCache::i()->InsertOrFind(&pfh, FileName, &fa, FieldIndex);

		if(iof == CCache::iof_Found)	/* ###>> Yee-Pee! It's Cached! - display whats in the cache */
		{
			pbHash = (BYTE*)(pfh->GetHash(dwHashLen));

			// if for some reason the hash value in the cache is empty
			if( pbHash && dwHashLen )
			{
				// convert to a displayable string
				ConvertToHex((WCHAR*)FieldValue, (maxlen/2), pbHash, dwHashLen, UnitIndex);
				return ft_stringw;
			}
			return ft_fieldempty;		// hash is empty
		}
		else									/* ###>> crap! It's not cached - calculate hash */
		{
			CMMFileBytes		mmFile(FileName);

			if(!mmFile.Open())
			{
				if(pfh)	// if is too small then object was not created
					pfh->SetNeedUpdate();	// the element in the cache is not valid and need a new hash calculation
				return ft_fileerror;
			}
	
			HashByFieldIndex(FieldIndex, mmFile, &pbHash, dwHashLen, NULL);	
	
			mmFile.Close();

			if(g_hashes.GetLastErrorCode() == HASHERROR_NO_ERROR)
			{
				// Do NOT update the cache if iof indicates that:
				//		1. there was an error.
				//		2. file is too small (pfh will be NULL).
				//		2. some other wird shit.

				if( (iof == CCache::iof_Inserted) || (iof == CCache::iof_FoundNeedUpdate) )
					pfh->SetHash(pbHash, dwHashLen);

				// convert to a displayable string
				ConvertToHex((WCHAR*)FieldValue, (maxlen/2), pbHash, dwHashLen, UnitIndex);
				return ft_stringw;
			}
			else
			{
				//Write2Log(L"ContentGetValueW Aborted=%d", (g_hashes.GetLastErrorCode() == HASHERROR_HASHING_ABORTED));
				if(pfh)
					pfh->SetNeedUpdate();	// the element in the cache is not valid and need a new hash calculation
				return ft_fieldempty;	// also if aborted
			}
		}		// if(iof == CCache::iof_Found)		

#else	// USE_CACHE

		CMMFileBytes		mmFile(FileName);

		if(!mmFile.Open())
			return ft_fileerror;
	
		HashByFieldIndex(FieldIndex, mmFile, &pbHash, dwHashLen, NULL);	
	
		mmFile.Close();

		if(g_hashes.GetLastErrorCode() == HASHERROR_NO_ERROR)
		{
			// convert to a displayable string
			ConvertToHex((WCHAR*)FieldValue, (maxlen/2), pbHash, dwHashLen, UnitIndex);
			return ft_stringw;
		}
		else
			return ft_fieldempty;	// also if aborted

#endif USE_CACHE

	}
	catch(...)
	{
		return ft_fileerror;
	}
}

//////////////////////////////////////////////////////////////////////////////////////////
//
int __stdcall ContentCompareFiles(PROGRESSCALLBACKPROC progressCallback, int compareIndex, char* filename1, char* filename2, FileDetailsStruct* filedetails)
{
	Write2Log(L"E ContentCompareFiles");

	WCHAR filename1W[MAX_FILE_PATH_NAME];
	WCHAR filename2W[MAX_FILE_PATH_NAME];

	awlcpy(filename1W, filename1, _countof(filename1W));
	awlcpy(filename2W, filename2, _countof(filename2W));

	return ContentCompareFilesW(progressCallback, compareIndex, filename1W, filename2W, filedetails);
}

//////////////////////////////////////////////////////////////////////////////////////////
//
int __stdcall ContentCompareFilesW(PROGRESSCALLBACKPROC progressCallback, int compareIndex, WCHAR* filename1, WCHAR* filename2, FileDetailsStruct* filedetails)
{
	// 1=equal, 2=equal if text, 0=not equal, -1=could not open files, -2=abort, -3=not our file type

	Write2Log(L"E ContentCompareFilesW");

	// check field range
	if( (compareIndex < 10000) || (compareIndex >= (10000+fieldcount)) )
		return -3;	// not our file type	

	Write2Log(L"Compare %d %s %s", compareIndex, filename1, filename2);

	try
	{
		CMMFileBytes		mmFile1(filename1);
		CMMFileBytes		mmFile2(filename2);

		if(!mmFile1.Open())
			return -1;	// could not open files

		if(!mmFile2.Open())
		{
			mmFile1.Close();
			return -1;	// could not open files
		}

		BYTE*		pbHash = NULL;
		DWORD		dwHashLen = 0;
		int		nFieldIndex = compareIndex-10000;
		BYTE		cHash1[HASH_CODE_BUFF_BYTE_SIZE];
		int		nLastErr;


		//g_hashes.SetProgressFactor(0.5);

		/************* hash file 1 *************/
		HashByFieldIndex(nFieldIndex, mmFile1, &pbHash, dwHashLen, progressCallback);
		mmFile1.Close();
	
		nLastErr = g_hashes.GetLastErrorCode();

		// user abort/cancel
		if(nLastErr == HASHERROR_HASHING_ABORTED)
		{
			Write2Log(L"Aborted Compare file1");
			return -2;	// abort
		}

		if(nLastErr != HASHERROR_NO_ERROR)
		{	// hash error
			Write2Log(L"Compare file1 error code %d", nLastErr);
			return -3;	// not our file type
		}

		// HASHERROR_NO_ERROR;
		//Write2Log(L"HashCode1 %s", ConvertToHex(szHashCode, HASH_CODE_BUFF_SIZE, pbHash, dwHashLen));

		// pbHash is temporary so save it for the comparison later on
		memcpy(cHash1, pbHash, dwHashLen);



		/************* hash file 2 *************/
		HashByFieldIndex(nFieldIndex, mmFile2, &pbHash, dwHashLen, progressCallback);
		mmFile2.Close();
	
		nLastErr = g_hashes.GetLastErrorCode();

		// user abort/cancel
		if(nLastErr == HASHERROR_HASHING_ABORTED)
		{
			Write2Log(L"Aborted Compare file2");
			return -2;	// abort
		}	
	
		if(nLastErr != HASHERROR_NO_ERROR)
		{	// hash error
			Write2Log(L"Compare file2 error code %d", nLastErr);
			return -3;	// not our file type
		}

		// HASHERROR_NO_ERROR;
		//Write2Log(L"HashCode2 %s", ConvertToHex(szHashCode, HASH_CODE_BUFF_SIZE, pbHash, dwHashLen));



		// compare hash codes
		if( memcmp(cHash1, pbHash, dwHashLen) == 0 )
			return 1;	// equal
		else
			return 0;	// not equal
	}
	catch(...)
	{
		return -3;	// not our file type
	}
}


//////////////////////////////////////////////////////////////////////////////////////////
//
void HashByFieldIndex(int FieldIndex, CMMFileBytes& mmFile, BYTE** ppbHash, DWORD& dwHashLen, PROGRESSCALLBACKPROC progressCallback)
{
	switch(FieldIndex)
	{
	case FDX_CRC32:			g_hashes.CRC32Hash(&mmFile, ppbHash, &dwHashLen, progressCallback);				break;
	case FDX_CRC32b:			g_hashes.CRC32bHash(&mmFile, ppbHash, &dwHashLen, progressCallback);				break;
	case FDX_eD2k_eMule:		g_hashes.EDonkey2kHash(&mmFile, ppbHash, &dwHashLen, progressCallback);			break;
	case FDX_GOST:				g_hashes.GOSTHash(&mmFile, ppbHash, &dwHashLen, progressCallback);				break;
	case FDX_HAVAL_128_3:	g_hashes.HAVALHash(128, 3, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_HAVAL_128_4:	g_hashes.HAVALHash(128, 4, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_HAVAL_128_5:	g_hashes.HAVALHash(128, 5, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_HAVAL_160_3:	g_hashes.HAVALHash(160, 3, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_HAVAL_160_4:	g_hashes.HAVALHash(160, 4, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_HAVAL_160_5:	g_hashes.HAVALHash(160, 5, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_HAVAL_192_3:	g_hashes.HAVALHash(192, 3, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_HAVAL_192_4:	g_hashes.HAVALHash(192, 4, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_HAVAL_192_5:	g_hashes.HAVALHash(192, 5, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_HAVAL_224_3:	g_hashes.HAVALHash(224, 3, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_HAVAL_224_4:	g_hashes.HAVALHash(224, 4, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_HAVAL_224_5:	g_hashes.HAVALHash(224, 5, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_HAVAL_256_3:	g_hashes.HAVALHash(256, 3, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_HAVAL_256_4:	g_hashes.HAVALHash(256, 4, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_HAVAL_256_5:	g_hashes.HAVALHash(256, 5, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_MD4:				g_hashes.MD4Hash(&mmFile, ppbHash, &dwHashLen, progressCallback);					break;
	case FDX_MD5:				g_hashes.MD5Hash(&mmFile, ppbHash, &dwHashLen, progressCallback);					break;
	case FDX_MURMUR_32:		g_hashes.Murmur32Hash(&mmFile, ppbHash, &dwHashLen, progressCallback);			break;
	case FDX_MURMUR_128:		g_hashes.Murmur128Hash(&mmFile, ppbHash, &dwHashLen, progressCallback);			break;
	case FDX_RIPEMD_128:		g_hashes.RIPEMDHash(128, &mmFile, ppbHash, &dwHashLen, progressCallback);		break;
	case FDX_RIPEMD_160:		g_hashes.RIPEMDHash(160, &mmFile, ppbHash, &dwHashLen, progressCallback);		break;
	case FDX_RIPEMD_256:		g_hashes.RIPEMDHash(256, &mmFile, ppbHash, &dwHashLen, progressCallback);		break;
	case FDX_RIPEMD_320:		g_hashes.RIPEMDHash(320, &mmFile, ppbHash, &dwHashLen, progressCallback);		break;
	case FDX_SALSA10:			g_hashes.Salsa10Hash(&mmFile, ppbHash, &dwHashLen, progressCallback);			break;
	case FDX_SALSA20:			g_hashes.Salsa20Hash(&mmFile, ppbHash, &dwHashLen, progressCallback);			break;
	case FDX_SHA1_160:		g_hashes.SHA160Hash(&mmFile, ppbHash, &dwHashLen, progressCallback);				break;
	case FDX_SHA2_224:		g_hashes.SHA224Hash(&mmFile, ppbHash, &dwHashLen, progressCallback);				break;
	case FDX_SHA2_256:		g_hashes.SHA256Hash(&mmFile, ppbHash, &dwHashLen, progressCallback);				break;
	case FDX_SHA2_384:		g_hashes.SHA384Hash(&mmFile, ppbHash, &dwHashLen, progressCallback);				break;
	case FDX_SHA2_512:		g_hashes.SHA512Hash(&mmFile, ppbHash, &dwHashLen, progressCallback);				break;
	case FDX_SHA3_224:		g_hashes.SHA3Hash(224, &mmFile, ppbHash, &dwHashLen, progressCallback);			break;
	case FDX_SHA3_256:		g_hashes.SHA3Hash(256, &mmFile, ppbHash, &dwHashLen, progressCallback);			break;
	case FDX_SHA3_384:		g_hashes.SHA3Hash(384, &mmFile, ppbHash, &dwHashLen, progressCallback);			break;
	case FDX_SHA3_512:		g_hashes.SHA3Hash(512, &mmFile, ppbHash, &dwHashLen, progressCallback);			break;
	case FDX_Snefru_128:		g_hashes.SnefruHash(128, &mmFile, ppbHash, &dwHashLen, progressCallback);		break;
	case FDX_Snefru_256:		g_hashes.SnefruHash(256, &mmFile, ppbHash, &dwHashLen, progressCallback);		break;
	case FDX_Tiger_128_3:	g_hashes.TigerHash(128, 3, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_Tiger_128_4:	g_hashes.TigerHash(128, 4, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_Tiger_160_3:	g_hashes.TigerHash(160, 3, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_Tiger_160_4:	g_hashes.TigerHash(160, 4, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_Tiger_192_3:	g_hashes.TigerHash(192, 3, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_Tiger_192_4:	g_hashes.TigerHash(192, 4, &mmFile, ppbHash, &dwHashLen, progressCallback);	break;
	case FDX_Whirlpool:		g_hashes.WhirlpoolHash(&mmFile, ppbHash, &dwHashLen, progressCallback);			break;
	default:						throw "ERROR";
	}
}






/****************************************************************************************************/
/****************************************************************************************************/
/****************************************************************************************************/
/****************************************************************************************************/
/****************************************************************************************************/
/****************************************************************************************************/
/****************************************************************************************************/

/*
	/*
	FILE*		pFile;	
	if( (pFile = _wfsopen(FileName, L"rbS", _SH_DENYNO)) == NULL )	// File opened is sharable
		return ft_fileerror;
	*/
/*
	FILE*		pFile1;
	FILE*		pFile2;

	if( (pFile1 = _wfsopen(filename1, L"rbS", _SH_DENYNO)) == NULL )	// File opened is sharable
		return -1;	// could not open files

	if( (pFile2 = _wfsopen(filename2, L"rbS", _SH_DENYNO)) == NULL )	// File opened is sharable
	{
		fclose(pFile1);
		return -1;	// could not open files
	}

*/