
// Hashes.h : header file
//

#include "Crc32.h"
#include "Tiger.h"
#include "Haval.h"
#include "Whirlpool.h"
#include "Ripemd.h"
#include "Gost.h"
#include "Snefru.h"
#include "Md4.h"
#include "Md5.h"
#include "EDonkey2k.h"
#include "Sha160.h"
#include "Sha256Sha224.h"
#include "Sha512Sha384.h"
#include "Murmur.h"
#include "Salsa.h"
#include "Keccak.h"

#include "MMFileBytes.h"

#pragma once

#define IMPLEMENT_WIN_CRYPT_HASHES
#define IMPLEMENT_HASH_BY_BYTE_ARRAY
#define IMPLEMENT_HASH_BY_FILE
#define IMPLEMENT_HASH_BY_MEM_MAP_FILE


#ifdef IMPLEMENT_WIN_CRYPT_HASHES
  #include "Wincrypt.h"
#endif IMPLEMENT_WIN_CRYPT_HASHES

#define ERROR_MSG_BUFF_SIZE 100
#define FILE_READ_BUFF_SIZE 1024		// should NOT be larger then max DWORD; fread() returns size_t that is cast to DWORD

#define WHIRLPOOL_HASH_CODE_SIZE 64			// Whirlpool is a 512 bit digest size that are 64 bytes
#define GOST_HASH_CODE_SIZE 32				// GOST is a 256 bit digest size that are 32 bytes
#define MD4_HASH_CODE_SIZE 16					// MD4 is a 128 bit digest size that are 16 bytes
#define MD5_HASH_CODE_SIZE 16					// MD5 is a 128 bit digest size that are 16 bytes
#define EDONKEY2K_HASH_CODE_SIZE MD4_HASH_CODE_SIZE		// EDonkey2k is a root hash of a list of MD4 hashes
#define SHA160_HASH_CODE_SIZE 20			// SHA160 is a 160 bit digest size that are 20 bytes
#define SHA224_HASH_CODE_SIZE 28			// SHA224 is a 224 bit digest size that are 28 bytes
#define SHA256_HASH_CODE_SIZE 32			// SHA256 is a 256 bit digest size that are 32 bytes
#define SHA384_HASH_CODE_SIZE 48			// SHA384 is a 384 bit digest size that are 48 bytes
#define SHA512_HASH_CODE_SIZE 64			// SHA512 is a 512 bit digest size that are 64 bytes
#define MURMUR128_HASH_CODE_SIZE 16		// Murmur128 is a 128 bit digest size that are 16 bytes
#define SALSA_HASH_CODE_SIZE 64			// Salsa10/20 is a 512 bit digest size that are 64 bytes

#define CHECK_USER_ABORT_INTERVAL 500

#define HASHERROR_NO_ERROR 0
#define HASHERROR_ACQUIRE_CRYPT_PROVIDER_CONTEXT 1		// error acquiring cryptography provider context
#define HASHERROR_CREATE_HASH_OBJ 2		// error creating hash object handle
#define HASHERROR_CREATE_HASH_DATA 3	// error creating hash data
#define HASHERROR_GET_HASH_VALUE_SIZE 4	// error getting size of hash value
#define HASHERROR_GET_HASH_VALUE 5	// error getting hash value
#define HASHERROR_CRC32_UNKNOWN_EXCEPTION 6	// unknown exception in CCrc32 class
#define HASHERROR_UNKNOWN_EXCEPTION 7	// unknown exception
#define HASHERROR_OPEN_MMFILE 8	// error opening memory mapped file
#define HASHERROR_READ_MMFILE 9	// error reading memory mapped file
#define HASHERROR_INVALID_FILE 10	// file pointer is invalid
#define HASHERROR_INVALID_BYTE_ARRAY 11	// pointer to byte array is invalid
#define HASHERROR_TIGER_UNKNOWN_EXCEPTION 12 // unknown exception in CTiger class
#define HASHERROR_HAVAL_UNKNOWN_EXCEPTION 13 // unknown exception in CHaval class
#define HASHERROR_INVALID_HAVAL_FPTLEN_OR_PASSES 14 // HAVAL fingerprint length or number of passes is invalid
#define HASHERROR_WHIRLPOOL_UNKNOWN_EXCEPTION 15 // unknown exception in CWhirlpool class
#define HASHERROR_INVALID_RIPEMD_FPTLEN 16 // RIPEMD fingerprint length is invalid
#define HASHERROR_RIPEMD_UNKNOWN_EXCEPTION 17 // unknown exception in CRipemd class
#define HASHERROR_INVALID_TIGER_FPTLEN_OR_PASSES 18 // Tiger fingerprint length or number of passes is invalid
#define HASHERROR_GOST_UNKNOWN_EXCEPTION 19 // unknown exception in CGost class
#define HASHERROR_INVALID_SNEFRU_FPTLEN 20 // Snefru fingerprint length is invalid
#define HASHERROR_SNEFRU_UNKNOWN_EXCEPTION 21 // unknown exception in CSnefru class
#define HASHERROR_INVALID_SHA_FPTLEN 22 // SHA fingerprint length is invalid
#define HASHERROR_MD4_UNKNOWN_EXCEPTION 23 // unknown exception in CMd4 class
#define HASHERROR_EDONKEY2K_UNKNOWN_EXCEPTION 24 // unknown exception in CEDonkey2k class
#define HASHERROR_MD5_UNKNOWN_EXCEPTION 25 // unknown exception in CMd5 class
#define HASHERROR_SHA160_UNKNOWN_EXCEPTION 26 // unknown exception in CSha160 class
#define HASHERROR_SHA256_SHA224_UNKNOWN_EXCEPTION 27 // unknown exception in CSha256Sha224 class
#define HASHERROR_SHA512_SHA384_UNKNOWN_EXCEPTION 28 // unknown exception in CSha512Sha384 class
#define HASHERROR_MURMUR_UNKNOWN_EXCEPTION 29 // unknown exception in CMurmur class
#define HASHERROR_SALSA_UNKNOWN_EXCEPTION 30 // unknown exception in CSalsa class
#define HASHERROR_INVALID_KECCAK_FPTLEN 31 // Keccak fingerprint length is invalid
#define HASHERROR_KECCAK_UNKNOWN_EXCEPTION 32 // unknown exception in CKeccak class

#define HASHERROR_HASHING_ABORTED 50	// operation aborted (possible only when hashing a FILE)

// The Keccak hashing algorithm is winner of the NIST hash function competition for the SHA3
#define KeccakHash SHA3Hash

typedef int (__stdcall *PROGRESSCALLBACKPROC)(int nextblockdata);


class CHashes : private CCrc32, CTiger, CHaval, CWhirlpool, CRipemd, CGost, CSnefru, CMd4, CMd5, CEDonkey2k,
										CSha160, CSha256Sha224, CSha512Sha384, CMurmur, CSalsa, CKeccak
{
public:
	CHashes(void);
	virtual ~CHashes(void);

private:

#ifdef IMPLEMENT_WIN_CRYPT_HASHES
	HCRYPTPROV		m_hCryptProv;
	HCRYPTHASH		m_hHash;
#endif IMPLEMENT_WIN_CRYPT_HASHES

	BYTE*				m_pbHashCodeBuffer;
	BYTE				m_bFileReadBuffer[FILE_READ_BUFF_SIZE];

	bool volatile	m_bAbortFileHashing;
	
	UINT		m_nLastErrorCode;
	WCHAR		m_szLastError[ERROR_MSG_BUFF_SIZE];

	double	m_dProgressFactor;
	DWORD		m_dwLastTimeCheckUserAbort;

public:

#ifdef IMPLEMENT_HASH_BY_BYTE_ARRAY
	bool		CRC32Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		CRC32bHash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		MD4Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		MD5Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		EDonkey2kHash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		GOSTHash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		SnefruHash(int nFptLen, BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		SHA160Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		SHA224Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		SHA256Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		SHA384Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		SHA512Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		TigerHash(int nFptLen, int nPasses, BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		HAVALHash(int nFptLen, int nPasses, BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		WhirlpoolHash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		RIPEMDHash(int nFptLen, BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		Murmur32Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		Murmur128Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		Salsa10Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		Salsa20Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		KeccakHash(int nFptLen, BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
 #ifdef IMPLEMENT_WIN_CRYPT_HASHES
	bool		WinCryptMD5Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		WinCryptSHAHash(int nFptLen, BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
	bool		WinCryptHash(DWORD dwProvType, ALG_ID Algid, BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen);
 #endif IMPLEMENT_WIN_CRYPT_HASHES
#endif IMPLEMENT_HASH_BY_BYTE_ARRAY

#ifdef IMPLEMENT_HASH_BY_FILE
	bool		CRC32Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		CRC32bHash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		MD4Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		MD5Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		EDonkey2kHash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		GOSTHash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		SnefruHash(int nFptLen, FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		SHA160Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		SHA224Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		SHA256Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		SHA384Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		SHA512Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		TigerHash(int nFptLen, int nPasses, FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		HAVALHash(int nFptLen, int nPasses, FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		WhirlpoolHash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		RIPEMDHash(int nFptLen, FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		Murmur32Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		Murmur128Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		Salsa10Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		Salsa20Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		KeccakHash(int nFptLen, FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
 #ifdef IMPLEMENT_WIN_CRYPT_HASHES
	bool		WinCryptMD5Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		WinCryptSHAHash(int nFptLen, FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		WinCryptHash(DWORD dwProvType, ALG_ID Algid, FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
 #endif IMPLEMENT_WIN_CRYPT_HASHES
#endif IMPLEMENT_HASH_BY_FILE

#ifdef IMPLEMENT_HASH_BY_MEM_MAP_FILE
	bool		CRC32Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		CRC32bHash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		MD4Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		MD5Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		EDonkey2kHash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		GOSTHash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		SnefruHash(int nFptLen, CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		SHA160Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		SHA224Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		SHA256Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		SHA384Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		SHA512Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		TigerHash(int nFptLen, int nPasses, CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		HAVALHash(int nFptLen, int nPasses, CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		WhirlpoolHash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		RIPEMDHash(int nFptLen, CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		Murmur32Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		Murmur128Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		Salsa10Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		Salsa20Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		KeccakHash(int nFptLen, CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
 #ifdef IMPLEMENT_WIN_CRYPT_HASHES
	bool		WinCryptMD5Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		WinCryptSHAHash(int nFptLen, CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
	bool		WinCryptHash(DWORD dwProvType, ALG_ID Algid, CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback = NULL);
 #endif IMPLEMENT_WIN_CRYPT_HASHES
#endif IMPLEMENT_HASH_BY_MEM_MAP_FILE

	void		SetProgressFactor(double dFactor)	{ m_dProgressFactor = dFactor; };
	bool		ItsTimeToCheckUserAbort();

	void		Abort()	{ m_bAbortFileHashing = true;	};

	int		GetLastErrorCode() const;
	WCHAR*	GetLastErrorMessage() const;
};

