
// Hashes.cpp : implementation file
//

#include "StdAfx.h"
#include "Hashes.h"
#include "Common.h"

/*	
	this macro checks whether the function pointer progressCallback of type PROGRESSCALLBACKPROC is not NULL.
	if its NULL then return false to NOT abort the processing.
	if its NOT NULL then call progressCallback() and check if the returned value is not 0 for Abort.
	also set the m_bAbortFileHashing flag to the abort value returnd from progressCallback().
*/
#define SAFE_MACRO_PROGRESS_CALLBACK_ABORT(n) (progressCallback ? (m_bAbortFileHashing=(progressCallback(n)!=0)) : false)

/*
	This macro incorporates the previous macro with an additional evaluation of the m_bAbortFileHashing flag.
	The m_bAbortFileHashing flag is evaluated first and if it's true then a user abort was submitted.
	If it's not true then the previous macro is evaluated.
	This macro was created to make sure that m_bAbortFileHashing flag will always be evaluated first in
	case it's true and will not be modified by the previous macro to false.
*/
#define SAFE_USER_ABORT(n) (m_bAbortFileHashing || SAFE_MACRO_PROGRESS_CALLBACK_ABORT(n))


/*
	The following macros return true if the fingerprint length or the 
	number of passes(rounds) is supported by the hashing algorithm
*/
// supported SHA fingerprint length are 160, 256, 384, or 512
#define SHA_SUPPORT_FINGERPRINT_LENGTH(fptlen) ((fptlen==160) || (fptlen==256) || (fptlen==384) || (fptlen==512))
// supported Tiger fingerprint length are 128, 160, or 192
#define TIGER_SUPPORT_FINGERPRINT_LENGTH(fptlen) ((fptlen==128) || (fptlen==160) || (fptlen==192))
// supported Tiger rounds are only 3 or 4
#define TIGER_SUPPORT_PASSES(passes) ((passes==3) || (passes==4))
// supported HAVAL fingerprint length are 128, 160, 192, 224 or 256
#define HAVAL_SUPPORT_FINGERPRINT_LENGTH(fptlen) ((fptlen==128) || (fptlen==160) || (fptlen==192) || (fptlen==224) || (fptlen==256))
// supported HAVAL rounds are only 3, 4, or 5
#define HAVAL_SUPPORT_PASSES(passes) ((passes==3) || (passes==4) || (passes==5))
// supported RIPEMD fingerprint length are 128, 160, 256 or 320
#define RIPEMD_SUPPORT_FINGERPRINT_LENGTH(fptlen) ((fptlen==128) || (fptlen==160) || (fptlen==256) || (fptlen==320))
// supported Snefru fingerprint length are 128 or 256
#define SNEFRU_SUPPORT_FINGERPRINT_LENGTH(fptlen) ((fptlen==128) || (fptlen==256))
// supported Keccak fingerprint length are 224, 256, 384 or 512
#define KECCAK_SUPPORT_FINGERPRINT_LENGTH(fptlen) ((fptlen==224) || (fptlen==256) || (fptlen==384) || (fptlen==512))


// simplefy the call to the RIPEMD init functions
#define RIPEMD_INIT(nFptLen, ctx) { \
		  if(nFptLen==128) CRipemd::Init128(ctx); \
	else if(nFptLen==160) CRipemd::Init160(ctx); \
	else if(nFptLen==256) CRipemd::Init256(ctx); \
	else if(nFptLen==320) CRipemd::Init320(ctx); \
	else throw "ERROR";	}

// simplefy the call to the Tiger Digest functions
#define TIGER_DIGEST(nFptLen, ctx, fpt) { \
		  if(nFptLen==128) CTiger::Digest128(ctx, fpt); \
	else if(nFptLen==160) CTiger::Digest160(ctx, fpt); \
	else if(nFptLen==192) CTiger::Digest192(ctx, fpt); \
	else throw "ERROR";	}

// simplefy the call to the Snefru Update functions
#define SNEFRU_UPDATE(nFptLen, ctx, data, dataLen) { \
		  if(nFptLen==128) CSnefru::Update128(ctx, data, dataLen); \
	else if(nFptLen==256) CSnefru::Update256(ctx, data, dataLen); \
	else throw "ERROR";	}

// simplefy the call to the Snefru Final functions
#define SNEFRU_FINAL(nFptLen, ctx) { \
		  if(nFptLen==128) CSnefru::Final128(ctx); \
	else if(nFptLen==256) CSnefru::Final256(ctx); \
	else throw "ERROR";	}

// simplefy the call to the Snefru Digest functions
#define SNEFRU_DIGEST(nFptLen, ctx, hashCode) { \
		  if(nFptLen==128) CSnefru::Digest128(ctx, hashCode); \
	else if(nFptLen==256) CSnefru::Digest256(ctx, hashCode); \
	else throw "ERROR";	}

#ifdef IMPLEMENT_WIN_CRYPT_HASHES
// simplefy the algorithm selection for the SHA
// SHA1's Provider is "Microsoft Base Cryptographic". For the rest it's "Microsoft Enhanced RSA and AES Cryptographic"
#define SHA_ALGORITHM(nFptLen, provType, algid) { \
	provType = (nFptLen==160 ? PROV_RSA_FULL : PROV_RSA_AES); \
		  if(nFptLen==160) algid = CALG_SHA1;						 \
	else if(nFptLen==256) algid = CALG_SHA_256;					 \
	else if(nFptLen==384) algid = CALG_SHA_384;					 \
	else if(nFptLen==512) algid = CALG_SHA_512;					 \
	else throw "ERROR";	}
#endif IMPLEMENT_WIN_CRYPT_HASHES

/////////////////////////////////////////////////////////////////////
//
CHashes::CHashes(void) :
		m_pbHashCodeBuffer(NULL), m_nLastErrorCode(HASHERROR_NO_ERROR), 
		m_bAbortFileHashing(true), m_dProgressFactor(1),
		m_dwLastTimeCheckUserAbort(::GetTickCount())		
{
	m_szLastError[0] = 0;
}


/////////////////////////////////////////////////////////////////////
//
CHashes::~CHashes(void)
{
	delete m_pbHashCodeBuffer;
}


/***********************************************************************************/
/**                                                                               **/
/**  Implement Hash By Byte Array Functions                                       **/
/**                                                                               **/
/***********************************************************************************/
#ifdef IMPLEMENT_HASH_BY_BYTE_ARRAY
/////////////////////////////////////////////////////////////////////
//
bool CHashes::CRC32Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	CCrc32::Init();

	for(DWORD i=0; i<dwDataLen; i++)
	{
		if( !CCrc32::Update(pbData[i]) )
		{
			m_nLastErrorCode = HASHERROR_CRC32_UNKNOWN_EXCEPTION;
			return false;
		}
	}

	DWORD		dwCrc32 = CCrc32::Digest();
	
	m_pbHashCodeBuffer = *pbHashCode = new BYTE[4];

	// convert the CRC32 DWORD's bytes to a byte array
	(*pbHashCode)[3] = (dwCrc32 >> 24) & 0xFF;
	(*pbHashCode)[2] = (dwCrc32 >> 16) & 0xFF;
	(*pbHashCode)[1] = (dwCrc32 >> 8) & 0xFF;
	(*pbHashCode)[0] = dwCrc32 & 0xFF;
	*pdwHashLen = 4;

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::CRC32bHash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	CCrc32::Init();

	for(DWORD i=0; i<dwDataLen; i++)
	{
		if( !CCrc32::Update_b(pbData[i]) )
		{
			m_nLastErrorCode = HASHERROR_CRC32_UNKNOWN_EXCEPTION;
			return false;
		}
	}

	DWORD		dwCrc32 = CCrc32::Digest();
	
	m_pbHashCodeBuffer = *pbHashCode = new BYTE[4];

	// convert the CRC32b DWORD's bytes to a byte array
	(*pbHashCode)[0] = (dwCrc32 >> 24) & 0xFF;
	(*pbHashCode)[1] = (dwCrc32 >> 16) & 0xFF;
	(*pbHashCode)[2] = (dwCrc32 >> 8) & 0xFF;
	(*pbHashCode)[3] = dwCrc32 & 0xFF;
	*pdwHashLen = 4;

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::MD4Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		md4_ctx	ctx;		

		CMd4::Init(&ctx);

		// add data to hash object
		CMd4::Update(&ctx, pbData, dwDataLen);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[MD4_HASH_CODE_SIZE];

		CMd4::Digest(&ctx, *pbHashCode);
		*pdwHashLen = MD4_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_MD4_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::MD5Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		md5_ctx	ctx;		

		CMd5::Init(&ctx);

		// add data to hash object
		CMd5::Update(&ctx, pbData, dwDataLen);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[MD5_HASH_CODE_SIZE];

		CMd5::Digest(&ctx, *pbHashCode);
		*pdwHashLen = MD5_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_MD5_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::EDonkey2kHash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		ed2k_ctx	ctx;		

		CEDonkey2k::Init(&ctx);

		// add data to hash object
		CEDonkey2k::Update(&ctx, pbData, dwDataLen);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[EDONKEY2K_HASH_CODE_SIZE];

		CEDonkey2k::Digest(&ctx, *pbHashCode);
		*pdwHashLen = EDONKEY2K_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_EDONKEY2K_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::GOSTHash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		gost_ctx	ctx;		

		CGost::Init(&ctx);

		// add data to hash object
		CGost::Update(&ctx, pbData, dwDataLen);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[GOST_HASH_CODE_SIZE];

		CGost::Digest(&ctx, *pbHashCode);
		*pdwHashLen = GOST_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_GOST_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SnefruHash(int nFptLen, BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !SNEFRU_SUPPORT_FINGERPRINT_LENGTH(nFptLen) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_SNEFRU_FPTLEN;
		return false;
	}

	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		snefru_ctx	ctx;	

		CSnefru::Init(&ctx);

		// add data to hash object
		SNEFRU_UPDATE(nFptLen, &ctx, pbData, dwDataLen);

		// assume fptlen is 128 or 256
		int	nCodeSize = nFptLen/8;			// convert bits to bytes

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[nCodeSize];

		SNEFRU_FINAL(nFptLen, &ctx);
		SNEFRU_DIGEST(nFptLen, &ctx, *pbHashCode);
		*pdwHashLen = nCodeSize;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SNEFRU_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SHA160Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		sha160_ctx	ctx;		

		CSha160::Init(&ctx);

		// add data to hash object
		CSha160::Update(&ctx, pbData, dwDataLen);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SHA160_HASH_CODE_SIZE];

		CSha160::Final(&ctx);
		CSha160::Digest(&ctx, *pbHashCode);
		*pdwHashLen = SHA160_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SHA160_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SHA224Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		sha256_sha224_ctx		ctx;		

		CSha256Sha224::Init224(&ctx);

		// add data to hash object
		CSha256Sha224::Update(&ctx, pbData, dwDataLen);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SHA224_HASH_CODE_SIZE];

		CSha256Sha224::Final(&ctx);
		CSha256Sha224::Digest224(&ctx, *pbHashCode);
		*pdwHashLen = SHA224_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SHA256_SHA224_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SHA256Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		sha256_sha224_ctx		ctx;		

		CSha256Sha224::Init256(&ctx);

		// add data to hash object
		CSha256Sha224::Update(&ctx, pbData, dwDataLen);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SHA256_HASH_CODE_SIZE];

		CSha256Sha224::Final(&ctx);
		CSha256Sha224::Digest256(&ctx, *pbHashCode);
		*pdwHashLen = SHA256_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SHA256_SHA224_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SHA384Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		sha512_sha384_ctx		ctx;		

		CSha512Sha384::Init384(&ctx);

		// add data to hash object
		CSha512Sha384::Update(&ctx, pbData, dwDataLen);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SHA384_HASH_CODE_SIZE];

		CSha512Sha384::Final(&ctx);
		CSha512Sha384::Digest384(&ctx, *pbHashCode);
		*pdwHashLen = SHA384_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SHA512_SHA384_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SHA512Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		sha512_sha384_ctx		ctx;		

		CSha512Sha384::Init512(&ctx);

		// add data to hash object
		CSha512Sha384::Update(&ctx, pbData, dwDataLen);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SHA512_HASH_CODE_SIZE];

		CSha512Sha384::Final(&ctx);
		CSha512Sha384::Digest512(&ctx, *pbHashCode);
		*pdwHashLen = SHA512_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SHA512_SHA384_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::TigerHash(int nFptLen, int nPasses, BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !TIGER_SUPPORT_FINGERPRINT_LENGTH(nFptLen) || !TIGER_SUPPORT_PASSES(nPasses) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_TIGER_FPTLEN_OR_PASSES;
		return false;
	}

	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		tiger_ctx		ctx;

		CTiger::Init(&ctx, nPasses);

		// add data to hash object
		CTiger::Update(&ctx, pbData, dwDataLen);

		// assume fptlen is 128, 160, or 192
		int	nCodeSize = nFptLen/8;			// convert bits to bytes

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[nCodeSize];

		CTiger::Final(&ctx);
		TIGER_DIGEST(nFptLen, &ctx, *pbHashCode);
		*pdwHashLen = nCodeSize;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_TIGER_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::HAVALHash(int nFptLen, int nPasses, BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !HAVAL_SUPPORT_FINGERPRINT_LENGTH(nFptLen) || !HAVAL_SUPPORT_PASSES(nPasses) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_HAVAL_FPTLEN_OR_PASSES;
		return false;
	}

	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		haval_ctx		ctx;

		CHaval::Init(&ctx, nFptLen, nPasses);

		// add data to hash object
		CHaval::Update(&ctx, pbData, dwDataLen);

		// assume fptlen is 128, 160, 192, 224 or 256
		int	nCodeSize = nFptLen/8;			// convert bits to bytes
		
		m_pbHashCodeBuffer = *pbHashCode = new BYTE[nCodeSize];

		CHaval::Digest(&ctx, *pbHashCode);
		*pdwHashLen = nCodeSize;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_HAVAL_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::WhirlpoolHash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		whirlpool_ctx	ctx;		

		CWhirlpool::Init(&ctx);

		// add data to hash object
		CWhirlpool::Update(&ctx, pbData, dwDataLen);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[WHIRLPOOL_HASH_CODE_SIZE];

		CWhirlpool::Digest(&ctx, *pbHashCode);
		*pdwHashLen = WHIRLPOOL_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_WHIRLPOOL_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::RIPEMDHash(int nFptLen, BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !RIPEMD_SUPPORT_FINGERPRINT_LENGTH(nFptLen) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_RIPEMD_FPTLEN;
		return false;
	}

	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		ripemd_ctx	ctx;

		RIPEMD_INIT(nFptLen, &ctx);

		// add data to hash object
		CRipemd::Update(&ctx, pbData, dwDataLen);

		// assume fptlen is 128, 160, 256 or 320
		int	nCodeSize = nFptLen/8;			// convert bits to bytes

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[nCodeSize];

		CRipemd::Digest(&ctx, *pbHashCode);
		*pdwHashLen = nCodeSize;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_RIPEMD_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::Murmur32Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;		

		murmur32_ctx		ctx;

		CMurmur::Init32(&ctx);

		// add data to hash object
		CMurmur::Update32(&ctx, pbData, dwDataLen);

		DWORD		dwHashCode = CMurmur::Digest32(&ctx);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[4];

		// convert the Murmur DWORD's bytes to a byte array
		(*pbHashCode)[3] = (dwHashCode >> 24) & 0xFF;
		(*pbHashCode)[2] = (dwHashCode >> 16) & 0xFF;
		(*pbHashCode)[1] = (dwHashCode >> 8) & 0xFF;
		(*pbHashCode)[0] = dwHashCode & 0xFF;
		*pdwHashLen = 4;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_MURMUR_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::Murmur128Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;		

		murmur128_ctx		ctx;

		CMurmur::Init128(&ctx);

		// add data to hash object
		CMurmur::Update128(&ctx, pbData, dwDataLen);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[MURMUR128_HASH_CODE_SIZE];

		CMurmur::Digest128(&ctx, *pbHashCode);
		*pdwHashLen = MURMUR128_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_MURMUR_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::Salsa10Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;		

		salsa_ctx		ctx;

		CSalsa::Init(&ctx, CSalsa::Salsa10);

		// add data to hash object
		CSalsa::Update(&ctx, pbData, dwDataLen);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SALSA_HASH_CODE_SIZE];

		CSalsa::Digest(&ctx, *pbHashCode);
		*pdwHashLen = SALSA_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SALSA_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::Salsa20Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;		

		salsa_ctx		ctx;

		CSalsa::Init(&ctx, CSalsa::Salsa20);

		// add data to hash object
		CSalsa::Update(&ctx, pbData, dwDataLen);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SALSA_HASH_CODE_SIZE];

		CSalsa::Digest(&ctx, *pbHashCode);
		*pdwHashLen = SALSA_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SALSA_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::KeccakHash(int nFptLen, BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !KECCAK_SUPPORT_FINGERPRINT_LENGTH(nFptLen) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_KECCAK_FPTLEN;
		return false;
	}

	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		CKeccak::Init(nFptLen);

		// add data to hash object
		CKeccak::Update(pbData, dwDataLen);

		// assume fptlen is 224, 256, 384 or 512
		int	nCodeSize = nFptLen/8;			// convert bits to bytes

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[nCodeSize];

		CKeccak::Digest(*pbHashCode);
		*pdwHashLen = nCodeSize;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_KECCAK_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

#ifdef IMPLEMENT_WIN_CRYPT_HASHES

/////////////////////////////////////////////////////////////////////
//
bool CHashes::WinCryptMD5Hash(BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	return this->WinCryptHash(PROV_RSA_FULL, CALG_MD5, pbData, dwDataLen, pbHashCode, pdwHashLen);
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::WinCryptSHAHash(int nFptLen, BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !SHA_SUPPORT_FINGERPRINT_LENGTH(nFptLen) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_SHA_FPTLEN;
		return false;
	}

	DWORD		dwProvType;
	ALG_ID	Algid;
	
	SHA_ALGORITHM(nFptLen, dwProvType, Algid);

	return this->WinCryptHash(dwProvType, Algid, pbData, dwDataLen, pbHashCode, pdwHashLen);
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::WinCryptHash(DWORD dwProvType, ALG_ID Algid, BYTE* pbData, DWORD dwDataLen, BYTE** pbHashCode, DWORD* pdwHashLen)
{
	if( !pbData )
	{
		m_nLastErrorCode = HASHERROR_INVALID_BYTE_ARRAY;
		return false;
	}


	bool		bRetStatus = false;	// pessimistic

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		m_hCryptProv = m_hHash = NULL;

		// Get a handle to a cryptography provider context.
		if( CryptAcquireContext(&m_hCryptProv, NULL, NULL, dwProvType, 0) )
		{
			// Acquire a hash object handle.
			if( CryptCreateHash(m_hCryptProv, Algid, 0, 0, &m_hHash) )
			{
				// add data to hash object
				if( CryptHashData(m_hHash, pbData, dwDataLen, 0) )
				{
					DWORD		dwLen;
					DWORD		dwCount = sizeof(dwLen);	

					// Acquire size of hash value
					if( CryptGetHashParam(m_hHash, HP_HASHSIZE, (BYTE*)&dwLen, &dwCount, 0) )
					{
						*pdwHashLen = dwLen;
						m_pbHashCodeBuffer = *pbHashCode = new BYTE[dwLen];

						// Acquire hash value
						if( CryptGetHashParam(m_hHash, HP_HASHVAL, *pbHashCode, &dwLen, 0) )
						{
							m_nLastErrorCode = HASHERROR_NO_ERROR;
							bRetStatus = true;
						}
						else
							m_nLastErrorCode = HASHERROR_GET_HASH_VALUE;
					}
					else
						m_nLastErrorCode = HASHERROR_GET_HASH_VALUE_SIZE;
				}
				else
					m_nLastErrorCode = HASHERROR_CREATE_HASH_DATA;
			}
			else
				m_nLastErrorCode = HASHERROR_CREATE_HASH_OBJ;
		}
		else
			m_nLastErrorCode = HASHERROR_ACQUIRE_CRYPT_PROVIDER_CONTEXT;

		if(m_hHash)
			CryptDestroyHash(m_hHash);

		if(m_hCryptProv)
			CryptReleaseContext(m_hCryptProv, 0);

		return bRetStatus;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_UNKNOWN_EXCEPTION;
		return false;
	}
}

#endif IMPLEMENT_WIN_CRYPT_HASHES

#endif IMPLEMENT_HASH_BY_BYTE_ARRAY


/***********************************************************************************/
/**                                                                               **/
/**  Implement Hash By File Functions                                             **/
/**                                                                               **/
/***********************************************************************************/
#ifdef IMPLEMENT_HASH_BY_FILE
/////////////////////////////////////////////////////////////////////
//
bool CHashes::CRC32Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	CCrc32::Init();

	size_t	r;
	DWORD		i;

	while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
	{
		for(i=0; i<r; i++)
		{
			if( !CCrc32::Update(m_bFileReadBuffer[i]) )
			{
				m_nLastErrorCode = HASHERROR_CRC32_UNKNOWN_EXCEPTION;
				return false;
			}
		}

		// check if abort was called
		if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
		{
			m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
			return false;
		}
	}

	DWORD		dwCrc32 = CCrc32::Digest();
	
	m_pbHashCodeBuffer = *pbHashCode = new BYTE[4];

	// convert the CRC32 DWORD's bytes to a byte array
	(*pbHashCode)[3] = (dwCrc32 >> 24) & 0xFF;
	(*pbHashCode)[2] = (dwCrc32 >> 16) & 0xFF;
	(*pbHashCode)[1] = (dwCrc32 >> 8) & 0xFF;
	(*pbHashCode)[0] = dwCrc32 & 0xFF;
	*pdwHashLen = 4;

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::CRC32bHash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	CCrc32::Init();

	size_t	r;
	DWORD		i;

	while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
	{
		for(i=0; i<r; i++)
		{
			if( !CCrc32::Update_b(m_bFileReadBuffer[i]) )
			{
				m_nLastErrorCode = HASHERROR_CRC32_UNKNOWN_EXCEPTION;
				return false;
			}
		}

		// check if abort was called
		if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
		{
			m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
			return false;
		}
	}

	DWORD		dwCrc32 = CCrc32::Digest();
	
	m_pbHashCodeBuffer = *pbHashCode = new BYTE[4];

	// convert the CRC32b DWORD's bytes to a byte array
	(*pbHashCode)[0] = (dwCrc32 >> 24) & 0xFF;
	(*pbHashCode)[1] = (dwCrc32 >> 16) & 0xFF;
	(*pbHashCode)[2] = (dwCrc32 >> 8) & 0xFF;
	(*pbHashCode)[3] = dwCrc32 & 0xFF;
	*pdwHashLen = 4;

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::MD4Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		md4_ctx		ctx;
		size_t		r;

		CMd4::Init(&ctx);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CMd4::Update(&ctx, m_bFileReadBuffer, (UINT)r); // 'size_t' to 'unsigned int' conversion; no loss of data

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[MD4_HASH_CODE_SIZE];

		CMd4::Digest(&ctx, *pbHashCode);
		*pdwHashLen = MD4_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_MD4_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::MD5Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		md5_ctx		ctx;
		size_t		r;

		CMd5::Init(&ctx);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CMd5::Update(&ctx, m_bFileReadBuffer, (UINT)r); // 'size_t' to 'unsigned int' conversion; no loss of data

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[MD5_HASH_CODE_SIZE];

		CMd5::Digest(&ctx, *pbHashCode);
		*pdwHashLen = MD5_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_MD5_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::EDonkey2kHash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		ed2k_ctx		ctx;
		size_t		r;

		CEDonkey2k::Init(&ctx);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CEDonkey2k::Update(&ctx, m_bFileReadBuffer, (UINT)r); // 'size_t' to 'unsigned int' conversion; no loss of data

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[EDONKEY2K_HASH_CODE_SIZE];

		CEDonkey2k::Digest(&ctx, *pbHashCode);
		*pdwHashLen = EDONKEY2K_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_EDONKEY2K_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::GOSTHash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		gost_ctx		ctx;
		size_t		r;

		CGost::Init(&ctx);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CGost::Update(&ctx, m_bFileReadBuffer, (UINT)r); // 'size_t' to 'unsigned int' conversion; no loss of data

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[GOST_HASH_CODE_SIZE];

		CGost::Digest(&ctx, *pbHashCode);
		*pdwHashLen = GOST_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_GOST_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SnefruHash(int nFptLen, FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !SNEFRU_SUPPORT_FINGERPRINT_LENGTH(nFptLen) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_SNEFRU_FPTLEN;
		return false;
	}

	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		snefru_ctx	ctx;
		size_t		r;

		CSnefru::Init(&ctx);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			SNEFRU_UPDATE(nFptLen, &ctx, m_bFileReadBuffer, (UINT)r); // 'size_t' to 'unsigned int' conversion; no loss of data

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		// assume fptlen is 128 or 256
		int	nCodeSize = nFptLen/8;			// convert bits to bytes

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[nCodeSize];

		SNEFRU_FINAL(nFptLen, &ctx);
		SNEFRU_DIGEST(nFptLen, &ctx, *pbHashCode);
		*pdwHashLen = nCodeSize;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SNEFRU_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SHA160Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		sha160_ctx		ctx;
		size_t			r;

		CSha160::Init(&ctx);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CSha160::Update(&ctx, m_bFileReadBuffer, (UINT)r); // 'size_t' to 'unsigned int' conversion; no loss of data

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SHA160_HASH_CODE_SIZE];

		CSha160::Final(&ctx);
		CSha160::Digest(&ctx, *pbHashCode);
		*pdwHashLen = SHA160_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SHA160_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SHA224Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		sha256_sha224_ctx		ctx;
		size_t			r;

		CSha256Sha224::Init224(&ctx);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CSha256Sha224::Update(&ctx, m_bFileReadBuffer, (UINT)r); // 'size_t' to 'unsigned int' conversion; no loss of data

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SHA224_HASH_CODE_SIZE];

		CSha256Sha224::Final(&ctx);
		CSha256Sha224::Digest224(&ctx, *pbHashCode);
		*pdwHashLen = SHA224_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SHA256_SHA224_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SHA256Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		sha256_sha224_ctx		ctx;
		size_t					r;

		CSha256Sha224::Init256(&ctx);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CSha256Sha224::Update(&ctx, m_bFileReadBuffer, (UINT)r); // 'size_t' to 'unsigned int' conversion; no loss of data

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SHA256_HASH_CODE_SIZE];

		CSha256Sha224::Final(&ctx);
		CSha256Sha224::Digest256(&ctx, *pbHashCode);
		*pdwHashLen = SHA256_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SHA256_SHA224_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SHA384Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		sha512_sha384_ctx		ctx;
		size_t					r;

		CSha512Sha384::Init384(&ctx);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CSha512Sha384::Update(&ctx, m_bFileReadBuffer, (UINT)r); // 'size_t' to 'unsigned int' conversion; no loss of data

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SHA384_HASH_CODE_SIZE];

		CSha512Sha384::Final(&ctx);
		CSha512Sha384::Digest384(&ctx, *pbHashCode);
		*pdwHashLen = SHA384_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SHA512_SHA384_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SHA512Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		sha512_sha384_ctx		ctx;
		size_t					r;

		CSha512Sha384::Init512(&ctx);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CSha512Sha384::Update(&ctx, m_bFileReadBuffer, (UINT)r); // 'size_t' to 'unsigned int' conversion; no loss of data

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SHA512_HASH_CODE_SIZE];

		CSha512Sha384::Final(&ctx);
		CSha512Sha384::Digest512(&ctx, *pbHashCode);
		*pdwHashLen = SHA512_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SHA512_SHA384_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::TigerHash(int nFptLen, int nPasses, FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !TIGER_SUPPORT_FINGERPRINT_LENGTH(nFptLen) || !TIGER_SUPPORT_PASSES(nPasses) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_TIGER_FPTLEN_OR_PASSES;
		return false;
	}

	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		tiger_ctx		ctx;
		size_t			r;

		CTiger::Init(&ctx, nPasses);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CTiger::Update(&ctx, m_bFileReadBuffer, (ULONG)r);	// 'size_t' to 'ULONG' conversion; no loss of data

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		// assume fptlen is 128, 160, or 192
		int	nCodeSize = nFptLen/8;			// convert bits to bytes

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[nCodeSize];

		CTiger::Final(&ctx);
		TIGER_DIGEST(nFptLen, &ctx, *pbHashCode);
		*pdwHashLen = nCodeSize;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_TIGER_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::HAVALHash(int nFptLen, int nPasses, FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !HAVAL_SUPPORT_FINGERPRINT_LENGTH(nFptLen) || !HAVAL_SUPPORT_PASSES(nPasses) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_HAVAL_FPTLEN_OR_PASSES;
		return false;
	}

	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		haval_ctx		ctx;
		size_t			r;

		CHaval::Init(&ctx, nFptLen, nPasses);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CHaval::Update(&ctx, m_bFileReadBuffer, (UINT)r); // 'size_t' to 'unsigned int' conversion; no loss of data

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		// assume fptlen is 128, 160, 192, 224 or 256
		int	nCodeSize = nFptLen/8;			// convert bits to bytes

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[nCodeSize];

		CHaval::Digest(&ctx, *pbHashCode);
		*pdwHashLen = nCodeSize;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_HAVAL_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::WhirlpoolHash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		whirlpool_ctx	ctx;
		size_t			r;

		CWhirlpool::Init(&ctx);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CWhirlpool::Update(&ctx, m_bFileReadBuffer, (UINT)r); // 'size_t' to 'unsigned int' conversion; no loss of data

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[WHIRLPOOL_HASH_CODE_SIZE];

		CWhirlpool::Digest(&ctx, *pbHashCode);
		*pdwHashLen = WHIRLPOOL_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_WHIRLPOOL_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::RIPEMDHash(int nFptLen, FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !RIPEMD_SUPPORT_FINGERPRINT_LENGTH(nFptLen) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_RIPEMD_FPTLEN;
		return false;
	}

	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		ripemd_ctx		ctx;
		size_t			r;

		RIPEMD_INIT(nFptLen, &ctx);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CRipemd::Update(&ctx, m_bFileReadBuffer, (UINT)r); // 'size_t' to 'unsigned int' conversion; no loss of data

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		// assume fptlen is 128, 160, 256 or 320
		int	nCodeSize = nFptLen/8;			// convert bits to bytes

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[nCodeSize];

		CRipemd::Digest(&ctx, *pbHashCode);
		*pdwHashLen = nCodeSize;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_RIPEMD_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::Murmur32Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*= NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		size_t					r;
		murmur32_ctx			ctx;

		CMurmur::Init32(&ctx);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CMurmur::Update32(&ctx, m_bFileReadBuffer, (UINT)r);

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		DWORD		wdHashCode = CMurmur::Digest32(&ctx);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[4];

		// convert the Murmur DWORD's bytes to a byte array
		(*pbHashCode)[3] = (wdHashCode >> 24) & 0xFF;
		(*pbHashCode)[2] = (wdHashCode >> 16) & 0xFF;
		(*pbHashCode)[1] = (wdHashCode >> 8) & 0xFF;
		(*pbHashCode)[0] = wdHashCode & 0xFF;
		*pdwHashLen = 4;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_MURMUR_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::Murmur128Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*= NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		size_t					r;

		murmur128_ctx		ctx;

		CMurmur::Init128(&ctx);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CMurmur::Update128(&ctx, m_bFileReadBuffer, (UINT)r);

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[MURMUR128_HASH_CODE_SIZE];

		CMurmur::Digest128(&ctx, *pbHashCode);
		*pdwHashLen = MURMUR128_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_MURMUR_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::Salsa10Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*= NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		size_t					r;

		salsa_ctx		ctx;

		CSalsa::Init(&ctx, CSalsa::Salsa10);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CSalsa::Update(&ctx, m_bFileReadBuffer, (UINT)r);

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SALSA_HASH_CODE_SIZE];

		CSalsa::Digest(&ctx, *pbHashCode);
		*pdwHashLen = SALSA_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SALSA_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::Salsa20Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*= NULL*/)
{
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		size_t					r;

		salsa_ctx		ctx;

		CSalsa::Init(&ctx, CSalsa::Salsa20);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CSalsa::Update(&ctx, m_bFileReadBuffer, (UINT)r);

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SALSA_HASH_CODE_SIZE];

		CSalsa::Digest(&ctx, *pbHashCode);
		*pdwHashLen = SALSA_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SALSA_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::KeccakHash(int nFptLen, FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !KECCAK_SUPPORT_FINGERPRINT_LENGTH(nFptLen) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_KECCAK_FPTLEN;
		return false;
	}

	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		size_t		r;

		CKeccak::Init(nFptLen);

		while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
		{
			// add data to hash object
			CKeccak::Update(m_bFileReadBuffer, (UINT)r); // 'size_t' to 'unsigned int' conversion; no loss of data

			// check if abort was called
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
				return false;
			}
		}

		// assume fptlen is 224, 256, 384 or 512
		int	nCodeSize = nFptLen/8;			// convert bits to bytes

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[nCodeSize];

		CKeccak::Digest(*pbHashCode);
		*pdwHashLen = nCodeSize;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_KECCAK_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

#ifdef IMPLEMENT_WIN_CRYPT_HASHES

/////////////////////////////////////////////////////////////////////
//
bool CHashes::WinCryptMD5Hash(FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	return this->WinCryptHash(PROV_RSA_FULL, CALG_MD5, pFile, pbHashCode, pdwHashLen, progressCallback);
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::WinCryptSHAHash(int nFptLen, FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !SHA_SUPPORT_FINGERPRINT_LENGTH(nFptLen) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_SHA_FPTLEN;
		return false;
	}

	DWORD		dwProvType;
	ALG_ID	Algid;
	
	SHA_ALGORITHM(nFptLen, dwProvType, Algid);

	return this->WinCryptHash(dwProvType, Algid, pFile, pbHashCode, pdwHashLen, progressCallback);
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::WinCryptHash(DWORD dwProvType, ALG_ID Algid, FILE* pFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{	
	if( !pFile )
	{
		m_nLastErrorCode = HASHERROR_INVALID_FILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	bool		bRetStatus = false;	// pessimistic

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		m_hCryptProv = m_hHash = NULL;

		// Get a handle to a cryptography provider context.
		if( CryptAcquireContext(&m_hCryptProv, NULL, NULL, dwProvType, 0) )
		{
			// Acquire a hash object handle.
			if( CryptCreateHash(m_hCryptProv, Algid, 0, 0, &m_hHash) )
			{
				size_t	r;
				bool		bDataHashComplete = true;	// optimistic

				while( (r = fread(m_bFileReadBuffer, sizeof(BYTE), FILE_READ_BUFF_SIZE, pFile)) != 0 )
				{
					// add data to hash object
					if( !CryptHashData(m_hHash, m_bFileReadBuffer, (DWORD)r, 0) )
					{
						bDataHashComplete = false;
						break;
					}

					// check if abort was called
					if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(FILE_READ_BUFF_SIZE*m_dProgressFactor)) )
						break;
				}

				// check how the while(r = fread()) terminated; user abort, CryptHashData failed.
				if(!m_bAbortFileHashing && bDataHashComplete)
				{
					DWORD		dwLen;
					DWORD		dwCount = sizeof(dwLen);	

					// Acquire size of hash value
					if( CryptGetHashParam(m_hHash, HP_HASHSIZE, (BYTE*)&dwLen, &dwCount, 0) )
					{
						*pdwHashLen = dwLen;
						m_pbHashCodeBuffer = *pbHashCode = new BYTE[dwLen];

						// Acquire hash value
						if( CryptGetHashParam(m_hHash, HP_HASHVAL, *pbHashCode, &dwLen, 0) )
						{
							m_nLastErrorCode = HASHERROR_NO_ERROR;
							bRetStatus = true;
						}
						else
							m_nLastErrorCode = HASHERROR_GET_HASH_VALUE;
					}
					else
						m_nLastErrorCode = HASHERROR_GET_HASH_VALUE_SIZE;
				}
				else	// if(!m_bAbortFileHashing && bDataHashComplete)
				{
					if(m_bAbortFileHashing)									// check if abort was called
						m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
					else															// CryptHashData was not successful
						m_nLastErrorCode = HASHERROR_CREATE_HASH_DATA;
				}
			}
			else
				m_nLastErrorCode = HASHERROR_CREATE_HASH_OBJ;
		}
		else
			m_nLastErrorCode = HASHERROR_ACQUIRE_CRYPT_PROVIDER_CONTEXT;

		if(m_hHash)
			CryptDestroyHash(m_hHash);

		if(m_hCryptProv)
			CryptReleaseContext(m_hCryptProv, 0);

		return bRetStatus;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_UNKNOWN_EXCEPTION;
		return false;
	}
}

#endif IMPLEMENT_WIN_CRYPT_HASHES

#endif IMPLEMENT_HASH_BY_FILE


/***********************************************************************************/
/**                                                                               **/
/**  Implement Hash By Memory Mapping Functions                                   **/
/**                                                                               **/
/***********************************************************************************/
#ifdef IMPLEMENT_HASH_BY_MEM_MAP_FILE
/////////////////////////////////////////////////////////////////////
//
bool CHashes::CRC32Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	CCrc32::Init();

	DWORD								i;
	CMMFileBytes::ReadStatus	rs;
	BYTE*								pBytes;
	DWORD								dwByteSize;

	while(true)
	{
		pBytes = pMMFile->Bytes();
		dwByteSize = pMMFile->BytesSize();

		for(i=0; i<dwByteSize; i++)
		{
			if( !CCrc32::Update(pBytes[i]) )
			{
				m_nLastErrorCode = HASHERROR_CRC32_UNKNOWN_EXCEPTION;
				return false;
			}
		}

		// check if abort was called
		if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(dwByteSize*m_dProgressFactor)) )
		{
			m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
			return false;
		}

		// read next bytes and check status
		if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
			break;
	}

	// check file status. Other then rs_Done means that an error occured.
	if( rs != CMMFileBytes::rs_Done )
	{
		m_nLastErrorCode = HASHERROR_READ_MMFILE;				
		return false;
	}

	DWORD		dwCrc32 = CCrc32::Digest();
	
	m_pbHashCodeBuffer = *pbHashCode = new BYTE[4];

	// convert the CRC32 DWORD's bytes to a byte array
	(*pbHashCode)[3] = (dwCrc32 >> 24) & 0xFF;
	(*pbHashCode)[2] = (dwCrc32 >> 16) & 0xFF;
	(*pbHashCode)[1] = (dwCrc32 >> 8) & 0xFF;
	(*pbHashCode)[0] = dwCrc32 & 0xFF;
	*pdwHashLen = 4;

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::CRC32bHash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;		// initial state

	CCrc32::Init();

	DWORD								i;
	CMMFileBytes::ReadStatus	rs;
	BYTE*								pBytes;
	DWORD								dwByteSize;

	while(true)
	{
		pBytes = pMMFile->Bytes();
		dwByteSize = pMMFile->BytesSize();

		for(i=0; i<dwByteSize; i++)
		{
			if( !CCrc32::Update_b(pBytes[i]) )
			{
				m_nLastErrorCode = HASHERROR_CRC32_UNKNOWN_EXCEPTION;
				return false;
			}
		}

		// check if abort was called
		if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(dwByteSize*m_dProgressFactor)) )
		{
			m_nLastErrorCode = HASHERROR_HASHING_ABORTED;				
			return false;
		}

		// read next bytes and check status
		if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
			break;
	}

	// check file status. Other then rs_Done means that an error occured.
	if( rs != CMMFileBytes::rs_Done )
	{
		m_nLastErrorCode = HASHERROR_READ_MMFILE;				
		return false;
	}

	DWORD		dwCrc32 = CCrc32::Digest();
	
	m_pbHashCodeBuffer = *pbHashCode = new BYTE[4];

	// convert the CRC32b DWORD's bytes to a byte array
	(*pbHashCode)[0] = (dwCrc32 >> 24) & 0xFF;
	(*pbHashCode)[1] = (dwCrc32 >> 16) & 0xFF;
	(*pbHashCode)[2] = (dwCrc32 >> 8) & 0xFF;
	(*pbHashCode)[3] = dwCrc32 & 0xFF;
	*pdwHashLen = 4;

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::MD4Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		md4_ctx							ctx;
		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		CMd4::Init(&ctx);
		
		while(true)
		{
			// add data to hash object
			CMd4::Update(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[MD4_HASH_CODE_SIZE];

		CMd4::Digest(&ctx, *pbHashCode);
		*pdwHashLen = MD4_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_MD4_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::MD5Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		md5_ctx							ctx;
		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		CMd5::Init(&ctx);
		
		while(true)
		{
			// add data to hash object
			CMd5::Update(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[MD5_HASH_CODE_SIZE];

		CMd5::Digest(&ctx, *pbHashCode);
		*pdwHashLen = MD5_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_MD5_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::EDonkey2kHash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		ed2k_ctx							ctx;
		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		CEDonkey2k::Init(&ctx);
		
		while(true)
		{
			// add data to hash object
			CEDonkey2k::Update(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[EDONKEY2K_HASH_CODE_SIZE];

		CEDonkey2k::Digest(&ctx, *pbHashCode);
		*pdwHashLen = EDONKEY2K_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_EDONKEY2K_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::GOSTHash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		gost_ctx							ctx;
		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		CGost::Init(&ctx);
		
		while(true)
		{
			// add data to hash object
			CGost::Update(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[GOST_HASH_CODE_SIZE];

		CGost::Digest(&ctx, *pbHashCode);
		*pdwHashLen = GOST_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_GOST_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SnefruHash(int nFptLen, CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !SNEFRU_SUPPORT_FINGERPRINT_LENGTH(nFptLen) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_SNEFRU_FPTLEN;
		return false;
	}

	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		snefru_ctx						ctx;
		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		CSnefru::Init(&ctx);
		
		while(true)
		{
			// add data to hash object
			SNEFRU_UPDATE(nFptLen, &ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		// assume fptlen is 128 or 256
		int	nCodeSize = nFptLen/8;			// convert bits to bytes

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[nCodeSize];

		SNEFRU_FINAL(nFptLen, &ctx);
		SNEFRU_DIGEST(nFptLen, &ctx, *pbHashCode);
		*pdwHashLen = nCodeSize;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SNEFRU_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SHA160Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		sha160_ctx						ctx;
		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		CSha160::Init(&ctx);
		
		while(true)
		{
			// add data to hash object
			CSha160::Update(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SHA160_HASH_CODE_SIZE];

		CSha160::Final(&ctx);
		CSha160::Digest(&ctx, *pbHashCode);
		*pdwHashLen = SHA160_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SHA160_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SHA224Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		sha256_sha224_ctx				ctx;
		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		CSha256Sha224::Init224(&ctx);
		
		while(true)
		{
			// add data to hash object
			CSha256Sha224::Update(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SHA224_HASH_CODE_SIZE];

		CSha256Sha224::Final(&ctx);
		CSha256Sha224::Digest224(&ctx, *pbHashCode);
		*pdwHashLen = SHA224_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SHA256_SHA224_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SHA256Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		sha256_sha224_ctx				ctx;
		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		CSha256Sha224::Init256(&ctx);
		
		while(true)
		{
			// add data to hash object
			CSha256Sha224::Update(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SHA256_HASH_CODE_SIZE];

		CSha256Sha224::Final(&ctx);
		CSha256Sha224::Digest256(&ctx, *pbHashCode);
		*pdwHashLen = SHA256_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SHA256_SHA224_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SHA384Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		sha512_sha384_ctx			ctx;
		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		CSha512Sha384::Init384(&ctx);
		
		while(true)
		{
			// add data to hash object
			CSha512Sha384::Update(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SHA384_HASH_CODE_SIZE];

		CSha512Sha384::Final(&ctx);
		CSha512Sha384::Digest384(&ctx, *pbHashCode);
		*pdwHashLen = SHA384_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SHA512_SHA384_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::SHA512Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		sha512_sha384_ctx			ctx;
		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		CSha512Sha384::Init512(&ctx);
		
		while(true)
		{
			// add data to hash object
			CSha512Sha384::Update(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SHA512_HASH_CODE_SIZE];

		CSha512Sha384::Final(&ctx);
		CSha512Sha384::Digest512(&ctx, *pbHashCode);
		*pdwHashLen = SHA512_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SHA512_SHA384_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::TigerHash(int nFptLen, int nPasses, CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !TIGER_SUPPORT_FINGERPRINT_LENGTH(nFptLen) || !TIGER_SUPPORT_PASSES(nPasses) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_TIGER_FPTLEN_OR_PASSES;
		return false;
	}

	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		tiger_ctx						ctx;
		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		CTiger::Init(&ctx, nPasses);

		while(true)
		{
			// add data to hash object
			CTiger::Update(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		// assume fptlen is 128, 160, or 192
		int	nCodeSize = nFptLen/8;			// convert bits to bytes

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[nCodeSize];

		CTiger::Final(&ctx);
		TIGER_DIGEST(nFptLen, &ctx, *pbHashCode);
		*pdwHashLen = nCodeSize;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_TIGER_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::HAVALHash(int nFptLen, int nPasses, CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !HAVAL_SUPPORT_FINGERPRINT_LENGTH(nFptLen) || !HAVAL_SUPPORT_PASSES(nPasses) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_HAVAL_FPTLEN_OR_PASSES;
		return false;
	}

	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		haval_ctx						ctx;
		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		CHaval::Init(&ctx, nFptLen, nPasses);
		
		while(true)
		{
			// add data to hash object
			CHaval::Update(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		// assume fptlen is 128, 160, 192, 224 or 256
		int	nCodeSize = nFptLen/8;			// convert bits to bytes

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[nCodeSize];

		CHaval::Digest(&ctx, *pbHashCode);
		*pdwHashLen = nCodeSize;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_HAVAL_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::WhirlpoolHash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		whirlpool_ctx					ctx;
		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		CWhirlpool::Init(&ctx);
		
		while(true)
		{
			// add data to hash object
			CWhirlpool::Update(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[WHIRLPOOL_HASH_CODE_SIZE];

		CWhirlpool::Digest(&ctx, *pbHashCode);
		*pdwHashLen = WHIRLPOOL_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_WHIRLPOOL_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::RIPEMDHash(int nFptLen, CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !RIPEMD_SUPPORT_FINGERPRINT_LENGTH(nFptLen) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_RIPEMD_FPTLEN;
		return false;
	}

	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		ripemd_ctx						ctx;
		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		RIPEMD_INIT(nFptLen, &ctx);
		
		while(true)
		{
			// add data to hash object
			CRipemd::Update(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		// assume fptlen is 128, 160, 256 or 320
		int	nCodeSize = nFptLen/8;			// convert bits to bytes

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[nCodeSize];

		CRipemd::Digest(&ctx, *pbHashCode);
		*pdwHashLen = nCodeSize;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_RIPEMD_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::Murmur32Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		murmur32_ctx		ctx;

		CMurmur::Init32(&ctx);
		
		while(true)
		{
			// add data to hash object
			CMurmur::Update32(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		DWORD		dwHashCode = CMurmur::Digest32(&ctx);

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[4];

		// convert the Murmur DWORD's bytes to a byte array
		(*pbHashCode)[3] = (dwHashCode >> 24) & 0xFF;
		(*pbHashCode)[2] = (dwHashCode >> 16) & 0xFF;
		(*pbHashCode)[1] = (dwHashCode >> 8) & 0xFF;
		(*pbHashCode)[0] = dwHashCode & 0xFF;
		*pdwHashLen = 4;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_MURMUR_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::Murmur128Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		murmur128_ctx		ctx;

		CMurmur::Init128(&ctx);
		
		while(true)
		{
			// add data to hash object
			CMurmur::Update128(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[MURMUR128_HASH_CODE_SIZE];

		CMurmur::Digest128(&ctx, *pbHashCode);
		*pdwHashLen = MURMUR128_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_MURMUR_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::Salsa10Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		salsa_ctx		ctx;

		CSalsa::Init(&ctx, CSalsa::Salsa10);
		
		while(true)
		{
			// add data to hash object
			CSalsa::Update(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SALSA_HASH_CODE_SIZE];

		CSalsa::Digest(&ctx, *pbHashCode);
		*pdwHashLen = SALSA_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SALSA_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::Salsa20Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		salsa_ctx		ctx;

		CSalsa::Init(&ctx, CSalsa::Salsa20);
		
		while(true)
		{
			// add data to hash object
			CSalsa::Update(&ctx, pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[SALSA_HASH_CODE_SIZE];

		CSalsa::Digest(&ctx, *pbHashCode);
		*pdwHashLen = SALSA_HASH_CODE_SIZE;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_SALSA_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::KeccakHash(int nFptLen, CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !KECCAK_SUPPORT_FINGERPRINT_LENGTH(nFptLen) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_KECCAK_FPTLEN;
		return false;
	}

	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		CMMFileBytes::ReadStatus	rs = CMMFileBytes::rs_Invalid;
		
		CKeccak::Init(nFptLen);
		
		while(true)
		{
			// add data to hash object
			CKeccak::Update(pMMFile->Bytes(), pMMFile->BytesSize());

			// check if abort was submitted
			if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
			{
				m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
				return false;
			}
										
			// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
			if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
				break;
		}
		
		// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
		if(rs != CMMFileBytes::rs_Done)
		{
			m_nLastErrorCode = HASHERROR_READ_MMFILE;
			return false;
		}

		// assume fptlen is 224, 256, 384 or 512
		int	nCodeSize = nFptLen/8;			// convert bits to bytes

		m_pbHashCodeBuffer = *pbHashCode = new BYTE[nCodeSize];

		CKeccak::Digest(*pbHashCode);
		*pdwHashLen = nCodeSize;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_KECCAK_UNKNOWN_EXCEPTION;
		return false;
	}

	m_nLastErrorCode = HASHERROR_NO_ERROR;
	return true;
}

#ifdef IMPLEMENT_WIN_CRYPT_HASHES

/////////////////////////////////////////////////////////////////////
//
bool CHashes::WinCryptMD5Hash(CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	return this->WinCryptHash(PROV_RSA_FULL, CALG_MD5, pMMFile, pbHashCode, pdwHashLen, progressCallback);
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::WinCryptSHAHash(int nFptLen, CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !SHA_SUPPORT_FINGERPRINT_LENGTH(nFptLen) )
	{
		m_nLastErrorCode = HASHERROR_INVALID_SHA_FPTLEN;
		return false;
	}

	DWORD		dwProvType;
	ALG_ID	Algid;
	
	SHA_ALGORITHM(nFptLen, dwProvType, Algid);

	return this->WinCryptHash(dwProvType, Algid, pMMFile, pbHashCode, pdwHashLen, progressCallback);
}

/////////////////////////////////////////////////////////////////////
//
bool CHashes::WinCryptHash(DWORD dwProvType, ALG_ID Algid, CMMFileBytes* pMMFile, BYTE** pbHashCode, DWORD* pdwHashLen, PROGRESSCALLBACKPROC progressCallback/*=NULL*/)
{
	if( !pMMFile->IsFileStart() )
	{
		m_nLastErrorCode = HASHERROR_OPEN_MMFILE;
		return false;
	}

	m_bAbortFileHashing = false;	// initial state

	bool		bRetStatus = false;	// pessimistic

	try
	{
		delete m_pbHashCodeBuffer;
		m_pbHashCodeBuffer = NULL;

		m_hCryptProv = m_hHash = NULL;

		// Get a handle to a cryptography provider context.
		if( CryptAcquireContext(&m_hCryptProv, NULL, NULL, dwProvType, 0) )
		{
			// Acquire a hash object handle.
			if( CryptCreateHash(m_hCryptProv, Algid, 0, 0, &m_hHash) )
			{
				bool				bDataHashComplete = true;	// optimistic

				CMMFileBytes::ReadStatus		rs = CMMFileBytes::rs_Invalid;

				while(true)
				{
					// add data to hash object
					if( !CryptHashData(m_hHash, pMMFile->Bytes(), pMMFile->BytesSize(), 0) )
					{
						bDataHashComplete = false;
						break;
					}

					// check if abort was submitted
					if( ItsTimeToCheckUserAbort() && SAFE_USER_ABORT((int)(pMMFile->BytesSize()*m_dProgressFactor)) )
						break;
										
					// read next file bytes and check file status. Other then rbs_OK means that all was read or an error occured.
					if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
						break;
				}

				// check how the while(true) terminated; MMFile read, user abort, CryptHashData failed.
				if(!m_bAbortFileHashing && rs == CMMFileBytes::rs_Done && bDataHashComplete)
				{
					DWORD		dwLen;
					DWORD		dwCount = sizeof(dwLen);	

					// Acquire size of hash value
					if( CryptGetHashParam(m_hHash, HP_HASHSIZE, (BYTE*)&dwLen, &dwCount, 0) )
					{
						*pdwHashLen = dwLen;
						m_pbHashCodeBuffer = *pbHashCode = new BYTE[dwLen];

						// Acquire hash value
						if( CryptGetHashParam(m_hHash, HP_HASHVAL, *pbHashCode, &dwLen, 0) )
						{
							m_nLastErrorCode = HASHERROR_NO_ERROR;
							bRetStatus = true;
						}
						else
							m_nLastErrorCode = HASHERROR_GET_HASH_VALUE;
					}
					else
						m_nLastErrorCode = HASHERROR_GET_HASH_VALUE_SIZE;
				}
				else	// if(rbs == CMMFileBytes::rbs_Done && !bUserAbort && bDataHashComplete)
				{			
					if(m_bAbortFileHashing)										// check if abort was called
						m_nLastErrorCode = HASHERROR_HASHING_ABORTED;
					else if(rs != CMMFileBytes::rs_Done)					// check is the entire MMFile was processed
						m_nLastErrorCode = HASHERROR_READ_MMFILE;
					else																// CryptHashData was not successful
						m_nLastErrorCode = HASHERROR_CREATE_HASH_DATA;
				}
			}
			else
				m_nLastErrorCode = HASHERROR_CREATE_HASH_OBJ;
		}
		else
			m_nLastErrorCode = HASHERROR_ACQUIRE_CRYPT_PROVIDER_CONTEXT;

		if(m_hHash)
			CryptDestroyHash(m_hHash);

		if(m_hCryptProv)
			CryptReleaseContext(m_hCryptProv, 0);

		return bRetStatus;
	}
	catch(...)
	{
		m_nLastErrorCode = HASHERROR_UNKNOWN_EXCEPTION;
		return false;
	}
}

#endif IMPLEMENT_WIN_CRYPT_HASHES

#endif IMPLEMENT_HASH_BY_MEM_MAP_FILE


/////////////////////////////////////////////////////////////////////
//
bool CHashes::ItsTimeToCheckUserAbort()
{
	DWORD dwNewTime = ::GetTickCount();

	if( (dwNewTime - m_dwLastTimeCheckUserAbort) < CHECK_USER_ABORT_INTERVAL )
		return false;

	m_dwLastTimeCheckUserAbort = dwNewTime;
	return true;
}

/////////////////////////////////////////////////////////////////////
//
int CHashes::GetLastErrorCode() const
{
	return m_nLastErrorCode;
}

/////////////////////////////////////////////////////////////////////
//
WCHAR* CHashes::GetLastErrorMessage() const 
{
	switch(m_nLastErrorCode)
	{
	case HASHERROR_NO_ERROR:
		return strlcpyW((WCHAR*)m_szLastError, L"", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_ACQUIRE_CRYPT_PROVIDER_CONTEXT:
		return strlcpyW((WCHAR*)m_szLastError, L"error acquiring cryptography provider context", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_CREATE_HASH_OBJ:
		return strlcpyW((WCHAR*)m_szLastError, L"error creating hash object handle", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_CREATE_HASH_DATA:
		return strlcpyW((WCHAR*)m_szLastError, L"error creating hash data", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_GET_HASH_VALUE_SIZE:
		return strlcpyW((WCHAR*)m_szLastError, L"error getting size of hash value", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_GET_HASH_VALUE:
		return strlcpyW((WCHAR*)m_szLastError, L"error getting hash value", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_CRC32_UNKNOWN_EXCEPTION:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown exception in CCrc32 class", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_UNKNOWN_EXCEPTION:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown exception", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_HASHING_ABORTED:
		return strlcpyW((WCHAR*)m_szLastError, L"operation aborted", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_OPEN_MMFILE:
		return strlcpyW((WCHAR*)m_szLastError, L"error opening memory mapped file", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_READ_MMFILE:
		return strlcpyW((WCHAR*)m_szLastError, L"error reading memory mapped file", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_INVALID_FILE:
		return strlcpyW((WCHAR*)m_szLastError, L"file pointer is invalid", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_INVALID_BYTE_ARRAY:
		return strlcpyW((WCHAR*)m_szLastError, L"pointer to byte array is invalid", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_TIGER_UNKNOWN_EXCEPTION:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown exception in CTiger class", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_HAVAL_UNKNOWN_EXCEPTION:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown exception in CHaval class", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_INVALID_HAVAL_FPTLEN_OR_PASSES:
		return strlcpyW((WCHAR*)m_szLastError, L"HAVAL fingerprint length or number of passes is invalid", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_WHIRLPOOL_UNKNOWN_EXCEPTION:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown exception in CWhirlpool class", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_INVALID_RIPEMD_FPTLEN:
		return strlcpyW((WCHAR*)m_szLastError, L"RIPEMD fingerprint length is invalid", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_RIPEMD_UNKNOWN_EXCEPTION:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown exception in CRipemd class", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_INVALID_TIGER_FPTLEN_OR_PASSES:
		return strlcpyW((WCHAR*)m_szLastError, L"Tiger fingerprint length or number of passes is invalid", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_INVALID_SNEFRU_FPTLEN:
		return strlcpyW((WCHAR*)m_szLastError, L"Snefru fingerprint length is invalid", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_INVALID_SHA_FPTLEN:
		return strlcpyW((WCHAR*)m_szLastError, L"SHA fingerprint length is invalid", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_MD4_UNKNOWN_EXCEPTION:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown exception in CMd4 class", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_EDONKEY2K_UNKNOWN_EXCEPTION:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown exception in CEDonkey2k class", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_MD5_UNKNOWN_EXCEPTION:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown exception in CMd5 class", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_SHA160_UNKNOWN_EXCEPTION:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown exception in CSha160 class", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_SHA256_SHA224_UNKNOWN_EXCEPTION:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown exception in CSha256Sha224 class", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_SHA512_SHA384_UNKNOWN_EXCEPTION:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown exception in CSha512Sha384 class", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_MURMUR_UNKNOWN_EXCEPTION:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown exception in CMurmur class", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_SALSA_UNKNOWN_EXCEPTION:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown exception in CSalsa class", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_INVALID_KECCAK_FPTLEN:
		return strlcpyW((WCHAR*)m_szLastError, L"Keccak fingerprint length is invalid", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	case HASHERROR_KECCAK_UNKNOWN_EXCEPTION:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown exception in CKeccak class", ERROR_MSG_BUFF_SIZE);
		//#####################################################################

	default:
		return strlcpyW((WCHAR*)m_szLastError, L"unknown error code", ERROR_MSG_BUFF_SIZE);
		//#####################################################################
	};
}