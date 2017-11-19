
// EDonkey2k.cpp : implementation file
//

/*
 * EDonkey2k - an implementation of EDonkey 2000 Hash Algorithm.
 * Written by Alexei Kravchenko.
 *
 * This file implements eMule-compatible version of algorithm.
 * Note that eDonkey and eMule ed2k hashes are different for
 * files containing exactly multiple of 9728000 bytes.
 * 
 * The file data is divided into full chunks of 9500 KiB (9728000 bytes) plus
 * a remainder chunk, and a separate 128-bit MD4 hash is computed for each. 
 * If the file length is an exact multiple of 9500 KiB, the remainder zero 
 * size chunk is still used at the end of the hash list. The ed2k hash is 
 * computed by concatenating the chunks' MD4 hashes in order and hashing the 
 * result using MD4. Although, if the file is composed of a single non-full 
 * chunk, its MD4 hash is returned with no further modifications.
 *
 * See http://en.wikipedia.org/wiki/EDonkey_network for algorithm description.
 */

#include "StdAfx.h"
#include "EDonkey2k.h"

/* each hashed file is divided into 9500 KiB sized chunks */
#define ED2K_CHUNK_SIZE 9728000

/////////////////////////////////////////////////////////////////////
//
CEDonkey2k::CEDonkey2k(void) : m_bUseEmuleAlgorithm(true)
{
}

/////////////////////////////////////////////////////////////////////
//
CEDonkey2k::~CEDonkey2k(void)
{
}

/////////////////////////////////////////////////////////////////////
// Initialize context before calculaing hash.
void CEDonkey2k::Init(ed2k_ctx* ctx, bool bUseEmuleAlgorithm/*=true*/)
{
	m_bUseEmuleAlgorithm = bUseEmuleAlgorithm;
	m_md4.Init(&ctx->md4_context);
	m_md4.Init(&ctx->md4_context_inner);
	ctx->filesize = 0;
}

/////////////////////////////////////////////////////////////////////
// Calculate message hash.
// Can be called repeatedly with chunks of the message to be hashed.
void CEDonkey2k::Update(ed2k_ctx* ctx, const UINT8* msg, UINT32 size)
{
	UINT8 chunk_md4_hash[16];
	UINT32 blockleft = ED2K_CHUNK_SIZE - (UINT32)ctx->md4_context_inner.length;
	ctx->filesize += size;

	/* note: eMule-compatible algorithm hashes by internal md4 
	* messages which sizes are multiple of 9728000 
	* and then processes obtained hash by external md4 */

	/* if internal ed2k chunk is full, then finalize it */

	        /* <--         eMule-compatible      --> */      /* <--     eDonkey2k-compatible      --> */
	while( (m_bUseEmuleAlgorithm && (size >= blockleft)) || (!m_bUseEmuleAlgorithm && (size > blockleft)) )
	{
		m_md4.Update(&ctx->md4_context_inner, msg, blockleft);
		msg += blockleft;
		size -= blockleft;
		blockleft = ED2K_CHUNK_SIZE;

		/* just finished an ed2k chunk, updating context */
		m_md4.Digest(&ctx->md4_context_inner, chunk_md4_hash);
		m_md4.Update(&ctx->md4_context, chunk_md4_hash, 16);
		m_md4.Init(&ctx->md4_context_inner);
	}

	if(size) {
		/* hash leftovers */
		m_md4.Update(&ctx->md4_context_inner, msg, size);
	}
}

/////////////////////////////////////////////////////////////////////
// Store calculated hash into the given array.
void CEDonkey2k::Digest(ed2k_ctx* ctx, UINT8 result[16])
{
	/* check if hashed message size is greater or equal to ED2K_CHUNK_SIZE */
	if ( ctx->md4_context.length ) {

		/* note: weird eMule algorithm always here flushes the md4_context_inner,
		* no matter if it contains data or is empty */

		/* if any data are left in the md4_context_inner */

		                             /* <--    eDonkey2k-compatible     --> */
		if(m_bUseEmuleAlgorithm || ( (UINT32)ctx->md4_context_inner.length > 0 ) )
		{
			UINT8 md4_digest_inner[16];
			m_md4.Digest(&ctx->md4_context_inner, md4_digest_inner);
			m_md4.Update(&ctx->md4_context, md4_digest_inner, 16);
		}
		m_md4.Digest(&ctx->md4_context, result);
	}
	else {
		/* return just the message MD4 hash */
		m_md4.Digest(&ctx->md4_context_inner, result);
	}
}



/*
#define USE_EMULE_ALGORITHM

/////////////////////////////////////////////////////////////////////
// Calculate message hash.
// Can be called repeatedly with chunks of the message to be hashed.
void CEDonkey2k::Update(ed2k_ctx* ctx, const UINT8* msg, UINT32 size)
{
	UINT8 chunk_md4_hash[16];
	UINT32 blockleft = ED2K_CHUNK_SIZE - (UINT32)ctx->md4_context_inner.length;
	ctx->filesize += size;

	/* note: eMule-compatible algorithm hashes by internal md4 
	* messages which sizes are multiple of 9728000 
	* and then processes obtained hash by external md4 *

	/* if internal ed2k chunk is full, then finalize it *
#ifdef USE_EMULE_ALGORITHM
	while ( size >= blockleft )
#else
	while ( size >  blockleft )
#endif
	{
		m_md4.Update(&ctx->md4_context_inner, msg, blockleft);
		msg += blockleft;
		size -= blockleft;
		blockleft = ED2K_CHUNK_SIZE;

		/* just finished an ed2k chunk, updating context *
		m_md4.Final(&ctx->md4_context_inner, chunk_md4_hash);
		m_md4.Update(&ctx->md4_context, chunk_md4_hash, 16);
		m_md4.Init(&ctx->md4_context_inner);
	}

	if(size) {
		/* hash leftovers *
		m_md4.Update(&ctx->md4_context_inner, msg, size);
	}
}


/////////////////////////////////////////////////////////////////////
// Store calculated hash into the given array.
void CEDonkey2k::Final(ed2k_ctx* ctx, UINT8 result[16])
{
	/* check if hashed message size is greater or equal to ED2K_CHUNK_SIZE *
	if ( ctx->md4_context.length ) {

		/* note: weird eMule algorithm always here flushes the md4_context_inner,
		* no matter if it contains data or is empty *
#ifndef USE_EMULE_ALGORITHM
		/* if any data are left in the md4_context_inner
		if ( (UINT32)ctx->md4_context_inner.length > 0 )
#endif
		{
			UINT8 md4_digest_inner[16];
			m_md4.Final(&ctx->md4_context_inner, md4_digest_inner);
			m_md4.Update(&ctx->md4_context, md4_digest_inner, 16);
		}
		m_md4.Final(&ctx->md4_context, result);
	}
	else {
		/* return just the message MD4 hash *
		m_md4.Final(&ctx->md4_context_inner, result);
	}
}














*/