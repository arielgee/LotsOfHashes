
// EDonkey2k.h : header file
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

#pragma once

#include "Md4.h"

/* algorithm context */
typedef struct _ed2k_ctx
{
	md4_ctx	md4_context;			/* context to hash block hashes */
	md4_ctx	md4_context_inner;	/* context to hash file blocks */
	UINT64	filesize;				/* calculated length of the hashed messaged */
} ed2k_ctx;


class CEDonkey2k
{
public:
	CEDonkey2k(void);
	virtual ~CEDonkey2k(void);

private:
	/* Note that eDonkey and eMule ed2k hashes are different for
	 * files containing an exact multiple of 9728000 bytes */
	bool		m_bUseEmuleAlgorithm;
	CMd4		m_md4;

public:
	void Init(ed2k_ctx* ctx, bool bUseEmuleAlgorithm = true);
	void Update(ed2k_ctx* ctx, const UINT8* msg, UINT32 size);
	void Digest(ed2k_ctx* ctx, UINT8 result[16]);
};

