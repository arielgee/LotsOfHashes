
// Md4.h : header file
//

/* md4.c - an implementation of MD4 Message-Digest Algorithm
 * based on RFC 1320.
 *
 */

/////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                         //
// MD4 - An implementation of MD4 Message-Digest Algorithm.                                //
// Based on RFC 1320.                                                                      //
//                                                                                         //
/////////////////////////////////////////////////////////////////////////////////////////////

#pragma once

#define md4_block_size 64
#define md4_hash_size  16

/* algorithm context */
typedef struct _md4_ctx
{
	UINT32		message[md4_block_size/4];		/* 512-bit buffer for leftovers */
	UINT64		length;								/* number of processed bytes */
	UINT32		hash[4];								/* 128-bit algorithm internal hashing state */
} md4_ctx;


class CMd4
{
public:
	CMd4(void);
	virtual ~CMd4(void);

private:
	static void process_block(UINT32 state[4], const UINT32* x);

public:
	void Init(md4_ctx* ctx);
	void Update(md4_ctx* ctx, const UINT8* msg, UINT32 size);
	void Digest(md4_ctx* ctx, UINT8 result[16]);
};

