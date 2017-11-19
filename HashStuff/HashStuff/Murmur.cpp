
// Murmur.cpp : implementation file
//

/*
 *  Murmur.cpp:  specifies the routines to the MurmurHash3 hashing library.
 *
 *  MurmurHash3 is a non-cryptographic hash written by Austin Appleby.
 *  The code is based on code available at http://code.google.com/p/smhasher.
 *
 *  From that site: "All MurmurHash versions are public domain software,
 *  and the author disclaims all copyright to their code."
 *
 *  Note - The x86 and x64 versions do _not_ produce the same results, as the
 *  algorithms are optimized for their respective platforms. You can still
 *  compile and run any of them on any platform, but your performance with the
 *  non-native version will be less than optimal.
 *
 */

#include "StdAfx.h"
#include "Murmur.h"

#define MURMUR32_MAGIC_1 0xcc9e2d51
#define MURMUR32_MAGIC_2 0x1b873593

#define MURMUR128_MAGIC_1 0x87c37b91114253d5
#define MURMUR128_MAGIC_2 0x4cf5ad432745937f

/////////////////////////////////////////////////////////////////////
//
static __forceinline UINT32 rotl32(UINT32 x, INT8 r)
{
	return (x << r) | (x >> (32 - r));
}

/////////////////////////////////////////////////////////////////////
//
static __forceinline UINT64 rotl64(UINT64 x, INT8 r)
{
	return (x << r) | (x >> (64 - r));
}

/////////////////////////////////////////////////////////////////////
//
static __forceinline UINT32 fmix(UINT32 k)
{
	k ^= k >> 16;
	k *= 0x85ebca6b;
	k ^= k >> 13;
	k *= 0xc2b2ae35;
	k ^= k >> 16;

	return k;
} 

/////////////////////////////////////////////////////////////////////
//
static __forceinline UINT64 fmix(UINT64 k)
{
	k ^= k >> 33;
	k *= 0xff51afd7ed558ccd;
	k ^= k >> 33;
	k *= 0xc4ceb9fe1a85ec53;
	k ^= k >> 33;

	return k;
} 

/////////////////////////////////////////////////////////////////////
//
CMurmur::CMurmur(void)
{
}

/////////////////////////////////////////////////////////////////////
//
CMurmur::~CMurmur(void)
{
}

/////////////////////////////////////////////////////////////////////
//
void CMurmur::Init32(murmur32_ctx* ctx, const UINT32 seed/*=0x0*/)
{
	ctx->h = seed;
	ctx->len = ctx->unparsed_len = 0;	
}

/////////////////////////////////////////////////////////////////////
//
void CMurmur::Init128(murmur128_ctx* ctx, const UINT32 seed/*=0x0*/)
{
	ctx->h1 = ctx->h2 = seed;
	ctx->len = ctx->unparsed_len = 0;
}

/////////////////////////////////////////////////////////////////////
//
void CMurmur::Update32(murmur32_ctx* ctx, const UINT8* data, size_t len)
{
	// body

	// update total length
	ctx->len += len;

	// If there were unparsed bytes from the last update, process them first.
	if(ctx->unparsed_len > 0)
	{
		size_t	needed = MURMUR32_BLOCK_SIZE - ctx->unparsed_len;

		// If the supplied data cannot fill up unparsed_bytes, append the data to unparsed_bytes and return
		if(needed > len)
		{
			memcpy(ctx->unparsed_bytes + ctx->unparsed_len, data, len);
			ctx->unparsed_len += len;
			return;
		}

		// Fill up unparsed_bytes and adjust data/len
		memcpy(ctx->unparsed_bytes + ctx->unparsed_len, data, needed);
		data += needed;
		len -= needed;

		// Apply the hash update
		updateBlock32(ctx, ((UINT32*)ctx->unparsed_bytes)[0]);

		// Reset the unparsed_bytes count
		ctx->unparsed_len = 0;
	}

	// Normal processing
	const __int64 nBlocks = len/MURMUR32_BLOCK_SIZE;

	const UINT32*	blocks = (const UINT32*)(data+nBlocks*MURMUR32_BLOCK_SIZE);
	
	for(__int64 i= -nBlocks; i; i++)
		updateBlock32(ctx, blocks[i]);

	// Copy leftover bytes to the context
	ctx->unparsed_len = len-((size_t)(nBlocks*MURMUR32_BLOCK_SIZE));	// the cast is cool because: nBlocks = len/MURMUR32_BLOCK_SIZE;

	//ASSERT(ctx->unparsed_len < sizeof(ctx->unparsed_bytes));
	//ASSERT(ctx->unparsed_len + nBlocks*MURMUR32_BLOCK_SIZE == len);

	memcpy(ctx->unparsed_bytes, (const UINT8*)blocks, ctx->unparsed_len);
}

/////////////////////////////////////////////////////////////////////
//
void CMurmur::Update128(murmur128_ctx* ctx, const UINT8* data, size_t len)
{
	// body

	// update total length
	ctx->len += len;

	// If there were unparsed bytes from the last update, process them first.
	if(ctx->unparsed_len > 0)
	{
		size_t	needed = MURMUR128_BLOCK_SIZE - ctx->unparsed_len;

		// If the supplied data cannot fill up unparsed_bytes, append the data to unparsed_bytes and return
		if(needed > len)
		{
			memcpy(ctx->unparsed_bytes + ctx->unparsed_len, data, len);
			ctx->unparsed_len += len;
			return;
		}

		// Fill up unparsed_bytes and adjust data/len
		memcpy(ctx->unparsed_bytes + ctx->unparsed_len, data, needed);
		data += needed;
		len -= needed;

		// Apply the hash update
		updateBlock128(ctx, ((UINT64*)ctx->unparsed_bytes)[0], ((UINT64*)ctx->unparsed_bytes)[1]);

		// Reset the unparsed_bytes count
		ctx->unparsed_len = 0;
	}

	// Normal processing
	const __int64 nBlocks = len/MURMUR128_BLOCK_SIZE;

	const UINT64*	blocks = (const UINT64*)data;

	for(__int64 i=0; i<nBlocks; i++)
		updateBlock128(ctx, blocks[i*2], blocks[i*2+1]);

	// Copy leftover bytes to the context
	ctx->unparsed_len = len-((size_t)(nBlocks*MURMUR128_BLOCK_SIZE));	// the cast is cool because: nBlocks = len/MURMUR128_BLOCK_SIZE;

	//ASSERT(ctx->unparsed_len < sizeof(ctx->unparsed_bytes));
	//ASSERT(ctx->unparsed_len + nBlocks*MURMUR128_BLOCK_SIZE == len);

	memcpy(ctx->unparsed_bytes, ((const UINT8*)blocks)+nBlocks*MURMUR128_BLOCK_SIZE, ctx->unparsed_len);
}

/////////////////////////////////////////////////////////////////////
//
UINT32 CMurmur::Digest32(murmur32_ctx* ctx)
{
	// tail

	UINT32	k1 = 0;

	switch(ctx->len & 3)		// fall through cases
	{
	case 3:	k1 ^= ctx->unparsed_bytes[2] << 16;
	case 2:	k1 ^= ctx->unparsed_bytes[1] << 8;
	case 1:	k1 ^= ctx->unparsed_bytes[0];
		k1 *= MURMUR32_MAGIC_1; k1 = rotl32(k1,15); k1 *= MURMUR32_MAGIC_2; ctx->h ^= k1;
	};

	// finalisation

	ctx->h ^= ctx->len;

	ctx->h = fmix(ctx->h);

	return ctx->h;
}

/////////////////////////////////////////////////////////////////////
//
void CMurmur::Digest128(murmur128_ctx* ctx, UINT8* digest)
{
	// tail

	//ASSERT(digest);

	UINT64	k1 = 0;
	UINT64	k2 = 0;	
	
	switch(ctx->len & 15)		// fall through cases
	{
	case 15:	k2 ^= UINT64(ctx->unparsed_bytes[14]) << 48;
	case 14:	k2 ^= UINT64(ctx->unparsed_bytes[13]) << 40;
	case 13:	k2 ^= UINT64(ctx->unparsed_bytes[12]) << 32;
	case 12:	k2 ^= UINT64(ctx->unparsed_bytes[11]) << 24;
	case 11:	k2 ^= UINT64(ctx->unparsed_bytes[10]) << 16;
	case 10:	k2 ^= UINT64(ctx->unparsed_bytes[ 9]) << 8;
	case 9:	k2 ^= UINT64(ctx->unparsed_bytes[ 8]) << 0;
				k2 *= MURMUR128_MAGIC_2; k2 = rotl64(k2,33); k2 *= MURMUR128_MAGIC_1; ctx->h2 ^= k2;
	case 8:	k1 ^= UINT64(ctx->unparsed_bytes[ 7]) << 56;
	case 7:	k1 ^= UINT64(ctx->unparsed_bytes[ 6]) << 48;
	case 6:	k1 ^= UINT64(ctx->unparsed_bytes[ 5]) << 40;
	case 5:	k1 ^= UINT64(ctx->unparsed_bytes[ 4]) << 32;
	case 4:	k1 ^= UINT64(ctx->unparsed_bytes[ 3]) << 24;
	case 3:	k1 ^= UINT64(ctx->unparsed_bytes[ 2]) << 16;
	case 2:	k1 ^= UINT64(ctx->unparsed_bytes[ 1]) << 8;
	case 1:	k1 ^= UINT64(ctx->unparsed_bytes[ 0]) << 0;
		k1 *= MURMUR128_MAGIC_1; k1 = rotl64(k1,31); k1 *= MURMUR128_MAGIC_2; ctx->h1 ^= k1;
	};

	// finalisation

	ctx->h1 ^= ctx->len;
	ctx->h2 ^= ctx->len;

	ctx->h1 += ctx->h2;
	ctx->h2 += ctx->h1;

	ctx->h1 = fmix(ctx->h1);
	ctx->h2 = fmix(ctx->h2);

	ctx->h1 += ctx->h2;
	ctx->h2 += ctx->h1;

	((UINT64*)digest)[0] = ctx->h1;
	((UINT64*)digest)[1] = ctx->h2;
}

/////////////////////////////////////////////////////////////////////
//
void CMurmur::updateBlock32(murmur32_ctx* ctx, UINT32 k1)
{
	k1 *= MURMUR32_MAGIC_1;
	k1 = rotl32(k1, 15);
	k1 *= MURMUR32_MAGIC_2;
		
	ctx->h ^= k1;
	ctx->h = rotl32(ctx->h, 13);
	ctx->h = ctx->h*5+0xe6546b64;
}

/////////////////////////////////////////////////////////////////////
//
void CMurmur::updateBlock128(murmur128_ctx* ctx, UINT64 k1, UINT64 k2)
{
	k1 *= MURMUR128_MAGIC_1;
	k1 = rotl64(k1, 31);
	k1 *= MURMUR128_MAGIC_2;
	ctx->h1 ^= k1;

	ctx->h1 = rotl64(ctx->h1, 27);
	ctx->h1 += ctx->h2;
	ctx->h1 = ctx->h1*5 + 0x52dce729;

	k2 *= MURMUR128_MAGIC_2;
	k2 = rotl64(k2, 33);
	k2 *= MURMUR128_MAGIC_1;
	ctx->h2 ^= k2;

	ctx->h2 = rotl64(ctx->h2, 31);
	ctx->h2 += ctx->h1;
	ctx->h2 = ctx->h2*5 + 0x38495ab5;
}
