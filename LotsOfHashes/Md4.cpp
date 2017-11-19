
// Md4.cpp : implementation file
//

/////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                         //
// MD4 - An implementation of MD4 Message-Digest Algorithm.                                //
// Based on RFC 1320.                                                                      //
//                                                                                         //
/////////////////////////////////////////////////////////////////////////////////////////////

#include "StdAfx.h"
#include "Md4.h"


/*
 * Define three auxiliary functions that each take as input
 * three 32-bit words and returns a 32-bit word.
 *   F(x,y,z) = XY v not(X) Z = ((Y xor Z) X) xor Z (the last form is faster)
 *   G(X,Y,Z) = XY v XZ v YZ
 *   H(X,Y,Z) = X xor Y xor Z
 */

#define MD4_F(x, y, z) ((((y) ^ (z)) & (x)) ^ (z))
#define MD4_G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define MD4_H(x, y, z) ((x) ^ (y) ^ (z))

/* ROTATE_LEFT rotates x left by n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* transformations for rounds 1, 2, and 3. */
#define MD4_ROUND1(a, b, c, d, x, s) { \
	(a) += MD4_F ((b), (c), (d)) + (x); \
	(a) = ROTATE_LEFT ((a), (s)); \
}

#define MD4_ROUND2(a, b, c, d, x, s) { \
	(a) += MD4_G ((b), (c), (d)) + (x) + 0x5a827999; \
	(a) = ROTATE_LEFT ((a), (s)); \
}

#define MD4_ROUND3(a, b, c, d, x, s) { \
	(a) += MD4_H ((b), (c), (d)) + (x) + 0x6ed9eba1; \
	(a) = ROTATE_LEFT ((a), (s)); \
}

#define IS_ALIGNED_32(p) (0 == (3 & ((const char*)(p) - (const char*)0)))

/////////////////////////////////////////////////////////////////////
//
CMd4::CMd4(void)
{
}


/////////////////////////////////////////////////////////////////////
//
CMd4::~CMd4(void)
{
}

/////////////////////////////////////////////////////////////////////
// Initialize context before calculaing hash.
void CMd4::Init(md4_ctx *ctx)
{
	ctx->length = 0;

	/* initialize state */
	ctx->hash[0] = 0x67452301;
	ctx->hash[1] = 0xefcdab89;
	ctx->hash[2] = 0x98badcfe;
	ctx->hash[3] = 0x10325476;
}


/////////////////////////////////////////////////////////////////////
// Calculate message hash.
// Can be called repeatedly with chunks of the message to be hashed.
void CMd4::Update(md4_ctx* ctx, const UINT8* msg, UINT32 size)
{
	UINT32 index = (UINT32)ctx->length & 63;
	ctx->length += size;

	/* fill partial block */
	if (index) {
		UINT32 left = md4_block_size - index;
		memcpy((char*)ctx->message + index, msg, (size < left ? size : left));
		if (size < left) return;

		/* process partitial block */
		this->process_block(ctx->hash, ctx->message);
		msg  += left;
		size -= left;
	}

	while (size >= md4_block_size) {
		UINT32* aligned_message_block;
		if( IS_ALIGNED_32(msg) ) {
			/* the most common case is processing a 32-bit aligned message 
			on a little-endian CPU without copying it */
			aligned_message_block = (UINT32*)msg;
		}
		else {
			memcpy(ctx->message, msg, md4_block_size);
			aligned_message_block = ctx->message;
		}

		this->process_block(ctx->hash, aligned_message_block);
		msg  += md4_block_size;
		size -= md4_block_size;
	}

	if(size) {
		/* save leftovers */
		memcpy(ctx->message, msg, size);
	}
}

/////////////////////////////////////////////////////////////////////
// Store calculated hash into the given array.
void CMd4::Digest(md4_ctx* ctx, UINT8 result[16])
{
	UINT32 index = ((UINT32)ctx->length & 63) >> 2;
	UINT32 shift = ((UINT32)ctx->length & 3) * 8;

	/* pad message and run for last block */

	/* append the byte 0x80 to the message */
	ctx->message[index]   &= ~(0xFFFFFFFF << shift);
	ctx->message[index++] ^= 0x80 << shift;

	/* if no room left in the message to store 64-bit message length */
	if(index>14) {
		/* then fill the rest with zeros and process it */
		while(index < 16) {
			ctx->message[index++] = 0;
		}
		this->process_block(ctx->hash, ctx->message);
		index = 0;
	}

	while(index < 14) {
		ctx->message[index++] = 0;
	}
	ctx->message[14] = (UINT32)(ctx->length << 3);
	ctx->message[15] = (UINT32)(ctx->length >> 29);
	this->process_block(ctx->hash, ctx->message);

	memcpy(result, &ctx->hash, 16);
}

/////////////////////////////////////////////////////////////////////
// The core transformation. Process a 512-bit block.
// The function has been taken from RFC 1320 with little changes.
void CMd4::process_block(UINT32 state[4], const UINT32* x)
{
	register UINT32 a, b, c, d;
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	MD4_ROUND1(a, b, c, d, x[ 0],  3);
	MD4_ROUND1(d, a, b, c, x[ 1],  7);
	MD4_ROUND1(c, d, a, b, x[ 2], 11);
	MD4_ROUND1(b, c, d, a, x[ 3], 19);
	MD4_ROUND1(a, b, c, d, x[ 4],  3);
	MD4_ROUND1(d, a, b, c, x[ 5],  7);
	MD4_ROUND1(c, d, a, b, x[ 6], 11);
	MD4_ROUND1(b, c, d, a, x[ 7], 19);
	MD4_ROUND1(a, b, c, d, x[ 8],  3);
	MD4_ROUND1(d, a, b, c, x[ 9],  7);
	MD4_ROUND1(c, d, a, b, x[10], 11);
	MD4_ROUND1(b, c, d, a, x[11], 19);
	MD4_ROUND1(a, b, c, d, x[12],  3);
	MD4_ROUND1(d, a, b, c, x[13],  7);
	MD4_ROUND1(c, d, a, b, x[14], 11);
	MD4_ROUND1(b, c, d, a, x[15], 19);
  
	MD4_ROUND2(a, b, c, d, x[ 0],  3);
	MD4_ROUND2(d, a, b, c, x[ 4],  5);
	MD4_ROUND2(c, d, a, b, x[ 8],  9);
	MD4_ROUND2(b, c, d, a, x[12], 13);
	MD4_ROUND2(a, b, c, d, x[ 1],  3);
	MD4_ROUND2(d, a, b, c, x[ 5],  5);
	MD4_ROUND2(c, d, a, b, x[ 9],  9);
	MD4_ROUND2(b, c, d, a, x[13], 13);
	MD4_ROUND2(a, b, c, d, x[ 2],  3);
	MD4_ROUND2(d, a, b, c, x[ 6],  5);
	MD4_ROUND2(c, d, a, b, x[10],  9);
	MD4_ROUND2(b, c, d, a, x[14], 13);
	MD4_ROUND2(a, b, c, d, x[ 3],  3);
	MD4_ROUND2(d, a, b, c, x[ 7],  5);
	MD4_ROUND2(c, d, a, b, x[11],  9);
	MD4_ROUND2(b, c, d, a, x[15], 13);

	MD4_ROUND3(a, b, c, d, x[ 0],  3);
	MD4_ROUND3(d, a, b, c, x[ 8],  9);
	MD4_ROUND3(c, d, a, b, x[ 4], 11);
	MD4_ROUND3(b, c, d, a, x[12], 15);
	MD4_ROUND3(a, b, c, d, x[ 2],  3);
	MD4_ROUND3(d, a, b, c, x[10],  9);
	MD4_ROUND3(c, d, a, b, x[ 6], 11);
	MD4_ROUND3(b, c, d, a, x[14], 15);
	MD4_ROUND3(a, b, c, d, x[ 1],  3);
	MD4_ROUND3(d, a, b, c, x[ 9],  9);
	MD4_ROUND3(c, d, a, b, x[ 5], 11);
	MD4_ROUND3(b, c, d, a, x[13], 15);
	MD4_ROUND3(a, b, c, d, x[ 3],  3);
	MD4_ROUND3(d, a, b, c, x[11],  9);
	MD4_ROUND3(c, d, a, b, x[ 7], 11);
	MD4_ROUND3(b, c, d, a, x[15], 15);
  
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}
