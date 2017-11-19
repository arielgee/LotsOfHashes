
// Salsa.cpp : implementation file
//

/*
 * Salsa.cpp:  specifies the routines to the SALSA-10/20 hashing functions.
 * SALSA-10/20 hash function.
 *
 * SALSA-20 is a stream cipher submitted to eSTREAM by Daniel J. Bernstein.
 * It is built on a pseudorandom function based on 32-bit addition, bitwise addition
 * (XOR) and rotation operations, which maps a 256-bit key, a 64-bit nonce (number
 * used once), and a 64-bit stream position to a 512-bit output.
 *
 * It is not patented, and Bernstein's implementation is in the public domain.
 *
 */


#include "StdAfx.h"
#include "Salsa.h"

#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))

/* {{{ salsa10
 
 The 64-byte input x to Salsa10 is viewed in little-endian form as 16 integers 
 x0, x1, x2, ..., x15 in {0,1,...,2^32-1}. These 16 integers are fed through 
 320 invertible modifications, where each modification changes one integer. 
 The modifications involve, overall,

    * 10 additions of constants modulo 2^32;
    * 320 more additions modulo 2^32;
    * 80 ``or'' operations;
    * 240 ``xor'' operations; and
    * 320 constant-distance rotations. 

 The resulting 16 integers are added to the original x0, x1, x2, ..., x15 
 respectively modulo 2^32, producing, in little-endian form, the 64-byte output 
 Salsa10(x).
 
 D.J.Bernstein
*/
static void salsa10Transform(UINT32 x[16], UINT32 in[16])
{
	int i;
	
	for (i = 10; i > 0; --i) {
		x[ 4] ^= R(x[ 0]+x[12], 6);  x[ 8] ^= R(x[ 4]+x[ 0],17);
		x[12] += R(x[ 8]|x[ 4],16);  x[ 0] += R(x[12]^x[ 8], 5);
		x[ 9] += R(x[ 5]|x[ 1], 8);  x[13] += R(x[ 9]|x[ 5], 7);
		x[ 1] ^= R(x[13]+x[ 9],17);  x[ 5] += R(x[ 1]^x[13],12);
		x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] += R(x[14]^x[10],15);
		x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],15);
		x[ 3] += R(x[15]|x[11],20);  x[ 7] ^= R(x[ 3]+x[15],16);
		x[11] += R(x[ 7]^x[ 3], 7);  x[15] += R(x[11]^x[ 7], 8);
		x[ 1] += R(x[ 0]|x[ 3], 8)^i;x[ 2] ^= R(x[ 1]+x[ 0],14);
		x[ 3] ^= R(x[ 2]+x[ 1], 6);  x[ 0] += R(x[ 3]^x[ 2],18);
		x[ 6] += R(x[ 5]^x[ 4], 8);  x[ 7] += R(x[ 6]^x[ 5],12);
		x[ 4] += R(x[ 7]|x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],15);
		x[11] ^= R(x[10]+x[ 9],18);  x[ 8] += R(x[11]^x[10],11);
		x[ 9] ^= R(x[ 8]+x[11], 8);  x[10] += R(x[ 9]|x[ 8], 6);
		x[12] += R(x[15]^x[14],17);  x[13] ^= R(x[12]+x[15],15);
		x[14] += R(x[13]|x[12], 9);  x[15] += R(x[14]^x[13], 7);
	}
	for (i = 0; i < 16; ++i) {
		x[i] += in[i];
	}
}
/* }}} */

/* {{{ salsa20
 
 The 64-byte input x to Salsa20 is viewed in little-endian form as 16 words 
 x0, x1, x2, ..., x15 in {0,1,...,2^32-1}. These 16 words are fed through 320 
 invertible modifications, where each modification changes one word. The 
 resulting 16 words are added to the original x0, x1, x2, ..., x15 respectively 
 modulo 2^32, producing, in little-endian form, the 64-byte output Salsa20(x).

 Each modification involves xor'ing into one word a rotated version of the sum 
 of two other words modulo 2^32. Thus the 320 modifications involve, overall, 
 320 additions, 320 xor's, and 320 rotations. The rotations are all by constant 
 distances.

 The entire series of modifications is a series of 10 identical double-rounds. 
 Each double-round is a series of 2 rounds. Each round is a set of 4 parallel 
 quarter-rounds. Each quarter-round modifies 4 words.
 
 D.J.Bernstein
*/
static void salsa20Transform(UINT32 x[16], UINT32 in[16])
{
	int i;
	
	for (i = 20; i > 0; i -= 2) {
		x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
		x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
		x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
		x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
		x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
		x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
		x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
		x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
		x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
		x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
		x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
		x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
		x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
		x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
		x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
		x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
	}
	for (i = 0; i < 16; ++i) {
		x[i] += in[i];
	}
}
/* }}} */

/////////////////////////////////////////////////////////////////////
//
CSalsa::CSalsa()
{
}

/////////////////////////////////////////////////////////////////////
//
CSalsa::~CSalsa(void)
{
}

/////////////////////////////////////////////////////////////////////
// resets the parameter block so that it's ready for a new hash.
void CSalsa::Init(salsa_ctx* ctx, SalsaHashType sh)
{
	memset(ctx, 0, sizeof(*ctx));
	if(sh == Salsa10)
		ctx->Transform = salsa10Transform;
	else if(sh == Salsa20)
		ctx->Transform = salsa20Transform;	
	else
		ctx->Transform = NULL;
}

/////////////////////////////////////////////////////////////////////
// should be used to pass successive blocks of data to be hashed.
void CSalsa::Update(salsa_ctx* ctx, const UINT8* data, size_t size)
{
	if (ctx->length + size < 64) {
		memcpy(&ctx->buffer[ctx->length], data, size);
		ctx->length += (unsigned char)size;		// cast is cool, only happends when (ctx->length + size < 64)
	} else {
		size_t i = 0, r = (ctx->length + size) % 64;
		
		if (ctx->length) {
			i = 64 - ctx->length;
			memcpy(&ctx->buffer[ctx->length], data, i);
			SalsaTransform(ctx, ctx->buffer);
			memset(ctx->buffer, 0, 64);
		}
		
		for (; i + 64 <= size; i += 64) {
			SalsaTransform(ctx, data + i);
		}
		
		memcpy(ctx->buffer, data + i, r);
		ctx->length = r;
	}
}


/////////////////////////////////////////////////////////////////////
// finishes the current hash computation and copies the digest value into a digest.
void CSalsa::Digest(salsa_ctx* ctx, UINT8* digest)
{
	UINT32 i, j;
	
	if (ctx->length) {
		SalsaTransform(ctx, ctx->buffer);
	}
	
	for (i = 0, j = 0; j < 64; i++, j += 4) {
		digest[j] = (UINT8) ((ctx->state[i] >> 24) & 0xff);
		digest[j + 1] = (UINT8) ((ctx->state[i] >> 16) & 0xff);
		digest[j + 2] = (UINT8) ((ctx->state[i] >> 8) & 0xff);
		digest[j + 3] = (UINT8) (ctx->state[i] & 0xff);
	}
	
	memset(ctx, 0, sizeof(*ctx));
}

/////////////////////////////////////////////////////////////////////
// 
inline void CSalsa::SalsaTransform(salsa_ctx* ctx, const unsigned char input[64])
{
	UINT32 i, j, a[16];

	for (i = 0, j = 0; j < 64; i++, j += 4) {
		a[i] = ((UINT32) input[j + 3]) | (((UINT32) input[j + 2]) << 8) |
			(((UINT32) input[j + 1]) << 16) | (((UINT32) input[j]) << 24);
	}
	
	if (!ctx->init) {
		memcpy(ctx->state, a, sizeof(a));
		ctx->init = 1;
	}
	
	ctx->Transform(ctx->state, a);
	memset(a, 0, sizeof(a));
}
