
// CSha256Sha224.h : header file
//

#pragma once

/* SHA256 and SHA224 */
#define SHA256_DIGEST_SIZE 32
#define SHA224_DIGEST_SIZE 28
#define SHA256_SHA224_DATA_SIZE 64

/* State is kept internally as 8 32-bit words. */
#define _SHA256_SHA224_DIGEST_LENGTH 8

typedef struct _sha256_sha224_ctx
{
  UINT32	state[_SHA256_SHA224_DIGEST_LENGTH];	/* State variables */
  UINT64	bitcount;										/* Bit counter */
  UINT8	block[SHA256_SHA224_DATA_SIZE];			/* SHA256/224 data buffer */
  UINT32	index;											/* index into buffer */
} sha256_sha224_ctx;


class CSha256Sha224
{
public:
	CSha256Sha224(void);
	virtual ~CSha256Sha224(void);

private:
	static void transform(UINT32* state, UINT32* data);
	static void block(sha256_sha224_ctx* ctx, const UINT8* block);
	static void digest(const sha256_sha224_ctx* ctx, UINT8* s, UINT32 len);

public:
	void Init224(sha256_sha224_ctx* ctx);
	void Init256(sha256_sha224_ctx* ctx);
	void Update(sha256_sha224_ctx* ctx, const UINT8* data, UINT32 length);
	void Final(sha256_sha224_ctx* ctx);
	void Digest224(const sha256_sha224_ctx* ctx, UINT8* digest);
	void Digest256(const sha256_sha224_ctx* ctx, UINT8* digest);
};

