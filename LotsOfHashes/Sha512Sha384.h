
// CSha512Sha384.h : header file
//

#pragma once

/* SHA512 and SHA384 */
#define SHA512_DIGEST_SIZE 64
#define SHA384_DIGEST_SIZE 48
#define SHA512_SHA384_DATA_SIZE 128

/* State is kept internally as 8 64-bit words. */
#define _SHA512_SHA384_STATE_LENGTH 8

typedef struct _sha512_sha384_ctx
{
  UINT64		state[_SHA512_SHA384_STATE_LENGTH];		/* State variables */
  UINT64		bitcount_low, bitcount_high;				/* Bit counter */
  UINT8		block[SHA512_SHA384_DATA_SIZE];			/* SHA512/384 data buffer */
  UINT32		index;											/* index into buffer */
} sha512_sha384_ctx;

class CSha512Sha384
{
public:
	CSha512Sha384(void);
	virtual ~CSha512Sha384(void);

private:
	static void transform(UINT64* state, UINT64* data);
	static void block(sha512_sha384_ctx* ctx, const UINT8* block);
	static void digest(const sha512_sha384_ctx* ctx, UINT8* s, UINT32 len);

public:
	void Init512(sha512_sha384_ctx* ctx);
	void Init384(sha512_sha384_ctx* ctx);
	void Update(sha512_sha384_ctx* ctx, const UINT8* data, UINT32 length);
	void Final(sha512_sha384_ctx* ctx);
	void Digest512(const sha512_sha384_ctx* ctx, UINT8 *digest);
	void Digest384(const sha512_sha384_ctx* ctx, UINT8 *digest);
};

