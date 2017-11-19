
// Ripemd.h : header file
//

#pragma once

/* The RIPEMD block sizes and message digest sizes, in bytes */

#define RIPEMD_DATASIZE    64
#define RIPEMD_DATALEN     16

#define RIPEMD128_DIGESTSIZE  16
#define RIPEMD160_DIGESTSIZE  20
#define RIPEMD256_DIGESTSIZE  32
#define RIPEMD320_DIGESTSIZE  40

#define RIPEMD_STATESIZE      10 /* state size in 32 bit words */


/* The structure for storing RIPEMD info */

typedef struct _ripemd_ctx {
	UINT32	digest[RIPEMD_STATESIZE];     /* chaining varialbles */
	UINT64	bitcount;                     /* 64-bit bit counter */
	UINT8		block[RIPEMD_DATASIZE];        /* RIPEMD data buffer */
	UINT32	index;                        /* index into buffer */
	UINT32	digest_len;                   /* determines the algorithm to use */
} ripemd_ctx;

class CRipemd
{
public:
	CRipemd(void);
	virtual ~CRipemd(void);

private:
	void				init(ripemd_ctx* ctx);
	static void		transform(ripemd_ctx* ctx, UINT32* data);
	static void		transform128(ripemd_ctx* ctx, UINT32* data);
	static void		transform160(ripemd_ctx* ctx, UINT32* data);
	static void		transform256(ripemd_ctx* ctx, UINT32* data);
	static void		transform320(ripemd_ctx* ctx, UINT32* data);
	static void		block(ripemd_ctx* ctx, UINT8* block);
	void				final(ripemd_ctx* ctx);

public:
	void Init128(ripemd_ctx* ctx);
	void Init160(ripemd_ctx* ctx);
	void Init256(ripemd_ctx* ctx);
	void Init320(ripemd_ctx* ctx);
	void Update(ripemd_ctx* ctx, UINT8* buffer, UINT32 len);	
	void Digest(ripemd_ctx* ctx, UINT8* s);
};

