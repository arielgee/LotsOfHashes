
// Whirlpool.h : header file
//

#pragma once
#pragma warning(disable: 4390)

/*
 * The number of rounds of the internal dedicated block cipher.
 */
#define R 10

#define WHIRLPOOL_DIGEST_SIZE 64
#define WHIRLPOOL_DATA_SIZE 64


typedef struct _whirlpool_ctx
{
	UINT8	buffer[WHIRLPOOL_DATA_SIZE];			/* buffer of data to hash */
	UINT64	hashlen[4];								/* number of hashed bits (256-bit) */
	UINT32	index;									/* index to buffer */
	UINT64	hash[WHIRLPOOL_DIGEST_SIZE/8];	/* the hashing state */
} whirlpool_ctx;


class CWhirlpool
{
public:
	CWhirlpool(void);
	virtual ~CWhirlpool(void);

private:
	static void	processBuffer(whirlpool_ctx* const ctx);		/* The core Whirlpool transform. */
	void			final(whirlpool_ctx* ctx);

public:
	void Init(whirlpool_ctx* ctx);
	void Update(whirlpool_ctx* ctx, const UINT8* data, UINT32 length);	
	void Digest(const whirlpool_ctx* ctx, UINT8* digest);
};

