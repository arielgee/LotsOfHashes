
// Snefru.h : header file
//

#pragma once

#define SNEFRU128_DATA_SIZE 48
#define SNEFRU128_DIGEST_SIZE 16
#define SNEFRU128_DIGEST_LEN (SNEFRU128_DIGEST_SIZE / 4)

#define SNEFRU256_DATA_SIZE 32
#define SNEFRU256_DIGEST_SIZE 32
#define SNEFRU256_DIGEST_LEN (SNEFRU256_DIGEST_SIZE / 4)

#define SNEFRU_BLOCK_SIZE  64
#define SNEFRU_BLOCK_LEN (SNEFRU_BLOCK_SIZE / 4)

typedef struct _snefru_ctx
{
	UINT8		buffer[SNEFRU128_DATA_SIZE];	 /* buffer of data to hash */
	UINT64	hashlen;                       /* number of hashed bits */
	UINT32	index;		                   /* index to buffer */
	UINT32	hash[SNEFRU_BLOCK_LEN];        /* the hashing state */
} snefru_ctx;


class CSnefru
{
public:
	CSnefru(void);
	virtual ~CSnefru(void);

private:
	static void update(snefru_ctx* ctx, const UINT8* data, UINT32 length, UINT32 data_size, UINT32 digest_len);
	static void digest(const snefru_ctx* ctx, UINT8* digest, UINT32 len);
	static void transform(UINT32* block, UINT32 len);
	static void processBuffer(snefru_ctx* ctx, int len);

public:
	void	Init(snefru_ctx* ctx);
	void	Update128(snefru_ctx* ctx, const UINT8* data, UINT32 length);
	void	Update256(snefru_ctx* ctx, const UINT8* data, UINT32 length);
	void	Final128(snefru_ctx* ctx);
	void	Final256(snefru_ctx* ctx);
	void	Digest128(const snefru_ctx* ctx, UINT8* digest);
	void	Digest256(const snefru_ctx* ctx, UINT8* digest);
};

