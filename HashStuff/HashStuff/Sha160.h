
// Sha160.h : header file
//

#pragma once

/* The SHA block size and message digest sizes, in bytes */
#define SHA_DATASIZE    64
#define SHA_DATALEN     16
#define SHA_DIGESTSIZE  20
#define SHA_DIGESTLEN    5


/* The structure for storing SHA info */
typedef struct _sha160_ctx
{
  UINT32		digest[SHA_DIGESTLEN];	/* Message digest */
  UINT32		count_l, count_h;			/* 64-bit block count */
  UINT8		block[SHA_DATASIZE];		/* SHA data buffer */
  UINT32		index;						/* index into buffer */
} sha160_ctx;


class CSha160
{
public:
	CSha160(void);
	virtual ~CSha160(void);

private:
	static void transform(sha160_ctx* ctx, UINT32* data);
	static void block(sha160_ctx* ctx, UINT8* block);

public:
	void Init(sha160_ctx* ctx);
	void Update(sha160_ctx* ctx, UINT8* buffer, UINT32 len);
	void Final(sha160_ctx* ctx);
	void Digest(sha160_ctx* ctx, UINT8* s);
};

