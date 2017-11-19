
// Tiger.h : header file
//

#pragma once

#define TIGER_DATASIZE 64
#define TIGER128_DIGESTSIZE 16
#define TIGER160_DIGESTSIZE 20
#define TIGER192_DIGESTSIZE 24

#define TIGER_DATALEN 8
#define TIGER128_DIGESTLEN 2
#define TIGER160_DIGESTLEN 2 /* 2.5 actually. */
#define TIGER192_DIGESTLEN 3

#define h0init 0x0123456789ABCDEFLL
#define h1init 0xFEDCBA9876543210LL
#define h2init 0xF096A5B4C3B2E187LL

typedef struct _tiger_ctx
{
	UINT64	digest[TIGER192_DIGESTLEN];	/* Message digest */ 
	UINT64	count;								/* 64-bit block count */
	UCHAR		block[TIGER_DATASIZE];			/* RIPEMD data buffer */  
	ULONG		index;								/* index into buffer */
} tiger_ctx;


class CTiger
{
public:
	CTiger(void);
	virtual ~CTiger(void);

private:
	static UCHAR		m_nPasses;

	static void block(tiger_ctx* ctx, UCHAR* str);

public:
	void Init(tiger_ctx* ctx, UCHAR nPasses);
	void Update(tiger_ctx* ctx, UCHAR* buffer, ULONG len);
	void Final(tiger_ctx *ctx);
		
	void Digest128(tiger_ctx* ctx, UCHAR* s);
	void Digest160(tiger_ctx* ctx, UCHAR* s);
	void Digest192(tiger_ctx* ctx, UCHAR* s);	
};

