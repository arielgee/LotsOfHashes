
// Gost.h : header file
//

/*
 *  gosthash.h 
 *  21 Apr 1998  Markku-Juhani Saarinen <mjos@ssh.fi>
 * 
 *  GOST R 34.11-94, Russian Standard Hash Function 
 *  header with function prototypes.
 *
 */

#pragma once

typedef struct _gost_ctx
{
	UINT32	sum[8];
	UINT32	hash[8];
	UINT32	len[8];
	UINT8		partial[32];
	UINT32	partial_bytes;
} gost_ctx;


class CGost
{
public:
	CGost(void);
	virtual ~CGost(void);

private:
	static void		compress(UINT32* h, UINT32* m);
	static void		bytes(gost_ctx* ctx, const UINT8* buf, UINT32 bits);

public:
	void Init(gost_ctx* ctx);
	void Update(gost_ctx* ctx, const UINT8* buf, UINT32 len);
	void Digest(gost_ctx* ctx, UINT8* digest);

};

