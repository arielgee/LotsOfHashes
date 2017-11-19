
// Md5.h : header file
//

#pragma once

typedef struct _md5_ctx
{
	UINT32		buf[4];
	UINT32		bits[2];
	UINT8			in[64];
} md5_ctx;


class CMd5
{
public:
	CMd5(void);
	virtual ~CMd5(void);

private:
	void transform(UINT32 buf[4], UINT32 const in[16]);

public:
	void Init(md5_ctx* ctx);
	void Update(md5_ctx* ctx, UINT8 const *buf, UINT32 len);
	void Digest(md5_ctx* ctx, UINT8 *digest);
};

