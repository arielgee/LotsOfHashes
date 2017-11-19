
// Murmur.h : header file
//

/*
 *  Murmur.h:  specifies the interface to the MurmurHash3 hashing library.
 *
 *  MurmurHash3 is a non-cryptographic hash written by Austin Appleby.
 *  The code is based on code available at http://code.google.com/p/smhasher.
 *
 *  From that site: "All MurmurHash versions are public domain software,
 *  and the author disclaims all copyright to their code."
 *
 *  Note - The x86 and x64 versions do _not_ produce the same results, as the
 *  algorithms are optimized for their respective platforms. You can still
 *  compile and run any of them on any platform, but your performance with the
 *  non-native version will be less than optimal.
 *
 */

#pragma once

#define MURMUR32_BLOCK_SIZE 4
#define MURMUR128_BLOCK_SIZE 16

typedef struct _murmur32_ctx
{
	UINT32	h;

	size_t	len;
	UINT8		unparsed_bytes[MURMUR32_BLOCK_SIZE];
	size_t	unparsed_len;
} murmur32_ctx;

typedef struct _murmur128_ctx
{
	UINT64	h1;
	UINT64	h2;

	size_t	len;
	UINT8		unparsed_bytes[MURMUR128_BLOCK_SIZE];
	size_t	unparsed_len;
} murmur128_ctx;

class CMurmur
{
public:
	CMurmur(void);
	virtual ~CMurmur(void);

private:
	static void updateBlock32(murmur32_ctx* ctx, UINT32 k1);
	static void updateBlock128(murmur128_ctx* ctx, UINT64 k1, UINT64 k2);

public:
	void Init32(murmur32_ctx* ctx, const UINT32 seed = 0x0);
	void Init128(murmur128_ctx* ctx, const UINT32 seed = 0x0);
	void Update32(murmur32_ctx* ctx, const UINT8* data, size_t len);
	void Update128(murmur128_ctx* ctx, const UINT8* data, size_t len);
	UINT32 Digest32(murmur32_ctx* ctx);
	void Digest128(murmur128_ctx* ctx, UINT8* digest);
};

