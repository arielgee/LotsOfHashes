
// Salsa.h : header file
//

/*
 * Salsa.h:  specifies the interface to the SALSA-10/20 hashing functions.
 * SALSA-10/20 hash function.
 *
 * SALSA-20 is a stream cipher submitted to eSTREAM by Daniel J. Bernstein.
 * It is built on a pseudorandom function based on 32-bit addition, bitwise addition
 * (XOR) and rotation operations, which maps a 256-bit key, a 64-bit nonce (number
 * used once), and a 64-bit stream position to a 512-bit output.
 *
 * It is not patented, and Bernstein's implementation is in the public domain.
 *
 */

#pragma once

typedef struct _salsa_ctx
{
	UINT32			state[16];
	unsigned char	init:1;
	unsigned char	length:7;
	unsigned char	buffer[64];

	void (*Transform)(UINT32 state[16], UINT32 data[16]);
} salsa_ctx;

class CSalsa
{
public:
	CSalsa();
	virtual ~CSalsa(void);

	enum SalsaHashType
	{
		Salsa10,
		Salsa20,
	};

private:
	static inline void SalsaTransform(salsa_ctx *ctx, const unsigned char input[64]);

public:
	void Init(salsa_ctx* ctx, SalsaHashType sh);
	void Update(salsa_ctx* ctx, const UINT8* data, size_t size);
	void Digest(salsa_ctx* ctx, UINT8* digest);
};
