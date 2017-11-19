
// Keccak.h : header file
//

/*
 *  Keccak.h:  specifies the interface to the Keccak-f[1600] cryptographic hash function.
 *
 *  Designed by Guido Bertoni, Joan Daemen, Michael Peeters, and Gilles Van Assche.
 *
 *  On October 2, 2012, Keccak was selected as the winner of the NIST hash function
 *  competition for the SHA-3. SHA-3 is not meant to replace SHA-2, as no significant
 *  attack on SHA-2 has been demonstrated. Because of the successful attacks on MD5,
 *  SHA-0 and theoretical attacks on SHA-1, NIST perceived a need for an alternative,
 *  dissimilar cryptographic hash, which became SHA-3.
 *
 *  Keccak-f[1600] uses the sponge construction in which message blocks are XORed into
 *  the initial bits of the state, which is then invertibly permuted. In the version
 *  used in SHA-3, the state consists of a 5ª5 array of 64-bit words, 1600 bits total.
 *  The authors claim 12.5 cycles per byte[6] on an Intel Core 2 CPU. However, in
 *  hardware implementations it is notably faster than all other finalists.
 *
 */

#pragma once

#include <vector>

class CKeccak
{
public:
	CKeccak();
	virtual ~CKeccak(void);

private:
	size_t	output_bits;
	size_t	bitrate;

	std::vector<UINT64>		S;
	size_t						S_pos;

public:
	void Init(size_t ot_bits);
	void Update(const UINT8* buf, UINT32 len);
	void Digest(UINT8* digest); 

	size_t	hash_block_size() const { return bitrate / 8; }
	size_t	output_length() const { return output_bits / 8; }
};

