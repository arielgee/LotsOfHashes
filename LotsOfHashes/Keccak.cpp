
// Keccak.cpp : implementation file
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

#include "StdAfx.h"
#include "Keccak.h"


/////////////////////////////////////////////////////////////////////
// Bit rotation left
// @param input the input word
// @param rot the number of bits to rotate
// @return input rotated left by rot bits
//
template<typename T> static __forceinline T rotate_left(T input, size_t rot)
{
	return static_cast<T>((input << rot) | (input >> (8*sizeof(T)-rot)));;
}

/////////////////////////////////////////////////////////////////////
// Bit rotation right
// @param input the input word
// @param rot the number of bits to rotate
// @return input rotated right by rot bits
//
template<typename T> static __forceinline T rotate_right(T input, size_t rot)
{
	return static_cast<T>((input >> rot) | (input << (8*sizeof(T)-rot)));
}

/////////////////////////////////////////////////////////////////////
// Load a little-endian word
// @param in a pointer to some bytes
// @param off an offset into the array
// @return off'th T of in, as a litte-endian value
//
template<typename T> static inline T load_little_endian(const UINT8 in[], size_t off)
{
	in += off * sizeof(T);
	T out = 0;
	for(size_t i = 0; i != sizeof(T); ++i)
		out = (out << 8) | in[sizeof(T)-1-i];
	return out;
}

/////////////////////////////////////////////////////////////////////
// Byte extraction
// @param byte_num which byte to extract, 0 == highest byte
// @param input the value to extract from
// @return byte byte_num of input
//
template<typename T> static inline UINT8 extract_byte(size_t byte_num, T input)
{
	return static_cast<UINT8>(input >> ((sizeof(T)-1-(byte_num&(sizeof(T)-1))) << 3));
}


/////////////////////////////////////////////////////////////////////
//
void keccak_f_1600(UINT64 A[25])
{
	static const UINT64 RC[24] = {
		0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
		0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
		0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
		0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
		0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
		0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
		0x8000000000008080, 0x0000000080000001, 0x8000000080008008
	};
 
	for(size_t i = 0; i != 24; ++i)
	{
		const UINT64 C0 = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
		const UINT64 C1 = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
		const UINT64 C2 = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
		const UINT64 C3 = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
		const UINT64 C4 = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];
 
		const UINT64 D0 = rotate_left(C0, 1) ^ C3;
		const UINT64 D1 = rotate_left(C1, 1) ^ C4;
		const UINT64 D2 = rotate_left(C2, 1) ^ C0;
		const UINT64 D3 = rotate_left(C3, 1) ^ C1;
		const UINT64 D4 = rotate_left(C4, 1) ^ C2;
 
		const UINT64 B00 = A[ 0] ^ D1;
		const UINT64 B01 = rotate_left(A[ 6] ^ D2, 44);
		const UINT64 B02 = rotate_left(A[12] ^ D3, 43);
		const UINT64 B03 = rotate_left(A[18] ^ D4, 21);
		const UINT64 B04 = rotate_left(A[24] ^ D0, 14);
		const UINT64 B05 = rotate_left(A[ 3] ^ D4, 28);
		const UINT64 B06 = rotate_left(A[ 9] ^ D0, 20);
		const UINT64 B07 = rotate_left(A[10] ^ D1, 3);
		const UINT64 B08 = rotate_left(A[16] ^ D2, 45);
		const UINT64 B09 = rotate_left(A[22] ^ D3, 61);
		const UINT64 B10 = rotate_left(A[ 1] ^ D2, 1);
		const UINT64 B11 = rotate_left(A[ 7] ^ D3, 6);
		const UINT64 B12 = rotate_left(A[13] ^ D4, 25);
		const UINT64 B13 = rotate_left(A[19] ^ D0, 8);
		const UINT64 B14 = rotate_left(A[20] ^ D1, 18);
		const UINT64 B15 = rotate_left(A[ 4] ^ D0, 27);
		const UINT64 B16 = rotate_left(A[ 5] ^ D1, 36);
		const UINT64 B17 = rotate_left(A[11] ^ D2, 10);
		const UINT64 B18 = rotate_left(A[17] ^ D3, 15);
		const UINT64 B19 = rotate_left(A[23] ^ D4, 56);
		const UINT64 B20 = rotate_left(A[ 2] ^ D3, 62);
		const UINT64 B21 = rotate_left(A[ 8] ^ D4, 55);
		const UINT64 B22 = rotate_left(A[14] ^ D0, 39);
		const UINT64 B23 = rotate_left(A[15] ^ D1, 41);
		const UINT64 B24 = rotate_left(A[21] ^ D2, 2);
 
		A[ 0] = B00 ^ (~B01 & B02);
		A[ 1] = B01 ^ (~B02 & B03);
		A[ 2] = B02 ^ (~B03 & B04);
		A[ 3] = B03 ^ (~B04 & B00);
		A[ 4] = B04 ^ (~B00 & B01);
		A[ 5] = B05 ^ (~B06 & B07);
		A[ 6] = B06 ^ (~B07 & B08);
		A[ 7] = B07 ^ (~B08 & B09);
		A[ 8] = B08 ^ (~B09 & B05);
		A[ 9] = B09 ^ (~B05 & B06);
		A[10] = B10 ^ (~B11 & B12);
		A[11] = B11 ^ (~B12 & B13);
		A[12] = B12 ^ (~B13 & B14);
		A[13] = B13 ^ (~B14 & B10);
		A[14] = B14 ^ (~B10 & B11);
		A[15] = B15 ^ (~B16 & B17);
		A[16] = B16 ^ (~B17 & B18);
		A[17] = B17 ^ (~B18 & B19);
		A[18] = B18 ^ (~B19 & B15);
		A[19] = B19 ^ (~B15 & B16);
		A[20] = B20 ^ (~B21 & B22);
		A[21] = B21 ^ (~B22 & B23);
		A[22] = B22 ^ (~B23 & B24);
		A[23] = B23 ^ (~B24 & B20);
		A[24] = B24 ^ (~B20 & B21);
 
		A[0] ^= RC[i];
	}
}

/////////////////////////////////////////////////////////////////////
//
CKeccak::CKeccak() : S(25)
{
}

/////////////////////////////////////////////////////////////////////
//
CKeccak::~CKeccak(void)
{
}

/////////////////////////////////////////////////////////////////////
//
void CKeccak::Init(size_t ot_bits)
{
	// support the parameters for the SHA-3 proposal 
	if(ot_bits != 224 && ot_bits != 256 && ot_bits != 384 && ot_bits != 512)
		throw "Keccak_1600: Invalid output length ";

	output_bits = ot_bits;
	bitrate = (1600 - 2*output_bits);
	std::fill(S.begin(), S.end(), 0);
	S_pos = 0;
}

/////////////////////////////////////////////////////////////////////
//
void CKeccak::Update(const UINT8* buf, UINT32 len)
{
	if(len == 0)
		return;
 
	while(len)
	{
		size_t to_take = min(len, bitrate / 8 - S_pos);
 
		len -= (UINT32)to_take;
 
		while(to_take && S_pos % 8)
		{
			S[S_pos / 8] ^= static_cast<UINT64>(buf[0]) << (8 * (S_pos % 8));
 
			++S_pos;
			++buf;
			--to_take;
		}
 
		while(to_take && to_take % 8 == 0)
		{
			S[S_pos / 8] ^= load_little_endian<UINT64>(buf, 0);
			S_pos += 8;
			buf += 8;
			to_take -= 8;
		}
 
		while(to_take)
		{
			S[S_pos / 8] ^= static_cast<UINT64>(buf[0]) << (8 * (S_pos % 8));
 
			++S_pos;
			++buf;
			--to_take;
		}
 
		if(S_pos == bitrate / 8)
		{
			keccak_f_1600(&S[0]);
			S_pos = 0;
		}
	}
}
 
/////////////////////////////////////////////////////////////////////
//
void CKeccak::Digest(UINT8* digest)
{
	std::vector<UINT8> padding(bitrate / 8 - S_pos);
 
	padding[0] = 0x01;
	padding[padding.size()-1] |= 0x80;
 
	Update(&padding[0], (UINT32)(padding.size()));
 
	// No need to run the permutation again because class only support limited output lengths

	for(size_t i = 0; i != output_bits/8; ++i)
		digest[i] = extract_byte(7 - (i % 8), S[i/8]); 
}
