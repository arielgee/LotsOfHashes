
// SelectAlgorithm.h : header file
//

#pragma once

typedef enum _algorithm_code
{
	ALC_CRC32 = 0,
	ALC_CRC32b,
	ALC_eD2k_eMule,
	ALC_GOST,
	ALC_HAVAL_128_3,
	ALC_HAVAL_128_4,
	ALC_HAVAL_128_5,
	ALC_HAVAL_160_3,
	ALC_HAVAL_160_4,
	ALC_HAVAL_160_5,
	ALC_HAVAL_192_3,
	ALC_HAVAL_192_4,
	ALC_HAVAL_192_5,
	ALC_HAVAL_224_3,
	ALC_HAVAL_224_4,
	ALC_HAVAL_224_5,
	ALC_HAVAL_256_3,
	ALC_HAVAL_256_4,
	ALC_HAVAL_256_5,
	ALC_MD4,
	ALC_MD5,
	ALC_MD5_WC,
	ALC_MURMUR_32,
	ALC_MURMUR_128,
	ALC_RIPEMD_128,
	ALC_RIPEMD_160,
	ALC_RIPEMD_256,
	ALC_RIPEMD_320,
	ALC_SALSA10,
	ALC_SALSA20,
	ALC_SHA1_160,
	ALC_SHA1_160_WC,
	ALC_SHA2_224,
	ALC_SHA2_256,
	ALC_SHA2_256_WC,
	ALC_SHA2_384,
	ALC_SHA2_384_WC,
	ALC_SHA2_512,
	ALC_SHA2_512_WC,
	ALC_SHA3_224,
	ALC_SHA3_256,
	ALC_SHA3_384,
	ALC_SHA3_512,
	ALC_Snefru_128,
	ALC_Snefru_256,
	ALC_Tiger_128_3,
	ALC_Tiger_128_4,
	ALC_Tiger_160_3,
	ALC_Tiger_160_4,
	ALC_Tiger_192_3,
	ALC_Tiger_192_4,
	ALC_Whirlpool,
	// ALC_Count - MUST BE LAST
	ALC_Count
} algorithm_code;

#define algorithmcount ALC_Count

class CSelectAlgorithm
{
public:
	CSelectAlgorithm(void);
	virtual ~CSelectAlgorithm(void);

	UINT		AlgorithmCount() { return algorithmcount; }

	WCHAR**	AlgorithmNames() { return algorithm_names; }
	bool*		AlgorithmSelections() { return algorithm_selection; }

	CString	NameOf(algorithm_code h) { return algorithm_names[h]; }
	bool		IsSelected(algorithm_code h) { return algorithm_selection[h]; }

	void		SetSelect(algorithm_code h, bool b) { algorithm_selection[h] = b; }

private:
	static WCHAR* algorithm_names[algorithmcount];
	static bool algorithm_selection[algorithmcount];
};

