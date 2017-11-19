
// SelectAlgorithm.cpp : implementation file
//

#include "StdAfx.h"
#include "SelectAlgorithm.h"

WCHAR* CSelectAlgorithm::algorithm_names[algorithmcount] = 
{
	L"CRC32", L"CRC32b", L"eD2k/eMule", L"GOST", L"HAVAL 128,3",
	L"HAVAL 128,4", L"HAVAL 128,5", L"HAVAL 160,3", L"HAVAL 160,4", L"HAVAL 160,5",
	L"HAVAL 192,3", L"HAVAL 192,4", L"HAVAL 192,5", L"HAVAL 224,3", L"HAVAL 224,4",
	L"HAVAL 224,5", L"HAVAL 256,3", L"HAVAL 256,4", L"HAVAL 256,5", L"MD4",
	L"MD5", L"MD5(wc)", L"Murmur 32", L"Murmur 128", L"RIPEMD 128",
	L"RIPEMD 160", L"RIPEMD 256", L"RIPEMD 320", L"Salsa10", L"Salsa20",
	L"SHA1 160", L"SHA1 160(wc)", L"SHA2 224", L"SHA2 256", L"SHA2 256(wc)",
	L"SHA2 384", L"SHA2 384(wc)", L"SHA2 512", L"SHA2 512(wc)", L"SHA3 224",
	L"SHA3 256", L"SHA3 384", L"SHA3 512", L"Snefru 128", L"Snefru 256",
	L"Tiger 128,3", L"Tiger 128,4", L"Tiger 160,3", L"Tiger 160,4", L"Tiger 192,3",
	L"Tiger 192,4", L"Whirlpool"
};

bool CSelectAlgorithm::algorithm_selection[algorithmcount] = 
{
	true, true, true, true, true,
	true, true, true, true, true,
	true, true, true, true, true,
	true, true, true, true, true,
	true, true, true, true, true,
	true, true, true, true, true,
	true, true, true, true, true,
	true, true, true, true, true,
	true, true, true, true, true,
	true, true, true, true, true,
	true, true
};

/////////////////////////////////////////////////////////////////////
//
CSelectAlgorithm::CSelectAlgorithm(void)
{
}


/////////////////////////////////////////////////////////////////////
//
CSelectAlgorithm::~CSelectAlgorithm(void)
{
}
