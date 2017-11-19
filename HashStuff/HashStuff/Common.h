
// Common.h : header file
//

#include "StdAfx.h"

#if !defined(__COMMON_H_B1476B99_A83D_40D5_B348_2AFAB2B7B904__)
#define __COMMON_H_B1476B99_A83D_40D5_B348_2AFAB2B7B904__

HMODULE			g_hModule = NULL;

/////////////////////////////////////////////////////////////////////
//
WCHAR* strlcpyW(WCHAR* dst, const WCHAR* src, size_t dstsize)
{
	size_t	i;
	size_t	dataSize = dstsize - 1;

	for(i = 0; i < dataSize && src[i] != '\0'; i++)
   	dst[i] = src[i];

	dst[i] = '\0';
	return dst;
}

bool CopyToClipboard(const TCHAR* pszData)
{
	BOOL				bOK;
	HGLOBAL			hGlobalMemory;
	TCHAR*			pszGlobalMemory;


	hGlobalMemory = ::GlobalAlloc(GMEM_MOVEABLE, (_tcslen(pszData)+1)*sizeof(TCHAR));

	// if fail to allocate memory
	if(!hGlobalMemory)
		return false;

	pszGlobalMemory = (TCHAR*)::GlobalLock(hGlobalMemory);

	// if fail to lock memory
	if(!pszGlobalMemory)
		return false;

	_tcscpy(pszGlobalMemory, pszData);

	::GlobalUnlock(hGlobalMemory);

	::OpenClipboard(NULL);
	::EmptyClipboard();

#ifdef UNICODE
	bOK = (::SetClipboardData(CF_UNICODETEXT, hGlobalMemory) == hGlobalMemory);
#else
	bOK = (::SetClipboardData(CF_TEXT, hGlobalMemory) == hGlobalMemory);
#endif

	::CloseClipboard();

	return (bOK == TRUE);
}

#endif