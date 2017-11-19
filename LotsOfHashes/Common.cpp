
// Common.cpp : implementation file
//

#include "StdAfx.h"

//////////////////////////////////////////////////////////////////////////////////////////
//
char* strlcpy(char* dst, const char* src, size_t dstsize)
{
	size_t	i;
	size_t	dataSize = dstsize - 1;

	for(i = 0; i < dataSize && src[i] != '\0'; i++)
   	dst[i] = src[i];

	dst[i] = '\0';
	return dst;
}

//////////////////////////////////////////////////////////////////////////////////////////
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

//////////////////////////////////////////////////////////////////////////////////////////
//
char* walcpy(char* dst, WCHAR* src, int dstsize)
{
	if(src)
	{
		WideCharToMultiByte(CP_ACP, 0, src, -1, dst, dstsize, NULL, NULL);
		dst[dstsize-1]=0;
		return dst;
	}
	else
		return NULL;
}

//////////////////////////////////////////////////////////////////////////////////////////
//
WCHAR* awlcpy(WCHAR* dst, char* src, int dstsize)
{
	if(src)
	{
		MultiByteToWideChar(CP_ACP, 0, src, -1, dst, dstsize);
		dst[dstsize-1]=0;
		return dst;
	}
	else
		return NULL;
}

/////////////////////////////////////////////////////////////////////
// create a HEX string from a byte array.
WCHAR* ConvertToHex(WCHAR* szHexRes, DWORD dwResLen, BYTE* pBytes, DWORD dwBytesLen, int nFlags/*=CONV_FLAG_UCASE*/)
{	
	WCHAR		szFmt[7];
	bool		bWithDelimiter = ((nFlags & MASK_FLAG_DELIMITER) == MASK_FLAG_DELIMITER);

	// handle case and handle delimiter 
	wsprintf(szFmt, L"%%02%c%c", ((nFlags & MASK_FLAG_LCASE) ? L'x' : L'X'), (bWithDelimiter ? L':' : L''));
	
	DWORD		i, dwOffset;	
	DWORD		dwBuffSize = dwResLen-1;
	DWORD		nFmtCharLen = (bWithDelimiter ? 3 : 2);  // number of characters in hex without delimiter is 2

	// scan the pBytes array using the i index. format & print each byte to m_szHexResult
	// the dwOffset jumps to the next nFmtCharLen chars (2 or 3 if delimiter requested) that will be written
	// dwBuffSize sets the maximum number of chars to be written
	// check dwOffset size so that it will not go outside the m_szHexResult buffer
	// wsprintf appends a terminating null character 

	for(i = 0; i < dwBytesLen && (dwOffset=i*nFmtCharLen) < dwBuffSize; i++)
		wsprintf(szHexRes + dwOffset, szFmt, pBytes[i]);
	
	if(bWithDelimiter)
		szHexRes[dwOffset+2] = 0;	// remove the trailing delimiter

	return szHexRes;
}


#ifdef WRITE_DEBUG_LOG_FILE
/////////////////////////////////////////////////////////////////////
//
void Print(TCHAR* szMsgFormat, va_list ap)
{
	if((szMsgFormat == NULL) || (wcslen(szMsgFormat) == 0))
		return;

	// create the log line
	int			nLenTimeStamp;
	TCHAR			szTimeStamp[40];
	
	_wstrtime_s(szTimeStamp, 30);	
	wcscat_s(szTimeStamp, _countof(szTimeStamp), L"> ");
	nLenTimeStamp = (int)wcslen(szTimeStamp);	

	int		nLen = nLenTimeStamp + _vsctprintf(szMsgFormat, ap) + 2;		// add space for '\n\0';		

	TCHAR*		pszMsg = new TCHAR[nLen];

	wcscpy_s(pszMsg, nLen, szTimeStamp);

	// start after the position of the time stamp
	_vstprintf_s(pszMsg+nLenTimeStamp, nLen-nLenTimeStamp, szMsgFormat, ap);
	wcscat_s(pszMsg, nLen, L"\n\0");

	FILE*		pFile;

	//open the file
	errno_t		err = _wfopen_s(&pFile, DEBUG_LOG_FILE_NAME, L"a");

	// if file was created/opend
	if(err == 0)
	{
		fwprintf_s(pFile, pszMsg);

		fflush(pFile);
		fclose(pFile);
	}

	delete pszMsg;
}

/////////////////////////////////////////////////////////////////////
//
void _Write2Log(TCHAR *szMsgFormat, ...)
{
	va_list      vl;

	va_start(vl, szMsgFormat);
	Print(szMsgFormat, vl);
	va_end(vl);
}

#endif
