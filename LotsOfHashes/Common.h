
// Common.h : header file
//
#include <time.h>

typedef unsigned __int64 QWORD, *LPQWORD;

#define MAKEQWORD(high, low) ((QWORD)((((QWORD)high)<<32) | ((QWORD)low)))
#define LODWORD(l) ((DWORD)(l))
#define HIDWORD(l) ((DWORD)(((QWORD)(l) >> 32) & 0xFFFFFFFF))


#define CONV_FLAG_UCASE					0
#define CONV_FLAG_LCASE					1
#define CONV_FLAG_UCASE_DELIMITER	2
#define CONV_FLAG_LCASE_DELIMITER	3

#define MASK_FLAG_LCASE			0x01
#define MASK_FLAG_DELIMITER	0x02

#define MAX_FILE_PATH_NAME 2048

#define USE_CACHE

//#define WRITE_DEBUG_LOG_FILE

#ifdef WRITE_DEBUG_LOG_FILE
	#define DEBUG_LOG_FILE_NAME L"C:\\LotsOfHashes.log"

	#define Write2Log _Write2Log

	void		_Write2Log(TCHAR *szMsgFormat, ...);
	void		Print(TCHAR* szMsgFormat, va_list ap);
#else
	// This will render the call to the _Write2Log subroutine inert; the call will be skiped and
	// not be performed. This include any calls to subroutines in the parameter list.
	#define Write2Log(...)	
#endif

WCHAR* strlcpyW(WCHAR* dst, const WCHAR* src, size_t dstsize);
char* strlcpy(char* dst, const char* src, size_t dstsize);

char* walcpy(char* dst, WCHAR* src, int dstsize);
WCHAR* awlcpy(WCHAR* dst, char* src, int dstsize);

WCHAR* ConvertToHex(WCHAR* szHexRes, DWORD dwResLen, BYTE* pBytes, DWORD dwBytesLen, int nFlags = CONV_FLAG_UCASE);
