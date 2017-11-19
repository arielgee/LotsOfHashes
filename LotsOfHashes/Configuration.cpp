
// Configuration.cpp : implementation file
//

#include "StdAfx.h"
#include "Configuration.h"

#define SECTION_CACHE L"cache"
#define KEY_FILE_SIZE_THRESHOLD L"FileSizeThreshold"
#define KEY_MAX_CACHE_ELEMENTS L"MaxCacheElements"


extern HMODULE		g_hModule;

CConfiguration* CConfiguration::m_pSingleton = NULL;

/////////////////////////////////////////////////////////////////////
//
CConfiguration::CConfiguration(void) :
		m_qwFileSizeThreshold(0), m_nMaxCacheElements(0)
{
	this->readPrivateProfile();
}


/////////////////////////////////////////////////////////////////////
//
CConfiguration::~CConfiguration(void)
{
}

/////////////////////////////////////////////////////////////////////
//
CConfiguration* CConfiguration::i()
{
	if(m_pSingleton == NULL)
		m_pSingleton = new CConfiguration();

	return m_pSingleton;
}

/////////////////////////////////////////////////////////////////////
//
void CConfiguration::Release()
{
	delete m_pSingleton;
	m_pSingleton = NULL;
}

/////////////////////////////////////////////////////////////////////
//
QWORD CConfiguration::FileSizeThreshold(QWORD defVal)
{
	// key not found; use default value and try to write it to ini file
	if(m_qwFileSizeThreshold == 0)
	{
		m_qwFileSizeThreshold = defVal;

		WCHAR		szFileName[MAX_FILE_PATH_NAME];

		// if got file name try to write it to ini file
		if( getFileName(szFileName, _countof(szFileName)) )
		{
			WCHAR		szBuff[64];

			swprintf_s(szBuff, L"%lu", m_qwFileSizeThreshold);
			::WritePrivateProfileStringW(SECTION_CACHE, KEY_FILE_SIZE_THRESHOLD, szBuff, szFileName);
		}
	}

	return m_qwFileSizeThreshold;
}

/////////////////////////////////////////////////////////////////////
//
UINT CConfiguration::MaxCacheElements(UINT defVal)
{
	// key not found; use default value and try to write it to ini file
	if(m_nMaxCacheElements == 0)
	{
		m_nMaxCacheElements = defVal;

		WCHAR		szFileName[MAX_FILE_PATH_NAME];

		// if got file name try to write it to ini file
		if( getFileName(szFileName, _countof(szFileName)) )
		{
			WCHAR		szBuff[64];

			swprintf_s(szBuff, L"%lu", m_nMaxCacheElements);
			::WritePrivateProfileStringW(SECTION_CACHE, KEY_MAX_CACHE_ELEMENTS, szBuff, szFileName);
		}
	}

	return m_nMaxCacheElements;
}

/////////////////////////////////////////////////////////////////////
//
void CConfiguration::readPrivateProfile()
{
	WCHAR		szFileName[MAX_FILE_PATH_NAME];

	// if can't get init file name; default values
	if( !getFileName(szFileName, _countof(szFileName)) )
		return;	

	// if key not found set to zero to indicate to use default values
	m_qwFileSizeThreshold = ::GetPrivateProfileIntW(SECTION_CACHE, KEY_FILE_SIZE_THRESHOLD, 0, szFileName);
	m_nMaxCacheElements = ::GetPrivateProfileIntW(SECTION_CACHE, KEY_MAX_CACHE_ELEMENTS, 0, szFileName);
}

/////////////////////////////////////////////////////////////////////
//
bool CConfiguration::getFileName(WCHAR* pszName, size_t size)
{
	// if global handle to dll module is not set; default values
	if( !g_hModule )
		return false;

	DWORD		dwLen = ::GetModuleFileNameW(g_hModule, pszName, (DWORD)size);

	// look for the extension's dot from the end; there must be one.
	WCHAR*		pszPos = wcsrchr(pszName, L'.');

	// The dot was not found; means default values
	if(pszPos == NULL)
		return false;

	// I entend to replace the existing extension with the "ini" extension.
	// This will check if adding 4 wchars after the dot ("ini" + 0_terminating) will not 
	// result in a buffer overflow
	// if it dose; means default values
	if( (pszPos == NULL) || ( ((pszPos - pszName) + 4) > (int)size ) )
		return false;

	// replace the extention with ".ini" extention including the 0_terminating
	// calculate the remaining buffer space for a safe copy
	wcsncpy_s(pszPos+1, (size-((pszPos+1) - pszName)), L"ini\0", _TRUNCATE);

	return true;
}

