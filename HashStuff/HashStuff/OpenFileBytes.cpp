
// OpenFileBytes.cpp : implementation file
//

#include "StdAfx.h"
#include "OpenFileBytes.h"

//#define MAKEQWORD(a, b)	((QWORD)( ((QWORD) ((DWORD) (a))) << 32 | ((DWORD) (b))))


/////////////////////////////////////////////////////////////////////
//
COpenFileBytes::COpenFileBytes(WCHAR* pzsFileName) : 
				m_hFile(NULL), m_hMapFile(NULL), m_pbFileBytes(NULL)
{
	m_pzsFileName = new WCHAR[wcslen(pzsFileName)+1];

	wcscpy(m_pzsFileName, pzsFileName);
}


/////////////////////////////////////////////////////////////////////
//
COpenFileBytes::~COpenFileBytes(void)
{
	this->Close();
	delete m_pzsFileName;
}

/////////////////////////////////////////////////////////////////////
//
bool COpenFileBytes::Open()
{
	// function call sequence error
	if(m_hFile || m_hMapFile || m_pbFileBytes)
		this->Close();		// error - close all and start as if nothing happend

	m_hFile = ::CreateFile(m_pzsFileName, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
							OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN/*FILE_ATTRIBUTE_NORMAL*/, NULL);

	if(m_hFile)
	{
		GetFileSizeEx(m_hFile, (PLARGE_INTEGER)(&m_ullFileSize));

		if( m_hMapFile = ::CreateFileMapping(m_hFile, NULL, PAGE_READONLY, 0, 0, NULL) )
		{
			if( m_pbFileBytes = (BYTE*)::MapViewOfFile(m_hMapFile, FILE_MAP_READ, 0, 0, 0) )
				return true;
		}
	}
	
	//DWORD		err = ::GetLastError();

	if(m_hMapFile)
	{
		::CloseHandle(m_hMapFile);
		m_hMapFile = NULL;
	}

	if(m_hFile)
	{
		::CloseHandle(m_hFile);
		m_hFile = NULL;
	}

	return false;
}

/////////////////////////////////////////////////////////////////////
//
void COpenFileBytes::Close()
{
	if(m_pbFileBytes)
	{
		::UnmapViewOfFile(m_pbFileBytes);
		m_pbFileBytes = NULL;
	}

	if(m_hMapFile)
	{
		::CloseHandle(m_hMapFile);
		m_hMapFile = NULL;
	}

	if(m_hFile)
	{
		::CloseHandle(m_hFile);
		m_hFile = NULL;
	}
}




/////////////////////////////////////////////////////////////////////
//
/*
void GetFileBytes(CString sFileName)
{
	// get file bytes
	CFile				file(sFileName, CFile::modeRead|CFile::shareDenyNone);

	m_ullFileSize = file.GetLength();
	m_pbFileBytes = new BYTE[m_ullFileSize];

	UINT				nBytesRead = file.Read(m_pbFileBytes, m_ullFileSize);

	if(nBytesRead != m_ullFileSize)
		throw "must be equal";

	file.Close();
}
*/