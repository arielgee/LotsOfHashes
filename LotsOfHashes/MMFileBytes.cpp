
// MMFileBytes.cpp : implementation file
//

#include "StdAfx.h"
#include "MMFileBytes.h"

/////////////////////////////////////////////////////////////////////
//
CMMFileBytes::CMMFileBytes(WCHAR* pzsFileName) :
				m_hMapFile(NULL), m_pbFileBytes(NULL), m_qwFileBytesLeft2Read(0), m_bFileStart(false)
{
	size_t		nLen = wcslen(pzsFileName)+1;

	m_pzsFileName = new WCHAR[nLen];
	wcscpy_s(m_pzsFileName, nLen, pzsFileName);

	SYSTEM_INFO		si;

	::GetSystemInfo(&si);
	m_dwAllocationGranularity = si.dwAllocationGranularity;
}


/////////////////////////////////////////////////////////////////////
//
CMMFileBytes::~CMMFileBytes(void)
{
	this->Close();
	delete m_pzsFileName;
}

/////////////////////////////////////////////////////////////////////
//
bool CMMFileBytes::Open()
{
	// function call sequence error
	if(m_hMapFile || m_pbFileBytes)
		this->Close();		// error - close all and start as if nothing happend

	HANDLE	hFile = ::CreateFile(m_pzsFileName, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
											NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	// continue only if file handle was created
	if(hFile != INVALID_HANDLE_VALUE)
	{
		::GetFileSizeEx(hFile, (PLARGE_INTEGER)(&m_qwFileSize));

		m_hMapFile = ::CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

		//DWORD		err = ::GetLastError();

		// close file handle; it isn't needed
		::CloseHandle(hFile);

		if(m_hMapFile)
		{
			m_qwFileOffset = 0;
			m_qwFileBytesLeft2Read = m_qwFileSize;
			return _ReadBytes();
		}	
	}

	m_bFileStart = false;
	return false;
}

/////////////////////////////////////////////////////////////////////
//
void CMMFileBytes::Close()
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

	m_bFileStart = false;
}

/////////////////////////////////////////////////////////////////////
//
CMMFileBytes::ReadStatus CMMFileBytes::ReadBytes()
{
	// function call sequence error
	if( !m_hMapFile || !m_pbFileBytes )
		return rs_ErrorFunctionCallSeq;

	::UnmapViewOfFile(m_pbFileBytes);
	m_pbFileBytes = NULL;

	m_bFileStart = false;

	if(m_qwFileBytesLeft2Read > 0)
		return (_ReadBytes() ? rs_OK : rs_ErrorRead);
	else
		return rs_Done;
}

/////////////////////////////////////////////////////////////////////
//
bool CMMFileBytes::ReinitBytes()
{
	// function call sequence error
	if( !m_hMapFile )
		return false;

	if(m_pbFileBytes)
	{
		::UnmapViewOfFile(m_pbFileBytes);
		m_pbFileBytes = NULL;
	}

	m_qwFileOffset = 0;
	m_qwFileBytesLeft2Read = m_qwFileSize;
	return _ReadBytes();
}

/////////////////////////////////////////////////////////////////////
//
bool CMMFileBytes::_ReadBytes()
{
	// how much bytes to map to the view
	// (There is NO possible loss of data when conversion from 'QWORD' to 'DWORD'. The value of m_qwFileBytesLeft2Read is
	// assigned to m_dwViewSize only if it's smaller then m_dwAllocationGranularity which is a DWORD)
	m_dwViewSize = (DWORD)(m_qwFileBytesLeft2Read < m_dwAllocationGranularity ? m_qwFileBytesLeft2Read : m_dwAllocationGranularity);			

	if( m_pbFileBytes = (BYTE*)::MapViewOfFile(m_hMapFile, FILE_MAP_READ, HIDWORD(m_qwFileOffset), LODWORD(m_qwFileOffset), m_dwViewSize) )
	{
		// when file offset is zero then its the file start
		m_bFileStart = (m_qwFileOffset == 0);
		m_qwFileOffset += m_dwViewSize;
		m_qwFileBytesLeft2Read -= m_dwViewSize;
		return true;
	}
	else
		return false;
}
