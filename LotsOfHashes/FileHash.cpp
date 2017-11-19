
// FileHash.cpp : implementation file
//

#include "StdAfx.h"
#include "FileHash.h"

/////////////////////////////////////////////////////////////////////
//
CFileHash::CFileHash(FILETIME* ft) : m_pcHashValue(NULL), m_hashSize(0)
{
	m_ftLastWriteTime = *ft;
}

/////////////////////////////////////////////////////////////////////
//
CFileHash::~CFileHash(void)
{
	delete m_pcHashValue;
}

/////////////////////////////////////////////////////////////////////
// By zeroing the cached file's LastWriteTime this element will not be synchronized
// with the disk file. 
void CFileHash::SetNeedUpdate()
{
	m_ftLastWriteTime.dwHighDateTime = m_ftLastWriteTime.dwLowDateTime = 0;
}

/////////////////////////////////////////////////////////////////////
//
const BYTE* CFileHash::GetHash(DWORD& size)
{
	size = m_hashSize;
	return m_pcHashValue;
}

/////////////////////////////////////////////////////////////////////
//
bool CFileHash::SetHash(BYTE* pcHash, DWORD size)
{
	if(pcHash && (size > 0) )
	{
		delete m_pcHashValue;

		m_hashSize = size;
		m_pcHashValue = new BYTE[m_hashSize];
		memcpy(m_pcHashValue, pcHash, m_hashSize);
		return true;
	}
	return false;
}

/////////////////////////////////////////////////////////////////////
//
//       P r i v a t e   M e m b e r   F u n c t i o n s
//
/////////////////////////////////////////////////////////////////////


/*

public:
	CFileHash(FILETIME* ft);
	//CFileHash(WCHAR* pszFileName, int nHashID);
	virtual ~CFileHash(void);

private:
	//WCHAR*		m_pszFileName;
	//int			m_nHashID;

	void		setName(WCHAR* pszName);

public:
	const WCHAR*		GetName()								{ return m_pszFileName; }


/////////////////////////////////////////////////////////////////////
//
CFileHash::CFileHash(WCHAR* pszFileName, int nHashID) :
			m_pszFileName(NULL), m_nHashID(-1), m_pcHashValue(NULL), m_hashSize(0)
{	
	m_ftLastWriteTime.dwHighDateTime = m_ftLastWriteTime.dwLowDateTime = 0;

	this->setName(pszFileName);
	m_nHashID = nHashID;
}

/////////////////////////////////////////////////////////////////////
//
void CFileHash::setName(WCHAR* pszName)
{
	delete m_pszFileName;
	m_pszFileName = NULL;

	if(pszName)
	{	
		size_t	nLen = wcslen(pszName) + 1; // length + 0 terminating

		m_pszFileName = new WCHAR[nLen];
		wmemcpy(m_pszFileName, pszName, nLen);
	}
}

/////////////////////////////////////////////////////////////////////
//
CFileHash::~CFileHash(void)
{
	//delete m_pszFileName;
	delete m_pcHashValue;
}

*/