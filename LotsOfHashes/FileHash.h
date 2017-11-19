
// FileHash.h : header file
//

#pragma once

class CFileHash
{
public:
	CFileHash(FILETIME* ft);
	virtual ~CFileHash(void);

private:
	FILETIME		m_ftLastWriteTime;	
	BYTE*			m_pcHashValue;
	DWORD			m_hashSize;

public:
	void					SetNeedUpdate();

	const FILETIME*	GetLastWriteTime()					{ return &m_ftLastWriteTime; };
	void					SetLastWriteTime(FILETIME* ft)	{ m_ftLastWriteTime = *ft; };

	const BYTE*			GetHash(DWORD& size);
	bool					SetHash(BYTE* pcHash, DWORD size);
};

