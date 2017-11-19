
// OpenFileBytes.h : header file
//

#pragma once

class COpenFileBytes
{
public:
	COpenFileBytes(WCHAR* pzsFileName);
	virtual ~COpenFileBytes(void);

private:
	WCHAR*			m_pzsFileName;

	HANDLE			m_hFile;	
	HANDLE			m_hMapFile;
	BYTE*				m_pbFileBytes;
	ULONGLONG		m_ullFileSize;

public:
	bool		Open();
	void		Close();

	BYTE*			Bytes() const { return m_pbFileBytes; };
	ULONGLONG	Size() const { return m_ullFileSize; };
};

