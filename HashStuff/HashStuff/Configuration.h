
// Configuration.h : header file
//

#pragma once

class CConfiguration
{
public:
	virtual ~CConfiguration(void);

private:
	CConfiguration(void);

	static CConfiguration*		m_pSingleton;

	QWORD		m_qwFileSizeThreshold;
	UINT		m_nMaxCacheElements;

	bool	getFileName(WCHAR* pszName, size_t size);
	void	readPrivateProfile();

public:
	static CConfiguration*	i();
	static void					Release();

	QWORD		FileSizeThreshold(QWORD defVal);
	UINT		MaxCacheElements(UINT defVal);

};

