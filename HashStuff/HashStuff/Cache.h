
// Cache.h : header file
//

#pragma once

#include <map>
#include <string>
#include "FileHash.h"
#include "CacheMemoryManager.h"

#define DEF_FILE_SIZE_THRESHOLD_BYTES ((QWORD)5120)

using namespace std;

typedef map<wstring, CFileHash*>							mapCache_t;
typedef map<wstring, CFileHash*>::iterator			iteratorCache_t;
typedef map<wstring, CFileHash*>::const_iterator	cIteratorCache_t;
typedef pair<wstring, CFileHash*>						pairFileHash_t;
typedef pair<iteratorCache_t, bool>						pairInsertRet_t;

class CCache : private CCacheMemoryManager
{
public:	
	virtual ~CCache(void);

	typedef enum insertOrFind_t
	{
		iof_Error,
		iof_Inserted,
		iof_Found,
		iof_FoundNeedUpdate,
		iof_TooSmall
	};

private:
	CCache(void);	// singleton

	static CCache*		m_pSingleton;

	mapCache_t		m_mapCache;
	WCHAR*			m_pszTempKeyBuffer;
	QWORD				m_qwFileSizeThresholdBytes;

	CFileHash*	find(const WCHAR* pszFileName, int nHashID);
	void			createKey(const WCHAR* pszFileName, int nHashID);
	void			freeMem();
	void			freeEmpties();

public:
	static CCache*		i();
	static void			Release();

	insertOrFind_t		InsertOrFind(CFileHash** ppfh, const WCHAR* pszFileName, WIN32_FILE_ATTRIBUTE_DATA* pfa, int nHashID);

	bool			Remove(const WCHAR* pszFileName, int nHashID);	
	void			Clear();
};

