
// Cache.cpp : implementation file
//

#include "StdAfx.h"
#include "Cache.h"

CCache* CCache::m_pSingleton = NULL;

/////////////////////////////////////////////////////////////////////
//
CCache::CCache(void) : m_pszTempKeyBuffer(NULL)
{
	m_qwFileSizeThresholdBytes = CConfiguration::i()->FileSizeThreshold(DEF_FILE_SIZE_THRESHOLD_BYTES);
}

/////////////////////////////////////////////////////////////////////
//
CCache::~CCache(void)
{
	freeMem();
}

/////////////////////////////////////////////////////////////////////
//
CCache* CCache::i()
{
	if(m_pSingleton == NULL)
		m_pSingleton = new CCache();

	return m_pSingleton;
}

/////////////////////////////////////////////////////////////////////
//
void CCache::Release()
{
	delete m_pSingleton;
	m_pSingleton = NULL;
}

/////////////////////////////////////////////////////////////////////
//
CCache::insertOrFind_t CCache::InsertOrFind(CFileHash** ppfh, const WCHAR* pszFileName, WIN32_FILE_ATTRIBUTE_DATA* pfa, int nHashID)
{
	freeEmpties();

	createKey(pszFileName, nHashID);

	// if its NULL then a key was not created; exit with an error
	if( !m_pszTempKeyBuffer )
		return iof_Error;

	// file size is too small; it will be faster to just hash it.
	if( MAKEQWORD(pfa->nFileSizeHigh, pfa->nFileSizeLow) < m_qwFileSizeThresholdBytes )
		return iof_TooSmall;

	// the new element is set with the file's last write time.
	*ppfh = new CFileHash(&(pfa->ftLastWriteTime));

	// try to insert the new key/object pair and check the operation result.
	pairInsertRet_t	pir = m_mapCache.insert( pairFileHash_t(m_pszTempKeyBuffer, *ppfh) );

	// element was inserted to the map and therefor was not found in the cache
	if(pir.second)
	{
		// Register the new cache element to the memory manager.
		CCacheMemoryManager::RegisterNew(&((pir.first)->second));
		return iof_Inserted;		// the returned ppfh pointer is available to the caller for updating.
	}

	// element already in the map

	// If ((pir.first)->second) is NULL then the CFileHash object referenced by this element was
	// deallocated by the CCacheMemoryManager.	
	if( ((pir.first)->second) == NULL )
	{
		// reuse the map element by re-referencing it with *ppfh that was just allocated.
		((pir.first)->second) = *ppfh;

		// Register the new cache element to the memory manager.
		CCacheMemoryManager::RegisterNew(&((pir.first)->second));
		return iof_FoundNeedUpdate;	// The called needs to hash the file and save the hash to the cache (returned ppfh pointer).
	}
	else
	{
		// since the file was found in the cache delete the newly allocated element and return the one that was found
		delete *ppfh;
		*ppfh = ((pir.first)->second);

		const FILETIME*	pft = (*ppfh)->GetLastWriteTime();

		// If the last write time is not identical then the disk file was modified and is not synchronized with
		// the cached data file. Update the LW time and return iof_FoundNeedUpdate instead of iof_Found.
		if( (pft->dwHighDateTime != pfa->ftLastWriteTime.dwHighDateTime) || (pft->dwLowDateTime != pfa->ftLastWriteTime.dwLowDateTime) )
		{
			// update the found element with the file's last write time
			(*ppfh)->SetLastWriteTime(&(pfa->ftLastWriteTime));
			return iof_FoundNeedUpdate;	// The called needs to hash the file and save the hash to the cache (returned CFileHash object).
		}
		else
			return iof_Found;		// file was not modified - cached hash value is valid
	}
}

/////////////////////////////////////////////////////////////////////
//
bool CCache::Remove(const WCHAR* pszFileName, int nHashID)
{
	createKey(pszFileName, nHashID);

	// if its not NULL then the key was created
	if(m_pszTempKeyBuffer)
	{
		try
		{
			CFileHash*	pfh = m_mapCache.at(m_pszTempKeyBuffer);

			m_mapCache.erase(m_pszTempKeyBuffer);
			delete pfh;
			return true;
		}
		catch(...) {}
	}

	return false;	// key not created or element not found 
}

/////////////////////////////////////////////////////////////////////
//
void CCache::Clear()
{	
	freeMem();	
}

/////////////////////////////////////////////////////////////////////
//
//       P r i v a t e   M e m b e r   F u n c t i o n s
//
/////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////
//
CFileHash* CCache::find(const WCHAR* pszFileName, int nHashID)
{
	createKey(pszFileName, nHashID);

	// if its not NULL then the key was created
	if(m_pszTempKeyBuffer)
	{
		try
		{
			CFileHash*	pfh = m_mapCache.at(m_pszTempKeyBuffer);
			return pfh;
		}
		catch(...) {}
	}
	return NULL;	// key not created or element not found 
}

/////////////////////////////////////////////////////////////////////
//
void CCache::createKey(const WCHAR* pszFileName, int nHashID)
{
	delete m_pszTempKeyBuffer;
	m_pszTempKeyBuffer = NULL;

	if( pszFileName && (nHashID > -1) )
	{
		// the char size of the string key: file_name/nHashID (hash ID is no more then 9999)
		m_pszTempKeyBuffer = new WCHAR[wcslen(pszFileName) + 6];	// 6 = (1 delimiter + 4 digits hash ID + 1 0-terminating)
		wsprintf(m_pszTempKeyBuffer, L"%d?%s", nHashID, pszFileName);
	}
}

/////////////////////////////////////////////////////////////////////
//
void CCache::freeMem()
{
	delete m_pszTempKeyBuffer;
	m_pszTempKeyBuffer = NULL;

	for(iteratorCache_t itr = m_mapCache.begin(); itr != m_mapCache.end(); itr++)
		delete (itr->second);

	m_mapCache.clear();

	CCacheMemoryManager::reset();
}

/////////////////////////////////////////////////////////////////////
//
void CCache::freeEmpties()
{
	// erase empties only if the size is twice the number of max elements	
	if(m_mapCache.size() >= (CCacheMemoryManager::m_nMaxCacheElements*2) )
	{
		iteratorCache_t	itr = m_mapCache.begin();
		iteratorCache_t	itrErase;

		while( itr != m_mapCache.end() )
		{
			if(itr->second == NULL)
			{
				itrErase = itr;	// if an iterator is used to erase an element the increment operator (itr++) will fails 
				itr++;
				m_mapCache.erase(itrErase);
			}
			else
				itr++;
		}
	}	
}

/////////////////////////////////////////////////////////////////////
//
