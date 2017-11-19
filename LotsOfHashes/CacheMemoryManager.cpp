
// CacheMemoryManager.cpp : implementation file
//

#include "StdAfx.h"
#include "CacheMemoryManager.h"


/////////////////////////////////////////////////////////////////////
//
CCacheMemoryManager::CCacheMemoryManager(void) : m_idxCacheElement(0)
{
	m_nMaxCacheElements = CConfiguration::i()->MaxCacheElements(MAX_CACHE_ELEMENTS);

	// create and initialize the cyclic array
	m_pppCacheElements = new CFileHash**[m_nMaxCacheElements];
	memset(m_pppCacheElements, 0, (sizeof(CFileHash**) * m_nMaxCacheElements) );
}

/////////////////////////////////////////////////////////////////////
//
CCacheMemoryManager::~CCacheMemoryManager(void)
{
	delete[] m_pppCacheElements;
}

/////////////////////////////////////////////////////////////////////
// Register the new cache element by saving the reference to the reference
// in the map.
void CCacheMemoryManager::RegisterNew(CFileHash** ppNew)
{
	// m_idxCacheElement determine the position of the new element.	
	// if this position is not NULL then this is a reference to a reference to
	// an old CFileHash object; delete it and set the reference IN THE MAP to NULL.
	// The member function CCache::InsertOrFind() is preper to handle references to
	// CFileHash objects that were deallocated but not erased from the map
	if(m_pppCacheElements[m_idxCacheElement])
	{
		delete (*(m_pppCacheElements[m_idxCacheElement]));
		(*(m_pppCacheElements[m_idxCacheElement])) = NULL;
	}

	// Register the referenced to the referenced to the new object
	m_pppCacheElements[m_idxCacheElement] = ppNew;

	// move the index to the next array element or to the start to simulate a Round-Robin
	m_idxCacheElement++;
	if(m_idxCacheElement >= m_nMaxCacheElements)
		m_idxCacheElement = 0;
}

/////////////////////////////////////////////////////////////////////
// do not free the m_pppCacheElements array; just initialize it
void CCacheMemoryManager::reset()
{	
	memset(m_pppCacheElements, 0, (sizeof(CFileHash**) * m_nMaxCacheElements) );
	m_idxCacheElement = 0;
}

