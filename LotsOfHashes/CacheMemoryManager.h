
// CacheMemoryManager.h : header file
//

/*
 * This class will manage the memory allocated by the CCache class.
 * It will limit the maximum number of cache elements (CFileHash) in the cache.
 * This class will manage a fixed size cyclic file slot array of all the pointers to the pointers in the map.
 * For each CFileHash object allocated by the CCache class and referenced by the map, this
 * cyclic array will hold a pointer the that reference in the map. 
 * As Round-Robin go, the oldest CFileHash object will be deallocated to make room to the
 * new CFileHash object. This is done to limit the number of allocated CFileHash objects and the memory usage.
 * MAX_CACHE_ELEMENTS sets the maximum number of allocated CFileHash objects.
 * The member function CCache::InsertOrFind() is preper to handle references to CFileHash objects
 * that were deallocated but not erased from the map
 * 
 * This Is Very Importent: Dealocated CFileHash objects are not erased from the map.
 *
 */

#pragma once

#include "FileHash.h"

#define MAX_CACHE_ELEMENTS 500		// sets the maximum number of elements in the cache.


class CCacheMemoryManager
{
public:
	CCacheMemoryManager(void);
	virtual ~CCacheMemoryManager(void);

private:	
	size_t			m_idxCacheElement;
	CFileHash***	m_pppCacheElements;		// a cyclic file slots (cache elements)

protected:
	size_t			m_nMaxCacheElements;

	void		reset();

public:
	void		RegisterNew(CFileHash** ppNew);
};

