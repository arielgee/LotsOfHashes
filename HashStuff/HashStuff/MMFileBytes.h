
// MMFileBytes.h : header file
//

#pragma once

class CMMFileBytes
{
public:
	CMMFileBytes(WCHAR* pzsFileName);
	virtual ~CMMFileBytes(void);

	enum ReadStatus
	{
		rs_Invalid,
		rs_OK,
		rs_Done,
		rs_ErrorRead,
		rs_ErrorFunctionCallSeq
	};

private:
	WCHAR*			m_pzsFileName;

	HANDLE			m_hMapFile;
	QWORD				m_qwFileSize;
	BYTE*				m_pbFileBytes;

	DWORD			m_dwAllocationGranularity;	
	DWORD			m_dwViewSize;
	QWORD			m_qwFileBytesLeft2Read;
	QWORD			m_qwFileOffset;

	bool			m_bFileStart;

	bool		_ReadBytes();

public:
	bool		Open();
	void		Close();

	ReadStatus			ReadBytes();	
	bool					ReinitBytes();

	bool					IsFileStart() { return m_bFileStart; };

	BYTE*			Bytes() const { return m_pbFileBytes; };
	DWORD			BytesSize() const { return m_dwViewSize; };
	QWORD			FileSize() const { return m_qwFileSize; };

};

