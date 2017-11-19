
// HashStuffDialog.h : header file
//

#include "Hashes.h"
#include "Cache.h"

#include "SelectAlgorithm.h"


#pragma once

#define MAX_RESULT_BUFF 129		// SHA-512 & Whirlpool returns a hash code of 512 bits that is the larger hash code
											// to display 512 bits in hex I need ((512bit / 8bit)Byte * 2Byte)wchar = 128 + 0 terminating

// CHashStuffDialog dialog
class CHashStuffDialog : public CDialogEx
{
// Construction
public:
	CHashStuffDialog(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_HASHSTUFF_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

public:	
	afx_msg void OnBnClickedBtnOpen();
	afx_msg void OnDblClkListResult(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedHashFile();	
	afx_msg void OnBnClickedHashByteArray();
	afx_msg void OnBnClickedHashMmFile();	

private:
	CSelectAlgorithm	m_selectAlgorithm;

	CString			m_sWindowText;
	CListCtrl*		m_lstResult;
	CHashes			m_dataHash;

	WCHAR		m_szHexResult[MAX_RESULT_BUFF];
	DWORD		m_dwStopWatchTicks;	

	void		InsertHash2List(algorithm_code Algo, CString sHash);	
	WCHAR*	ConvertToHex(BYTE* pbHash, DWORD dwHashLen);

	void		futileScan(CMMFileBytes* pMMFile);

	//WCHAR*	ConvertToHex(DWORD dwHash);
	//WCHAR*	ConvertTiger192ToHex(BYTE* pbHash, DWORD dwHashLen);
public:
	afx_msg void OnBnClickedSelectAlg();
};
