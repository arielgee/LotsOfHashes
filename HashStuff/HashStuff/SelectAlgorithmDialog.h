
// SelectAlgorithmDialog.h : header file
//

#include "SelectAlgorithm.h"

#pragma once


// CSelectAlgorithmDialog dialog

class CSelectAlgorithmDialog : public CDialogEx
{
	DECLARE_DYNAMIC(CSelectAlgorithmDialog)

public:
	CSelectAlgorithmDialog(CSelectAlgorithm* pSelectAlgorithm, CWnd* pParent = NULL);
	virtual ~CSelectAlgorithmDialog();

// Dialog Data
	enum { IDD = IDD_SELECT_ALGORITHM_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_lstSelect;
	virtual BOOL OnInitDialog();

private:
	CSelectAlgorithm* m_pSelectAlgorithm;
public:
	afx_msg void OnBnClickedBtnAll();
	afx_msg void OnBnClickedBtnNone();
	afx_msg void OnBnClickedOk();
	afx_msg void OnClickLstSelect(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedBtnAllAndOk();
	afx_msg void OnBnClickedBtnInvert();
};
