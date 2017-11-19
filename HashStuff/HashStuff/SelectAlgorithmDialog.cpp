// SelectAlgorithmDialog.cpp : implementation file
//

#include "stdafx.h"
#include "HashStuff.h"
#include "SelectAlgorithmDialog.h"
#include "afxdialogex.h"


// CSelectAlgorithmDialog dialog

IMPLEMENT_DYNAMIC(CSelectAlgorithmDialog, CDialogEx)

CSelectAlgorithmDialog::CSelectAlgorithmDialog(CSelectAlgorithm* pSelectAlgorithm, CWnd* pParent /*=NULL*/)
	: CDialogEx(CSelectAlgorithmDialog::IDD, pParent), m_pSelectAlgorithm(NULL)
{	
	m_pSelectAlgorithm = pSelectAlgorithm;
}

CSelectAlgorithmDialog::~CSelectAlgorithmDialog()
{
}

void CSelectAlgorithmDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LST_SELECT, m_lstSelect);
}


BEGIN_MESSAGE_MAP(CSelectAlgorithmDialog, CDialogEx)
	ON_BN_CLICKED(IDC_BTN_ALL, &CSelectAlgorithmDialog::OnBnClickedBtnAll)
	ON_BN_CLICKED(IDC_BTN_NONE, &CSelectAlgorithmDialog::OnBnClickedBtnNone)
	ON_BN_CLICKED(IDOK, &CSelectAlgorithmDialog::OnBnClickedOk)
	ON_NOTIFY(NM_CLICK, IDC_LST_SELECT, &CSelectAlgorithmDialog::OnClickLstSelect)
	ON_BN_CLICKED(ID_BTN_ALL_AND_OK, &CSelectAlgorithmDialog::OnBnClickedBtnAllAndOk)
	ON_BN_CLICKED(IDC_BTN_INVERT, &CSelectAlgorithmDialog::OnBnClickedBtnInvert)
END_MESSAGE_MAP()


// CSelectAlgorithmDialog message handlers


BOOL CSelectAlgorithmDialog::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	int	idx = 0;

	m_lstSelect.InsertColumn(idx++, L"Algorithm", LVCFMT_LEFT, 125);

	ListView_SetExtendedListViewStyleEx(m_lstSelect.m_hWnd, LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_CHECKBOXES, LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_CHECKBOXES);

	for(int i=0; i<m_pSelectAlgorithm->AlgorithmCount(); i++)
	{
		m_lstSelect.InsertItem(i, m_pSelectAlgorithm->NameOf((algorithm_code)i));
		m_lstSelect.SetCheck(i, m_pSelectAlgorithm->IsSelected((algorithm_code)i));
	}

	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

void CSelectAlgorithmDialog::OnBnClickedBtnAll()
{
	m_lstSelect.SetCheck(-1, 1);
	m_lstSelect.SetFocus();
}

void CSelectAlgorithmDialog::OnBnClickedBtnNone()
{
	m_lstSelect.SetCheck(-1, 0);
	m_lstSelect.SetFocus();
}

void CSelectAlgorithmDialog::OnBnClickedBtnInvert()
{
	for(int i=0; i<m_lstSelect.GetItemCount(); i++)
		m_lstSelect.SetCheck(i, !(m_lstSelect.GetCheck(i)));
}

void CSelectAlgorithmDialog::OnBnClickedOk()
{
	for(int i=0; i<m_lstSelect.GetItemCount(); i++)
		m_pSelectAlgorithm->SetSelect((algorithm_code)i, m_lstSelect.GetCheck(i));

	CDialogEx::OnOK();
}


void CSelectAlgorithmDialog::OnClickLstSelect(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	
	// + iItem is -1 if list was clicked outside an item's rect
	// + ptAction.x is in the range of 0-15 if the checkbox was clicked
	if( (pNMItemActivate->iItem != -1) && (pNMItemActivate->ptAction.x > 15) )
		m_lstSelect.SetCheck(pNMItemActivate->iItem, !(m_lstSelect.GetCheck(pNMItemActivate->iItem)));

	*pResult = 0;
}


void CSelectAlgorithmDialog::OnBnClickedBtnAllAndOk()
{
	this->OnBnClickedBtnAll();
	this->OnBnClickedOk();
}

