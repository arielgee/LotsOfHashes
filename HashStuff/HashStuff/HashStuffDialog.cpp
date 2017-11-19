
// HashStuffDialog.cpp : implementation file
//

#include "stdafx.h"
#include "HashStuff.h"
#include "HashStuffDialog.h"
#include "afxdialogex.h"
#include "OpenFileBytes.h"
#include "MMFileBytes.h"
#include <share.h>
#include "SelectAlgorithmDialog.h"

extern bool CopyToClipboard(const TCHAR* pszData);

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define HASH_USING_FILE
#define HASH_USING_BYTE_ARRAY
#define HASH_USING_MM_FILE


#define STOP_WATCH(h) { \
	m_dwStopWatchTicks = ::GetTickCount(); \
	h; \
	m_dwStopWatchTicks = ::GetTickCount() - m_dwStopWatchTicks; }

#define BEGIN_EXECUTE_SECTION(alg) if(m_selectAlgorithm.IsSelected(alg)) { 
#define END_EXECUTE_SECTION } 

/////////////////////////////////////////////////////////////////////
//
CHashStuffDialog::CHashStuffDialog(CWnd* pParent /*=NULL*/)
	: CDialogEx(CHashStuffDialog::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

/////////////////////////////////////////////////////////////////////
//
void CHashStuffDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CHashStuffDialog, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BTN_OPEN, &CHashStuffDialog::OnBnClickedBtnOpen)
	ON_NOTIFY(NM_DBLCLK, IDC_LST_RESULT, &CHashStuffDialog::OnDblClkListResult)
	ON_BN_CLICKED(ID_HASH_MM_FILE, &CHashStuffDialog::OnBnClickedHashMmFile)
	ON_BN_CLICKED(ID_HASH_BYTE_ARRAY, &CHashStuffDialog::OnBnClickedHashByteArray)
	ON_BN_CLICKED(ID_HASH_FILE, &CHashStuffDialog::OnBnClickedHashFile)
	ON_BN_CLICKED(ID_SELECT_ALG, &CHashStuffDialog::OnBnClickedSelectAlg)
END_MESSAGE_MAP()


// CHashStuffDialog message handlers

/////////////////////////////////////////////////////////////////////
//
BOOL CHashStuffDialog::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	this->GetWindowText(m_sWindowText);
#ifdef _WIN64
	m_sWindowText += " x64";
#else
	m_sWindowText += " x86";
#endif	
	this->SetWindowText(m_sWindowText);

	m_lstResult = (CListCtrl*)GetDlgItem(IDC_LST_RESULT);

	int	idx = 0;

	m_lstResult->InsertColumn(idx++, L"#", LVCFMT_LEFT, 25);
	m_lstResult->InsertColumn(idx++, L"Algorithm", LVCFMT_LEFT, 80);
	m_lstResult->InsertColumn(idx++, L"Hash", LVCFMT_LEFT, 770);
	m_lstResult->InsertColumn(idx++, L"Ticks", LVCFMT_LEFT, 45);

	ListView_SetExtendedListViewStyleEx(m_lstResult->m_hWnd, LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES, LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);


	/********************************/
	//CCache::i()->_test();

	//CCache::i()->Release();
	/*******************************/

	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

/////////////////////////////////////////////////////////////////////
//
void CHashStuffDialog::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CHashStuffDialog::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

/////////////////////////////////////////////////////////////////////
//
void CHashStuffDialog::OnBnClickedBtnOpen()
{
	CFileDialog		dlg(TRUE);

	if( dlg.DoModal() == IDOK )
	{		
		SetDlgItemText(IDC_EDIT_FILE, dlg.GetOFN().lpstrFile);
		GetDlgItem(IDC_EDIT_FILE)->UpdateWindow();
		OnBnClickedHashMmFile();
	}
}

/////////////////////////////////////////////////////////////////////
//
void CHashStuffDialog::OnDblClkListResult(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);

	TCHAR		szHash[MAX_RESULT_BUFF];

	ListView_GetItemText(m_lstResult->m_hWnd, pNMItemActivate->iItem, 2, szHash, MAX_RESULT_BUFF);

	CopyToClipboard(szHash);

	*pResult = 0;
}

/////////////////////////////////////////////////////////////////////
//
void CHashStuffDialog::OnBnClickedSelectAlg()
{
	CSelectAlgorithmDialog		dlg(&m_selectAlgorithm);

	if(dlg.DoModal() == IDOK)
		OnBnClickedHashMmFile();
}

#ifdef HASH_USING_FILE
/////////////////////////////////////////////////////////////////////
//
void CHashStuffDialog::OnBnClickedHashFile()
{
	this->SetWindowText(m_sWindowText + " - [Using FILE]");

	CWaitCursor		wait;

	m_lstResult->DeleteAllItems();
	m_lstResult->UpdateWindow();
	SetDlgItemText(IDC_TOTAL_TICKCOUNT, L"");
	GetDlgItem(IDC_TOTAL_TICKCOUNT)->UpdateWindow();

	DWORD		dwTicks = ::GetTickCount();

	CString		sFileName;

	GetDlgItemText(IDC_EDIT_FILE, sFileName);
	
	FILE*		pFile;

	if( (pFile = _wfsopen(sFileName, L"rbS", _SH_DENYNO)) == NULL )
		return;


	BYTE*		pbHash = NULL;
	DWORD		dwHashLen = 0;
	bool		bRet;

	m_lstResult->LockWindowUpdate();

	// ++++++++++++++++++++++ CRC32 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_CRC32)
	STOP_WATCH(bRet = m_dataHash.CRC32Hash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_CRC32, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ CRC32b +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_CRC32b)
	STOP_WATCH(bRet = m_dataHash.CRC32bHash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_CRC32b, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ eD2k/eMule +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_eD2k_eMule)
	STOP_WATCH(bRet = m_dataHash.EDonkey2kHash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_eD2k_eMule, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ GOST ++++++++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_GOST)
	STOP_WATCH(bRet = m_dataHash.GOSTHash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_GOST, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL128,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_128_3)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(128, 3, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_128_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL128,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_128_4)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(128, 4, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_128_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL128,5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_128_5)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(128, 5, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_128_5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL160,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_160_3)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(160, 3, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_160_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL160,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_160_4)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(160, 4, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_160_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL160,5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_160_5)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(160, 5, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_160_5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL192,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_192_3)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(192, 3, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_192_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL192,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_192_4)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(192, 4, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_192_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL192,5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_192_5)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(192, 5, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_192_5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL224,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_224_3)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(224, 3, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_224_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL224,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_224_4)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(224, 4, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_224_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL224,5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_224_5)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(224, 5, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_224_5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL256,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_256_3)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(256, 3, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_256_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL256,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_256_4)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(256, 4, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_256_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL256,5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_256_5)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(256, 5, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_256_5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ MD4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_MD4)
	STOP_WATCH(bRet = m_dataHash.MD4Hash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_MD4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ MD5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_MD5)
	STOP_WATCH(bRet = m_dataHash.MD5Hash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_MD5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ MD5(wc) +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_MD5_WC)
	STOP_WATCH(bRet = m_dataHash.WinCryptMD5Hash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_MD5_WC, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Murmur32 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_MURMUR_32)
	STOP_WATCH(bRet = m_dataHash.Murmur32Hash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_MURMUR_32, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Murmur128 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_MURMUR_128)
	STOP_WATCH(bRet = m_dataHash.Murmur128Hash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_MURMUR_128, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ RIPEMD128 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_RIPEMD_128)
	STOP_WATCH(bRet = m_dataHash.RIPEMDHash(128, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_RIPEMD_128, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ RIPEMD160 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_RIPEMD_160)
	STOP_WATCH(bRet = m_dataHash.RIPEMDHash(160, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_RIPEMD_160, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ RIPEMD256 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_RIPEMD_256)
	STOP_WATCH(bRet = m_dataHash.RIPEMDHash(256, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_RIPEMD_256, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ RIPEMD320 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_RIPEMD_320)
	STOP_WATCH(bRet = m_dataHash.RIPEMDHash(320, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_RIPEMD_320, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Salsa10 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SALSA10)
	STOP_WATCH(bRet = m_dataHash.Salsa10Hash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SALSA10, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Salsa20 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SALSA20)
	STOP_WATCH(bRet = m_dataHash.Salsa20Hash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SALSA20, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA160 ++++++++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA1_160)
	STOP_WATCH(bRet = m_dataHash.SHA160Hash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA1_160, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA160(wc) ++++++++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA1_160_WC)
	STOP_WATCH(bRet = m_dataHash.WinCryptSHAHash(160, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA1_160_WC, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA224 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_224)
	STOP_WATCH(bRet = m_dataHash.SHA224Hash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_224, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA256 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_256)
	STOP_WATCH(bRet = m_dataHash.SHA256Hash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_256, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA256(wc) +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_256_WC)
	STOP_WATCH(bRet = m_dataHash.WinCryptSHAHash(256, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_256_WC, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA384 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_384)
	STOP_WATCH(bRet = m_dataHash.SHA384Hash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_384, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA384(wc) +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_384_WC)
	STOP_WATCH(bRet = m_dataHash.WinCryptSHAHash(384, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_384_WC, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA512 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_512)
	STOP_WATCH(bRet = m_dataHash.SHA512Hash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_512, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA512(wc) +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_512_WC)
	STOP_WATCH(bRet = m_dataHash.WinCryptSHAHash(512, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_512_WC, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Keccak224 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA3_224)
	STOP_WATCH(bRet = m_dataHash.SHA3Hash(224, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA3_224, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Keccak256 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA3_256)
	STOP_WATCH(bRet = m_dataHash.SHA3Hash(256, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA3_256, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Keccak384 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA3_384)
	STOP_WATCH(bRet = m_dataHash.SHA3Hash(384, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA3_384, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Keccak512 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA3_512)
	STOP_WATCH(bRet = m_dataHash.SHA3Hash(512, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA3_512, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Snefru128 ++++++++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Snefru_128)
	STOP_WATCH(bRet = m_dataHash.SnefruHash(128, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Snefru_128, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Snefru256 ++++++++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Snefru_256)
	STOP_WATCH(bRet = m_dataHash.SnefruHash(256, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Snefru_256, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Tiger128,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_128_3)
	STOP_WATCH(bRet = m_dataHash.TigerHash(128, 3, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_128_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Tiger128,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_128_4)
	STOP_WATCH(bRet = m_dataHash.TigerHash(128, 4, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_128_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Tiger160,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_160_3)
	STOP_WATCH(bRet = m_dataHash.TigerHash(160, 3, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_160_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Tiger160,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_160_4)
	STOP_WATCH(bRet = m_dataHash.TigerHash(160, 4, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_160_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Tiger192,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_192_3)
	STOP_WATCH(bRet = m_dataHash.TigerHash(192, 3, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_192_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Tiger192,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_192_4)
	STOP_WATCH(bRet = m_dataHash.TigerHash(192, 4, pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_192_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Whirlpool +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Whirlpool)
	STOP_WATCH(bRet = m_dataHash.WhirlpoolHash(pFile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Whirlpool, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	//fseek(pFile, 0, SEEK_SET);
	END_EXECUTE_SECTION

	m_lstResult->UnlockWindowUpdate();

	fclose(pFile);

	dwTicks = ::GetTickCount() - dwTicks;

	TCHAR		szTicks[50];

	wsprintf(szTicks, L"%d", dwTicks);
	SetDlgItemText(IDC_TOTAL_TICKCOUNT, szTicks);	
}
#endif HASH_USING_FILE

#ifdef HASH_USING_BYTE_ARRAY
/////////////////////////////////////////////////////////////////////
//
void CHashStuffDialog::OnBnClickedHashByteArray()
{
	this->SetWindowText(m_sWindowText + " - [Using BYTE array]");

	CWaitCursor		wait;

	m_lstResult->DeleteAllItems();	
	m_lstResult->UpdateWindow();
	SetDlgItemText(IDC_TOTAL_TICKCOUNT, L"");
	GetDlgItem(IDC_TOTAL_TICKCOUNT)->UpdateWindow();

	DWORD		dwTicks = ::GetTickCount();
	


	CString		sFileName;

	GetDlgItemText(IDC_EDIT_FILE, sFileName);
	
	COpenFileBytes		fileBytes(sFileName.GetBuffer());

	if( !fileBytes.Open() )
		return;
	

	BYTE*		pbHash = NULL;
	DWORD		dwHashLen = 0;
	bool		bRet;

	m_lstResult->LockWindowUpdate();

	// ++++++++++++++++++++++ CRC32 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_CRC32)
	STOP_WATCH(bRet = m_dataHash.CRC32Hash(fileBytes.Bytes(), fileBytes.Size(),  &pbHash, &dwHashLen));
	InsertHash2List(ALC_CRC32, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ CRC32b +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_CRC32b)
	STOP_WATCH(bRet = m_dataHash.CRC32bHash(fileBytes.Bytes(), fileBytes.Size(),  &pbHash, &dwHashLen));
	InsertHash2List(ALC_CRC32b, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ eD2k/eMule +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_eD2k_eMule)
	STOP_WATCH(bRet = m_dataHash.EDonkey2kHash(fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_eD2k_eMule, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ GOST ++++++++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_GOST)
	STOP_WATCH(bRet = m_dataHash.GOSTHash(fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_GOST, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ HAVAL128,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_128_3)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(128, 3, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_128_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ HAVAL128,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_128_4)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(128, 4, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_128_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ HAVAL128,5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_128_5)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(128, 5, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_128_5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ HAVAL160,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_160_3)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(160, 3, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_160_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ HAVAL160,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_160_4)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(160, 4, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_160_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ HAVAL160,5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_160_5)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(160, 5, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_160_5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ HAVAL192,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_192_3)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(192, 3, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_192_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ HAVAL192,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_192_4)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(192, 4, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_192_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ HAVAL192,5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_192_5)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(192, 5, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_192_5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ HAVAL224,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_224_3)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(224, 3, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_224_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ HAVAL224,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_224_4)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(224, 4, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_224_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ HAVAL224,5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_224_5)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(224, 5, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_224_5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ HAVAL256,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_256_3)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(256, 3, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_256_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ HAVAL256,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_256_4)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(256, 4, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_256_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ HAVAL256,5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_256_5)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(256, 5, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_256_5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ MD4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_MD4)
	STOP_WATCH(bRet = m_dataHash.MD4Hash(fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_MD4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ MD5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_MD5)
	STOP_WATCH(bRet = m_dataHash.MD5Hash(fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_MD5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ MD5(wc) +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_MD5_WC)
	STOP_WATCH(bRet = m_dataHash.WinCryptMD5Hash(fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_MD5_WC, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION	

	// ++++++++++++++++++++++ Murmur32 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_MURMUR_32)
	STOP_WATCH(bRet = m_dataHash.Murmur32Hash(fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_MURMUR_32, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ Murmur128 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_MURMUR_128)
	STOP_WATCH(bRet = m_dataHash.Murmur128Hash(fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_MURMUR_128, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ RIPEMD128 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_RIPEMD_128)
	STOP_WATCH(bRet = m_dataHash.RIPEMDHash(128, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_RIPEMD_128, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ RIPEMD160 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_RIPEMD_160)
	STOP_WATCH(bRet = m_dataHash.RIPEMDHash(160, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_RIPEMD_160, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ RIPEMD256 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_RIPEMD_256)
	STOP_WATCH(bRet = m_dataHash.RIPEMDHash(256, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_RIPEMD_256, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ RIPEMD320 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_RIPEMD_320)
	STOP_WATCH(bRet = m_dataHash.RIPEMDHash(320, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_RIPEMD_320, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ Salsa10 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SALSA10)
	STOP_WATCH(bRet = m_dataHash.Salsa10Hash(fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_SALSA10, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ Salsa20 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SALSA20)
	STOP_WATCH(bRet = m_dataHash.Salsa20Hash(fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_SALSA20, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ SHA160 ++++++++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA1_160)
	STOP_WATCH(bRet = m_dataHash.SHA160Hash(fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA1_160, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ SHA160(wc) ++++++++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA1_160_WC)
	STOP_WATCH(bRet = m_dataHash.WinCryptSHAHash(160, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA1_160_WC, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ SHA224 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_224)
	STOP_WATCH(bRet = m_dataHash.SHA224Hash(fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_224, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ SHA256 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_256)
	STOP_WATCH(bRet = m_dataHash.SHA256Hash(fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_256, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ SHA256(wc) +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_256_WC)
	STOP_WATCH(bRet = m_dataHash.WinCryptSHAHash(256, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_256_WC, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ SHA384 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_384)
	STOP_WATCH(bRet = m_dataHash.SHA384Hash(fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_384, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA384(wc) +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_384_WC)
	STOP_WATCH(bRet = m_dataHash.WinCryptSHAHash(384, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_384_WC, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ SHA512 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_512)
	STOP_WATCH(bRet = m_dataHash.SHA512Hash(fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_512, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ SHA512(wc) +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_512_WC)
	STOP_WATCH(bRet = m_dataHash.WinCryptSHAHash(512, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_512_WC, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Keccak224 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA3_224)
	STOP_WATCH(bRet = m_dataHash.SHA3Hash(224, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA3_224, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ Keccak256 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA3_256)
	STOP_WATCH(bRet = m_dataHash.SHA3Hash(256, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA3_256, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ Keccak384 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA3_384)
	STOP_WATCH(bRet = m_dataHash.SHA3Hash(384, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA3_384, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ Keccak512 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA3_512)
	STOP_WATCH(bRet = m_dataHash.SHA3Hash(512, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA3_512, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ Snefru128 ++++++++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Snefru_128)
	STOP_WATCH(bRet = m_dataHash.SnefruHash(128, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_Snefru_128, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ Snefru256 ++++++++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Snefru_256)
	STOP_WATCH(bRet = m_dataHash.SnefruHash(256, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_Snefru_256, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ Tiger128,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_128_3)
	STOP_WATCH(bRet = m_dataHash.TigerHash(128, 3, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_128_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ Tiger128,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_128_4)
	STOP_WATCH(bRet = m_dataHash.TigerHash(128, 4, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_128_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ Tiger160,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_160_3)
	STOP_WATCH(bRet = m_dataHash.TigerHash(160, 3, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_160_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ Tiger160,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_160_4)
	STOP_WATCH(bRet = m_dataHash.TigerHash(160, 4, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_160_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ Tiger192,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_192_3)
	STOP_WATCH(bRet = m_dataHash.TigerHash(192, 3, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_192_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ Tiger192,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_192_4)
	STOP_WATCH(bRet = m_dataHash.TigerHash(192, 4, fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_192_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	// ++++++++++++++++++++++ Whirlpool +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Whirlpool)
	STOP_WATCH(bRet = m_dataHash.WhirlpoolHash(fileBytes.Bytes(), fileBytes.Size(), &pbHash, &dwHashLen));
	InsertHash2List(ALC_Whirlpool, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	END_EXECUTE_SECTION
	
	m_lstResult->UnlockWindowUpdate();

	fileBytes.Close();

	dwTicks = ::GetTickCount() - dwTicks;

	TCHAR		szTicks[50];

	wsprintf(szTicks, L"%d", dwTicks);
	SetDlgItemText(IDC_TOTAL_TICKCOUNT, szTicks);	
}

#endif HASH_USING_BYTE_ARRAY

#ifdef HASH_USING_MM_FILE
/////////////////////////////////////////////////////////////////////
//
void CHashStuffDialog::OnBnClickedHashMmFile()
{
	this->SetWindowText(m_sWindowText + " - [Using Memory Map file]");

	CWaitCursor		wait;

	m_lstResult->DeleteAllItems();
	m_lstResult->UpdateWindow();
	SetDlgItemText(IDC_TOTAL_TICKCOUNT, L"");
	GetDlgItem(IDC_TOTAL_TICKCOUNT)->UpdateWindow();

	DWORD		dwTicks = ::GetTickCount();

	CString		sFileName;

	GetDlgItemText(IDC_EDIT_FILE, sFileName);
	
	CMMFileBytes	mmfile(sFileName.GetBuffer());

	if( !mmfile.Open() )
		return;


	BYTE*		pbHash = NULL;
	DWORD		dwHashLen = 0;
	bool		bRet;

	m_lstResult->LockWindowUpdate();

	// do this so the OS system will cache the file
	futileScan(&mmfile);
	mmfile.ReinitBytes();

	// ++++++++++++++++++++++ CRC32 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_CRC32)
	STOP_WATCH(bRet = m_dataHash.CRC32Hash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_CRC32, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ CRC32b +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_CRC32b)
	STOP_WATCH(bRet = m_dataHash.CRC32bHash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_CRC32b, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ eD2k/eMule +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_eD2k_eMule)
	STOP_WATCH(bRet = m_dataHash.EDonkey2kHash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_eD2k_eMule, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ GOST +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_GOST)
	STOP_WATCH(bRet = m_dataHash.GOSTHash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_GOST, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL128,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_128_3)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(128, 3, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_128_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL128,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_128_4)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(128, 4, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_128_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL128,5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_128_5)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(128, 5, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_128_5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL160,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_160_3)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(160, 3, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_160_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL160,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_160_4)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(160, 4, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_160_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL160,5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_160_5)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(160, 5, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_160_5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL192,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_192_3)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(192, 3, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_192_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL192,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_192_4)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(192, 4, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_192_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL192,5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_192_5)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(192, 5, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_192_5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL224,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_224_3)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(224, 3, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_224_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL224,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_224_4)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(224, 4, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_224_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL224,5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_224_5)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(224, 5, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_224_5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL256,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_256_3)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(256, 3, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_256_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL256,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_256_4)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(256, 4, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_256_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ HAVAL256,5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_HAVAL_256_5)
	STOP_WATCH(bRet = m_dataHash.HAVALHash(256, 5, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_HAVAL_256_5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ MD4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_MD4)
	STOP_WATCH(bRet = m_dataHash.MD4Hash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_MD4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ MD5 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_MD5)
	STOP_WATCH(bRet = m_dataHash.MD5Hash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_MD5, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ MD5(wc) +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_MD5_WC)
	STOP_WATCH(bRet = m_dataHash.WinCryptMD5Hash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_MD5_WC, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Murmur32 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_MURMUR_32)
	STOP_WATCH(bRet = m_dataHash.Murmur32Hash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_MURMUR_32, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Murmur128 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_MURMUR_128)
	STOP_WATCH(bRet = m_dataHash.Murmur128Hash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_MURMUR_128, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ RIPEMD128 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_RIPEMD_128)
	STOP_WATCH(bRet = m_dataHash.RIPEMDHash(128, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_RIPEMD_128, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ RIPEMD160 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_RIPEMD_160)
	STOP_WATCH(bRet = m_dataHash.RIPEMDHash(160, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_RIPEMD_160, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ RIPEMD256 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_RIPEMD_256)
	STOP_WATCH(bRet = m_dataHash.RIPEMDHash(256, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_RIPEMD_256, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ RIPEMD320 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_RIPEMD_320)
	STOP_WATCH(bRet = m_dataHash.RIPEMDHash(320, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_RIPEMD_320, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Salsa10 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SALSA10)
	STOP_WATCH(bRet = m_dataHash.Salsa10Hash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SALSA10, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Salsa20 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SALSA20)
	STOP_WATCH(bRet = m_dataHash.Salsa20Hash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SALSA20, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA160 ++++++++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA1_160)
	STOP_WATCH(bRet = m_dataHash.SHA160Hash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA1_160, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA160(wc) ++++++++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA1_160_WC)
	STOP_WATCH(bRet = m_dataHash.WinCryptSHAHash(160, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA1_160_WC, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA224 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_224)
	STOP_WATCH(bRet = m_dataHash.SHA224Hash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_224, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA256 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_256)
	STOP_WATCH(bRet = m_dataHash.SHA256Hash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_256, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA256(wc) +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_256_WC)
	STOP_WATCH(bRet = m_dataHash.WinCryptSHAHash(256, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_256_WC, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA384 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_384)
	STOP_WATCH(bRet = m_dataHash.SHA384Hash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_384, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA384(wc) +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_384_WC)
	STOP_WATCH(bRet = m_dataHash.WinCryptSHAHash(384, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_384_WC, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA512 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_512)
	STOP_WATCH(bRet = m_dataHash.SHA512Hash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_512, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ SHA512(wc) +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA2_512_WC)
	STOP_WATCH(bRet = m_dataHash.WinCryptSHAHash(512, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA2_512_WC, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Keccak224 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA3_224)
	STOP_WATCH(bRet = m_dataHash.SHA3Hash(224, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA3_224, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Keccak256 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA3_256)
	STOP_WATCH(bRet = m_dataHash.SHA3Hash(256, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA3_256, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Keccak384 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA3_384)
	STOP_WATCH(bRet = m_dataHash.SHA3Hash(384, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA3_384, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Keccak512 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_SHA3_512)
	STOP_WATCH(bRet = m_dataHash.SHA3Hash(512, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_SHA3_512, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Snefru128 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Snefru_128)
	STOP_WATCH(bRet = m_dataHash.SnefruHash(128, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Snefru_128, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Snefru256 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Snefru_256)
	STOP_WATCH(bRet = m_dataHash.SnefruHash(256, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Snefru_256, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Tiger128,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_128_3)
	STOP_WATCH(bRet = m_dataHash.TigerHash(128, 3, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_128_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Tiger128,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_128_4)
	STOP_WATCH(bRet = m_dataHash.TigerHash(128, 4, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_128_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Tiger160,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_160_3)
	STOP_WATCH(bRet = m_dataHash.TigerHash(160, 3, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_160_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Tiger160,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_160_4)
	STOP_WATCH(bRet = m_dataHash.TigerHash(160, 4, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_160_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Tiger192,3 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_192_3)
	STOP_WATCH(bRet = m_dataHash.TigerHash(192, 3, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_192_3, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Tiger192,4 +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Tiger_192_4)
	STOP_WATCH(bRet = m_dataHash.TigerHash(192, 4, &mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Tiger_192_4, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));

	mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	// ++++++++++++++++++++++ Whirlpool +++++++++++++++++++
	BEGIN_EXECUTE_SECTION(ALC_Whirlpool)
	STOP_WATCH(bRet = m_dataHash.WhirlpoolHash(&mmfile, &pbHash, &dwHashLen));
	InsertHash2List(ALC_Whirlpool, (bRet ? ConvertToHex(pbHash, dwHashLen) : m_dataHash.GetLastErrorMessage()));
	
	//mmfile.ReinitBytes();
	END_EXECUTE_SECTION

	m_lstResult->UnlockWindowUpdate();

	mmfile.Close();

	dwTicks = ::GetTickCount() - dwTicks;

	TCHAR		szTicks[50];

	wsprintf(szTicks, L"%d", dwTicks);
	SetDlgItemText(IDC_TOTAL_TICKCOUNT, szTicks);
}

#endif HASH_USING_MM_FILE

/////////////////////////////////////////////////////////////////////
//
void CHashStuffDialog::InsertHash2List(algorithm_code Algo, CString sHash)
{
	TCHAR		szIdx[5];
	TCHAR		szTicks[10];

	int		idx = m_lstResult->GetItemCount();

	wsprintf(szIdx, L"%d", idx+1);
	wsprintf(szTicks, L"%d", m_dwStopWatchTicks);

	m_lstResult->InsertItem(idx, szIdx);
	m_lstResult->SetItemText(idx, 1, m_selectAlgorithm.NameOf(Algo));
	m_lstResult->SetItemText(idx, 2, sHash);	
	m_lstResult->SetItemText(idx, 3, szTicks);
}

/////////////////////////////////////////////////////////////////////
// create a HEX string from the byte array.
WCHAR* CHashStuffDialog::ConvertToHex(BYTE* pBytes, DWORD dwLen)
{	
//	for(DWORD i=0; i<dwLen; i++)
//		wsprintf(m_szHexResult+(i*2), L"%2.2X", pBytes[i]);	// appends a terminating null character 

	DWORD		dwOffset;
	DWORD		dwBuffSize = MAX_RESULT_BUFF-1;

	// scan the pBytes array using the i index. format & print each byte to m_szHexResult
	// the dwOffset jumps to the next 2 bytes that will be written
	// dwBuffSize sets the maximum number of bytes to be written
	// check dwOffset size so that it will not go outside the m_szHexResult buffer
	// wsprintf appends a terminating null character 

	for(DWORD i=0; i<dwLen && (dwOffset=i*2)<dwBuffSize; i++)
		wsprintf(m_szHexResult + dwOffset, L"%02x", pBytes[i]);
		
	return m_szHexResult;
}

/////////////////////////////////////////////////////////////////////
// 
void CHashStuffDialog::futileScan(CMMFileBytes* pMMFile)
{
	if( !pMMFile->IsFileStart() )
		return;

	DWORD								i;
	CMMFileBytes::ReadStatus	rs;
	BYTE*								pBytes;
	DWORD								dwByteSize;
	BYTE								byte;

	while(true)
	{
		pBytes = pMMFile->Bytes();
		dwByteSize = pMMFile->BytesSize();

		for(i=0; i<dwByteSize; i++)
			byte = pBytes[i];

		// read next bytes and check status
		if( (rs = pMMFile->ReadBytes()) != CMMFileBytes::rs_OK )
			break;
	}
}


/* old stuff
/////////////////////////////////////////////////////////////////////
// create a HEX string from the byte array that was created by Tiger algorithm; always 24 bytes long.
WCHAR* CHashStuffDialog::ConvertTiger192ToHex(BYTE* pbHash, DWORD dwHashLen)
{
	if(dwHashLen != 24)
	{
		m_szHexResult[0] = 0;
	}
	else
	{
		int	i;		

		for(i = 0; i < 8; i++)
			wsprintf(m_szHexResult+(i*2), L"%02X", pbHash[7-i]);

		for(i = 8; i < 16; i++)
			wsprintf(m_szHexResult+(i*2), L"%02X", pbHash[23-i]);

		for(i = 16; i < 24; i++)
			wsprintf(m_szHexResult+(i*2), L"%02X", pbHash[39-i]);
	}

	return m_szHexResult;
}
*/

/*
/////////////////////////////////////////////////////////////////////
//
WCHAR* CHashStuffDialog::ConvertToHex(DWORD dw)
{
	//int	n = _snwprintf_s(m_szHexResult, MAX_RESULT_BUFF, _TRUNCATE, L"%08x", dw);
	//m_szHexResult[n] = 0;
	_snwprintf_s(m_szHexResult, MAX_RESULT_BUFF, _TRUNCATE, L"%08x", dw);

	return m_szHexResult;
}
*/


