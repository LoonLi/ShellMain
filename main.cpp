#include <iostream>
#include <windef.h>
#include <stdarg.h>
#include "winbase.h"
#include <Windows.h>

using namespace std;

UINT   m_nImageSize = 0;//映像大小
PIMAGE_NT_HEADERS m_pntHeaders = 0;//PE结构指针
PIMAGE_SECTION_HEADER m_psecHeader = 0;//第一个SECTION结构指针
PCHAR m_pImageBase = 0 ; //映像基址


int main()
{
    HANDLE hFile = CreateFile("notepad.exe",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    if( hFile == INVALID_HANDLE_VALUE){
        cout<<"Fail to open the file!"<<endl;
        return 0;
    }
    //读DOS头
    DWORD fsize=GetFileSize(hFile,NULL);
	DWORD buffersize=fsize;//+0x2000;
	BYTE *buffer = new BYTE[buffersize];
    DWORD read;
	ReadFile(hFile,buffer,fsize,&read,NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) buffer;//获取到dos头
    cout << "DOS signature: " << dosHeader->e_magic << endl;
    if (dosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
		cout << "DOS signature mismatch!" << endl;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)&buffer[dosHeader->e_lfanew];//获取到NT头
	cout << "NT signature: " << ntHeaders->Signature << endl;
	if (ntHeaders->Signature!=IMAGE_NT_SIGNATURE)
		cout << "NT signature mismatch!" << endl;



    DWORD nFileSize = GetFileSize(hFile,NULL);//文件大小
    WORD nSectionNum = ntHeaders->FileHeader.NumberOfSections;//区块数
    DWORD nImageSize = ntHeaders->OptionalHeader.SizeOfImage;//映像尺寸
    DWORD nFileAlign = ntHeaders->OptionalHeader.FileAlignment;//文件中区块对齐大小
    DWORD nSectionAlign = ntHeaders->OptionalHeader.SectionAlignment;//内存中区块对齐值
    DWORD nHeaderSize = ntHeaders->OptionalHeader.SizeOfHeaders;//文件头大小

    //m_nImageSize = AlignSize(nImageSize,nSectionAlign);
    m_pImageBase = new char[m_nImageSize];
    memset(m_pImageBase,0,m_nImageSize);//清空申请内存
    SetFilePointer(hFile,0,NULL,FILE_BEGIN);
    ReadFile(hFile,m_pImageBase,nHeaderSize,&read,NULL);//这个语句会导致内存错误，原因暂时不明
    m_pntHeaders = (PIMAGE_NT_HEADERS)((DWORD)m_pImageBase + dosHeader->e_lfanew);
    //计算IMAGE_NT_HEADERS大小
    DWORD nNtHeaderSize = sizeof(ntHeaders->FileHeader)+sizeof(ntHeaders->Signature)+ntHeaders->FileHeader.SizeOfOptionalHeader;
    //cout<<nNtHeaderSize<<endl;
    m_psecHeader = (PIMAGE_SECTION_HEADER)((DWORD)m_pntHeaders + nNtHeaderSize);
    //循环依次读出SECTION数据到映像中的虚拟地址处
    PIMAGE_SECTION_HEADER psecHeader = m_psecHeader;
    for(WORD nIndex = 0;nIndex<nSectionNum;++nIndex,++psecHeader)
    {
        DWORD nRawDataSize = psecHeader->SizeOfRawData;
        DWORD nRawDataOffset = psecHeader->PointerToRawData;
        DWORD nVirtualAddress = psecHeader->VirtualAddress;
        DWORD nvirtualSize = psecHeader->Misc.VirtualSize;
        SetFilePointer(hFile,nRawDataOffset,NULL,FILE_BEGIN);//定位到下一SECTION
        ReadFile(hFile,&m_pImageBase[nVirtualAddress],nRawDataSize,NULL,NULL);//读数据到映像中
        cout<<nIndex<<endl;
    }



    delete []m_pImageBase;
    delete []buffer;
	CloseHandle(hFile);
    return 0;
}
