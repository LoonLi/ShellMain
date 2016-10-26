#include <iostream>
#include <windef.h>
#include <stdarg.h>
#include "winbase.h"
#include <Windows.h>

using namespace std;

UINT   m_nImageSize = 0;//ӳ���С
PIMAGE_NT_HEADERS m_pntHeaders = 0;//PE�ṹָ��
PIMAGE_SECTION_HEADER m_psecHeader = 0;//��һ��SECTION�ṹָ��
PCHAR m_pImageBase = 0 ; //ӳ���ַ


int main()
{
    HANDLE hFile = CreateFile("notepad.exe",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    if( hFile == INVALID_HANDLE_VALUE){
        cout<<"Fail to open the file!"<<endl;
        return 0;
    }
    //��DOSͷ
    DWORD fsize=GetFileSize(hFile,NULL);
	DWORD buffersize=fsize;//+0x2000;
	BYTE *buffer = new BYTE[buffersize];
    DWORD read;
	ReadFile(hFile,buffer,fsize,&read,NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) buffer;//��ȡ��dosͷ
    cout << "DOS signature: " << dosHeader->e_magic << endl;
    if (dosHeader->e_magic!=IMAGE_DOS_SIGNATURE)
		cout << "DOS signature mismatch!" << endl;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)&buffer[dosHeader->e_lfanew];//��ȡ��NTͷ
	cout << "NT signature: " << ntHeaders->Signature << endl;
	if (ntHeaders->Signature!=IMAGE_NT_SIGNATURE)
		cout << "NT signature mismatch!" << endl;



    DWORD nFileSize = GetFileSize(hFile,NULL);//�ļ���С
    WORD nSectionNum = ntHeaders->FileHeader.NumberOfSections;//������
    DWORD nImageSize = ntHeaders->OptionalHeader.SizeOfImage;//ӳ��ߴ�
    DWORD nFileAlign = ntHeaders->OptionalHeader.FileAlignment;//�ļ�����������С
    DWORD nSectionAlign = ntHeaders->OptionalHeader.SectionAlignment;//�ڴ����������ֵ
    DWORD nHeaderSize = ntHeaders->OptionalHeader.SizeOfHeaders;//�ļ�ͷ��С

    //m_nImageSize = AlignSize(nImageSize,nSectionAlign);
    m_pImageBase = new char[m_nImageSize];
    memset(m_pImageBase,0,m_nImageSize);//��������ڴ�
    SetFilePointer(hFile,0,NULL,FILE_BEGIN);
    ReadFile(hFile,m_pImageBase,nHeaderSize,&read,NULL);//������ᵼ���ڴ����ԭ����ʱ����
    m_pntHeaders = (PIMAGE_NT_HEADERS)((DWORD)m_pImageBase + dosHeader->e_lfanew);
    //����IMAGE_NT_HEADERS��С
    DWORD nNtHeaderSize = sizeof(ntHeaders->FileHeader)+sizeof(ntHeaders->Signature)+ntHeaders->FileHeader.SizeOfOptionalHeader;
    //cout<<nNtHeaderSize<<endl;
    m_psecHeader = (PIMAGE_SECTION_HEADER)((DWORD)m_pntHeaders + nNtHeaderSize);
    //ѭ�����ζ���SECTION���ݵ�ӳ���е������ַ��
    PIMAGE_SECTION_HEADER psecHeader = m_psecHeader;
    for(WORD nIndex = 0;nIndex<nSectionNum;++nIndex,++psecHeader)
    {
        DWORD nRawDataSize = psecHeader->SizeOfRawData;
        DWORD nRawDataOffset = psecHeader->PointerToRawData;
        DWORD nVirtualAddress = psecHeader->VirtualAddress;
        DWORD nvirtualSize = psecHeader->Misc.VirtualSize;
        SetFilePointer(hFile,nRawDataOffset,NULL,FILE_BEGIN);//��λ����һSECTION
        ReadFile(hFile,&m_pImageBase[nVirtualAddress],nRawDataSize,NULL,NULL);//�����ݵ�ӳ����
        cout<<nIndex<<endl;
    }



    delete []m_pImageBase;
    delete []buffer;
	CloseHandle(hFile);
    return 0;
}
