#pragma once


typedef struct _DiskClearupInfo
{
	LONGLONG KeepTime;//���������ʱ��
	LONGLONG ShouldDelSize;	//Ӧ��ɾ�����ļ���С
	LONGLONG DelSize;	//������ɾ�����ļ���С
	LONGLONG DelFailedSize;	//����ɾ��ʧ�ܵ��ļ���С
	LONGLONG TagSize;//����������ɾ�����ļ���С
	ULONG ShouldDelCount;//Ӧ��ɾ�����ļ���
	ULONG DelCount;//������ɾ�����ļ���
	ULONG DelFailedCount;//����ɾ��ʧ�ܵ��ļ���
	ULONG DelListItem;//����ɾ�����嵥����
} DiskClearupInfo, * PDiskClearupInfo;

class CUserDisk
{
public:
	CUserDisk();
	~CUserDisk();

	void httpProcess(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen);
	//��ȡ�嵥
	void HiPullList(IHttpSession* sender);
	//�ϴ����������嵥
	void HiUploadList(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen);
	//�����ļ��Ƿ���ڣ�������Ҫ�ϴ���
	void HiCheckFile(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen);
	//�ϴ��ļ�
	void HiUploadFile(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen);
	//�����ļ���ʧ���ֶ������嵥
	void HiLostFile(IHttpSession* sender, const char* Target, size_t TargetLen);

	//Disk��������
	void DiskClearup(int KeepDays);
private:
	void DiskListClearup(PDiskClearupInfo pInfo, std::set<FILE_INDEX, mLess_FileId> const& sFid);
	void DiskClearup(PDiskClearupInfo pInfo, std::set<FILE_INDEX, mLess_FileId>& sFid,
		std::filesystem::path const& dir, int level);

private:
	volatile LONG m_Flags;
	CRITICAL_SECTION m_csList;//����m_mutexs
	std::map<UINT, CRWLock> m_RwList;//�����嵥�ļ�����
};

