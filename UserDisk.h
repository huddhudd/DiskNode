#pragma once


typedef struct _DiskClearupInfo
{
	LONGLONG KeepTime;//本次清理的时间
	LONGLONG ShouldDelSize;	//应该删除的文件大小
	LONGLONG DelSize;	//本次已删除的文件大小
	LONGLONG DelFailedSize;	//本次删除失败的文件大小
	LONGLONG TagSize;//本次清理标记删除的文件大小
	ULONG ShouldDelCount;//应该删除的文件数
	ULONG DelCount;//本次已删除的文件数
	ULONG DelFailedCount;//本次删除失败的文件数
	ULONG DelListItem;//本次删除的清单项数
} DiskClearupInfo, * PDiskClearupInfo;

class CUserDisk
{
public:
	CUserDisk();
	~CUserDisk();

	void httpProcess(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen);
	//拉取清单
	void HiPullList(IHttpSession* sender);
	//上传本次增量清单
	void HiUploadList(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen);
	//过滤文件是否存在，保留需要上传的
	void HiCheckFile(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen);
	//上传文件
	void HiUploadFile(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen);
	//发现文件丢失后手动遍历清单
	void HiLostFile(IHttpSession* sender, const char* Target, size_t TargetLen);

	//Disk缓存清理
	void DiskClearup(int KeepDays);
private:
	void DiskListClearup(PDiskClearupInfo pInfo, std::set<FILE_INDEX, mLess_FileId> const& sFid);
	void DiskClearup(PDiskClearupInfo pInfo, std::set<FILE_INDEX, mLess_FileId>& sFid,
		std::filesystem::path const& dir, int level);

private:
	volatile LONG m_Flags;
	CRITICAL_SECTION m_csList;//保护m_mutexs
	std::map<UINT, CRWLock> m_RwList;//串行清单文件操作
};

