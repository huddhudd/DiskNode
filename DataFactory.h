#pragma once


class CDataProvider : public IDataProvider
{
public:
	explicit CDataProvider(HANDLE hFile);
	~CDataProvider();

	//千万别给关闭了
	HANDLE Handle() {
		return hFile_;
	}
	HRESULT file_size(LONGLONG* size);
	BOOL read(PVOID buffer, ULONG Length, const LARGE_INTEGER* Offset = nullptr, PDWORD lpNumberOfBytesRead = nullptr);
public:
	virtual void WINAPI OnCloseFile(BOOL Deleted) override;
	//返回 <0时表示发生错误,不要调用OnReadFileComplete, >=0 时必须调用OnReadFileComplete
	virtual LONG WINAPI OnReadFile(_In_ LPCFLT_NOTIFICATION Notify,
		_In_ LPCCACHE_CONTEXT pCtxCache) override;
private:
	HANDLE hFile_;
	HANDLE hHeap_;
};

class CBigFile
{
public:
	CBigFile();
	~CBigFile();

	LONG Write(const void* pData, const LARGE_INTEGER* offset, ULONG Length);
	BOOL Delete(BOOLEAN del);
	LONG Rename(LPCWSTR ChildPath, ULONG PathLen);
	LONG GetHash(unsigned char sha1[]);
	//请一定不要关闭
	HANDLE Handle()const {
		return _hFile;
	}
	BOOL IsExpires(ULONGLONG tick)const;

public:
	LONG WINAPI AddRef() {
		return InterlockedIncrement(&_refCount);
	}
	LONG WINAPI Release() {
		LONG Count = InterlockedDecrement(&_refCount);
		if (0 == Count) {
			delete this;
		}
		return Count;
	}
	PINIT_ONCE GetInitOnce() {
		return &_InitOnce;
	}
	ULONG GetRef() const {
		return _refCount;
	}
	operator bool()const {
		return !!_hFile;
	}
	VOID Set(std::wstring& strVolDir, HANDLE hFile) {
		_strVolDir.swap(strVolDir);
		_hFile = hFile;
	}

private:
	volatile LONG _refCount;
	ULONG _Flags;
	INIT_ONCE _InitOnce;
	ULONGLONG _LastWriteTime;
	HANDLE _hFile;
	std::wstring _strVolDir;
};

class COnceBigFileParam
{
public:
	explicit COnceBigFileParam(const char* pre, const char* name, const unsigned long long file_size);
	~COnceBigFileParam()
	{
	}

	LARGE_INTEGER Context;//result
	LARGE_INTEGER FileSize;
	CBigFile* Self;
	std::wstring const* pName;
	std::wstring strName;
};

constexpr LONGLONG kHundredNsPerSec = 10'000'000LL;
constexpr LONGLONG kSecsPerDay = 24 * 60 * 60; // 1 天 = 24 * 60 * 60 秒
//24 * 3600 * 10000000LL
const ULONGLONG day_to_100ns = kSecsPerDay * kHundredNsPerSec; // 天→100 ns
// 1 年（按 365 天/年简单估算）+ 宽限 2 天
constexpr LONGLONG kOneYearsIn100ns = 365 * kSecsPerDay * kHundredNsPerSec;
constexpr LONGLONG kGrace2DaysIn100ns = 2LL * kSecsPerDay * kHundredNsPerSec;

class CDataFactory : public IPlugin
{
public:
	explicit CDataFactory();
	~CDataFactory();
	static CDataFactory* Get();

	IDiskPt* GetDiskPt()const {
		return _pDiskPt;
	}

	int Init(IDiskPt* pDiskPt, std::filesystem::path const& MainIni);
	int Run();
	void ReqClearup();

	void GetCacheDataDirs(std::vector<std::shared_ptr<std::filesystem::path>>& vCcDirs);
	//获取第一个缓存目录
	std::filesystem::path GetCacheDirFront();
	std::filesystem::path GetUserTmpDir(UINT uid, BOOL CreateIfNotExist = FALSE);
	int GetCcKeepDays(FileKeepTimeType id)const {
		return _CcKeepDays[id];
	}
	BOOL IsFileExist(_In_ const wchar_t* ChildPath,//"ArchData\8a\1c\8AC1B25923E3F09309D49329976DB1B9F173760A"
		_In_ ULONG PathLen, ULONG KeepIndex = ULONG_MAX);
	BOOL IsFileExist(_In_ const wchar_t* ChildPath,//"ArchData\8a\1c\8AC1B25923E3F09309D49329976DB1B9F173760A"
		_In_ ULONG PathLen, PFILE_BASIC_INFORMATION bsiInfo);
	HRESULT SaveFile(_In_ const wchar_t* ChildPath,//"ArchData\8a\1c\8AC1B25923E3F09309D49329976DB1B9F173760A"
		_In_ ULONG PathLen, const char* pData, size_t DataLen);
	HRESULT DelHashFile(_In_ const wchar_t* ChildPath,//"ArchData\8a\1c\8AC1B25923E3F09309D49329976DB1B9F173760A"
		_In_ ULONG PathLen, LONGLONG keepTime);

	LONG DoOpenFile(
		_In_ const wchar_t* ChildPath,//"ArchData\8a\1c\8AC1B25923E3F09309D49329976DB1B9F173760A"
		_In_ ULONG PathLen,
		_Out_ CDataProvider** pDataProvider);

	CBigFile* RemoveBigFile(std::wstring const& name);

	const NTSTATUS
	(WINAPI
		* ZwQueryAttributesFile)(
			_In_ POBJECT_ATTRIBUTES ObjectAttributes,
			_Out_ PFILE_BASIC_INFORMATION FileInformation);
	const NTSTATUS
	(WINAPI
		* ZwSetInformationFile)(
			_In_ HANDLE FileHandle,
			_Out_ PIO_STATUS_BLOCK IoStatusBlock,
			_In_reads_bytes_(Length) PVOID FileInformation,
			_In_ ULONG Length,
			_In_ MYFILE_INFORMATION_CLASS FileInformationClass
		);

public:
	virtual void OnEventNotify(
		_In_ PLUGIN_NOTIFY_TYPE NotifyType,
		_In_opt_ PVOID NotifyParam1,
		_In_opt_ PVOID NotifyParam2) override;
	//磁盘打开文件
	virtual LONG DoOpenFile(
		_In_ PCCACHE_CONTEXT pCtxCache,
		_In_ const LARGE_INTEGER* IdOfFile,
		_Out_ IDataProvider** pDataProvider) override;

	//下载清单文件同步完成
	//如果服务器返回404, 应该返回STATUS_ALREADY_COMPLETE
	//应检查数据头部sha判断是否有更新,没有更新时返回STATUS_ALREADY_COMPLETE
	virtual LONG DoGetListFile(_In_ std::function<LONG(PFILES_LIST pData)>const& complete,
		_In_ PCCACHE_CONTEXT pCtxCache, _In_ PCSTR pToken) override;

private:
	//刷新配置
	void RefreshConfig();
	
	//用户清单缓存清理
	void UserListClearup(DWORD appid);

	static BOOL CALLBACK InitOnceExecuteBigFile(
		PINIT_ONCE InitOnce, PVOID Parameter, PVOID* Context);

	void Uninit();

private:
	IDiskPt* _pDiskPt;
	HANDLE _evtClearup;
	ThreadPoolEx* _tp;
	SRWLOCK _vCacheDirsLock;
	std::vector<std::shared_ptr<std::filesystem::path>> _CacheDirs;//UserCache[0]
	size_t CcDirsMaxLength;
	//文件保留天数
	int _CcKeepDays[FKTT_MAX] = {0};
	
	CNvCache _nvCache;
	CUserDisk _userDisk;
	CUserConfig _userConfig;

	CRITICAL_SECTION _csBigFile;
	std::map<std::wstring, CBigFile*> _mBigFile;

	volatile long _flags;
};



