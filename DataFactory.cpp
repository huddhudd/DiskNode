#include "common.h"

namespace {
	CDataFactory g_Factory;
}

CDataProvider::CDataProvider(HANDLE hFile):
	hFile_(hFile), 
	hHeap_(GetProcessHeap())
{
	//每次打开文件都修改一下文件修改时间作为缓存清理的依据
	FILETIME ft = {};
	GetSystemTimeAsFileTime(&ft);
	SetFileTime(hFile, nullptr, nullptr, &ft);
}

CDataProvider::~CDataProvider()
{
	if(hFile_) {
		CloseHandle(hFile_);
		hFile_ = NULL;
	}
}

HRESULT CDataProvider::file_size(LONGLONG* size)
{
	if (GetFileSizeEx(hFile_, (PLARGE_INTEGER)size))
		return S_OK;
	return HRESULT_FROM_WIN32(GetLastError());
}

BOOL CDataProvider::read(PVOID buffer, ULONG Length, 
	const LARGE_INTEGER* Offset /*= nullptr*/, PDWORD lpNumberOfBytesRead /*= nullptr*/)
{
	DWORD NumberOfBytesRead = 0;
	OVERLAPPED ov;

	RtlZeroMemory(&ov, sizeof(ov));
	if (Offset) {
		ov.Offset = Offset->LowPart;
		ov.OffsetHigh = Offset->HighPart;
	}
	auto ret = ReadFile(hFile_,
		buffer, Length,
		&NumberOfBytesRead,
		&ov);
	if (lpNumberOfBytesRead)
		*lpNumberOfBytesRead = NumberOfBytesRead;
	return ret;
}

void WINAPI CDataProvider::OnCloseFile(BOOL Deleted)
{
	CloseHandle(hFile_);
	hFile_ = NULL;
	delete this;
}

LONG WINAPI CDataProvider::OnReadFile(_In_ LPCFLT_NOTIFICATION Notify,
	_In_ LPCCACHE_CONTEXT pCtxCache)
{
	USER_REPLY_INFO ReplyInfo;
	PVOID buffer;

	buffer = HeapAlloc(hHeap_, 0, pCtxCache->SignOrLen);
	if (NULL == buffer)
		return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);

	if (!read(buffer, pCtxCache->SignOrLen, &pCtxCache->Offset)) {
		auto Error = GetLastError();
		HeapFree(hHeap_, 0, buffer);
		return HRESULT_FROM_WIN32(Error);
	}

	ReplyInfo.status = STATUS_SUCCESS;
	ReplyInfo.Length = pCtxCache->SignOrLen;
	g_Factory.GetDiskPt()->OnRequestComplete(Notify, &ReplyInfo, buffer);
	HeapFree(hHeap_, 0, buffer);
	return STATUS_SUCCESS;
}

CBigFile::CBigFile()
	: _refCount(2), _Flags(0)
	, _InitOnce(RTL_RUN_ONCE_INIT)
	, _LastWriteTime(GetTickCount64())
	, _hFile(NULL)
{
}

CBigFile::~CBigFile()
{
	if (_hFile) {
		CloseHandle(_hFile);
		_hFile = NULL;
	}
}

LONG CBigFile::Write(const void* pData, const LARGE_INTEGER* offset, ULONG Length)
{
	DWORD NumberOfBytesWritten;
	OVERLAPPED ov = { 0 };
	ov.Offset = offset->LowPart;
	ov.OffsetHigh = offset->HighPart;

	if (!WriteFile(_hFile, pData, Length, &NumberOfBytesWritten, &ov))
		return HRESULT_FROM_WIN32(GetLastError());

	_LastWriteTime = GetTickCount64();
	return S_OK;
}

BOOL CBigFile::IsExpires(ULONGLONG tick)const {
	if (_refCount > 1)
		return FALSE;
	return _LastWriteTime + 60000 < tick;
}

BOOL CBigFile::Delete(BOOLEAN del)
{
	if (_hFile) {
		FILE_DISPOSITION_INFO info({ del });
		return SetFileInformationByHandle(_hFile, FileDispositionInfo, &info, sizeof(info));
	}
	return TRUE;
}

LONG CBigFile::Rename(LPCWSTR ChildPath, ULONG PathLen)
{
	_strVolDir.append(ChildPath, PathLen);
	DWORD dwBufferSize = (DWORD)(_strVolDir.size() << 1);
	auto info = (PFILE_RENAME_INFO)_strVolDir.data();

	*(PVOID*)info = NULL;
	info->ReplaceIfExists = TRUE;
	info->RootDirectory = NULL;
	info->FileNameLength = dwBufferSize - UFIELD_OFFSET(FILE_RENAME_INFO, FileName);
	dwBufferSize += 2;
	if (!SetFileInformationByHandle(_hFile, FileRenameInfo, info, dwBufferSize)) {
		DWORD error = GetLastError();
		if (ERROR_PATH_NOT_FOUND != error)
			return HRESULT_FROM_WIN32(error);

		CreateDirectories(info->FileName, (info->FileNameLength >> 1) - PathLen);
		if (!SetFileInformationByHandle(_hFile, FileRenameInfo, info, dwBufferSize))
			return HRESULT_FROM_WIN32(GetLastError());
	}
	return S_OK;
}

LONG CBigFile::GetHash(unsigned char sha1[])
{
#define BlockSize 1048576 // 1024*1024
	HRESULT hr;
	DWORD NumberOfBytesRead;
	LARGE_INTEGER Length;
	BYTE* buffer = NULL;
	SHA1_CTX sha1_ctx;
	OVERLAPPED ov = { 0 };

	if (!GetFileSizeEx(_hFile, &Length))
		return HRESULT_FROM_WIN32(GetLastError());

	SIZE_T bufsize = min(Length.QuadPart, BlockSize);
	buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufsize);
	if (NULL == buffer)
		return HRESULT_FROM_WIN32(GetLastError());

	SHA1Init(&sha1_ctx);
	for (int i = 0; Length.QuadPart;)
	{
		NumberOfBytesRead = 0;
		bufsize = min(Length.QuadPart, BlockSize);
		if (!ReadFile(_hFile, buffer, (DWORD)bufsize, &NumberOfBytesRead, &ov))
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
			HeapFree(GetProcessHeap(), 0, buffer);
			return hr;
		}

		if (0 == NumberOfBytesRead) {
			if (i++ > 5) {
				HeapFree(GetProcessHeap(), 0, buffer);
				return -1;
			}
			continue;
		}
		
		SHA1Update(&sha1_ctx, buffer, NumberOfBytesRead);
		Length.QuadPart -= (LONGLONG)NumberOfBytesRead;
		*(LONGLONG*)&ov.Offset += (LONGLONG)NumberOfBytesRead;
		i = 0;
	}

	SHA1Final(sha1, &sha1_ctx);
	HeapFree(GetProcessHeap(), 0, buffer);
	return S_OK;
}

COnceBigFileParam::COnceBigFileParam(const char* pre, const char* name, const unsigned long long file_size)
	: Context({ 0 })
{
	FileSize.QuadPart = file_size;
	strName = CodeHelper::tou16(pre, -1, CP_UTF8);
	strName.push_back(L'_');
	strName += CodeHelper::tou16(name, -1, CP_UTF8);
	std::transform(strName.begin(), strName.end(), strName.begin(), towlower);
	pName = &strName;
}

CDataFactory::CDataFactory():
	_pDiskPt(nullptr),
	_evtClearup(CreateEvent(NULL, FALSE, FALSE, NULL)),
	_vCacheDirsLock(SRWLOCK_INIT),
	CcDirsMaxLength(0),
	_flags(0)
{
	_tp = new ThreadPoolEx(1, max(std::thread::hardware_concurrency(), 20));
	InitializeCriticalSection(&_csBigFile);
}

CDataFactory::~CDataFactory()
{
	Uninit();

	CloseHandle(_evtClearup);
	DeleteCriticalSection(&_csBigFile);
}

void CDataFactory::Uninit()
{
	InterlockedOr(&_flags, 1);
	if (_tp) {
		auto tp = _tp;
		_tp = nullptr;
		delete tp;
	}
	for (auto&& [n, file] : _mBigFile) {
		file->Release();
	}
}

CDataFactory* CDataFactory::Get()
{
	return &g_Factory;
}

int CDataFactory::Init(IDiskPt* pDiskPt, std::filesystem::path const& MainIni)
{
	ULONG Length;
	std::error_code ec;
	WCHAR szKey[32];
	WCHAR szPath[MAX_PATH];
	LPCWSTR appKey[] = {L"UserCache", L"DiskCache" };
	std::vector<CcPath> vCcPath;

	_pDiskPt = pDiskPt;

	auto hNtdll = GetModuleHandleW(L"ntdll.dll");
	(FARPROC&)ZwQueryAttributesFile = GetProcAddress(hNtdll, "ZwQueryAttributesFile");
	(FARPROC&)ZwSetInformationFile = GetProcAddress(hNtdll, "ZwSetInformationFile");
	if (nullptr == ZwQueryAttributesFile || nullptr == ZwSetInformationFile)
		return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);

	Length = GetPrivateProfileIntW(L"UserCache", L"NvCacheMinKeepDays", 0, g_MainIni.c_str());
	if (45 == Length){//TODO: 记得在20250620前删除
		WritePrivateProfileStringW(L"UserCache", L"NvCacheMinKeepDays", std::to_wstring(7).c_str(), g_MainIni.c_str());
	}
	RefreshConfig();

	auto hr = _nvCache.Init();
	if (FAILED(hr)) {
		_log.errorW(L"[%s]NvCache init failed:0x%X", __FUNCTIONW__, hr);
		return hr;
	}

	// 获取缓存目录
	for (int j = 0; j < ARRAYSIZE(appKey); ++j)
	{
		for (int i = 0; i < 256; ++i)
		{
			swprintf_s(szKey, L"%d", i);
			Length = GetPrivateProfileString(appKey[j], szKey, L"",
				szPath, MAX_PATH, MainIni.c_str());
			if (0 == Length)
				continue;

			std::wstring strPath(szPath);
			auto& tail = strPath.back();
			if (tail == L'/')
				tail = L'\\';
			else if (tail != L'\\')
				strPath.push_back(L'\\');
			strPath.append(L"CloudDiskCache\\");

			std::filesystem::path path(std::move(strPath));
			std::filesystem::create_directories(path, ec);
			if (ec)// 失败
				continue;
			auto info = std::filesystem::space(path, ec);
			if (ec)
				continue;

			vCcPath.emplace_back(std::make_shared<std::filesystem::path>(std::move(path)), info.available);
		}
		if (!vCcPath.empty())
			break;
	}
	if (vCcPath.empty()) {
		return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED_WITH_CACHED_HANDLE);
	}

	std::sort(vCcPath.begin(), vCcPath.end(),
		[](CcPath& a, CcPath& b) {
			return a.available > b.available;
		});
	auto last_time = std::filesystem::file_time_type::clock::now();
	last_time = last_time - std::chrono::duration_cast<std::filesystem::file_time_type::duration>(std::chrono::minutes(9));

	for (auto& p : vCcPath) {
		_CacheDirs.emplace_back(p.Path);
		if (CcDirsMaxLength < p.Path->native().length())
			CcDirsMaxLength = p.Path->native().length();

		//遍历上次上传的临时文件
		auto upload = *p.Path / UPLOAD_PREFIX;
		std::error_code ec;
		for (const auto& entry : std::filesystem::directory_iterator(upload, ec))
		{
			auto& path = entry.path();
			if (entry.is_directory()) {
				std::filesystem::remove_all(path, ec);
				continue;
			}
			
			auto write_time = entry.last_write_time(ec);
			if (ec || write_time < last_time) {
				std::filesystem::remove(path, ec);
				continue;
			}
			
			std::wstring strName = std::filesystem::relative(path, upload, ec);
			if (strName.empty()) {
				std::filesystem::remove(path, ec);
				continue;
			}

			auto hFile = CreateFileW(
				path.c_str(),
				GENERIC_READ | GENERIC_WRITE | DELETE,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				NULL,
				OPEN_EXISTING,
				FILE_FLAG_BACKUP_SEMANTICS,
				NULL);
			if (INVALID_HANDLE_VALUE == hFile) {
				std::filesystem::remove(path, ec);
				continue;
			}

			std::transform(strName.begin(), strName.end(), strName.begin(), towlower);
			RefCounted<CBigFile> pFile(new CBigFile);
			_mBigFile.emplace(std::move(strName), pFile.get());
			std::wstring strVolDir(L">>>>>>>>>>>");
			strVolDir.resize(UFIELD_OFFSET(FILE_RENAME_INFO, FileName) >> 1);
			strVolDir.append(*p.Path);
			pFile->Set(strVolDir, hFile);
			PVOID Context = NULL;
			InitOnceExecuteOnce(pFile->GetInitOnce(), &CDataFactory::InitOnceExecuteBigFile,
				nullptr, (PVOID*)&Context);
		}
	}

	std::thread([this](size_t CcDirsCount) {// 定时清理缓存目录，定时排序
		HRESULT hr;
		std::error_code ec;
		std::vector<CcPath> vCcPath;

		AcquireSRWLockShared(&_vCacheDirsLock);
		for (auto& p : _CacheDirs)
			vCcPath.emplace_back(p, 0);
		ReleaseSRWLockShared(&_vCacheDirsLock);

		for (auto& p : vCcPath) {//清理旧的缓存
			_log.infoW(L"[使用缓存]%s", p.Path->c_str());
			auto oldCcDir = *p.Path / L"NvCacheData\\";
			std::filesystem::remove_all(oldCcDir, ec);
			oldCcDir = *p.Path / L"NvCcData\\";
			std::filesystem::remove_all(oldCcDir, ec);
			//_log.infoW(L"[删除旧缓存]%u, %s", ec.value(), oldCcDir.c_str());
		}

		{
			Sleep(30000);
			//开始处理临时文件
			std::set<ULONGLONG> sUid;
			ConnInfoParam cbConn = { [&sUid](const char* pSeat, ULONGLONG uid, ULONG Flags) {
				if (uid)
					sUid.emplace(uid);
				return false;
				} };

			PluginCallbackParam Param = { CDCtrl_GetConnInfo };
			Param.lpInBuffer = (LPVOID)&cbConn;
			Param.dwInBufferSize = sizeof(cbConn);
			hr = _pDiskPt->SendPluginCallback(ROLE_DISK, &Param, nullptr);
			if (SUCCEEDED(hr)) {
				UserSave::TempFileHandle(vCcPath, sUid);
			}
		}
		vCcPath.clear();

		for (UINT c = 0; ; ++c)
		{
			if (2 == (c % 3)) {//0.5小时清理nv
			//if (1) {
				std::set<std::string> Seats;
				ConnInfoParam cbConn = { [&Seats](const char* pSeat, ULONGLONG uid, ULONG Flags) {
					Seats.emplace(pSeat);
					return false;
					} };

				PluginCallbackParam Param = { CDCtrl_GetConnInfo };
				Param.lpInBuffer = (LPVOID)&cbConn;
				Param.dwInBufferSize = sizeof(cbConn);
				hr = _pDiskPt->SendPluginCallback(ROLE_DISK, &Param, nullptr);
				//if (SUCCEEDED(hr))
				{
					_nvCache.NvClearup(Seats);
				}
			}

			if (3 == (c % 24)) {//1天清理
				RefreshConfig();
				_nvCache.NvClearup(_CcKeepDays[FileKeepTimeType::NvCache]);
				if (3 == (c % 48)) {//2天清理
					_userDisk.DiskClearup(_CcKeepDays[FileKeepTimeType::Disk]);
					_userConfig.CfgClearup(_CcKeepDays[FileKeepTimeType::Arch]);
				}
			}

			{//清理大文件
				std::vector<RefCounted<CBigFile>> vBigFile;
				auto tick = GetTickCount64();
				EnterCriticalSection(&_csBigFile);
				for (auto it = _mBigFile.begin(); it != _mBigFile.end();) {
					if (it->second->IsExpires(tick)) {
						vBigFile.emplace_back(it->second);
						it = _mBigFile.erase(it);
						continue;
					}
					++it;
				}
				LeaveCriticalSection(&_csBigFile);
				for (auto& pFile : vBigFile) {
					pFile->Delete(TRUE);
				}
			}

			auto Wait = WaitForSingleObject(_evtClearup, 600000);
			if (WAIT_OBJECT_0 == Wait) {//http接口请求立即清理
				RefreshConfig();
				_userDisk.DiskClearup(_CcKeepDays[FileKeepTimeType::Disk]);
				UserSave::Clearup(_CcKeepDays[FileKeepTimeType::Arch]);
				continue;
			}

			if (2 == (c % 3)) {//半小时清理ui请求的挂起数据
				UserSave::ClearupTask();
			}

			auto size = GetPrivateProfileIntW(L"DiskCache", L"reserve", 100, g_MainIni.c_str());
			if (size < 100)
				size = 100;
			size *= 4;
			ULONGLONG ReserveSize = (ULONGLONG)size * 1024 * 1024 * 1024;

			AcquireSRWLockShared(&_vCacheDirsLock);
			for (auto& p : _CacheDirs)
				vCcPath.emplace_back(p, 0);
			ReleaseSRWLockShared(&_vCacheDirsLock);

			auto bRecycle = false;
			for (auto& p : vCcPath) {
				auto info = std::filesystem::space(*p.Path, ec);
				if (ec)
					continue;
				p.available = info.available;
				if (info.available <= ReserveSize)
				{//触发回收存档
					if (info.capacity <= ReserveSize) {//磁盘较小时取空闲1/3
						if ((double)info.available / (double)info.capacity < 0.33) {
							bRecycle = true;
						}
					}
					else {
						bRecycle = true;
					}
				}
			}

			//按空闲大小排序
			if (CcDirsCount > 1) {
				// 重新排序
				std::sort(vCcPath.begin(), vCcPath.end(),
					[](CcPath& a, CcPath& b) {
						return a.available > b.available;
					});
				AcquireSRWLockExclusive(&_vCacheDirsLock);
				_CacheDirs.clear();
				for (auto& p : vCcPath) {
					_CacheDirs.emplace_back(p.Path);
				}
				ReleaseSRWLockExclusive(&_vCacheDirsLock);
			}

			vCcPath.clear();

			if (bRecycle) {//回收存档和磁盘
				RefreshConfig();
				_userDisk.DiskClearup(_CcKeepDays[FileKeepTimeType::Disk]);
				UserSave::Clearup(_CcKeepDays[FileKeepTimeType::Arch]);
			}
		}
	}, vCcPath.size()).detach();
	return S_OK;
}

int CDataFactory::Run()
{
	_pDiskPt->RegCallback(ROLE_UserData, [this](IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen) {
		if (_flags & 1)
			return false;
		sender->AddRef();
		_tp->enqueue(
			[](IHttpSession* sender, http_verb hVerb, std::string target) {
				httpProcess_UserData(sender, hVerb, target.c_str(), target.size());
				sender->Release();
			},
			sender, hVerb, std::move(std::string(Target, TargetLen))
		);
		return true;
	});

	_pDiskPt->RegCallback("UserSave", [this](IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen) {
		if (_flags & 1)
			return false;
		sender->AddRef();
		_tp->enqueue(
			[](IHttpSession* sender, http_verb hVerb, std::string target) {
				httpProcess_UserSave(sender, hVerb, target.c_str(), target.size());
				sender->Release();
			},
			sender, hVerb, std::move(std::string(Target, TargetLen))
		);
		return true;
	});
	_pDiskPt->RegCallback("NvCache", [this](IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen) {
		if (_flags & 1)
			return false;
		sender->AddRef();
		_tp->enqueue(
			[this](IHttpSession* sender, http_verb hVerb, std::string target) {
				_nvCache.httpProcess(sender, hVerb, target.c_str(), target.size());
				sender->Release();
			},
			sender, hVerb, std::move(std::string(Target, TargetLen))
		);
		return true;
		});
	_pDiskPt->RegCallback("UserDisk", [this](IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen) {
		if (_flags & 1)
			return false;
		sender->AddRef();
		_tp->enqueue(
			[this](IHttpSession* sender, http_verb hVerb, std::string target) {
				_userDisk.httpProcess(sender, hVerb, target.c_str(), target.size());
				sender->Release();
			},
			sender, hVerb, std::move(std::string(Target, TargetLen))
		);
		return true;
		});

	_pDiskPt->RegCallback("UserCfg", [this](IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen) {
		if (_flags & 1)
			return false;
		sender->AddRef();
		_tp->enqueue(
			[this](IHttpSession* sender, http_verb hVerb, std::string target) {
				_userConfig.httpProcess(sender, hVerb, target.c_str(), target.size());
				sender->Release();
			},
			sender, hVerb, std::move(std::string(Target, TargetLen))
		);
		return true;
		});

	//上传大文件
	_pDiskPt->RegCallback("upload_file", 
		[this](IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen) {
			size_t dataLen = 0;
			auto postData = sender->GetPostData(&dataLen);
			if (nullptr == postData || 0 == dataLen) {
				sender->Response(405, "text/json", R"({"code":1,"msg":"Bad Request"})", 30);
				return true;
			}
			if (_flags & 1)
				return false;

			auto name = sender->GetQueryParam("len", nullptr);
			const auto size = name ? strtoull(name, nullptr, 10) : 0;
			name = sender->GetQueryParam("off", nullptr);
			const auto offset = name ? strtoull(name, nullptr, 10) : 0;
			name = sender->GetQueryParam("size", nullptr);
			const auto file_size = name ? strtoull(name, nullptr, 10) : 0;
			if (0 == size || size != dataLen || size > 512ULL * 1024 * 1024 || 
				offset > 200ULL * 1024 * 1024 * 1024 || file_size > 200ULL * 1024 * 1024 * 1024) {
				sender->Response(405, "text/json", R"({"code":2,"msg":"invalid data len"})", 35);
				_log.errorU(u8"[upload_file]dataLen:%Iu/%llu url:%.*s", dataLen, size, TargetLen, Target);
				return true;
			}

			name = sender->GetQueryParam("name", nullptr);
			auto chunked = sender->GetQueryParam("chunked", nullptr);
			if (nullptr == name || '\0' == name[0] || nullptr == chunked || '\0' == chunked[0]) {
				sender->Response(405, "text/json", R"({"code":3,"msg":"invalid file name"})", 36);
				return true;
			}

			COnceBigFileParam param(chunked, name, file_size);

			{
				EnterCriticalSection(&_csBigFile);
				auto it = _mBigFile.find(param.strName);
				if (it != _mBigFile.end()) {
					param.Self = it->second;
					param.Self->AddRef();
				}
				else {
					param.Self = new CBigFile;
					auto res = _mBigFile.emplace(std::move(param.strName), param.Self);
					param.pName = &res.first->first;
				}
				LeaveCriticalSection(&_csBigFile);
			}

			InitOnceExecuteOnce(param.Self->GetInitOnce(), &CDataFactory::InitOnceExecuteBigFile,
				&param, (PVOID*)&param.Context);
			if (FAILED(param.Context.HighPart)) {
				CStringA strMsg;
				strMsg.Format(R"({"code":4,"msg":"open file is failed:0x%X"})", param.Context.HighPart);
				sender->Response(500, "text/json", strMsg.GetString(), strMsg.GetLength());
				param.Self->Release();
				return true;
			}

			param.Context.HighPart = param.Self->Write(postData, (const LARGE_INTEGER*)&offset, (ULONG)size);
			param.Self->Release();
			if (FAILED(param.Context.HighPart)) {
				CStringA strMsg;
				strMsg.Format(R"({"code":5,"msg":"write file is failed:0x%X"})", param.Context.HighPart);
				sender->Response(500, "text/json", strMsg.GetString(), strMsg.GetLength());
				_log.errorW(L"[upload_file]write file failed 0x%X, off:0x%llX, len:0x%llX, %s", 
					param.Context.HighPart, offset, size, param.pName->c_str());
				return true;
			}
			sender->Response(200, "text/json", R"({"code":0,"msg":"ok"})", 21);
			return true;
		});

	return S_OK;
}

BOOL CALLBACK CDataFactory::InitOnceExecuteBigFile(
	PINIT_ONCE InitOnce, PVOID Parameter, PVOID* Context)
{
	if (nullptr == Parameter)
		return TRUE;

	COnceBigFileParam* param = (COnceBigFileParam*)Parameter;
	std::error_code ec;
	std::wstring strVolDir(L">>>>>>>>>>>");
	auto file = g_Factory.GetCacheDirFront();

	strVolDir.resize(UFIELD_OFFSET(FILE_RENAME_INFO, FileName) >> 1);
	strVolDir.append(LR"(\\?\)");
	strVolDir.append(file.native());

	file /= UPLOAD_PREFIX;
	std::filesystem::create_directories(file, ec);
	file /= *param->pName;

	auto hFile = CreateFileW(
		file.c_str(),
		GENERIC_READ | GENERIC_WRITE | DELETE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		CREATE_ALWAYS,
		FILE_FLAG_BACKUP_SEMANTICS,
		NULL);
	if (INVALID_HANDLE_VALUE == hFile) {
		param->Context.HighPart = HRESULT_FROM_WIN32(GetLastError());
		return FALSE;
	}

	if (param->FileSize.QuadPart)
	{//预申请空间
		if (!SetFileInformationByHandle(hFile, FileEndOfFileInfo, 
			&param->FileSize, sizeof(FILE_END_OF_FILE_INFO))) {
			param->Context.HighPart = HRESULT_FROM_WIN32(GetLastError());
			CloseHandle(hFile);
			return FALSE;
		}
	}
	param->Self->Set(strVolDir, hFile);
	return TRUE;
}

CBigFile* CDataFactory::RemoveBigFile(std::wstring const& name)
{
	CBigFile* pFile = nullptr;
	EnterCriticalSection(&_csBigFile);
	auto it = _mBigFile.find(name);
	if (it != _mBigFile.end()) {
		pFile = it->second;
		_mBigFile.erase(it);
	}
	LeaveCriticalSection(&_csBigFile);
	return pFile;
}

void CDataFactory::RefreshConfig()
{
	int KeepDays;
	KeepDays = GetPrivateProfileIntW(L"UserCache", L"ArchMinKeepDays", 90, g_MainIni.c_str());
	if (KeepDays < 8)
		KeepDays = 7;
	_CcKeepDays[Arch] = KeepDays;
	KeepDays = GetPrivateProfileIntW(L"UserCache", L"NvCacheMinKeepDays", 7, g_MainIni.c_str());
	if (KeepDays < 2)
		KeepDays = 2;
	_CcKeepDays[NvCache] = KeepDays;
	KeepDays = GetPrivateProfileIntW(L"UserCache", L"DiskMinKeepDays", 60, g_MainIni.c_str());
	if (KeepDays < 2)
		KeepDays = 2;
	_CcKeepDays[Disk] = KeepDays;
}

//用户清单缓存清理
void CDataFactory::UserListClearup(DWORD appid)
{
	std::error_code ec;
	WCHAR szTail[24];
	swprintf_s(szTail, L".%u.list", appid);

	auto strListDir = g_current_dir / USER_LIST_DIR;
	for (auto&& p : std::filesystem::recursive_directory_iterator(strListDir, ec)) {
		if (p.is_directory())
			continue;
		if (APPID_SAVEDATA == appid) {

		}
		if (0 == _wcsnicmp(p.path().filename().c_str(), szTail, wcslen(szTail)))
			continue;


	}
}

void CDataFactory::ReqClearup()
{
	SetEvent(_evtClearup);
}

void CDataFactory::GetCacheDataDirs(std::vector<std::shared_ptr<std::filesystem::path>>& vCcDirs)
{
	CRWLockGuard lock(_vCacheDirsLock, FALSE);
	vCcDirs = _CacheDirs;
}

//获取第一个缓存目录
std::filesystem::path CDataFactory::GetCacheDirFront()
{
	CRWLockGuard lock(_vCacheDirsLock, FALSE);
	if (_CacheDirs.empty())
		return L"";
	return *_CacheDirs.front();
}

std::filesystem::path CDataFactory::GetUserTmpDir(UINT uid, BOOL CreateIfNotExist /*= FALSE*/)
{
	std::error_code ec;
	wchar_t ChildPath[40];
	swprintf_s(ChildPath, TMP_PREFIX "%u", uid);
	std::filesystem::path pathUserTemp;

	CRWLockGuard lock(_vCacheDirsLock, !!CreateIfNotExist);
	for (auto& dir : _CacheDirs) {
		pathUserTemp = *dir / ChildPath;
		auto Attrib = GetFileAttributes(pathUserTemp.c_str());
		if (INVALID_FILE_ATTRIBUTES == Attrib)
			continue;
		if (Attrib & FILE_ATTRIBUTE_DIRECTORY)
			return pathUserTemp;
		DeleteFile(pathUserTemp.c_str());
	}
	if (CreateIfNotExist) {
		auto pathUserTemp = *_CacheDirs.front() / ChildPath;
		std::filesystem::create_directories(pathUserTemp, ec);
		return pathUserTemp;
	}
	return std::filesystem::path();
}

BOOL CDataFactory::IsFileExist(_In_ const wchar_t* ChildPath,//"ArchData\8a\1c\8AC1B25923E3F09309D49329976DB1B9F173760A"
	_In_ ULONG PathLen, ULONG KeepIndex /*= ULONG_MAX*/)
{
	std::error_code ec;
	LARGE_INTEGER currft;
	LARGE_INTEGER keepft;
	if (KeepIndex < FileKeepTimeType::FKTT_MAX) {
		GetSystemTimeAsFileTime((LPFILETIME)&currft);
		keepft.QuadPart = currft.QuadPart - (LONGLONG)_CcKeepDays[KeepIndex] * day_to_100ns;
	}

	std::wstring FileName;
	FileName.reserve(CcDirsMaxLength + PathLen + 4);
	FileName.assign(L"\\??\\");

	CRWLockGuard lock(_vCacheDirsLock, FALSE);
	for (auto& dir : _CacheDirs) {
		/*auto Attrib = GetFileAttributes(FileName.c_str());
		if (Attrib & FILE_ATTRIBUTE_DIRECTORY)
			continue;*/

		FileName.resize(4);
		FileName.append(dir->native());
		FileName.append(ChildPath, PathLen);
		UNICODE_STRING usName;
		OBJECT_ATTRIBUTES oa;
		FILE_BASIC_INFORMATION basicInfo;

		usName.Buffer = (PWCH)FileName.c_str();
		usName.Length = (USHORT)(2 * FileName.size());
		usName.MaximumLength = usName.Length + 2;
		InitializeObjectAttributes(&oa, &usName,
			OBJ_CASE_INSENSITIVE, NULL, NULL);
		auto status = ZwQueryAttributesFile(&oa, &basicInfo);
		if (!NT_SUCCESS(status))
			continue;
		if (basicInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			std::filesystem::remove_all(&FileName[4], ec);
			continue;
		}
		if (KeepIndex < FileKeepTimeType::FKTT_MAX &&
			keepft.QuadPart > basicInfo.LastWriteTime.QuadPart)
		{//更新下文件写入时间
			auto hFile = CreateFileW(
				&FileName[4],
				FILE_WRITE_ATTRIBUTES,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL);
			if (INVALID_HANDLE_VALUE != hFile) {
				SetFileTime(hFile, nullptr, nullptr, (LPFILETIME)&currft);
				CloseHandle(hFile);
			}
		}
		return TRUE;
	}
	return FALSE;
}

BOOL CDataFactory::IsFileExist(_In_ const wchar_t* ChildPath,//"ArchData\8a\1c\8AC1B25923E3F09309D49329976DB1B9F173760A"
	_In_ ULONG PathLen, PFILE_BASIC_INFORMATION bsiInfo)
{
	std::error_code ec;

	std::wstring FileName;
	FileName.reserve(CcDirsMaxLength + PathLen + 4);
	FileName.assign(L"\\??\\");

	CRWLockGuard lock(_vCacheDirsLock, FALSE);
	for (auto& dir : _CacheDirs) {
		/*auto Attrib = GetFileAttributes(FileName.c_str());
		if (Attrib & FILE_ATTRIBUTE_DIRECTORY)
			continue;*/

		FileName.resize(4);
		FileName.append(dir->native());
		FileName.append(ChildPath, PathLen);
		UNICODE_STRING usName;
		OBJECT_ATTRIBUTES oa;

		usName.Buffer = (PWCH)FileName.c_str();
		usName.Length = (USHORT)(2 * FileName.size());
		usName.MaximumLength = usName.Length + 2;
		InitializeObjectAttributes(&oa, &usName,
			OBJ_CASE_INSENSITIVE, NULL, NULL);
		auto status = ZwQueryAttributesFile(&oa, bsiInfo);
		if (!NT_SUCCESS(status))
			continue;
		if (bsiInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			std::filesystem::remove_all(&FileName[4], ec);
			continue;
		}
		return TRUE;
	}
	return FALSE;
}

HRESULT CDataFactory::SaveFile(_In_ const wchar_t* ChildPath,//"ArchData\8a\1c\8AC1B25923E3F09309D49329976DB1B9F173760A"
	_In_ ULONG PathLen, const char* pData, size_t DataLen)
{
	BOOLEAN DelFile;
	DWORD dwWritten;
	std::error_code ec;
	LARGE_INTEGER FileSize = { 0 };

	std::wstring FileName;
	FileName.reserve(CcDirsMaxLength + PathLen);

	CRWLockGuard lock(_vCacheDirsLock, TRUE);
	for (auto& dir : _CacheDirs) {
		FileName.assign(dir->native());
		FileName.append(ChildPath, PathLen);
		auto hFile = CreateFileW(
			FileName.c_str(),
			FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
		if (INVALID_HANDLE_VALUE == hFile) {
			dwWritten = GetLastError();
			if (ERROR_FILE_NOT_FOUND == dwWritten || ERROR_PATH_NOT_FOUND == dwWritten)
				continue;
			std::filesystem::remove_all(FileName, ec);
			continue;
		}
		GetFileSizeEx(hFile, &FileSize);
		CloseHandle(hFile);
		if ((size_t)FileSize.QuadPart == DataLen)
			return S_FALSE;
		DeleteFile(FileName.c_str());
	}

	auto file = *_CacheDirs.front() / ChildPath;
	std::filesystem::create_directories(file.parent_path(), ec);
	HANDLE hFile = CreateFileW(
		file.c_str(),
		GENERIC_WRITE | DELETE,
		0,//FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if(INVALID_HANDLE_VALUE == hFile)
		return HRESULT_FROM_WIN32(GetLastError());

	if (!WriteFile(hFile, pData, (DWORD)DataLen, &dwWritten, NULL)) {
		dwWritten = GetLastError();
		DelFile = TRUE;
		SetFileInformationByHandle(hFile, FileDispositionInfo, &DelFile, sizeof(DelFile));
		CloseHandle(hFile);
		return HRESULT_FROM_WIN32(dwWritten);
	}

	CloseHandle(hFile);
	return S_OK;
}

HRESULT CDataFactory::DelHashFile(_In_ const wchar_t* ChildPath,//"ArchData\8a\1c\8AC1B25923E3F09309D49329976DB1B9F173760A"
	_In_ ULONG PathLen, LONGLONG keepTime)
{
	HRESULT hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	FILE_BASIC_INFORMATION basicInfo;
	std::error_code ec;

	std::wstring FileName;
	FileName.reserve(CcDirsMaxLength + PathLen + 4);
	FileName.assign(L"\\??\\");

	CRWLockGuard lock(_vCacheDirsLock, FALSE);
	for (auto& dir : _CacheDirs) {
		FileName.resize(4);
		FileName.append(dir->native());
		FileName.append(ChildPath, PathLen);
		UNICODE_STRING usName;
		OBJECT_ATTRIBUTES oa;

		usName.Buffer = (PWCH)FileName.c_str();
		usName.Length = (USHORT)(2 * FileName.size());
		usName.MaximumLength = usName.Length + 2;
		InitializeObjectAttributes(&oa, &usName,
			OBJ_CASE_INSENSITIVE, NULL, NULL);
		auto status = ZwQueryAttributesFile(&oa, &basicInfo);
		if (!NT_SUCCESS(status))
			continue;
		if (basicInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			std::filesystem::remove_all(&FileName[4], ec);
			continue;
		}

		//对比修改时间
		if (basicInfo.LastWriteTime.QuadPart >= keepTime)
			return S_FALSE;
		//删除文件
		if (DeleteFileW(&FileName[4]))
			return S_OK;
		return HRESULT_FROM_WIN32(GetLastError());
	}
	return hr;
}

LONG CDataFactory::DoOpenFile(
	_In_ const wchar_t* ChildPath,
	_In_ ULONG PathLen,
	_Out_ CDataProvider** pDataProvider)
{
	std::vector<std::shared_ptr<std::filesystem::path>> CcDirs;
	AcquireSRWLockShared(&_vCacheDirsLock);
	CcDirs = _CacheDirs;
	ReleaseSRWLockShared(&_vCacheDirsLock);

	std::wstring FileName;
	FileName.reserve(CcDirsMaxLength + PathLen);

	for (auto& dir : CcDirs) {
		FileName.assign(dir->native());
		FileName.append(ChildPath, PathLen);
		for (int i = 0; i < 3; ++i) {
			if (i) Sleep(200);
			auto hFile = CreateFileW(
				FileName.c_str(),
				FILE_READ_DATA | FILE_WRITE_ATTRIBUTES,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL);
			if (INVALID_HANDLE_VALUE == hFile) {
				auto Error = GetLastError();
				if (ERROR_SHARING_VIOLATION == Error)
					continue;
				if (ERROR_FILE_NOT_FOUND == Error || ERROR_PATH_NOT_FOUND == Error)
					break;
				//return HRESULT_FROM_WIN32(Error);


				break;
			}

			auto pFile = new CDataProvider(hFile);
			if (nullptr == pFile) {
				CloseHandle(hFile);
				return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_MEMORY);
			}
			*pDataProvider = pFile;
			return S_OK;
		}
	}
	return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
}

void CDataFactory::OnEventNotify(
	_In_ PLUGIN_NOTIFY_TYPE NotifyType,
	_In_opt_ PVOID NotifyParam1,
	_In_opt_ PVOID NotifyParam2)
{
	switch (NotifyType)
	{
	case DISK_NETBAR_CLIENT_CONN:
	{
		auto evt = (PCEventNotifyClientConn)NotifyParam1;
		if(0 == evt->uid)
			break;
		if (_flags & 1)
			break;
		//断开超时30S后自动合并清单
		if (0 == evt->Action/* || 10 == evt->Action || 11 == evt->Action*/) {
			auto uid = evt->uid;
			_tp->enqueue([uid]() {
				if (UserSave::MergeTempFiles((UINT)uid) == 0) {
					UserSave::MakeFilesList((UINT)uid);
				}
				});
		}
		break;
	}
	case DISK_PROCESS_IS_TERMINATING:
	{
		Uninit();
		break;
	}
	default:
		break;
	}
}

LONG CDataFactory::DoOpenFile(
	_In_ PCCACHE_CONTEXT pCtxCache,
	_In_ const LARGE_INTEGER* IdOfFile,
	_Out_ IDataProvider** pDataProvider)
{
	if((pCtxCache->AppId & 0xF0000000) != 0x40000000)
		return S_FALSE;//向下传递
	if (_flags & 1)
		return S_FALSE;//向下传递

	auto appid = GetSteamAppId(pCtxCache->AppId);
	int pathLen;
	WCHAR szChildName[64];
	if (APPID_SAVEDATA == appid) {//用户存档文件
		wcscpy_s(szChildName, ARRAYSIZE(szChildName), ARCH_PREFIX);
		pathLen = ARRAYSIZE(ARCH_PREFIX);
	}
	else if (APPID_NVCACHE == appid) {//nvcache文件
		wcscpy_s(szChildName, ARRAYSIZE(szChildName), NVCC_PREFIX);
		pathLen = ARRAYSIZE(NVCC_PREFIX);
	}
	else if (APPID_USERDISK  == appid || APPID_SAVEDATAEXT == appid) {//用户磁盘或用户存档扩展文件
		wcscpy_s(szChildName, ARRAYSIZE(szChildName), USERDISK_PREFIX);
		pathLen = ARRAYSIZE(USERDISK_PREFIX);
	}
	else {
		return S_FALSE;//向下传递
	}

	pathLen += DataFilePath::HashToName(&pCtxCache->Sha, &szChildName[--pathLen]);
	CDataProvider* pFile = nullptr;
	HRESULT hr = DoOpenFile(szChildName, pathLen, &pFile);
	if (FAILED(hr)) {
		_log.errorW(L"[%s]打开数据文件失败! hr:0x%x, appid:%u, file:%s", 
			__FUNCTIONW__, hr, appid, szChildName);
		if (APPID_USERDISK == appid || APPID_SAVEDATAEXT == appid)
			return S_FALSE;//向下传递

		if (APPID_SAVEDATA == appid && HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) == hr) {
			char name[44];
			BinToHexA(&pCtxCache->Sha, name, 20);
			CStringA strRes;
			auto ret = UserSave::Process_LostFile(name, strRes);
			_log.errorU(u8"[%s]del hash(%s):%d %s", __FUNCTION__, name, ret, strRes.GetString());
		}
		return hr;
	}
	*pDataProvider = static_cast<IDataProvider*>(pFile);
	return hr;
}

//下载清单文件同步完成
//如果服务器返回404, 应该返回STATUS_ALREADY_COMPLETE
//应检查数据头部sha判断是否有更新,没有更新时返回STATUS_ALREADY_COMPLETE
LONG CDataFactory::DoGetListFile(_In_ std::function<LONG(PFILES_LIST pData)>const& complete,
	_In_ PCCACHE_CONTEXT pCtxCache, _In_ PCSTR pToken)
{
	return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
}
