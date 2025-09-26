#include "Common.h"
#include "UserDisk.h"

CUserDisk::CUserDisk():
	m_Flags(0)
{
	InitializeCriticalSection(&m_csList);
}

CUserDisk::~CUserDisk()
{
	DeleteCriticalSection(&m_csList);
}

void CUserDisk::httpProcess(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen)
{
	//"/UserDisk/";
	Target += 10;
	TargetLen -= 10;

	if (IsUriPath(Target, TargetLen, "list", 4))//拉取清单
		return CUserDisk::HiPullList(sender);

	if (IsUriPath(Target, TargetLen, "check_files", 11))//过滤文件是否存在，保留需要上传的
		return CUserDisk::HiCheckFile(sender, hVerb, Target + 11, TargetLen - 11);
	if (IsUriPath(Target, TargetLen, "upload_file", 11))//上传文件
		return CUserDisk::HiUploadFile(sender, hVerb, Target + 11, TargetLen - 11);

	if (IsUriPath(Target, TargetLen, "upload_list", 11))//上传本次增量清单
		return CUserDisk::HiUploadList(sender, hVerb, Target + 11, TargetLen - 11);

	if (IsUriPath(Target, TargetLen, "lost_file", 9))//发现文件丢失后手动遍历清单
		return CUserDisk::HiLostFile(sender, Target + 9, TargetLen - 9);

	sender->Response(404, "text/json", nullptr, 0);
}

//拉取清单
void CUserDisk::HiPullList(IHttpSession* sender)
{
	auto name = sender->GetQueryParam("uid", nullptr);
	const auto uid = name ? strtoul(name, nullptr, 10) : 0;
	if (0 == uid) {
		sender->Response(405, "text/json", R"({"code":1,"msg":"Bad Request"})", 30);
		return;
	}
	ULONG AppId = APPID_USERDISK;
	name = sender->GetQueryParam("doc", nullptr);
	if (name && '1' == name[0])
		AppId = APPID_SAVEDATAEXT;

	auto strUid = std::to_wstring(uid);
	auto newList = g_current_dir / USER_LIST_DIR;
	newList /= strUid;
	newList /= strUid + L"." + std::to_wstring(AppId);
	newList += L".list";

	std::string strListData; // 清单数据
	DWORD err = 0;
	{
		EnterCriticalSection(&m_csList);
		CRWLockGuard lock(m_RwList[uid], RW_DELAYLOCK);
		LeaveCriticalSection(&m_csList);

		lock.Lock();
		if (FALSE == QHFile::ReadAll(newList.c_str(), &strListData, &err)) {
			strListData.clear();
		}
	}
	if (strListData.empty()) {
		sender->Response(404, "text/json;charset=utf-8", R"({"code":2,"msg":"Not Found"})", 28);
		if (ERROR_FILE_NOT_FOUND != err && ERROR_PATH_NOT_FOUND != err)
			_log.errorW(L"[%s]读取清单错误:0x%X, file:%s", __FUNCTIONW__, err, newList.c_str());
		return;
	}
	sender->Response(200, "stream/fileslist", strListData.c_str(), strListData.size());
	return;
}

//上传本次增量清单
void CUserDisk::HiUploadList(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen)
{
	size_t dataLen = 0;
	auto postData = sender->GetPostData(&dataLen);
	if (nullptr == postData || 0 == dataLen) {
		sender->Response(405, "text/json", R"({"code":1,"msg":"Bad Request"})", 30);
		return;
	}

	auto name = sender->GetQueryParam("size", nullptr);
	const auto size = name ? strtoull(name, nullptr, 10) : 0;
	name = sender->GetQueryParam("uid", nullptr);
	const auto uid = name ? strtoul(name, nullptr, 10) : 0;
	if (0 == uid) {
		sender->Response(405, "text/json;charset=utf-8", R"({"code":1,"msg":"Bad params"})", 29);
		return;
	}
	if (0 == size || size != dataLen) {
		_log.errorU(u8"[%s]dataLen:%Iu/%llu url:%.*s", __FUNCTION__, dataLen, size, TargetLen, Target);
		sender->Response(405, "text/json", R"({"code":2,"msg":"invalid data len"})", 35);
		return;
	}
	ULONG AppId = APPID_USERDISK;
	name = sender->GetQueryParam("doc", nullptr);
	if (name && '1' == name[0])
		AppId = APPID_SAVEDATAEXT;

	yyjson json(postData, dataLen);
	if (!json.isArr() || 0 == json.GetCount()) {
		sender->Response(405, "text/json", R"({"code":4,"msg":"Bad Request"})", 30);
		return;
	}

	auto strUid = std::to_wstring(uid);
	auto newList = g_current_dir / USER_LIST_DIR;
	newList /= strUid;
	newList /= strUid + L"." + std::to_wstring(AppId);
	newList += L".list";

	std::error_code ec;
	std::filesystem::create_directories(newList.parent_path(), ec);

	// 读入旧清单，然后复刻用户操作
	WCHAR szChildName[64];
	std::string flBuf(INLIST_MAX, '\0');
	std::string oldList;
	std::wstring strFileName;
	std::wstring strNewName;
	DWORD err = 0;
	CACHE_CONTEXT header;
	FILETIME ft = { 0 };

	wcscpy_s(szChildName, ARRAYSIZE(szChildName), USERDISK_PREFIX);

	header.cbSize = sizeof(CACHE_CONTEXT);
	header.LocalFlags = 0;
	header.ChannelSupport = CSF_CDN;
	header.ChannelIndex = CHANNEL_SUPPORT_CDN;
	header.Flags = CACHECTX_FLAG_ENUMALL;
	header.SignOrLen = FILEIOCTL_SIGN;
	header.AppId = AppId | 0x40000000;
	header.FileId = 0;
	header.FileSize.QuadPart = sizeof(CACHE_CONTEXT);
	header.Sha.Ver = 0;
	header.Sha.md5[0].QuadPart = 0;
	header.Sha.md5[1].QuadPart = *(ULONG64*)&ft;
	header.SizeOfHeader = sizeof(CACHE_CONTEXT);

	CList_Order lo(
		[&](LPCWSTR path, size_t len, BOOL bDir) -> ULONG {
			if (!path)
				return 0;

			static std::once_flag flag;
			std::call_once(flag, []() {CrcGenerateTable();});
			auto crc = CrcCalc(path, len << 1);
			if (bDir)
				crc = CrcUpdate(crc, L"\\", 2);
			return crc;
		});
	lo.set_failed_callback([](int err, CStringW& strMsg) {
		_log.errorW(L"[ListGen]err:%d, %s", err, strMsg.GetString());
		});

	auto iter = json.iter();
	yyjson item;
	yyjson newName;

	// 加个锁
	EnterCriticalSection(&m_csList);
	CRWLockGuard lock(m_RwList[uid], RW_EXCLUSIVE | RW_DELAYLOCK);
	LeaveCriticalSection(&m_csList);
	lock.Lock();

	if (!QHFile::ReadAll(newList.c_str(), &oldList, &err)) {
		if (ERROR_FILE_NOT_FOUND != err && ERROR_PATH_NOT_FOUND != err) {
			sender->Response(500, "text/json", R"({"code":4,"msg":"Internal Server Error"})", 40);
			_log.errorW(L"[%s]读取清单错误:0x%X, file:%s", __FUNCTIONW__, err, newList.c_str());
			return;
		}
	}

	if (DecompressList(oldList)) {
		err = lo.set_orglist(oldList);
		if (FAILED(err)) {
			_log.errorW(L"[%s]旧清单错误:0x%X,忽略, file:%s", __FUNCTIONW__, err, newList.c_str());
		}
	}
	else if(0 == err) {
		_log.errorW(L"[%s]解压失败,忽略旧清单, file:%s", __FUNCTIONW__, newList.c_str());
	}
	err = lo.set_header(&header);

//[
//{
//"add":{//有则修改，无则添加
//	"hash":"0b0bd88b6b2901c047b8c223ae5c51236c2f79f1",
//	"path":"aaa.txt",
//	"size":4874612,
//	"attr":32,
//	"time":13345788111235454
//}
//},
//
//{"del":{"name":"ddd.txt"}},
//{"ren":{"aaaa\\bbb\\cc\\dd.txt":"aaaa\\bbb\\cc\\ddd.txt"}},  // dd.txt -> ddd.txt
//{"del":{"name":"aaaa\\bbb\\cc"}},
//{"ren":{"aaaa\\bbb":"aaaa\\bbbbbb"}},
//
//{
//"add":{"hash":"040bd88b6b2901c047b8c223ae5c51236c2f79f2",
//"path":"bbb.txt",
//"size":4874612,
//"attr":32}
//}
//]
	lo.set_auto_add_folder(true);
	while (iter.next(&item)) {
		auto add = item["add"];
		if (add.isObj()) {
			auto hash = add["hash"].toPChar("");
			auto path = add["path"].toPChar("");
			if('\0' == path[0])
				continue;
			auto size = add["size"].toInt64();
			auto attr = add["attr"].toInt();
			auto time = add["time"].toInt64();

			if (attr & FILE_ATTRIBUTE_DIRECTORY) {
				lo.add_folder(path, (LONGLONG)time, attr);
				continue;
			}
			if (strlen(hash) != 40)
				continue;

			lo.add_file(
				path,
				(LONGLONG)time,
				(LONGLONG)size,
				hash,
				CSF_CDN,
				CHANNEL_SUPPORT_CDN,
				attr | FILE_ATTRIBUTE_ARCHIVE
			);
			continue;
		}
		auto del = item["del"];
		if (del.isObj()) {
			auto name = del["name"].toPChar("");
			if ('\0' == name[0])
				continue;

			if (CodeHelper::toW(strFileName, name, -1, CP_UTF8)) {
				std::transform(strFileName.begin(), strFileName.end(), strFileName.begin(), towlower);
				lo.del_item(strFileName.c_str());
			}
			continue;
		}
		auto ren = item["ren"];
		if (ren.isObj()) {
			const char* oldName = nullptr;
			if (!ren.iter().next(&oldName, &newName))
				continue;
			auto name = newName.toPChar("");
			if ('\0' == name[0])
				continue;
			if (0 == CodeHelper::toW(strFileName, oldName, -1, CP_UTF8))
				continue;
			if (0 == CodeHelper::toW(strNewName, name, -1, CP_UTF8))
				continue;

			std::transform(strFileName.begin(), strFileName.end(), strFileName.begin(), towlower);
			lo.ren_item(strFileName.c_str(), strFileName.size(), strNewName.c_str(), strNewName.size());
			continue;
		}
	}

	GetSystemTimeAsFileTime(&ft);
	lo.header()->Sha.md5[1].QuadPart = *(ULONG64*)&ft;

	lo.get_result(oldList);
	if (oldList.size() <= sizeof(CACHE_CONTEXT))
	{//空的
		DeleteFile(newList.c_str());
		sender->Response(200, "text/json", R"({"code":0,"msg":"empty"})", 24);
		return;
	}

	if(!LF::CompressMemToFileW(oldList.data(), oldList.size(), newList.c_str())){
		sender->Response(500, "text/json", R"({"code":500,"msg":"write file error"})", 37);
		return;
	}

	sender->Response(200, "text/json", R"({"code":0,"msg":"ok"})", 21);
	return;
}

//过滤文件是否存在，保留需要上传的
void CUserDisk::HiCheckFile(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen)
{
	size_t dataLen = 0;
	auto postData = sender->GetPostData(&dataLen);
	if (nullptr == postData || 0 == dataLen) {
		sender->Response(405, "text/json", R"({"code":1,"msg":"Bad Request"})", 30);
		return;
	}

	auto name = sender->GetQueryParam("deep", nullptr);
	const auto deepCheck = name ? strtoul(name, nullptr, 10) : 0;
	name = sender->GetQueryParam("steam", nullptr);
	const auto steamCheck = name ? strtoul(name, nullptr, 10) : 0;
	name = sender->GetQueryParam("size", nullptr);
	const auto size = name ? strtoull(name, nullptr, 10) : 0;
	if (0 == size || size != dataLen) {
		_log.errorU(u8"[%s]dataLen:%Iu/%llu url:%.*s", __FUNCTION__, dataLen, size, TargetLen, Target);
		sender->Response(405, "text/json", R"({"code":2,"msg":"invalid data len"})", 35);
		return;
	}
	yyjson json(postData, dataLen);
	if (json.isNull()) {
		sender->Response(405, "text/json", R"({"code":4,"msg":"Bad Request"})", 30);
		return;
	}

	auto pathSteam = g_cache_dir / L"$filelist";
	WCHAR szChildName[64];
	wcscpy_s(szChildName, ARRAYSIZE(szChildName), USERDISK_PREFIX);

	std::error_code ec;
	CACHE_CONTEXT ctx = { 0 };
	ctx.cbSize = sizeof(CACHE_CONTEXT);
	ctx.SignOrLen = FILEIOCTL_SIGN;

	yyjson_mut res(false);
	res["code"] = 0;
	res["msg"] = "ok";
	auto files = res.AddArray("files");

	auto iter = json.iter();
	yyjson val;
	while (iter.next(&val)) {
		auto hash = val["hash"].toPChar("");
		if (strlen(hash) != 40 || !is_hex_string(hash)) {
			_log.errorU(u8"[%s]数据非法，hash:%s", __FUNCTION__, hash);
			continue;
		}

		DataFilePath::HashToName(hash, &szChildName[9]);
		// 看看对应的数据文件还在不在
		if (CDataFactory::Get()->IsFileExist(szChildName, 9 + 46UL, FileKeepTimeType::Disk))//缓存中存在文件
			continue;

		auto steamCM = pathSteam / &szChildName[9];
		steamCM += L".cm";
		if (std::filesystem::exists(steamCM, ec))
			continue;

		HexToBinA(hash, &ctx.Sha, 40);
		PCACHE_FILE pCacheFile = nullptr;
		auto hr = CcGetFile(&pCacheFile, &ctx);
		if (SUCCEEDED(hr)) {
			pCacheFile->Release();
			continue;
		}

		auto file = files.AddObject();
		file.Add((strptr)"hash", (strptr)hash);
	}

	size_t resLen = 0;
	if (deepCheck && 0 != files.GetCount()) {//查询下云端是否有数据，忽略错误
		std::string strResponse;
		LCD::PCompressData pcd = nullptr;
		auto pJson = files.stringfy(&resLen);
		if (resLen > 4096 && LCD::Compress(pJson, resLen, &pcd, &resLen)) {//压缩一下
			files.free(pJson);
			pJson = (char*)pcd;
		}
		CStringA strUrl = "server/upload/check";
		if (steamCheck)
			strUrl += "?steamfile=1";
		auto status = http::Post(strUrl.GetString(), pJson, resLen, &strResponse);
		if (pcd)
			LCD::Free(pcd);
		else
			files.free(pJson);
		if (200 == status) {
			sender->Response(200, "text/json", strResponse.c_str(), strResponse.size());
			return;
		}
	}
	
	auto pJson = res.stringfy(&resLen);
	sender->Response(200, "text/json", pJson, resLen);
	res.free(pJson);
}

//上传文件
void CUserDisk::HiUploadFile(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen)
{
	auto hash = sender->GetQueryParam("hash", nullptr);
	if (nullptr == hash || strlen(hash) != 40 || !is_hex_string(hash)) {
#ifdef _DEBUG
		_log.errorU(u8"[%s]code:1 hash is invalid, url:%.*s", __FUNCTION__, TargetLen, Target);
#endif // _DEBUG
		sender->Response(405, "text/json", R"({"code":1,"msg":"Bad Request"})", 30);
		return;
	}

	WCHAR szChildName[64];
	unsigned char sha1[20];
	FILE_INDEX fid;

	auto name = sender->GetQueryParam("chunked", nullptr);
	if (name && name[0]) {//大文件
		HRESULT hr;
		COnceBigFileParam param(name, hash, 0);
		RefCounted<CBigFile> pFile(CDataFactory::Get()->RemoveBigFile(param.strName));
		if (!pFile) {
			sender->Response(405, "text/json", R"({"code":11,"msg":"file not found"})", 34);
#ifdef _DEBUG
			_log.errorW(L"[%s]BigFile is not found, %s", __FUNCTIONW__, param.strName.c_str());
#endif // _DEBUG
			return;
		}

		HexToBinA(hash, &fid, 40);
		wcscpy_s(szChildName, ARRAYSIZE(szChildName), USERDISK_PREFIX);
		DataFilePath::HashToName(&fid, &szChildName[9]);
		if (CDataFactory::Get()->IsFileExist(szChildName, 9 + 46UL, FileKeepTimeType::Disk)) {//缓存中存在文件
			sender->Response(200, "text/json", R"({"code":0,"msg":"exist"})", 24);
			pFile->Delete(TRUE);
			return;
		}

		for (int i = 0; i < 100; ++i) {
			if (1 == pFile->GetRef())
				break;
			Sleep(50);
		}

		CStringA strMsg;
		hr = pFile->GetHash(sha1);
		if (S_OK != hr) {
			strMsg.Format(R"({"code":12,"msg":"get file hash failed 0x%X"})", hr);
			sender->Response(500, "text/json", strMsg.GetString(), strMsg.GetLength());
			_log.errorW(L"[%s]get file hash failed 0x%X %s", __FUNCTIONW__, hr, param.strName.c_str());
			pFile->Delete(TRUE);
			return;
		}
		if (0 != memcmp(&fid, sha1, sizeof(sha1))) {
#ifdef _DEBUG
			_log.errorU(u8"[%s]code:14 hash is not equal, url:%.*s", __FUNCTION__, TargetLen, Target);
#endif // _DEBUG
			sender->Response(405, "text/json", R"({"code":14,"msg":"Invaild hash"})", 32);
			//pFile->Delete(TRUE);
			return;
		}
		hr = pFile->Rename(szChildName, 9 + 46UL);
		if (S_OK != hr) {
			strMsg.Format(R"({"code":13,"msg":"file rename failed 0x%X"})", hr);
			sender->Response(500, "text/json", strMsg.GetString(), strMsg.GetLength());
			_log.errorW(L"[%s]file rename failed 0x%X %s", __FUNCTIONW__, hr, param.strName.c_str());
			pFile->Delete(TRUE);
			return;
		}
		sender->Response(200, "text/json", R"({"code":0,"msg":"ok"})", 21);
		return;
	}

	size_t dataLen = 0;
	auto postData = sender->GetPostData(&dataLen);
	if (nullptr == postData || 0 == dataLen) {
#ifdef _DEBUG
		_log.errorU(u8"[%s]code:405 PostData is empty, url:%.*s", __FUNCTION__, TargetLen, Target);
#endif // _DEBUG
		sender->Response(405, "text/json", R"({"code":1,"msg":"Bad Request"})", 30);
		return;
	}

	name = sender->GetQueryParam("size", nullptr);
	const auto size = name ? strtoull(name, nullptr, 10) : 0;
	if (0 == size || size != dataLen) {
		_log.errorU(u8"[%s]dataLen:%Iu/%llu url:%.*s", __FUNCTION__, dataLen, size, TargetLen, Target);
		sender->Response(405, "text/json", R"({"code":2,"msg":"invalid data len"})", 35);
		return;
	}

	SHA1_CTX ctx;
	SHA1Init(&ctx);
	SHA1Update(&ctx, (const unsigned char*)postData, (uint32_t)dataLen);
	SHA1Final(sha1, &ctx);

	HexToBinA(hash, &fid, 40);
	if (0 != memcmp(&fid, sha1, sizeof(sha1))) {
#ifdef _DEBUG
		_log.errorU(u8"[%s]code:4 hash is not equal, url:%.*s", __FUNCTION__, TargetLen, Target);
#endif // _DEBUG
		sender->Response(405, "text/json", R"({"code":4,"msg":"Invaild hash"})", 31);
		return;
	}

	wcscpy_s(szChildName, ARRAYSIZE(szChildName), USERDISK_PREFIX);
	DataFilePath::HashToName(&fid, &szChildName[9]);
	auto hr = CDataFactory::Get()->SaveFile(szChildName, 9 + 46UL, postData, dataLen);
	if (FAILED(hr)) {
		CStringA str;
		str.Format(u8R"({"code":5,"msg":"Save file failed(0x%X)."})", hr);
		sender->Response(500, "text/json", str.GetString(), str.GetLength());
		_log.errorW(L"[%s]Save file failed 0x%X %s", __FUNCTIONW__, hr, szChildName);
		return;
	}
	sender->Response(200, "text/json", R"({"code":0,"msg":"ok"})", 21);
}

//发现文件丢失后手动遍历清单
void CUserDisk::HiLostFile(IHttpSession* sender, const char* Target, size_t TargetLen)
{
	size_t dataLen = 0;
	auto postData = sender->GetPostData(&dataLen);
	if (nullptr == postData || 0 == dataLen) {
#ifdef _DEBUG
		_log.errorU(u8"[%s]code:405 PostData is empty, url:%.*s", __FUNCTION__, TargetLen, Target);
#endif // _DEBUG
		sender->Response(405, "text/json", R"({"code":1,"msg":"Bad Request"})", 30);
		return;
	}

	yyjson json(postData, dataLen);
	if (json.isNull()) {
		sender->Response(405, "text/json", R"({"code":4,"msg":"Bad Request"})", 30);
		return;
	}
	auto fs = json["files"];
	auto FileCount = fs.GetCount();
	if (0 == FileCount || !fs.isArr()) {
		sender->Response(405, "text/json;charset=utf-8", R"({"code":2,"msg":"Empty Array"})", 30);
		return;
	}

	std::set<FILE_INDEX, mLess_FileId> sFid;

	size_t successCount = 0;
	FILE_INDEX fid;
	auto files = fs.iter();
	yyjson val;
	while (files.next(&val)) {
		auto name = val.toPChar("");
		if (40 != strlen(name))
			break;

		++successCount;
		HexToBinA(name, &fid, 40);
		sFid.emplace(fid);
	}
	if (successCount != FileCount) {
		CStringA strMsg;
		strMsg.Format(R"({"code":3,"msg":"hash error %Iu/%Iu"})", ++successCount, FileCount);
		sender->Response(405, "text/json;charset=utf-8", strMsg.GetString(), strMsg.GetLength());
		return;
	}

	DiskClearupInfo Info;
	ZeroMemory(&Info, sizeof(Info));
	DiskListClearup(&Info, sFid);

	_log.infoU(u8"[%s]DelListItem:%u, files:%Iu, req:%.*s", __FUNCTION__, Info.DelListItem, FileCount, dataLen, postData);

	CStringA strMsg;
	strMsg.Format(R"({"code":0,"msg":"complete enum list, DelListItem:%u, files:%Iu"})", Info.DelListItem, FileCount);
	sender->Response(200, "text/json;charset=utf-8", strMsg.GetString(), strMsg.GetLength());
}

void CUserDisk::DiskClearup(int KeepDays)
{
	auto cleaning = InterlockedOr(&m_Flags, 1);
	if (cleaning & 1)
		return;

	std::thread([this, KeepDays]() {
		std::set<FILE_INDEX, mLess_FileId> sFid;
		std::vector<std::shared_ptr<std::filesystem::path>> vCcDirs;

		Sleep(200);
		_log.infoU(u8"[%s]%u, 清理用户磁盘及存档扩展", "CUserDisk::DiskClearup", GetCurrentThreadId());

		CDataFactory::Get()->GetCacheDataDirs(vCcDirs);

		/*auto last_time = std::filesystem::file_time_type::clock::now() -
			std::chrono::duration_cast<std::filesystem::file_time_type::duration>(std::chrono::hours(KeepDays * 24));*/
		DiskClearupInfo Info;
		GetSystemTimeAsFileTime((LPFILETIME)&Info.KeepTime);
		Info.KeepTime -= (LONGLONG)KeepDays * day_to_100ns;

		for (auto& p : vCcDirs)
		{
			ZeroMemory(&Info.ShouldDelSize, sizeof(Info) - sizeof(Info.KeepTime));
			sFid.clear();

			auto dir = *p / USERDISK_PREFIX;
			DiskClearup(&Info, sFid, dir, 0);

			if (!sFid.empty())//处理清单中的文件
				DiskListClearup(&Info, sFid);

			_log.infoW(L"[%s]complete KeepDays:%d, ListItem:%u, Tag(%Iu,%lluMB), Should(%u,%lluMB),Deleted(%u,%lluMB),DelFailed(%u,%lluMB),%s",
				L"CUserDisk::DiskClearup", KeepDays, Info.DelListItem,
				sFid.size(), Info.TagSize / (1024 * 1024),
				Info.ShouldDelCount, Info.ShouldDelSize / (1024 * 1024),
				Info.DelCount, Info.DelSize / (1024 * 1024),
				Info.DelFailedCount, Info.DelFailedSize / (1024 * 1024),
				dir.c_str());
		}

		InterlockedAnd(&m_Flags, ~1);
		}
	).detach();
}

void CUserDisk::DiskClearup(PDiskClearupInfo pInfo, std::set<FILE_INDEX, mLess_FileId>& sFid,
	std::filesystem::path const& dir, int level)
{
	std::error_code ec;
	HANDLE Handle;
	WIN32_FIND_DATAW fData;
	FILE_INDEX fid;

	Handle = FindFirstFileW((dir / L"*.*").c_str(), &fData);
	if (INVALID_HANDLE_VALUE == Handle) {
		auto error = GetLastError();
		if (ERROR_PATH_NOT_FOUND == error)
			return;
		_log.errorW(L"[%s]open dir is failed: %u, %s",
			__FUNCTIONW__, error, dir.c_str());
		return;
	}

	do {
		// 1. 跳过 “.” “..”
		if (fData.cFileName[0] == L'.' &&
			(fData.cFileName[1] == L'\0' ||
				(fData.cFileName[1] == L'.' && fData.cFileName[2] == L'\0')))
			continue;

		// 2. 非法目录或文件名直接删掉
		if (fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (level >= 2 || 2 != wcslen(fData.cFileName) || !is_hex_string(fData.cFileName))
			{
				std::filesystem::remove_all(dir / fData.cFileName, ec);
				continue;
			}

			DiskClearup(pInfo, sFid, dir / fData.cFileName, level + 1);
			continue;
		}
		if (level != 2 || 40 != wcslen(fData.cFileName) || !is_hex_string(fData.cFileName))
		{
			std::filesystem::remove(dir / fData.cFileName, ec);
			continue;
		}
		// 3. 取得最后写入时间
		auto lastWrite = *reinterpret_cast<const LONGLONG*>(&fData.ftLastWriteTime);
		// 4. 保留期内直接跳过
		if (lastWrite >= pInfo->KeepTime)
			continue;

		// 5. 取得文件名
		auto file = dir / fData.cFileName;
		// 先删除清单项，文件多保留2天，
		if (lastWrite + kOneYearsIn100ns >= pInfo->KeepTime) {// 第一次发现过期 → 把时间往前拨 1 年
			// 6. 修改文件时间
			DWORD Error = 0;
			HANDLE hFile = CreateFileW(file.c_str(),
				FILE_WRITE_ATTRIBUTES,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				nullptr, OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL, nullptr);
			if (INVALID_HANDLE_VALUE != hFile) {
				lastWrite -= kOneYearsIn100ns;
				SetFileTime(hFile, (PFILETIME)&lastWrite, nullptr, (PFILETIME)&lastWrite);
				CloseHandle(hFile);
			}
			else {
				Error = GetLastError();
				if (0 == Error)
					Error = -1;
			}
			_log.infoW(L"[Clearup]设置删除标记用户磁盘文件:%s(%u), %llu",
				file.c_str(), Error,
				FileTimeToUtc(&fData.ftLastWriteTime, TRUE));

			HexToBinW(fData.cFileName, &fid, 40);
			sFid.emplace(fid);

			pInfo->TagSize += fData.nFileSizeLow;
			if (fData.nFileSizeHigh)
				pInfo->TagSize += ((LONGLONG)fData.nFileSizeHigh << 32);
			continue;
		}

		//如果修改时间在1年之前
		if (pInfo->KeepTime > lastWrite + kOneYearsIn100ns + kGrace2DaysIn100ns) {
			SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_NORMAL);
			auto delSuccess = DeleteFileW(file.c_str());

			_log.infoW(L"[Clearup]删除用户磁盘文件:%s(%u), %llu", 
				file.c_str(), delSuccess ? 0 : GetLastError(), FileTimeToUtc(&fData.ftLastWriteTime, TRUE));

			if (delSuccess) {
				++pInfo->DelCount;      // 统计真正被删的数量
				pInfo->DelSize += fData.nFileSizeLow;
				if (fData.nFileSizeHigh)
					pInfo->DelSize += ((LONGLONG)fData.nFileSizeHigh << 32);
			}
			else {
				++pInfo->DelFailedCount;      // 统计删除失败的数量
				pInfo->DelFailedSize += fData.nFileSizeLow;
				if (fData.nFileSizeHigh)
					pInfo->DelFailedSize += ((LONGLONG)fData.nFileSizeHigh << 32);
			}
			continue;
		}

		++pInfo->ShouldDelCount;
		pInfo->ShouldDelSize += fData.nFileSizeLow;
		if (fData.nFileSizeHigh)
			pInfo->ShouldDelSize += ((LONGLONG)fData.nFileSizeHigh << 32);
	} while (FindNextFileW(Handle, &fData));
	FindClose(Handle);
}

void CUserDisk::DiskListClearup(PDiskClearupInfo pInfo, std::set<FILE_INDEX, mLess_FileId>const& sFid)
{
	HANDLE Handle;
	WIN32_FIND_DATAW fData;
	ULONG FileCount[4] = { 0 };
	UNICODE_STRING usName;
	OBJECT_ATTRIBUTES oa;
	CStringW strListFile;
	std::string ListBuf;

	auto strListDir = g_current_dir / USER_LIST_DIR;
	Handle = FindFirstFileW((strListDir / L"*.*").c_str(), &fData);
	if (INVALID_HANDLE_VALUE == Handle) {
		_log.errorW(L"[%s]open dir is failed: %u, %s",
			__FUNCTIONW__, GetLastError(), strListDir.c_str());
		return;
	}

	InitializeObjectAttributes(&oa, &usName,
		OBJ_CASE_INSENSITIVE, NULL, NULL);
	auto enumListClearup = [this, &oa, pInfo, &FileCount, &ListBuf, &sFid](CStringW const& strListFile, PCWSTR pszUid) {
		DWORD err;
		UINT uid;
		FILE_BASIC_INFORMATION bsiInfo;

		oa.ObjectName->Buffer = (PWCH)strListFile.GetString();
		oa.ObjectName->MaximumLength = oa.ObjectName->Length = (USHORT)(2 * strListFile.GetLength());
		auto status = CDataFactory::Get()->ZwQueryAttributesFile(&oa, &bsiInfo);
		if (!NT_SUCCESS(status) || bsiInfo.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			return;

		ListBuf.clear();
		uid = wcstoul(pszUid, nullptr, 10);
		// 加个锁，防止多个用户同时修改清单
		EnterCriticalSection(&m_csList);
		CRWLockGuard lock(m_RwList[uid], RW_EXCLUSIVE | RW_DELAYLOCK);
		LeaveCriticalSection(&m_csList);
		lock.Lock();

		// 4. 保留期以前的直接删除
		if (*(PLONGLONG)&bsiInfo.LastAccessTime < pInfo->KeepTime) {
			++FileCount[0];
			SetFileAttributesW(strListFile, FILE_ATTRIBUTE_NORMAL);
			auto delSuccess = DeleteFileW(strListFile);
			if (delSuccess)
				++FileCount[1];
			_log.infoW(L"[Clearup]清理用户磁盘清单:%s(%u),过期:%llu",
				pszUid, delSuccess ? 0 : GetLastError(), FileTimeToUtc((LPFILETIME)&bsiInfo.LastAccessTime, TRUE));
			return;
		}

		if (!QHFile::ReadAll(strListFile, &ListBuf, &err)) {
			_log.errorW(L"[DiskListClearup]读取清单错误:0x%X, file:%s", 
				err, pszUid);
			return;
		}
		if (!DecompressList(ListBuf)) {
			_log.errorW(L"[DiskListClearup]读取清单内容错误:%s", pszUid);
			return;
		}

		bool hasModify = false;
		auto pListHeader = (PCACHE_CONTEXT)ListBuf.data();
		if (ListBuf.size() > sizeof(CACHE_CONTEXT) &&
			ListBuf.size() >= (size_t)pListHeader->FileSize.QuadPart &&
			FILEIOCTL_SIGN == pListHeader->SignOrLen) {
			PFILE_ITEM pItemPre = nullptr;
			ULONG cbItemLen = (ULONG)(pListHeader->FileSize.QuadPart - pListHeader->SizeOfHeader);
			for (PFILE_ITEM cur = (PFILE_ITEM)&ListBuf[pListHeader->SizeOfHeader];
				cbItemLen >= sizeof(FILE_ITEM);) {
				if (!(cur->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
					sFid.end() != sFid.find(cur->CcInfo.Sha))
				{
					_log.infoW(L"[Clearup]清理用户磁盘清单,剔除文件:%s(0x%X), %s, %s",
						((PMYFILE_ID)&cur->CcInfo.Sha)->wstr().c_str(), (ULONG_PTR)cur - (ULONG_PTR)pListHeader,
						cur->FileName(), pszUid);

					++pInfo->DelListItem;
					hasModify = true;
					// 删除清单项
					if (pItemPre) {
						if (cur->NextEntryOffset) {
							pItemPre->NextEntryOffset += cur->NextEntryOffset;
							cbItemLen -= cur->NextEntryOffset;
							cur = (PFILE_ITEM)Add2Ptr(cur, cur->NextEntryOffset);
							continue;
						}
						else {
							pItemPre->NextEntryOffset = 0;
							ListBuf.resize((size_t)((ULONG_PTR)cur - (ULONG_PTR)pListHeader));
							break;
						}
					}
					else {
						if (cur->NextEntryOffset) {
							cbItemLen -= cur->NextEntryOffset;
							pItemPre = (PFILE_ITEM)Add2Ptr(cur, cur->NextEntryOffset);
							auto NextEntryOffset = pItemPre->NextEntryOffset;
							if (NextEntryOffset)
								pItemPre->NextEntryOffset += cur->NextEntryOffset;
							else
								NextEntryOffset = pItemPre->FileNameOffset + pItemPre->FileNameLength;
							CopyMemory(cur, pItemPre, NextEntryOffset);
							pItemPre = nullptr;
							continue;
						}
						else {//清单变为空了，直接删除
							++FileCount[2];
							SetFileAttributes(strListFile, FILE_ATTRIBUTE_NORMAL);
							auto delSuccess = DeleteFileW(strListFile);
							if (delSuccess)
								++FileCount[3];
							hasModify = false;

							_log.infoW(L"[Clearup]清理用户磁盘清单:%s(%u)", 
								pszUid, delSuccess ? 0 : GetLastError());
							break;
						}
					}
				}
				if (0 == cur->NextEntryOffset)
					break;
				pItemPre = cur;
				cbItemLen -= cur->NextEntryOffset;
				cur = (PFILE_ITEM)Add2Ptr(cur, cur->NextEntryOffset);
			}
		}

		if (hasModify && FALSE == LF::CompressMemToFileW(ListBuf.data(), ListBuf.size(), strListFile)) {
			_log.errorW(L"[DiskListClearup]写入清单错误, file:%s", strListFile.GetString());
		}
	};

	do {
		if (L'.' == fData.cFileName[0])
			continue;
		if (!(fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			continue;
		auto len = wcslen(fData.cFileName);
		if (len > 10 || !is_number_string(fData.cFileName))
			continue;
		if (10 == len && fData.cFileName[0] > L'4')
			continue;

		strListFile.Format(L"\\??\\%s\\%s\\%s.%u.list", strListDir.c_str(), fData.cFileName, fData.cFileName, APPID_USERDISK);
		enumListClearup(strListFile, &strListFile.GetString()[strListDir.native().size() + 5]);
		strListFile.Format(L"\\??\\%s\\%s\\%s.%u.list", strListDir.c_str(), fData.cFileName, fData.cFileName, APPID_SAVEDATAEXT);
		enumListClearup(strListFile, &strListFile.GetString()[strListDir.native().size() + 5]);

	} while (FindNextFileW(Handle, &fData));
	FindClose(Handle);

	if (FileCount[0] || FileCount[2]) {
		_log.infoW(L"[Clearup]清理用户磁盘清单,过期(%u/%u),清空(%u/%u)",
			FileCount[0], FileCount[1], FileCount[2], FileCount[3]);
	}
}
