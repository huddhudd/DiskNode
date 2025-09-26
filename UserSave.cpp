#include <map>
#include <mutex>
#include <string>
#include <fstream>
#include <filesystem>

#include "Common.h"
#include "UserSave.h"
#include "base64.hpp"
#pragma comment(lib, "Rpcrt4.lib")

sqlite3help g_sh;
std::mutex g_mtxSH; // 修改数据库时需要锁

std::map<std::string, std::shared_ptr<SHAREDTASK>> g_shared_tasks;
std::mutex g_shared_tasks_lock;
long g_shared_threads = 0;
long g_shared_threads_max = 5;

std::map<std::string, std::shared_ptr<USETASK>> g_use_tasks;
std::mutex g_use_tasks_lock;
long g_use_threads = 0;
long g_use_threads_max = 5;

std::map<std::string, std::shared_ptr<SAVETASK>> g_save_tasks;
std::mutex g_save_tasks_lock;
long g_save_threads = 0;
long g_save_threads_max = 5;

//删除列表记录文件(.reqdel)保护
std::mutex g_reqdel_lock;

constexpr auto TASKKEEPTIME = 1800000ULL;

uint64_t FileTimeToUnixTime(const FILETIME& ft) {
	ULARGE_INTEGER ul;
	ul.LowPart = ft.dwLowDateTime;
	ul.HighPart = ft.dwHighDateTime;
	return ul.QuadPart / 10000000ULL - 11644473600ULL;
}

FILETIME FileTimeFromLastWriteTime(const std::filesystem::file_time_type lastWrite) {
	// 将其转换为系统时钟的时间点
	auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
		lastWrite - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now()
	);

	// 计算 Unix 时间以来的 100 纳秒计时
	auto unix_time = std::chrono::duration_cast<std::chrono::nanoseconds>(sctp.time_since_epoch()).count() / 100;

	// 将其转换为 Windows 时间，将 Unix 时间调整到 Windows 时间的基准 (1601-01-01)
	int64_t windows_time = unix_time + 116444736000000000LL + 1;

	// 将 64 位 windows_time 转换为 FILETIME
	FILETIME ft;
	ft.dwLowDateTime = static_cast<DWORD>(windows_time & 0xFFFFFFFF);
	ft.dwHighDateTime = static_cast<DWORD>((windows_time >> 32) & 0xFFFFFFFF);

	return ft;
}

int64_t getTimeStamp()
{
	auto now = std::chrono::system_clock::now();
	auto duration = now.time_since_epoch();
	auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
	return millis;
}

static UINT GetUidFromToken(const char* token)
{
	auto first = strchr(token, '.');
	if (nullptr == first)
		return 0;
	auto end = strchr(++first, '.');
	if (nullptr == end)
		return 0;

	auto str = base64::decode(first, end - first);
	if(str.empty())
		return 0;

	yyjson json(str.c_str(), str.size());
	return json["uid"].toUInt();
}

// 返回UID
UINT GetTokenFromHeader(IHttpSession* sender, std::string& token)
{
	size_t ValLength = 0;
	auto ptr = sender->GetHeaderValue("MyAuthorization", &ValLength);
	if (nullptr == ptr)
		ptr = sender->GetHeaderValue("Authorization", &ValLength);
	if (ptr) {
		token.assign(ptr, ValLength);
		return GetUidFromToken(token.c_str());
	}
	token.clear();
	return 0;
}
 
void UserSave::Init()
{
	HRESULT hr;
	std::error_code ec;
	auto dbPath = g_current_dir / ArchDB_NAME;
	std::filesystem::create_directories(dbPath.parent_path(), ec);
	auto dbfile = dbPath.u8string();
	auto r = g_sh.Open(dbfile.c_str(), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_SHAREDCACHE, nullptr);
	if (r != SQLITE_OK) {
		_log.errorU(u8"[%s]sqlite open failed(%d):%s", __FUNCTION__, r, dbfile.c_str());
		return;
	}

	// 创建表
	const char* create_table_sql[] = {
R"(CREATE TABLE IF NOT EXISTS "DelRecord" (
"id"  INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
"rid"  INTEGER NOT NULL,
"uid"  INTEGER NOT NULL,
"hash"  TEXT,
"file"  TEXT,
"size"  INTEGER,
"time"  INTEGER
);

CREATE INDEX "timeIdx"
ON "DelRecord" ("time" ASC);
)",

R"(CREATE TABLE IF NOT EXISTS "files" (
"id"  INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
"rid"  INTEGER NOT NULL,
"uid"  INTEGER NOT NULL,
"file"  TEXT,
"size"  INTEGER,
"hash"  TEXT,
"creation"  INTEGER,
"attr"  INTEGER,
"ver"  INTEGER,
"rec_time"  INTEGER,
CONSTRAINT "files_unique_uid_file_ver" UNIQUE ("uid", "file", "ver")
);

CREATE INDEX "rid_idx"
ON "files" ("rid" ASC);

CREATE INDEX "uid_idx"
ON "files" ("uid" ASC);

CREATE INDEX "ver_idx"
ON "files" ("ver" ASC);
)",

R"(CREATE TABLE IF NOT EXISTS "history" (
"id"  INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
"rid"  INTEGER  NOT NULL,
"uid"  INTEGER  NOT NULL,
"ver"  INTEGER,
"rec_time"  INTEGER,
"name"  TEXT,
"size"  INTEGER,
"capture"  TEXT,
"comment"  TEXT,
"add"  TEXT,
"inuse"  INTEGER,
CONSTRAINT "history_unique" UNIQUE ("uid", "rid", "ver")
);

CREATE INDEX "uid_hidx"
ON "history" ("uid" ASC);

CREATE INDEX "ver_hidx"
ON "history" ("ver" ASC);
)" };

	for (auto& sql : create_table_sql) {
		hr = g_sh.exec(sql);
	}
	LONG err = GetPrivateProfileIntW(L"local", L"userdoc_cleardb", 0, g_MainIni.c_str());
	if (err) {
		hr = g_sh.exec_direct("VACUUM;");
		WritePrivateProfileStringW(L"local", L"userdoc_cleardb", L"0", g_MainIni.c_str());
		_log.infoW(L"[%s]db VACUUM: %d", __FUNCTIONW__, hr);
	}

	// 设置同步模式为 NORMAL
	hr = g_sh.exec_direct("PRAGMA synchronous=NORMAL;");
	// 启用 WAL 模式
	hr = g_sh.exec_direct("PRAGMA journal_mode=WAL;");
	//在使用这些优化方法时，请确保你了解它们对数据完整性和恢复能力的影响，并根据你的应用需求做出适当的决策。
}

int UserSave::GetTempFiles(std::filesystem::path pathUserTemp, UINT rid, std::vector<TempFileInfo>& files)
{
	if (rid)
		pathUserTemp /= std::to_wstring(rid);

	std::error_code ec;
	if (!std::filesystem::exists(pathUserTemp, ec) || ec) {
		return -1;
	}

	for (auto&& p : std::filesystem::recursive_directory_iterator(pathUserTemp, ec)) {
		if (p.is_directory(ec)) {
			continue;
		}

		auto& file = p.path();
		auto fileName = std::filesystem::relative(file, pathUserTemp, ec);
		if (fileName.empty()) {
			continue;
		}

		TempFileInfo tfi;
		if (rid) {
			tfi.rid = rid;
			tfi.path = fileName;
			tfi.size = p.file_size(ec);
			auto t = FileTimeFromLastWriteTime(p.last_write_time(ec));
			auto unixTime = FileTimeToUnixTime(t);
			tfi.time = unixTime;
		}
		else {
			auto path = wcschr(fileName.c_str(), L'\\'); // 第一层文件夹是规则id
			if (!path) {
				continue;
			}
			path++;

			tfi.rid = wcstoul(fileName.c_str(), nullptr, 10);
			tfi.path = path;
			tfi.size = p.file_size(ec);
			auto t = FileTimeFromLastWriteTime(p.last_write_time(ec));
			auto unixTime = FileTimeToUnixTime(t);
			tfi.time = unixTime;
		}

		files.emplace_back(tfi);
	}
	return (int)files.size();
}

HRESULT DeleteArchivePic(std::filesystem::path path, const int KeepDays)
{
	HANDLE Handle;
	WIN32_FIND_DATAW fData;
	LONGLONG KeepTime;
	GetSystemTimeAsFileTime((LPFILETIME)&KeepTime);
	KeepTime -= (LONGLONG)KeepDays * day_to_100ns;

	Handle = FindFirstFileW((path / L"*.jpg").c_str(), &fData);
	if (INVALID_HANDLE_VALUE == Handle) {
		/*_log.errorW(L"[%s]open dir is failed: %u, %s",
			__FUNCTIONW__, GetLastError(), path.c_str());*/
		return HRESULT_FROM_WIN32(GetLastError());
	}

	do {
		if (fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			continue;
		if (*(PLONGLONG)&fData.ftLastWriteTime > KeepTime)
			continue;

		DeleteFileW((path / fData.cFileName).c_str());
	} while (FindNextFileW(Handle, &fData));
	FindClose(Handle);
	return S_OK;
}

struct mLess_char {
	_NODISCARD bool operator()(const char* _Left, const char* _Right) const {
		return _stricmp(_Left, _Right) < 0;
	}
};

void SplitReqDelFileList(std::string& strFile, const char* seps, std::set<const char*, mLess_char>& sList)
{
	char* next_token = NULL;
	char* token = strtok_s(&strFile[0], seps, &next_token);
	while (NULL != token) {
		sList.insert(token);
		token = strtok_s(NULL, seps, &next_token);
	}
}

int GetReqDelFileSql(PCWSTR pFileName, UINT uid, UINT rid, Int64 ver, CStringA& sqlDel)
{
	std::string strText;
	QHFile::ReadAll(pFileName, &strText);
	if (strText.empty())
		return 0;

	std::set<const char*, mLess_char> sList;
	SplitReqDelFileList(strText,"|\r\n", sList);
	if (sList.empty())
		return 0;
	//DELETE FROM files WHERE uid=1108494 AND rid=666666 AND ver=1743498161385 AND rec_time!=1743498161385 AND file COLLATE NOCASE IN('666666\%uSERPROFILE%\test\test\C盘文件.txt')
	sqlDel.Format("DELETE FROM files WHERE uid=%u AND rid=%u AND ver='%llu' AND rec_time!='%llu' AND file COLLATE NOCASE IN(",
		uid, rid, ver, ver);
	for (auto it : sList) {
		sqlDel.AppendFormat("'%u\\%s',", rid, it);
	}
	sqlDel.SetAt(sqlDel.GetLength() -1, ')');
	return (int)sList.size();
}

//必须在事务内调用
int GeneralNewVersion(UINT uid, Int64 llNow, std::filesystem::path const& pathTempData, std::set<DWORD> const& setRid)
{
	int r;
	sqlite3stmthelp stmtQuery;
	r = g_sh.prepare(stmtQuery, "SELECT id,ver,name FROM history WHERE uid='%u' AND rid=? AND inuse=1", uid);
	if (r != SQLITE_OK) {
		_log.errorU(u8"[%s]%d sqlite prepare failed(%d)", __FUNCTION__, 3, r);
		return -3;
	}

	sqlite3stmthelp stmtSize;
	r = g_sh.prepare(stmtSize, "SELECT sum(size) FROM files WHERE uid='%u' AND rid=? AND ver=%llu", uid, llNow);
	if (r != SQLITE_OK) {
		_log.errorU(u8"[%s]%d sqlite prepare failed(%d)", __FUNCTION__, 4, r);
		return -4;
	}

	sqlite3stmthelp stmtDel;
	r = g_sh.prepare(stmtDel, "SELECT ver FROM history WHERE uid='%u' AND rid=? AND inuse!=1 ORDER BY ver DESC LIMIT -1 OFFSET 9", uid);
	if (r != SQLITE_OK) {
		_log.errorU(u8"[%s]%d sqlite prepare failed(%d)", __FUNCTION__, 5, r);
		return -5;
	}

	/*sqlite3stmthelp stmtVerify;
	r = g_sh.prepare(stmtVerify, "SELECT rid FROM files WHERE uid='%u' AND rid=? AND ver=%llu LIMIT 1", uid, llNow);
	if (r != SQLITE_OK) {
		_log.errorU(u8"[%s]%d sqlite prepare failed(%d)", __FUNCTION__, 6, r);
		return -6;
	}*/

	std::error_code ec;
	size_t size;
	CStringA strSqlDelFiles;
	auto picPath = (g_current_dir / USER_LIST_DIR / std::to_wstring(uid)).wstring();
	picPath.push_back(L'\\');
	auto picPathSize = picPath.size();
	picPath.resize(picPathSize + ARRAYSIZE(L"2147483647.9223372036854775807.jpg  "));
	//picPath.append(L"2147483647.9223372036854775807.jpg  ");
	auto picFileName = picPath.c_str();

	std::vector<Int64> vDelVers;
	std::lock_guard<std::mutex> lock(g_reqdel_lock);
	for (auto& ruleid : setRid) {
		stmtQuery.reset();
		stmtQuery.bind(1, ruleid);

		Int64 OldDefaultId = 0;
		auto name = "";
		r = stmtQuery.step();
		if (r == SQLITE_ROW) {
			OldDefaultId = stmtQuery.GetInt64(0);
			name = stmtQuery.GetText(2, "");
			r = g_sh.exec(R"(INSERT OR IGNORE INTO files (uid, rid, file, size, hash, creation, attr, ver, rec_time) 
							SELECT uid, rid, file, size, hash, creation, attr, %llu, rec_time FROM files WHERE uid='%u' AND rid='%u' AND ver=%llu)",
				llNow, uid, ruleid, stmtQuery.GetInt64(1));
			if (r != SQLITE_OK) {
				return -5;
			}
		}

		strSqlDelFiles.Empty();

		auto file = (pathTempData / std::to_wstring(ruleid)).wstring();
		size = file.size();
		file += DEL_REQ_EXT;
		
		if (GetReqDelFileSql(file.c_str(), uid, ruleid, llNow, strSqlDelFiles) > 0) {
			r = g_sh.exec_direct(strSqlDelFiles);
 
		}

		if (OldDefaultId) {
			r = g_sh.exec("UPDATE history SET inuse=0 WHERE id='%llu'", OldDefaultId);
			if (r != SQLITE_OK) {
				return -6;
			}
		}

		int64_t appSize = 0;
		stmtSize.reset();
		stmtSize.bind(1, ruleid);
		r = stmtSize.step();
		if (SQLITE_ROW == r) {
			appSize = stmtSize.GetInt64(0);
		}

		r = g_sh.exec("INSERT INTO history(uid,rid,ver,rec_time,name,size,inuse) VALUES('%u','%u',%llu,%llu,'%s',%llu,1)",
			uid, ruleid, llNow, llNow, name, appSize);
		if (r != SQLITE_OK) {
			return -7;
		}

		file.resize(size);
		file += L".jpg";

		auto picFile = g_current_dir / USER_LIST_DIR;
		picFile /= std::to_wstring(uid);
		picFile /= std::to_wstring(ruleid);
		picFile += L".";
		picFile += std::to_wstring(llNow);
		picFile += L".jpg";

		std::filesystem::create_directories(picFile.parent_path(), ec);
		CopyFile(file.c_str(), picFile.c_str(), FALSE);
	}

	g_sh.commit();

	g_sh.begin();
	// 保存10个版本，其他的删除
	for (auto& ruleid : setRid) {
		auto file = (pathTempData / std::to_wstring(ruleid)).wstring();
		size = file.size();
		file += DEL_REQ_EXT;
		DeleteFile(file.c_str());
		file.resize(size);
		file += L".jpg";
		DeleteFile(file.c_str());

		vDelVers.clear();
		stmtDel.reset();
		stmtDel.bind(1, ruleid);
		while (stmtDel.step() == SQLITE_ROW) {
			vDelVers.emplace_back(stmtDel.GetInt64(0));
		}
		if (vDelVers.empty())
			continue;

		//SELECT * FROM history WHERE uid=1108494 AND rid=1005 AND inuse!=1 ORDER BY ver DESC LIMIT -1 OFFSET 9
		strSqlDelFiles.Format("DELETE FROM history WHERE uid='%u' AND rid='%u' AND ver IN(",
			uid, ruleid);
		for (auto& v : vDelVers) {
			strSqlDelFiles.AppendFormat("'%llu',", v);
			swprintf_s((PWCHAR)&picFileName[picPathSize], 36, L"%u.%llu.jpg", ruleid, v);
			DeleteFile(picFileName);
		}
		strSqlDelFiles.SetAt(strSqlDelFiles.GetLength() - 1, ')');

		auto pSql = strSqlDelFiles.GetString();
		r = g_sh.exec_direct(pSql);

		memcpy((void*)(pSql + 12), "files  ", 7);
		r = g_sh.exec_direct(pSql);
 
	}

	return SQLITE_OK;
}

int UserSave::MergeTempFiles(UINT uid, UINT rid /*= 0*/)
{
	int r;
	auto pathUserTemp = CDataFactory::Get()->GetUserTmpDir(uid, FALSE);
	if (pathUserTemp.empty())
		return 1;

	if (rid)
		pathUserTemp /= std::to_wstring(rid);

	if (!g_sh.m_db) {
		auto dbPath = g_current_dir / ArchDB_NAME;
		auto dbfile = dbPath.u8string();
		std::lock_guard<std::mutex> guard(g_mtxSH);
		r = g_sh.Open(dbfile.c_str(), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_SHAREDCACHE, nullptr);
		if (r != SQLITE_OK) {
			_log.errorU(u8"[%s]sqlite open failed(%d):%s", __FUNCTION__, r, dbfile.c_str());
			return -1;
		}
	}

	std::error_code ec;
	if (!std::filesystem::exists(pathUserTemp, ec) || ec) {
		if (!rid)
			return 1;

		pathUserTemp += DEL_REQ_EXT;
		auto dwAttrib = GetFileAttributes(pathUserTemp.c_str());
		if (dwAttrib & FILE_ATTRIBUTE_DIRECTORY) {
			return 1;
		}

		std::set<DWORD> setRid;
		setRid.insert(rid);

		std::lock_guard<std::mutex> lock(g_mtxSH);
		g_sh.begin();
		try {
			r = GeneralNewVersion(uid, getTimeStamp(), pathUserTemp.parent_path(), setRid);
			if (r != SQLITE_OK) {
				g_sh.rollback();
				return 1;
			}
			g_sh.commit();
		}
		catch (std::exception const& e) {
			g_sh.rollback();
			_log.errorA("[%s]exception uid:%u, rid:%u, %s", __FUNCTION__,
				uid, rid, e.what());
			return -8;
		}
		return 0;
	}

	sqlite3stmthelp stmtInsert;
	r = g_sh.prepare(stmtInsert, "INSERT INTO files (uid, rid, file, size, hash, creation, attr, ver, rec_time) VALUES(%u, ?, ?, ?, ?, ?, ?, ?, ?)",
		uid);
	if (r != SQLITE_OK) {
		_log.errorU(u8"[%s]%d sqlite prepare failed(%d)", __FUNCTION__, 2, r);
		return -2;
	}

	FILE_INDEX fid;
	int fileCount = 0;
	size_t ridLen = 0;
	std::filesystem::path DataDir = pathUserTemp.parent_path().parent_path();
	CHAR hash[44];
	std::string u8_file;
	std::set<DWORD> setRid;
	if (rid) {
		u8_file = std::to_string(rid);
		u8_file.push_back('\\');
		ridLen = u8_file.size();
		DataDir = DataDir.parent_path();
	}

	WCHAR szChildName[64];
	wcscpy_s(szChildName, ARRAYSIZE(szChildName), ARCH_PREFIX);

	int failed = 0;

	{
		std::lock_guard<std::mutex> lock(g_mtxSH);
		g_sh.begin();
		const auto llNow = getTimeStamp();
		try	{
			for (auto&& p : std::filesystem::recursive_directory_iterator(pathUserTemp, ec)) {
				if (p.is_directory(ec)) {
					continue;
				}

				auto& file = p.path();
				auto fileName = std::filesystem::relative(file, pathUserTemp, ec);
				if (fileName.empty()) {
					continue;
				}
				if (!rid && std::wstring::npos == fileName.native().find(L'\\')) {//忽略根下的文件
					if (fileName.extension() == DEL_REQ_EXT)
						setRid.insert(wcstoul(fileName.c_str(), nullptr, 10));
					continue;
				}

				DWORD dwAttr = GetFileAttributesW(file.c_str());
				auto filesize = p.file_size(ec);
				if (ec) {
					_log.errorA("[%s]GetFileSize failed(%d), %u, %s", __FUNCTION__,
						ec.value(), ec.message().c_str(), file.string().c_str());
					continue;
				}

				if ((LONGLONG)filesize > 0) {
					auto res = GetFileHash(file.c_str(), &fid, false, nullptr);
					if (res <= 0) {
						++failed;
						_log.errorW(L"[%s]GetFileHash failed(%d), %u, %s", __FUNCTIONW__, res, failed, file.c_str());
						continue;
					}

					DataFilePath::HashToName(&fid, &szChildName[9]);
					if (CDataFactory::Get()->IsFileExist(szChildName, 9 + 46UL, FileKeepTimeType::Arch)) {//缓存中存在文件
						DeleteFileW(file.c_str());
					}
					else {
						auto DataFileName = DataDir / szChildName;
						std::filesystem::create_directories(DataFileName.parent_path(), ec);
						if (!MoveFileExW(file.c_str(), DataFileName.c_str(), MOVEFILE_REPLACE_EXISTING)) {
							++failed;
							_log.errorW(L"[%s]MoveFile failed(%d), %u, %s -> %s", __FUNCTIONW__, res, failed, file.c_str(), DataFileName.c_str());
							continue;
						}
					}
					BinToHexA(&fid, hash, 20);
				}
				else {//空文件
					DeleteFileW(file.c_str());
					hash[0] = '\0';
				}

				DWORD ruleid;
				if (rid) {
					ruleid = rid;
					u8_file.resize(ridLen);
					u8_file.append(fileName.u8string());
				}
				else {
					ruleid = wcstoul(fileName.c_str(), nullptr, 10);// 第一层文件夹是规则id
					u8_file = fileName.u8string();
				}

				setRid.insert(ruleid);
				fileCount++;
				auto ft = FileTimeFromLastWriteTime(p.last_write_time(ec));

				stmtInsert.bind(1, ruleid);
				stmtInsert.bind(2, u8_file.c_str());
				stmtInsert.bind(3, p.file_size(ec));
				stmtInsert.bind(4, hash[0] ? hash : "da39a3ee5e6b4b0d3255bfef95601890afd80709");
				stmtInsert.bind(5, *(ULONG64*)&ft);
				stmtInsert.bind(6, dwAttr);
				stmtInsert.bind(7, llNow);
				stmtInsert.bind(8, llNow);
				stmtInsert.step();
				stmtInsert.reset();
			}

			if (rid && setRid.empty()) {
				auto file = pathUserTemp;
				file += DEL_REQ_EXT;
				auto dwAttrib = GetFileAttributes(file.c_str());
				if (!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
					setRid.insert(rid);
				}
			}

			if (!setRid.empty()) {
				if (rid)
					r = GeneralNewVersion(uid, llNow, pathUserTemp.parent_path(), setRid);
				else
					r = GeneralNewVersion(uid, llNow, pathUserTemp, setRid);
				if (r != SQLITE_OK) {
					g_sh.rollback();
					return r;
				}
			}

			g_sh.commit();

			DataDir.clear();
			if (failed == 0) {
				DataDir = pathUserTemp;
				pathUserTemp += L".del." + std::to_wstring(llNow);
				std::filesystem::rename(DataDir, pathUserTemp, ec);
			}
		}
		catch (std::exception const& e) {
			g_sh.rollback();
			_log.errorA("[%s]exception uid:%u, rid:%u, %s", __FUNCTION__,
				uid, rid, e.what());
			return -8;
		}
	}

	if (!DataDir.empty()) {
		std::filesystem::remove_all(DataDir, ec);
	}
	if (failed == 0) {
		std::error_code ec;
		std::filesystem::remove_all(pathUserTemp, ec);
	}
	return 0;
}

int UserSave::DeleteTempFiles(UINT uid, UINT rid /*= 0*/)
{
	auto pathUserTemp = CDataFactory::Get()->GetUserTmpDir(uid, FALSE);
	if (pathUserTemp.empty())
		return 1;

	if (rid)
		pathUserTemp /= std::to_wstring(rid);

	std::error_code ec;
	std::filesystem::remove_all(pathUserTemp, ec);
	if (rid) {
		auto picFile = pathUserTemp;
		picFile += L".jpg";
		DeleteFile(picFile.c_str());

		pathUserTemp += DEL_REQ_EXT;
		DeleteFile(pathUserTemp.c_str());
	}
	return 0;
}

UINT UserSave::DeleteTempFiles(UINT uid, UINT rid, yyjson::iterator& files)
{
	auto pathUserTemp = CDataFactory::Get()->GetUserTmpDir(uid, TRUE);
	auto pathFile = pathUserTemp / std::to_wstring(rid);

	std::string strDelList;
	yyjson val;
	UINT FailedCount = 0;
	while (files.next(&val)) {
		auto name = val.toPChar();
		if (name) {
			strDelList.append(name);
			strDelList.append("|\r\n");

			auto tmp = pathFile / std::filesystem::u8path(name);
			if (!SetFileAttributes(tmp.c_str(), FILE_ATTRIBUTE_ARCHIVE)) {
				auto dwError = GetLastError();
				if (ERROR_FILE_NOT_FOUND == dwError || ERROR_PATH_NOT_FOUND == dwError)
					continue;
			}

			auto delName = pathUserTemp / tmp.filename();
			delName += L".del." + std::to_wstring(time(nullptr));
			if (MoveFileEx(tmp.c_str(), delName.c_str(), MOVEFILE_REPLACE_EXISTING)) {
				DeleteFileW(delName.c_str());
			}
			else if (!DeleteFileW(tmp.c_str())) {
				_log.errorW(L"[%s]del file failed(%u), %s", __FUNCTIONW__, GetLastError(), tmp.c_str());
				++FailedCount;
			}
		}
	}

	pathFile += DEL_REQ_EXT;
	DWORD dwError = S_OK;
	{
		std::lock_guard<std::mutex> lock(g_reqdel_lock);
		HANDLE hFile = CreateFileW(pathFile.c_str(),
			FILE_APPEND_DATA,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE != hFile) {
			DWORD dwBytesWritten;
			if (!WriteFile(hFile, strDelList.data(), (DWORD)strDelList.size(), &dwBytesWritten, NULL))
				dwError = GetLastError();
			CloseHandle(hFile);
		}
		else {
			dwError = GetLastError() | 0x80000000;
		}
	}
	if (S_OK != dwError) {
		_log.errorW(L"[%s]reqdel file write failed(%u), %s", __FUNCTIONW__, dwError, pathFile.c_str());
	}

	return FailedCount;
}

int UserSave::MakeFilesList(UINT uid)
{
	WCHAR szChildName[64];
	wcscpy_s(szChildName, ARRAYSIZE(szChildName), ARCH_PREFIX);

	if (!g_sh.m_db) {
		auto dbPath = g_current_dir / ArchDB_NAME;
		auto dbfile = dbPath.u8string();
		std::lock_guard<std::mutex> guard(g_mtxSH);
		auto r = g_sh.Open(dbfile.c_str(), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_SHAREDCACHE, nullptr);
		if (r != SQLITE_OK) {
			_log.errorU(u8"[%s]sqlite open failed(%d):%s", __FUNCTION__, r, dbfile.c_str());
			return -1;
		}
	}

	sqlite3stmthelp stmtFiles;
	auto r = g_sh.prepare(stmtFiles, "SELECT files.hash,files.file,files.size,files.creation,files.attr FROM files "
		"JOIN history ON files.ver=history.ver AND files.uid=history.uid AND history.rid=files.rid AND history.inuse=1 WHERE files.uid='%u' "
		"ORDER BY files.rid ASC", uid);
	if (r != SQLITE_OK) {
		_log.errorU(u8"[%s]sqlite prepare failed(%d)", __FUNCTION__, r);
		return -2;
	}

	sqlite3stmthelp stmtEmpty;
	r = g_sh.prepare(stmtEmpty, "SELECT rid FROM history h WHERE uid='%llu' AND inuse=1 AND NOT EXISTS("
		"SELECT id FROM files WHERE uid=h.uid AND rid=h.rid and ver=h.ver LIMIT 1)", uid);
	if (r != SQLITE_OK) {
		_log.errorU(u8"[%s]sqlite prepare failed(%d)", __FUNCTION__, r);
		return -3;
	}

	FILETIME ft = { 0 };
	GetSystemTimeAsFileTime(&ft);

	CACHE_CONTEXT header = { 0 };
	header.cbSize = sizeof(CACHE_CONTEXT);
	header.SizeOfHeader = sizeof(CACHE_CONTEXT);
	header.LocalFlags = 0;
	header.ChannelSupport = CSF_CDN;
	header.ChannelIndex = CHANNEL_SUPPORT_CDN;
	header.Flags = CACHECTX_FLAG_ENUMALL;
	header.AppId = APPID_SAVEDATA | 0x40000000;
	header.FileId = 0;
	header.FileSize.QuadPart = sizeof(CACHE_CONTEXT);
	header.Sha.Ver = 0;
	header.Sha.md5[0].QuadPart = 0;
	header.Sha.md5[1].QuadPart = *(ULONG64*)&ft;
	header.SignOrLen = FILEIOCTL_SIGN;

	FileListControl fc;
	fc.set_header(&header);
	fc.set_getfileid_callback(
		[&](LPCWSTR path, BOOL bDir) -> ULONG {
			static std::once_flag flag;
			std::call_once(flag, []() {
				CrcGenerateTable();
				});

			path = wcschr(path, L'\\');
			if (!path) {
				return 0;
			}
			path++;

			auto pathlen = wcslen(path);
			auto crc = CrcCalc(path, pathlen * 2);
			if (bDir) {
				crc = CrcUpdate(crc, L"\\", 2);
			}
			return crc;
		}
	);

	int fileCount = 0;
	DWORD err = 0;
	std::filesystem::path file;
	std::error_code ec;
	std::set<std::string> setFiles;
	FILE_INDEX fid = { 0 };

	{
		std::lock_guard<std::mutex> guard(g_mtxSH);
		while (stmtFiles.step() == SQLITE_ROW) {
			fileCount++;

			auto hash = stmtFiles.GetText(0, "");
			auto path = stmtFiles.GetText(1, "");
			if (!hash[0] || !path[0]) {
				continue;
			}

			if (setFiles.find(path) != setFiles.end()) {
				continue;
			}
			setFiles.insert(path);

			HexToBinA(hash, &fid, 40);
			DataFilePath::HashToName(&fid, &szChildName[9]);
			if (!CDataFactory::Get()->IsFileExist(szChildName, 9 + 46UL)) {//缓存中不存在文件
				g_sh.exec("DELETE FROM files WHERE hash='%s'", hash);
				continue;
			}

			auto size = stmtFiles.GetInt64(2);
			file = std::filesystem::u8path(path);
			fc.add_file(
				file.c_str(),
				size,
				stmtFiles.GetInt64(3),
				&fid,
				CSF_CDN,
				CHANNEL_SUPPORT_CDN,
				stmtFiles.GetInt(4)
			);
		}

		while (stmtEmpty.step() == SQLITE_ROW) {
			fc.add_folder(
				std::to_wstring((UINT)stmtEmpty.GetInt(0)).c_str(),
				*(PLONGLONG)&ft,
				FILE_ATTRIBUTE_DIRECTORY);
		}
	}

	auto strUid = std::to_wstring(uid);
	auto newList = g_current_dir / USER_LIST_DIR;
	newList /= strUid;
	newList /= strUid + L"." + std::to_wstring(APPID_SAVEDATA);
	newList += L".list";

	if (fileCount == 0) {
		DeleteFileW(newList.c_str());
		DeleteArchivePic(newList.parent_path(), 0);
		return 1;
	}

	std::string flBuf;
	auto flSize = fc.get_result_size();
	flBuf.resize(flSize);
	fc.get_result(flBuf.data(), flSize);
	std::filesystem::create_directories(newList.parent_path(), ec);
	if (FALSE == QHFile::WriteAll(newList.c_str(), flBuf.data(), (DWORD)flBuf.size(), &err)) {
		_log.errorW(L"[%s]写入文件失败(%d)：%s", __FUNCTIONW__, err, newList.c_str());
		return -3;
	}

	return 0;
}

int UserSave::GetSaveInfo(UINT uid, UINT rid, const char*& saveinfo)
{
	if (uid == 0) {
		return -1;
	}

	yyjson_mut json(false);
	auto jsonLastVer = json.AddObject("lastVersion");
	auto jsonHistory = json.AddObject("history");
	auto jsonHistoryVers = jsonHistory.AddObject("versions");

	int r;
	sqlite3stmthelp stmt;
	if (rid)
		r = g_sh.prepare(stmt, "SELECT rid,ver FROM history WHERE uid=%u AND inuse=1 AND rid='%u'", uid, rid);
	else
		r = g_sh.prepare(stmt, "SELECT rid,ver FROM history WHERE uid=%u AND inuse=1", uid);
	if (r != SQLITE_OK) {
		_log.errorU(u8"[%s]prepare failed:%d, err:%s sql:%s", __FUNCTION__, r, stmt.GetLastError(), stmt.GetLastSql());
		return -1;
	}

	sqlite3stmthelp stmtQueryFile;
	r = g_sh.prepare(stmtQueryFile, "SELECT file,size,creation FROM files WHERE uid=%u AND rid=? AND ver=?", uid);
	if (r != SQLITE_OK) {
		_log.errorU(u8"[%s]prepare failed:%d, err:%s sql:%s", __FUNCTION__, r, stmtQueryFile.GetLastError(), stmtQueryFile.GetLastSql());
		return -1;
	}

	sqlite3stmthelp stmtQueryHistory;
	r = g_sh.prepare(stmtQueryHistory, "SELECT id,ver,size,rec_time FROM history WHERE uid=%u AND rid=? ORDER BY ver DESC", uid);
	if (r != SQLITE_OK) {
		_log.errorU(u8"[%s]prepare failed:%d, err:%s sql:%s", __FUNCTION__, r, stmtQueryHistory.GetLastError(), stmtQueryHistory.GetLastSql());
		return -1;
	}

	std::map<std::string, int64_t> mapVers;
	while (stmt.step() == SQLITE_ROW) {
		auto n = (DWORD)stmt.GetInt(0);
		auto v = stmt.GetInt64(1);
		mapVers.emplace(std::to_string(n), v);
	}
	stmt.Release();

	size_t totalFiles = 0;
	size_t totalVers = 0;

	for (auto&& [strRid, v] : mapVers) {
		auto item = jsonLastVer.AddObject((strptr)strRid.c_str());
		item.Add("version", v);

		size_t totalSize = 0;
		size_t verFiles = 0;

		stmtQueryFile.bind(1, strRid.c_str());
		stmtQueryFile.bind(2, v);
		for (auto files = item.AddArray("files"); stmtQueryFile.step() == SQLITE_ROW;) {
			verFiles++;
			auto f = stmtQueryFile.GetText(0, "");
			auto fs = stmtQueryFile.GetInt64(1);
			auto t = stmtQueryFile.GetInt64(2);
			totalSize += fs;

			auto path = strchr(f, '\\'); // 第一层文件夹是应用名
			if (path) {
				f = path + 1;
			}

			t = FileTimeToUnixTime(*(FILETIME*)&t);

			auto itemFile = files.AddObject();
			itemFile.Add("file", (strctx)f);
			itemFile.Add("size", fs);
			itemFile.Add("time", t);
		}
		stmtQueryFile.reset();

		item.Add("total_size", totalSize);
		item.Add("total_files", verFiles);
		totalFiles += verFiles;

		stmtQueryHistory.bind(1, strRid.c_str());
		for (auto itemHisVer = jsonHistoryVers.AddArray((strptr)strRid.c_str()); stmtQueryHistory.step() == SQLITE_ROW;) {
			auto item_ = itemHisVer.AddObject();
			item_.Add("id", stmtQueryHistory.GetInt64(0));
			item_.Add("ver", stmtQueryHistory.GetInt64(1));
			item_.Add("size", stmtQueryHistory.GetInt64(2));
			auto t = stmtQueryHistory.GetInt64(3);
			item_.Add("time", (uint64_t)(t / 1000));
			totalVers++;
		}
		stmtQueryHistory.reset();
	}
	jsonHistory.Add("total_versions", totalVers);
	jsonHistory.Add("total_files", totalFiles);

	size_t jsonLen = 0;
	saveinfo = json.stringfy(&jsonLen);
	return (int)jsonLen;
}

void UserSave::TempFileHandle(std::vector<CcPath>const& vCcPath, std::set<ULONGLONG>const& sUid)
{
	for (auto& p : vCcPath)
	{
		auto tmp = *p.Path / TMP_PREFIX;

		std::error_code ec;
		for (const auto& entry : std::filesystem::directory_iterator(tmp, ec))
		{
			if (entry.is_symlink(ec))
				continue;
			if (!entry.is_directory(ec))
				continue;
			
			auto uid = wcstoul(entry.path().filename().c_str(), nullptr, 10);
			if (!uid)
				continue;
			if(sUid.end() != sUid.find(uid))
				continue;

			if (UserSave::MergeTempFiles(uid) == 0) {
				UserSave::MakeFilesList(uid);
			}
		}
	}
}

static int CheckFileList(UINT uid, const char* hash)
{
	auto strUid = std::to_wstring(uid);
	auto newList = g_current_dir / USER_LIST_DIR;
	newList /= strUid;
	newList /= strUid + L"." + std::to_wstring(APPID_SAVEDATA);
	newList += L".list";

	std::string strListData; // 清单数据
	DWORD err = 0;
	if (FALSE == QHFile::ReadAll(newList.c_str(), &strListData, &err)) {
		strListData.clear();
	}

	if (strListData.empty())
		return 2;

	WCHAR szChildName[64];
	wcscpy_s(szChildName, ARRAYSIZE(szChildName), ARCH_PREFIX);

	FILE_INDEX fid;
	if (hash)
		HexToBinA(hash, &fid, 40);

	FILETIME ft = { 0 };
	GetSystemTimeAsFileTime(&ft);

	CACHE_CONTEXT header = { 0 };
	header.cbSize = sizeof(CACHE_CONTEXT);
	header.SizeOfHeader = sizeof(CACHE_CONTEXT);
	header.LocalFlags = 0;
	header.ChannelSupport = CSF_CDN;
	header.ChannelIndex = CHANNEL_SUPPORT_CDN;
	header.Flags = CACHECTX_FLAG_ENUMALL;
	header.AppId = APPID_SAVEDATA | 0x40000000;
	header.FileId = 0;
	header.FileSize.QuadPart = sizeof(CACHE_CONTEXT);
	header.Sha.Ver = 0;
	header.Sha.md5[0].QuadPart = 0;
	header.Sha.md5[1].QuadPart = *(ULONG64*)&ft;
	header.SignOrLen = FILEIOCTL_SIGN;

	FileListControl fc;
	fc.set_header(&header);
	fc.set_getfileid_callback(
		[&](LPCWSTR path, BOOL bDir) -> ULONG {
			static std::once_flag flag;
			std::call_once(flag, []() {
				CrcGenerateTable();
				});

			path = wcschr(path, L'\\');
			if (!path) {
				return 0;
			}
			path++;

			auto pathlen = wcslen(path);
			auto crc = CrcCalc(path, pathlen * 2);
			if (bDir) {
				crc = CrcUpdate(crc, L"\\", 2);
			}
			return crc;
		}
	);

	std::set<std::string> vHash;
	FilesListReader flr(strListData.data());
	for (auto& cur : flr) {
		if (cur->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			continue;
		}

		if (hash) {//仅清除清单
			if (memcmp(&fid, &cur->CcInfo.Sha, sizeof(fid)))
			{
				fc.add_file(
					cur->FileName(),
					cur->CcInfo.FileSize.QuadPart,
					cur->CreationTime.QuadPart,
					&cur->CcInfo.Sha,
					CSF_CDN,
					CHANNEL_SUPPORT_CDN,
					cur->FileAttributes
				);
			}
			continue;
		}

		DataFilePath::HashToName(&cur->CcInfo.Sha, &szChildName[9]);
		if (CDataFactory::Get()->IsFileExist(szChildName, 9 + 46UL, FileKeepTimeType::Arch)) {//缓存中存在文件
			fc.add_file(
				cur->FileName(),
				cur->CcInfo.FileSize.QuadPart,
				cur->CreationTime.QuadPart,
				&cur->CcInfo.Sha,
				CSF_CDN,
				CHANNEL_SUPPORT_CDN,
				cur->FileAttributes
			);
		}
		else {
			_log.warningW(L"[%s]剔除用户 %u 存档清单中的文件：%s, %s", __FUNCTIONW__, 
				uid, ((PMYFILE_ID)&cur->CcInfo.Sha)->wstr().c_str(), cur->FileName());
			vHash.insert(((PMYFILE_ID)&cur->CcInfo.Sha)->str());
		}
	}

	std::string flBuf;
	auto flSize = fc.get_result_size();
	if (flSize <= sizeof(CACHE_CONTEXT))
	{//空的
		DeleteFileW(newList.c_str());
		DeleteArchivePic(newList.parent_path(), 0);
		_log.warningW(L"[%s]用户 %u 存档清单已经空了,删除", __FUNCTIONW__, uid);
	}
	else {
		flBuf.resize(flSize);
		fc.get_result(flBuf.data(), flSize);
		if (FALSE == QHFile::WriteAll(newList.c_str(), flBuf.data(), (DWORD)flBuf.size(), &err)) {
			_log.errorW(L"[%s]写入文件失败(%d)：%s", __FUNCTIONW__, err, newList.c_str());
			return -3;
		}
	}
	
	for (auto& name : vHash)
	{
		std::lock_guard<std::mutex> guard(g_mtxSH);
		g_sh.exec("DELETE FROM files WHERE hash='%s'", name.c_str());
	}

	/*sqlite3stmthelp stmt;
	auto r = g_sh.prepare(stmt, "SELECT uid FROM files WHERE hash=?");
	if (r != SQLITE_OK) {
		_log.errorU(u8"[%s]sqlite prepare failed(%d)", __FUNCTION__, r);
		return -4;
	}

	std::set<UINT> uids;
	for (auto& name : vHash)
	{
		stmt.bind(1, name.c_str(), name.size());
		while (stmt.step() == SQLITE_ROW) {
			uids.insert(stmt.GetInt(0));
		}
		{
			std::lock_guard<std::mutex> guard(g_mtxSH);
			r = g_sh.exec("DELETE FROM files WHERE hash='%s'", name);
		}
	}

	for (auto& uid : uids)
	{
		CheckFileList();
	}*/
	return 0;
}


class CDelFileWork
{
public:
	class CDelFileItem
	{
	public:
		char szHash[40];
		char align;
		bool del;
		unsigned short index;
	};

	CDelFileWork(std::vector<std::shared_ptr<std::filesystem::path>>const& vCcDirs, std::vector<CDelFileItem>& vNeedDelFiles)
	{
		_vCcDirs = vCcDirs;
		_vNeedDelFiles.swap(vNeedDelFiles);
	}
	~CDelFileWork() {}
	void Failed(std::vector<CDelFileItem>& vNeedDelFiles)
	{
		_vNeedDelFiles.swap(vNeedDelFiles);
		delete this;
	}
	DWORD WINAPI DelFilesWorkItem()
	{
		for (auto& df : _vNeedDelFiles) {
			auto path = *_vCcDirs[df.index] / ARCH_PREFIX / DataFilePath(df.szHash).w_str();
			DeleteFileW(path.c_str());
		}
		delete this;
		return 0;
	}
private:
	std::vector<std::shared_ptr<std::filesystem::path>> _vCcDirs;
	std::vector<CDelFileItem> _vNeedDelFiles;
};

void UserSave::Clearup(const int ArchKeepDays)
{
	// 删除超过60天没读取的数据
	// 读取的时间记录在文件的修改时间上， 每次打开文件都会更新修改时间
	std::error_code ec;
	ULONG DelFilesCount = 0; 
	sqlite3stmthelp stmt;
	auto r = g_sh.prepare(stmt, "SELECT uid FROM files WHERE hash=?");
	if (r != SQLITE_OK) {
		_log.errorU(u8"[%s]sqlite prepare failed(%d)", __FUNCTION__, r);
		return ;
	}

	CDelFileWork::CDelFileItem node;
	std::vector<CDelFileWork::CDelFileItem> vPlanDelFiles;
	std::vector<std::shared_ptr<std::filesystem::path>> vCcDirs;
	CDataFactory::Get()->GetCacheDataDirs(vCcDirs);

	_log.infoU(u8"[%s]ArchData Start Recycle, KeepDays:%d", __FUNCTION__, ArchKeepDays);

	node.align = 0;
	vPlanDelFiles.reserve(1000);

	try {
		unsigned short count = (unsigned short)vCcDirs.size();
		for (unsigned short i = 0; i < count; ++i) {
			auto pathCache = *vCcDirs[i] / ARCH_PREFIX;
			for (auto&& p : std::filesystem::recursive_directory_iterator(pathCache, ec)) {
				if (p.is_directory(ec))
					continue;

				auto ftime_epoch =
					std::chrono::time_point_cast<std::chrono::system_clock::duration>(
						p.last_write_time(ec) - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now()
					);

				auto days = std::chrono::duration_cast<std::chrono::hours>(std::chrono::system_clock::now() - ftime_epoch).count() / 24;
				if (days < ArchKeepDays - 7)
					continue;

				auto& path = p.path();
				auto hash = path.filename().string();
				if (hash.size() != (sizeof(node.szHash))) {
					DeleteFileW(path.c_str());
					continue;
				}
				CopyMemory(node.szHash, hash.c_str(), sizeof(node.szHash));
				node.index = i;
				node.del = days > ArchKeepDays;
				vPlanDelFiles.emplace_back(node);
			}
		}
		//generateRule();
	}
	catch (std::exception const& e) {
		//g_sh.rollback();
		_log.errorA("[%s]exception %s", __FUNCTION__,
			e.what());
	}

	_log.infoU(u8"[%s]ArchData PlanDelFiles:%zu", __FUNCTION__, vPlanDelFiles.size());

	std::set<UINT> uids;
	std::vector<CDelFileWork::CDelFileItem> vNeedDelFiles;
	vNeedDelFiles.reserve(100);
	auto pfnThread = &CDelFileWork::DelFilesWorkItem;
	auto llNow = getTimeStamp();

	for (auto& df : vPlanDelFiles)
	{
		bool hasRec = false;
		stmt.bind(1, df.szHash, (int)sizeof(df.szHash));
		while (stmt.step() == SQLITE_ROW) {
			uids.insert(stmt.GetInt(0));
			hasRec = true;
		}
		stmt.reset();
		if (hasRec) {
			if (df.del)
				hasRec = false;
			else
				df.del = true;
		}
		else {
			df.del = false;
		}
		if (hasRec)
			continue;

		++DelFilesCount;
		vNeedDelFiles.emplace_back(df);
		if (vNeedDelFiles.size() < 100)
			continue;

		auto submit = new CDelFileWork(vCcDirs, vNeedDelFiles);
		if (submit) {
			if (!QueueUserWorkItem((LPTHREAD_START_ROUTINE&)pfnThread,
				submit, WT_EXECUTELONGFUNCTION)) {
				submit->Failed(vNeedDelFiles);
			}
			else {
				vNeedDelFiles.reserve(100);
			}
		}
	}

	_log.infoU(u8"[%s]ArchData DelFilesCount:%u", __FUNCTION__, DelFilesCount);

	DelFilesCount = 0;
	{
		//g_sh.begin();

		for (auto& df : vPlanDelFiles)
		{
			if (!df.del)
				continue;
			++DelFilesCount;
			std::lock_guard<std::mutex> guard(g_mtxSH);
			g_sh.exec("INSERT INTO DelRecord (hash, file, size, time, uid, rid) SELECT hash, file, size, %llu, uid, rid FROM files WHERE hash='%s'",
				llNow, df.szHash);
			g_sh.exec("DELETE FROM files WHERE hash='%s'", df.szHash);
		}

		auto tExpired = llNow - (static_cast<long long>(3600000 * 24) * 60);

		{
			std::lock_guard<std::mutex> guard(g_mtxSH);
			g_sh.exec("DELETE FROM DelRecord WHERE time < %llu", tExpired);
		}
		//g_sh.commit();
	}

	_log.infoU(u8"[%s]DELETE files table:%u", __FUNCTION__, DelFilesCount);

	{
		std::vector<CDelFileWork::CDelFileItem> tmp;
		vPlanDelFiles.swap(tmp);
	}

	// 重新生成所有清单
	for (auto uid : uids) {
		MakeFilesList(uid);
	}
	for (auto uid : uids) {
		auto newList = g_current_dir / USER_LIST_DIR;
		newList /= std::to_wstring(uid);
		DeleteArchivePic(newList, ArchKeepDays);
	}

	for (auto& df : vNeedDelFiles) {
		auto path = *vCcDirs[df.index] / ARCH_PREFIX / DataFilePath(df.szHash).w_str();
		DeleteFileW(path.c_str());
	}

	_log.infoU(u8"[%s]ArchData uids count:%zu", __FUNCTION__, uids.size());
	//_log.infoU(u8"[%s]ArchData DelFileCount:%u, DelSize:%lluMB", __FUNCTION__, DelFilesCount, DelSize / (1024 * 1024));
}

int UserSave::AddUse(UINT uid, std::string& token, int64_t id, int64_t sid, std::string& task_id)
{
	{
		std::lock_guard<std::mutex> lock(g_use_tasks_lock);
		for (auto&& [_, task] : g_use_tasks) {
			if (task->id == id && task->sid == sid) {
				if (task->status == 3 || task->status == 2) {
					task_id = _;
					task->sid = sid;
					task->token.swap(token);
					task->status = 0;
					task->comp_time = UINT64_MAX - TASKKEEPTIME;
					begin_use_process();
					return 1;
				}
				else if (task->status == 1) {
					task_id = _;
					return 0;
				}
				return -1;
			}
		}
	}

	// 生成一个UUID作为任务ID
	UUID taskId = { 0 };
	auto r = UuidCreate(&taskId);
	if (r != RPC_S_OK) {
		_log.errorU(u8"[%s]UuidCreate failed, error: %d", __FUNCTION__, r);
		return -2;
	}

	RPC_CSTR taskIdStr = nullptr;
	r = UuidToStringA(&taskId, &taskIdStr);
	if (r != RPC_S_OK) {
		_log.errorU(u8"[%s]UuidToStringA failed, error: %d", __FUNCTION__, r);
		return -3;
	}

	task_id = (char*)taskIdStr;
	RpcStringFreeA(&taskIdStr);

	auto task = std::make_shared<USETASK>();
	task->sid = sid;
	task->id = id;
	task->uid = uid;
	task->token.swap(token);
	task->status = 0;
	task->comp_time = UINT64_MAX - TASKKEEPTIME;

	{
		std::lock_guard<std::mutex> lock(g_use_tasks_lock);
		g_use_tasks.emplace(task_id, task);
	}

	begin_use_process();
	return 0;
}

static bool DownSharedFiles(yyjson::iterator& files, std::string& err)
{
	WCHAR szChildName[64];
	wcscpy_s(szChildName, ARRAYSIZE(szChildName), ARCH_PREFIX);
	ThreadPoolEx tpFile(0, std::thread::hardware_concurrency());
	ThreadPoolEx tp(0, std::thread::hardware_concurrency() * 2);

	std::error_code ec;
	yyjson val;
	std::vector<std::future<bool>> futures;
	bool bFailed = false;
	while (files.next(&val)) {
		auto hash = val["hash"].toPChar("");
		if (strlen(hash) != 40)
			continue;
		DataFilePath::HashToName(hash, &szChildName[9]);
		if (CDataFactory::Get()->IsFileExist(szChildName, 9 + 46UL, FileKeepTimeType::Arch))//缓存中存在文件
			continue;

		futures.emplace_back(tpFile.enqueue(
			[&bFailed, &tp](std::string strHash, size_t size) ->bool {
				if (bFailed) {
					return false;
				}

				const auto pathCurr = CDataFactory::Get()->GetCacheDirFront();
				auto tmp = pathCurr / TMP_PREFIX "download" / DataFilePath(strHash.c_str()).w_str();

				// 先创建文件，并占用空间
				std::error_code ec;
				std::filesystem::create_directories(tmp.parent_path(), ec);

				auto hFile = CreateFileW(tmp.c_str(), 
					GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, nullptr, 
					CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
				if (hFile == INVALID_HANDLE_VALUE) {
					auto Error = GetLastError();
					if (ERROR_SHARING_VIOLATION == Error) {
						// 文件已经存在，直接返回
						_log.warningW(L"[DownSharedFiles]CreateFileW failed, ignore error: %d, file:%s", Error, tmp.c_str());
						return true;
					}
					_log.errorW(L"[DownSharedFiles]CreateFileW failed, error: %d, file:%s", Error, tmp.c_str());
					bFailed = true;
					return false;
				}

				AutoRelease ar([&tmp, &hFile]() {
					if (hFile != INVALID_HANDLE_VALUE) {
						CloseHandle(hFile);
					}

					DeleteFileW(tmp.c_str());
					});

				if (!SetFilePointerEx(hFile, *(LARGE_INTEGER*)&size, nullptr, FILE_BEGIN)) {
					_log.errorW(L"[DownSharedFiles]SetFilePointerEx failed, error: %d, file:%s", GetLastError(), tmp.c_str());
					bFailed = true;
					return false;
				}

				if (!SetEndOfFile(hFile)) {
					_log.errorW(L"[DownSharedFiles]SetEndOfFile failed, error: %d, file:%s", GetLastError(), tmp.c_str());
					bFailed = true;
					return false;
				}

				std::string url = "DataCenter/"; url += DataFilePath(strHash.c_str()).str();
				// 将\\ 替换为/
				std::replace(url.begin(), url.end(), '\\', '/');

				// 分块下载，每块50M
				bool bFailed_ = false;
				for (int i = 0; i < 3; i++) {
					bFailed_ = false;
					std::vector<std::future<bool>> futures_;
					for (size_t offset = 0; offset < size;) {
						auto size_ = min(size - offset, 50 * 1024 * 1024);
						futures_.emplace_back(tp.enqueue(
							[&]() -> bool {
								if (bFailed || bFailed_) {
									return false;
								}
								std::string buf;
								buf.reserve(size_);

								auto s = http::Get(url.c_str(), offset, size_, &buf);
								if (s != 200 && s != 206) {
									_log.errorU(u8"[DownSharedFiles]下载失败! status:%d url:%s", s, url.c_str());
									bFailed_ = true;
									if (s == 404) {
										bFailed = true;
									}
									return false;
								}

								DWORD dwBytesWritten = 0;
								OVERLAPPED ov = { 0 };
								ov.Offset = offset & 0xFFFFFFFF;
								ov.OffsetHigh = offset >> 32;
								if (!WriteFile(hFile, buf.data(), (DWORD)buf.size(), &dwBytesWritten, &ov)) {
									bFailed_ = true;
									return false;
								}

								return true;
							}
						));
						offset += size_;
					}

					std::for_each(futures_.begin(), futures_.end(), [](auto& f) { f.get(); });
					if (bFailed) {
						return false;
					}

					if (!bFailed_) {
						FILE_INDEX fid = { 0 };
						if (GetFileHash(hFile, &fid, nullptr, TRUE)) {
							FILE_INDEX fid2 = { 1 };
							HexToBinA(strHash.c_str(), &fid2, 40);
							if (0 == memcmp(&fid, &fid2, sizeof(fid)))
								break;
						}
					}

					Sleep(1000);
				}

				if (bFailed) {
					return false;
				}

				if (bFailed_) {
					bFailed = true;
					return false;
				}

				CloseHandle(hFile);
				hFile = INVALID_HANDLE_VALUE;

				auto dst = pathCurr / ARCH_PREFIX;
				dst /= DataFilePath(strHash.c_str()).w_str();
				std::filesystem::create_directories(dst.parent_path(), ec);
				MoveFileW(tmp.c_str(), dst.c_str());
				return true;
			},
			hash, val["size"].toUInt64()
		));
	}

	std::for_each(futures.begin(), futures.end(), [](auto& f) { f.get(); });;
	if (bFailed) {
		err = u8"拉取存档文件失败！ 0x9";
	}
	return !bFailed;
}

static bool DownShared(UINT uid, LPCSTR token, int64_t sid, int64_t& id, std::string& err)
{
	std::string url = "/server/usersave/share_down";
	url += "?shared_id=" + std::to_string(sid);
	url += "&uid="; url += std::to_string(uid);
	url += "&token="; url += token;

	std::string strResponse;
	auto status = http::Get(url.c_str(), &strResponse);

	if (status != 200) {
		err = u8"拉取存档失败，请稍候再试！0x1";
		_log.errorU(u8"[%s]拉取存档失败! status:%d, res:%s", __FUNCTION__, status, strResponse.c_str());
		return false;
	}

	yyjson json(strResponse.c_str(), strResponse.size());
	if (json.isNull()) {
		err = u8"拉取存档失败，请稍候再试！0x2";
		_log.errorU(u8"[%s]json解析失败! %s", __FUNCTION__, strResponse.c_str());
		return false;
	}

	if (0 != json["code"].toInt()) {
		err = json["msg"].toPChar("");
		_log.errorU(u8"[%s]拉取存档失败! %s", __FUNCTION__, strResponse.c_str());
		return false;
	}

	auto info = json["data"]["info"];
	auto files = json["data"]["files"].iter();
	if (!DownSharedFiles(files, err)) {
		_log.errorU(u8"[%s]拉取存档文件失败! %s", __FUNCTION__, err.c_str());
		return false;
	}

	auto llNow = getTimeStamp();
	auto rid = info["rid"].toUInt();
	auto name = info["name"].toPChar("");
	auto rec_time = info["rec_time"].toUInt64();
	auto capture = info["capture"].toPChar("");
	auto comment = info["comment"].toPChar("");
	auto add = info["add"].toPChar("");

	sqlite3stmthelp stmt, stmtHistory;
	auto r = g_sh.prepare(stmt, "INSERT INTO files (uid, rid, file, size, hash, creation, attr, ver, rec_time) VALUES(%u, %u, ?, ?, ?, ?, ?, %llu, %llu)",
		uid, rid, llNow, llNow);
	if (r != SQLITE_OK) {
		err = u8"拉取存档失败，请稍候再试！0x4";
		_log.errorU(u8"[%s]prepare failed:%d, err:%s sql:%s", __FUNCTION__, r, stmt.GetLastError(), stmt.GetLastSql());
		return false;
	}
	r = g_sh.prepare(stmtHistory,
		"INSERT INTO history (uid, rid, `ver`, rec_time, `name`, `size`, capture, `comment`, `add`) "
		"VALUES(%u, %u, '%llu', '%llu', ?, ?, ?, ?, ?)",
		uid, rid, llNow, rec_time);
	if (r != SQLITE_OK) {
		err = u8"拉取存档失败，请稍候再试！0x7";
		_log.errorU(u8"[%s]prepare failed:%d, err:%s sql:%s", __FUNCTION__, r, stmtHistory.GetLastError(), stmtHistory.GetLastSql());
		return false;
	}

	yyjson val;
	int64_t total_size = 0;
	files.first();

	{
		std::lock_guard<std::mutex> guard(g_mtxSH);
		g_sh.begin();
		while (files.next(&val)) {
			stmt.reset();
			stmt.bind(1, val["file"].toPChar(""));
			auto size = val["size"].toInt64();
			total_size += size;
			stmt.bind(2, size);
			stmt.bind(3, val["hash"].toPChar(""));
			stmt.bind(4, val["creation"].toUInt64());
			stmt.bind(5, val["attr"].toUInt64());
			r = stmt.step();
		}

		stmtHistory.bind(1, name);
		stmtHistory.bind(2, total_size);
		stmtHistory.bind(3, capture);
		stmtHistory.bind(4, comment);
		stmtHistory.bind(5, add);
		r = stmtHistory.step();
		if (r != SQLITE_DONE) {
			g_sh.rollback();
			err = u8"拉取存档失败，请稍候再试！0x8";
			_log.errorU(u8"[%s]step failed:%d", __FUNCTION__, r);
			return false;
		}

		id = g_sh.last_insert_rowid();
		g_sh.commit();
	}

	return true;
}

static bool UseSave(UINT uid, int64_t id, std::string& err)
{
	sqlite3stmthelp stmt;
	auto r = g_sh.prepare(stmt, "SELECT rid FROM history WHERE id=%llu AND uid='%u'", id, uid);
	if (r != SQLITE_OK) {
		err = u8"应用存档失败，请稍候再试！0x1";
		_log.errorU(u8"[%s]prepare failed:%d, err:%s sql:%s", __FUNCTION__, r, stmt.GetLastError(), stmt.GetLastSql());
		return false;
	}

	r = stmt.step();
	if (r == SQLITE_DONE) {
		err = u8"该存档不存在！0x6";
		return false;
	}
	if (r != SQLITE_ROW) {
		err = u8"应用存档失败，请稍候再试！0x2";
		_log.errorU(u8"[%s]step failed:%d", __FUNCTION__, r);
		return false;
	}

	auto rid = stmt.GetInt(0);
	r = g_sh.prepare(stmt, "SELECT id FROM history WHERE uid='%u' AND rid='%u' AND inuse=1", uid, rid);
	if (r != SQLITE_OK) {
		err = u8"拉取存档失败，请稍候再试！0x3";
		_log.errorU(u8"[%s]prepare failed:%d, err:%s sql:%s", __FUNCTION__, r, stmt.GetLastError(), stmt.GetLastSql());
		return false;
	}
	int64_t idOld = 0;
	r = stmt.step();
	if (r == SQLITE_ROW) {
		idOld = stmt.GetInt64(0);
		if(id == idOld)//默认就是它，不需要切换
			return true;
	}

	{
		std::lock_guard<std::mutex> lock(g_mtxSH);
		g_sh.begin();
		if (idOld) {
			r = g_sh.exec("UPDATE history SET inuse=0 WHERE id='%u'", idOld);
			if (r != SQLITE_OK) {
				err = u8"拉取存档失败，请稍候再试！0x4";
				_log.errorU(u8"[%s]prepare failed:%d", __FUNCTION__, r);
				g_sh.rollback();
				return false;
			}
		}
		r = g_sh.exec("UPDATE history SET inuse=1 WHERE id='%u'", id);
		if (r != SQLITE_OK) {
			err = u8"拉取存档失败，请稍候再试！0x5";
			_log.errorU(u8"[%s]prepare failed:%d", __FUNCTION__, r);
			g_sh.rollback();
			return false;
		}
		g_sh.commit();
	}

	if (UserSave::MakeFilesList(uid) < 0) {
		err = u8"拉取存档失败，请稍候再试！0x6";
		_log.errorU(u8"[%s]MakeFilesList failed", __FUNCTION__);
		return false;
	}
	return true;
}

static void DoUseTask(std::shared_ptr<USETASK> task)
{
	if (0 == task->uid) {
		task->status = 3;
		task->msg = u8"参数错误！";
		return;
	}

	if (task->id) {
		UserSave::MergeTempFiles(task->uid);
		if (false == UseSave(task->uid, task->id, task->msg)) {
			task->status = 3;
			return;
		}
		task->status = 2;
		return;
	}
	else if (task->sid) {
		UserSave::MergeTempFiles(task->uid);

		int64_t id = 0;
		if (false == DownShared(task->uid, task->token.c_str(), task->sid, id, task->msg)) {
			task->status = 3;
			return;
		}
		if (false == UseSave(task->uid, id, task->msg)) {
			task->status = 3;
			return;
		}
		task->status = 2;
		return;
	}
	else {
		task->status = 3;
		task->msg = u8"参数错误！";
		return;
	}
}


void UserSave::thread_use_process()
{
	do {
		std::shared_ptr<USETASK> task = nullptr;

		{
			std::lock_guard<std::mutex> lock(g_use_tasks_lock);
			for (auto&& [_, t] : g_use_tasks) {
				if (t->status == 0) {
					task = t;
					task->status = 1;
					break;
				}
			}
		}

		if (task) {
			DoUseTask(task);
			task->comp_time = GetTickCount64();
		}
		else {
			break;
		}
	} while (true);

	InterlockedDecrement(&g_use_threads);
}

void UserSave::begin_use_process()
{
	auto threads = InterlockedIncrement(&g_use_threads);
	if (threads < g_use_threads_max) {
		std::thread(thread_use_process).detach();
	}
	else {
		InterlockedDecrement(&g_use_threads);
	}
}

int UserSave::AddSave(INT type, UINT uid, UINT rid, std::string& task_id)
{
	{
		std::lock_guard<std::mutex> lock(g_save_tasks_lock);
		for (auto&& [_, task] : g_save_tasks) {
			if (task->uid == uid && task->type == type) {
				if (rid != task->rid)
					continue;

				if (task->status == 3 || task->status == 2) {
					task_id = _;
					task->status = 0;
					task->comp_time = UINT64_MAX - TASKKEEPTIME;
					begin_save_process();
					return 1;
				}
				else if (task->status == 1) {
					task_id = _;
					return 0;
				}
				return -1;
			}
		}
	}

	// 生成一个UUID作为任务ID
	UUID taskId = { 0 };
	auto r = UuidCreate(&taskId);
	if (r != RPC_S_OK) {
		_log.errorU(u8"[%s]UuidCreate failed, error: %d", __FUNCTION__, r);
		return -2;
	}

	RPC_CSTR taskIdStr = nullptr;
	r = UuidToStringA(&taskId, &taskIdStr);
	if (r != RPC_S_OK) {
		_log.errorU(u8"[%s]UuidToStringA failed, error: %d", __FUNCTION__, r);
		return -3;
	}

	task_id = (char*)taskIdStr;
	RpcStringFreeA(&taskIdStr);

	auto task = std::make_shared<SAVETASK>();
	task->uid = uid;
	task->type = type;
	task->rid = rid;
	task->status = 0;
	task->comp_time = UINT64_MAX - TASKKEEPTIME;

	{
		std::lock_guard<std::mutex> lock(g_use_tasks_lock);
		g_save_tasks.emplace(task_id, task);
	}

	begin_save_process();
	return 0;
}

static void DoSaveTask(std::shared_ptr<SAVETASK> task)
{
	if (task->type == 0) {
		auto r = UserSave::MergeTempFiles(task->uid, task->rid);
		if (r < 0) {
			task->status = 3;
			task->msg = u8"存档失败! 0x1";
			_log.errorU(u8"[%s]MakeFilesList failed, 0x1", __FUNCTION__);
			return;
		}
		else if (r == 0 && UserSave::MakeFilesList(task->uid) < 0) {
			task->status = 3;
			task->msg = u8"存档失败! 0x2";
			_log.errorU(u8"[%s]MakeFilesList failed, 0x2", __FUNCTION__);
			return;
		}

	}
	else if (task->type == 1) {
		auto r = UserSave::DeleteTempFiles(task->uid, task->rid);
		if (r < 0) {
			task->status = 3;
			task->msg = u8"操作失败! 0x3";
			_log.errorU(u8"[%s]MakeFilesList failed, 0x3", __FUNCTION__);
			return;
		}
	}

	task->status = 2;
	return;
}

void UserSave::thread_save_process()
{
	do {
		std::shared_ptr<SAVETASK> task = nullptr;

		{
			std::lock_guard<std::mutex> lock(g_save_tasks_lock);
			for (auto&& [_, t] : g_save_tasks) {
				if (t->status == 0) {
					task = t;
					task->status = 1;
					break;
				}
			}
		}

		if (task) {
			DoSaveTask(task);
			task->comp_time = GetTickCount64();
		}
		else {
			break;
		}
	} while (true);

	InterlockedDecrement(&g_save_threads);
}

void UserSave::begin_save_process()
{
	auto threads = InterlockedIncrement(&g_save_threads);
	if (threads < g_save_threads_max) {
		std::thread(thread_save_process).detach();
	}
	else {
		InterlockedDecrement(&g_save_threads);
	}
}

uint64_t UserSave::GetLastSaveId(UINT uid, UINT rid)
{
	if (!uid || !rid)
		return 0;

	sqlite3stmthelp stmt;
	auto r = g_sh.prepare(stmt, "SELECT id FROM history WHERE uid='%u' AND rid='%u' AND inuse=1", uid, rid);
	if (r != SQLITE_OK) {
		return 0;
	}
	if (SQLITE_ROW != stmt.step()) {
		return 0;
	}

	auto id = stmt.GetInt64(0);
	return id;
}

int UserSave::Process_LostFile(const char* hash, CStringA& strRes)
{
	sqlite3stmthelp stmt;
	auto r = g_sh.prepare(stmt, "SELECT uid FROM files WHERE hash=?");
	if (r != SQLITE_OK) {
		_log.errorW(L"[%s]sqlite prepare failed(%d)", __FUNCTIONW__, r);
		return -1;
	}

	std::set<UINT> uids;
	stmt.bind(1, hash, 40);
	while (stmt.step() == SQLITE_ROW) {
		uids.insert(stmt.GetInt(0));
	}
	{
		std::lock_guard<std::mutex> guard(g_mtxSH);
		r = g_sh.exec("DELETE FROM files WHERE hash='%s'", hash);
	}
	if (uids.empty())
		return 0;

	strRes.Format(R"({"code":0,"data":{"deldb":%d,)", r);
	for (auto& uid : uids)
	{
		r = CheckFileList(uid, hash);
		strRes.AppendFormat("\"%u\":%d,", uid, r);
	}
	strRes.SetAt(strRes.GetLength() - 1, '}');
	strRes.Append("}");
	return (int)uids.size();
}

static void httpProcess_UserSaveList(IHttpSession* sender)
{
	std::string token;
	auto uid = GetTokenFromHeader(sender, token);
	if (uid == 0) {
		sender->Response(200, "text/json", R"({"code":1,"msg":"invalid params"})", 33);
		return;
	}

	sqlite3stmthelp stmt;
	auto r = g_sh.prepare(stmt,
		"SELECT rid, size, ver, rec_time FROM history WHERE history.inuse=1 AND history.uid = '%llu'",
		uid);
	if (r != SQLITE_OK) {
		_log.errorW(L"[%s]prepare failed. %d", __FUNCTIONW__, r);
		sender->Response(200, "text/json", R"({"code":2,"msg":"database error"})", 33);
		return;
	}

	yyjson_mut json(false);
	json.Add("code", 0);
	json.Add("msg", "ok");
	auto data = json.AddArray("data");

	while (stmt.step() == SQLITE_ROW) {
		auto rid = (DWORD)stmt.GetInt(0);
		auto size = stmt.GetInt64(1);
		auto ver = stmt.GetInt64(2);
		auto rec_time = stmt.GetInt64(3);

		auto item = data.AddObject();
		item.AddFormat((strptr)"uid", "%u", uid);
		item.Add("rid", rid);
		item.Add("ver", ver);
		item.Add("rec_time", rec_time);
		item.Add("size", size);
		item.AddFormat((strptr)"path", "\\Users\\Save\\%u\\%u", uid, rid);
		item.AddFormat((strptr)"pic", "UserSave/ArchivePic/%u/%u.%llu.jpg", uid, rid, ver);
	}

	size_t strLen = 0;
	auto str = json.stringfy(&strLen);

	sender->Response(200, "text/json", str, strLen);

	json.free(str);
	return;
}

static void httpProcess_UserSaveHistory(IHttpSession* sender)
{
	std::string token;
	const auto uid = GetTokenFromHeader(sender, token);
	auto ptr = sender->GetQueryParam("rid", nullptr);
	const auto rid = ptr ? strtoul(ptr, nullptr, 10) : 0;
	if (0 == uid || 0 == rid) {
		sender->Response(200, "text/json", R"({"code":1,"msg":"invalid params"})", 33);
		return;
	}
	ptr = sender->GetQueryParam("show_files", nullptr);
	BOOL bShowFiles = FALSE;
	if (ptr && *ptr == '1') {
		bShowFiles = TRUE;
	}

	sqlite3stmthelp stmtQuery;
	auto r = g_sh.prepare(stmtQuery, "SELECT * FROM history WHERE uid='%u' AND rid='%u' ORDER BY ver DESC", uid, rid);
	if (r != SQLITE_OK) {
		sender->Response(200, "text/json", R"({"code":2,"msg":"db error"})", 27);
		return;
	}
	sqlite3stmthelp stmtFile;
	r = g_sh.prepare(stmtFile, "SELECT file,size,creation FROM files WHERE uid='%u' AND ver=? AND rid='%u'", uid, rid);
	if (r != SQLITE_OK) {
		sender->Response(200, "text/json", R"({"code":3,"msg":"db error"})", 27);
		return;
	}

	yyjson_mut json(false);
	json.Add("code", 0);
	json.Add("msg", "ok");
	for (auto data = json.AddArray("data"); SQLITE_ROW == stmtQuery.step(); ) {
		auto item = data.AddObject();
		item.Add("id", stmtQuery.GetInt64(0));
		item.Add("uid", uid);
		item.Add("rid", rid);
		auto ver = stmtQuery.GetInt64(3);
		item.Add("ver", ver);
		item.Add("rec_time", stmtQuery.GetInt64(4));
		item.Add("name", (strctx)stmtQuery.GetText(5, ""));
		item.Add("size", stmtQuery.GetInt64(6));
		item.Add("capture", (strctx)stmtQuery.GetText(7, ""));
		item.Add("comment", (strctx)stmtQuery.GetText(8, ""));
		item.Add("add", (strctx)stmtQuery.GetText(9, ""));
		item.Add("inuse", (UINT)stmtQuery.GetInt(10));
		item.AddFormat((strptr)"pic", "UserSave/ArchivePic/%u/%u.%llu.jpg", uid, rid, ver);
		if (bShowFiles) {
			stmtFile.bind(1, ver);
			for (auto files = item.AddArray("files"); stmtFile.step() == SQLITE_ROW;) {
				auto file = files.AddObject();
				file.Add("file", (strctx)stmtFile.GetText(0, ""));
				file.Add("size", stmtFile.GetInt64(1));
				auto time = stmtFile.GetInt64(2);
				file.Add("time", FileTimeToUnixTime(*(FILETIME*)&time));
			}
			stmtFile.reset();
		}
	}

	size_t strLen = 0;
	auto str = json.stringfy(&strLen);
	sender->Response(200, "text/json", str, strLen);

	json.free(str);
	return;
}

static void httpProcess_UserSaveArchivePic(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen)
{// "/1108494/666666.1743996353733.jpg"
	auto pathList = g_current_dir / USER_LIST_DIR;
	pathList += Target;

	std::string strResponse;
	DWORD err = 0;
	if (FALSE == QHFile::ReadAll(pathList.c_str(), &strResponse, &err)) {
		strResponse.clear();
	}

	if (!strResponse.empty()) {
		sender->Response(200, "image/jpeg", strResponse.c_str(), strResponse.size());
		return;
	}

	sender->Response(404, "text/json;charset=utf-8", R"({"code":2,"msg":"Not Found"})", 28);
}

static void httpProcess_UserSaveDelete(IHttpSession* sender)
{
	std::string token;
	auto uid = GetTokenFromHeader(sender, token);
	auto ptr = sender->GetQueryParam("id", nullptr);
	const auto id = ptr ? strtoull(ptr, nullptr, 10) : 0;
	if (0 == uid || 0 == id) {
		sender->Response(200, "text/json", R"({"code":1,"msg":"invalid params"})", 33);
		return;
	}

	sqlite3stmthelp stmtQuery;
	auto r = g_sh.prepare(stmtQuery, "SELECT rid,ver FROM history WHERE uid='%u' and id=%llu", uid, id);
	if (r != SQLITE_OK) {
		sender->Response(200, "text/json", R"({"code":2,"msg":"db error"})", 27);
		_log.errorU(u8"[%s]%d db error. %d", __FUNCTION__, 2, r);
		return;
	}
	sqlite3stmthelp stmtDel;
	r = g_sh.prepare(stmtDel, "delete from files where uid='%u' and rid=? and ver=?", uid);
	if (r != SQLITE_OK) {
		sender->Response(200, "text/json", R"({"code":3,"msg":"db error"})", 27);
		_log.errorU(u8"[%s]%d db error. %d", __FUNCTION__, 3, r);
		return;
	}

	{
		std::lock_guard<std::mutex> lck(g_mtxSH);
		if (stmtQuery.step() != SQLITE_ROW) {
			sender->Response(200, "text/json", u8R"({"code":4,"msg":"该存档不存在!"})", 38);
			return;
		}
		/*DWORD inuse = stmtQuery.GetInt(2);
		if (inuse) {
			sender->Response(200, "text/json", u8R"({"code":5,"msg":"不能删除默认存档!"})", 44);
			return;
		}*/

		r = g_sh.exec("delete from history where uid='%u' and id=%llu", uid, id);
		if (r != SQLITE_OK) {
			sender->Response(200, "text/json", R"({"code":6,"msg":"db error"})", 27);
			_log.errorU(u8"[%s]%d db error. %d", __FUNCTION__, 6, r);
			return;
		}

		DWORD rid = stmtQuery.GetInt(0);
		int64_t ver = stmtQuery.GetInt64(1);
		stmtDel.bind(1, rid);
		stmtDel.bind(2, ver);
		r = stmtDel.step();
		if (r != SQLITE_DONE) {
			sender->Response(200, "text/json", R"({"code":7,"msg":"db error"})", 27);
			_log.errorU(u8"[%s]%d db error. %d", __FUNCTION__, 7, r);
			return;
		}
	}

	sender->Response(200, "text/json", R"({"code":0,"msg":"ok"})", 21);
	return;
}

static void httpProcess_UserSaveName(IHttpSession* sender)
{
	std::string token;
	auto uid = GetTokenFromHeader(sender, token);
	auto ptr = sender->GetQueryParam("id", nullptr);
	const auto id = ptr ? strtoull(ptr, nullptr, 10) : 0;

	size_t nameLen = 0;
	auto pName = sender->GetQueryParam("name", &nameLen);
	if (0 == uid || 0 == id || !pName || nameLen == 0) {
		sender->Response(200, "text/json", R"({"code":1,"msg":"invalid params"})", 33);
		return;
	}
	sqlite3stmthelp stmt;
	auto r = g_sh.prepare(stmt, "UPDATE history SET name=? WHERE uid='%u' and id='%llu'", uid, id);
	if (r != SQLITE_OK) {
		sender->Response(200, "text/json", R"({"code":2,"msg":"db error"})", 27);
		_log.errorU(u8"[%s]%d db error. %d", __FUNCTION__, 2, r);
		return;
	}

	{
		std::lock_guard<std::mutex> lck(g_mtxSH);
		stmt.bind(1, pName, (int)nameLen);
		r = stmt.step();
		if (r != SQLITE_DONE) {
			sender->Response(200, "text/json", R"({"code":3,"msg":"db error"})", 27);
			_log.errorU(u8"[%s]%d db error. %d", __FUNCTION__, 3, r);
			return;
		}
	}

	sender->Response(200, "text/json", R"({"code":0,"msg":"ok"})", 21);
	return;
}

static void httpProcess_UserSaveShare(IHttpSession* sender, http_verb hVerb)
{
	std::string token;
	auto uid = GetTokenFromHeader(sender, token);
	auto ptr = sender->GetQueryParam("rid", nullptr);
	const auto rid = ptr ? strtoul(ptr, nullptr, 10) : 0;
	ptr = sender->GetQueryParam("sid", nullptr);
	const auto sid = ptr ? strtoull(ptr, nullptr, 10) : 0;
	ptr = sender->GetQueryParam("id", nullptr);
	auto id = ptr ? strtoull(ptr, nullptr, 10) : 0;
	if (0 == uid || (0 == id && 0 == rid)) {
		sender->Response(200, "text/json", R"({"code":1,"msg":"invalid params"})", 33);
		return;
	}

	if (0 == id) {
		id = UserSave::GetLastSaveId(uid, rid);
		if (0 == id) {
			sender->Response(200, "text/json", u8R"({"code":4,"msg":"该游戏尚未有存档！"})", 46);
			return;
		}
	}

	size_t postDataLen = 0;
	auto postData = sender->GetPostData(&postDataLen);
	std::string strPostData;
	if (postData && postDataLen) {
		strPostData.assign(postData, postDataLen);
	}

	std::string taskIdStr;
	auto r = UserSave::shared::AddShared(uid, token, id, sid, strPostData, taskIdStr);
	if (r < 0) {
		if (r == -1) {
			sender->Response(200, "text/json", u8R"({"code":3,"msg":"该存档已经提交共享"})", 46);
			return;
		}
		sender->Response(200, "text/json", R"({"code":2,"msg":"error"})", 24);
		return;
	}

	yyjson_mut json(false);
	json.Add("code", 0);
	json.Add("msg", "ok");
	auto data = json.AddObject("data");
	data.Add("task_id", taskIdStr.c_str());

	size_t strLen = 0;
	auto str = json.stringfy(&strLen);

	sender->Response(200, "text/json", str, strLen);

	json.free(str);
	return;
}

static void httpProcess_UserSaveShareTask(IHttpSession* sender)
{
	std::string token;
	auto uid = GetTokenFromHeader(sender, token);
	auto pTaskId = sender->GetQueryParam("task_id", nullptr);
	if (0 == uid && !pTaskId) {
		sender->Response(200, "text/json", R"({"code":1,"msg":"invalid params"})", 33);
		return;
	}

	yyjson_mut json(false);
	json.Add("code", 0);
	json.Add("msg", "ok");
	auto data = json.AddArray("data");

	std::shared_ptr<SHAREDTASK> task = nullptr;
	{
		std::lock_guard<std::mutex> lock(g_shared_tasks_lock);
		if (pTaskId) {
			auto it = g_shared_tasks.find(pTaskId);
			if (it != g_shared_tasks.end()) {
				pTaskId = it->first.c_str();
				task = it->second;
			}
		}
		else {
			for (auto&& [task_id, t] : g_shared_tasks) {
				if (uid == task->h.uid) {
					task = t;
					pTaskId = task_id.c_str();
					break;
				}
			}
		}
	}

	if (task) {
		auto item = data.AddObject();
		item.Add("task_id", (strptr)pTaskId);
		item.Add("status", task->status);
		item.Add("err", (strptr)task->msg.c_str());
		item.Add("db_id", task->h.id);
		item.Add("uid", task->h.uid);
		item.Add("rid", task->h.rid);
		item.Add("ver", task->h.ver);
		item.Add("rec_time", task->h.rec_time);
		item.Add("name", (strptr)task->h.name.c_str());
		item.Add("size", task->h.size);
		item.Add("capture", (strptr)task->h.capture.c_str());
		item.Add("comment", (strptr)task->h.comment.c_str());
		item.Add("add", (strptr)task->h.add.c_str());
		item.Add("uploaded", task->uploaded);
		item.Add("files", task->files);
		item.Add("files_uploaded", task->files_uploaded);
	}

	size_t jsonLen = 0;
	auto jsonStr = json.stringfy(&jsonLen);

	sender->Response(200, "text/json", jsonStr, jsonLen);

	json.free(jsonStr);
	return;
}

static void httpProcess_UserSaveUse(IHttpSession* sender)
{
	std::string token;
	auto uid = GetTokenFromHeader(sender, token);
	auto ptr = sender->GetQueryParam("sid", nullptr);
	const auto sid = ptr ? strtoull(ptr, nullptr, 10) : 0;
	ptr = sender->GetQueryParam("id", nullptr);
	auto id = ptr ? strtoull(ptr, nullptr, 10) : 0;
	if (0 == uid || (0 == sid && 0 == id)) {
		sender->Response(200, "text/json", R"({"code":1,"msg":"invalid params"})", 33);
		return;
	}

	std::string taskIdStr;
	auto r = UserSave::AddUse(uid, token, id, sid, taskIdStr);
	if (r < 0) {
		sender->Response(200, "text/json", R"({"code":2,"msg":"error"})", 24);
		return;
	}

	yyjson_mut json(false);
	json.Add("code", 0);
	json.Add("msg", "ok");
	auto data = json.AddObject("data");
	data.Add("task_id", taskIdStr.c_str());

	size_t strLen = 0;
	auto str = json.stringfy(&strLen);

	sender->Response(200, "text/json", str, strLen);

	json.free(str);
}

static void httpProcess_UserSaveUseTask(IHttpSession* sender)
{
	std::string token;
	auto uid = GetTokenFromHeader(sender, token);
	auto pTaskId = sender->GetQueryParam("task_id", nullptr);
	if (!pTaskId && 0 == uid) {
		sender->Response(200, "text/json", R"({"code":1,"msg":"invalid params"})", 33);
		return;
	}
	yyjson_mut json(false);
	json.Add("code", 0);
	json.Add("msg", "ok");
	auto data = json.AddArray("data");

	std::shared_ptr<USETASK> task = nullptr;
	{
		std::lock_guard<std::mutex> lock(g_use_tasks_lock);
		if (pTaskId) {
			auto it = g_use_tasks.find(pTaskId);
			if (it != g_use_tasks.end()) {
				pTaskId = it->first.c_str();
				task = it->second;
			}
		}
		else {
			for (auto&& [task_id, t] : g_use_tasks) {
				if (uid == task->uid) {
					task = t;
					pTaskId = task_id.c_str();
					break;
				}
			}
		}
	}

	if (task) {
		auto item = data.AddObject();
		item.Add("task_id", (strptr)pTaskId);
		item.Add("status", task->status);
		item.Add("err", (strptr)task->msg.c_str());
		item.Add("id", task->id);
		item.Add("uid", task->uid);
	}

	size_t jsonLen = 0;
	auto jsonStr = json.stringfy(&jsonLen);

	sender->Response(200, "text/json", jsonStr, jsonLen);

	json.free(jsonStr);
	return;
}

static void httpProcess_UserSaveUnSaveInfo(IHttpSession* sender)
{
	std::string token;
	auto uid = GetTokenFromHeader(sender, token);
	auto ptr = sender->GetQueryParam("rid", nullptr);
	const auto rid = ptr ? strtoul(ptr, nullptr, 10) : 0;
	int r;
	if (0 == uid) {
		sender->Response(200, "text/json", R"({"code":1,"msg":"invalid params"})", 33);
		return;
	}

	auto pathUserTemp = CDataFactory::Get()->GetUserTmpDir(uid, FALSE);
	if (pathUserTemp.empty()) {
		sender->Response(200, "text/json", R"({"code":2,"msg":"tmp dir is empty"})", 35);
		return;
	}

	std::vector<UserSave::TempFileInfo> vecTempFiles;
	r = UserSave::GetTempFiles(pathUserTemp, rid, vecTempFiles);

	yyjson_mut ret(false);
	ret.Add("code", 0);
	auto json = ret.AddObject("data");
	auto unsaved = json.AddObject("unsaved");
	auto files = unsaved.AddObject("files");

	std::map<UINT, yyjson_mut> mRuleIds;
	size_t totalFiles = 0;
	size_t totalSize = 0;
	for (auto&& tf : vecTempFiles) {
		auto fit = mRuleIds.find(tf.rid);
		if (fit == mRuleIds.end()) {
			//item = files.AddArray((strctx)std::to_string(tf.rid).c_str()).AddObject();
			auto it = mRuleIds.emplace(tf.rid, files.AddArray((strctx)std::to_string(tf.rid).c_str()));
			fit = it.first;
		}

		totalFiles++;
		totalSize += tf.size;

		yyjson_mut item = fit->second.AddObject();
		item.Add("file", (strctx)tf.path.u8string().c_str());
		item.Add("size", tf.size);
		item.Add("time", tf.time);
	}
	unsaved.Add("total_size", totalSize);
	unsaved.Add("total_files", totalFiles);

	std::vector<std::filesystem::path> vDelFiles;
	if (rid) {
		auto path = pathUserTemp / std::to_wstring(rid);
		path += DEL_REQ_EXT;
		/*auto Attrib = GetFileAttributesW(path.c_str());
		if (!(Attrib & FILE_ATTRIBUTE_DIRECTORY))*/
		vDelFiles.emplace_back(std::move(path));
	}
	else {
		std::error_code ec;
		for (const auto& entry : std::filesystem::directory_iterator(pathUserTemp, ec))
		{
			if (entry.is_directory(ec))
				continue;
			auto& path = entry.path();
			if (path.filename().extension() == DEL_REQ_EXT)
				vDelFiles.emplace_back(path);
		}
	}

	auto delfiles = unsaved.AddObject("delfiles");
	std::string strText;
	for (auto&& delFile : vDelFiles) {
		strText.clear();
		QHFile::ReadAll(delFile.c_str(), &strText);
		if (strText.empty())
			continue;

		std::set<const char*, mLess_char> sList;
		SplitReqDelFileList(strText, "|\r\n", sList);
		if (sList.empty())
			continue;

		auto item = delfiles.AddArray((strctx)delFile.stem().u8string().c_str());
		for (auto& f : sList)
			item.AddMember((strctx)f);
	}

	size_t jsonLen = 0;
	auto jsonStr = ret.stringfy(&jsonLen);
	if (!jsonStr) {
		sender->Response(200, "text/json", R"({"code":4,"msg":"failed"})", 25);
		return;
	}

	sender->Response(200, "text/json", jsonStr, jsonLen);
	ret.free(jsonStr);
	return;
}

static void httpProcess_UserSaveSaveInfo(IHttpSession* sender)
{
	std::string token;
	auto uid = GetTokenFromHeader(sender, token);
	auto ptr = sender->GetQueryParam("rid", nullptr);
	const auto rid = ptr ? strtoul(ptr, nullptr, 10) : 0;
	if (0 == uid) {
		sender->Response(200, "text/json", R"({"code":1,"msg":"invalid params"})", 33);
		return;
	}

	const char* saveinfo = nullptr;
	auto r = UserSave::GetSaveInfo(uid, rid, saveinfo);
	if (r < 0) {
		sender->Response(200, "text/json", R"({"code":2,"msg":"failed"})", 25);
		return;
	}
	if (nullptr == saveinfo) {
		sender->Response(200, "text/json", R"({"code":4,"msg":"failed"})", 25);
		return;
	}

	CStringA strRes;
	strRes.Format(R"({"code":0,"data":%.*s})", r, saveinfo);
	yyjson_mut::free((void*)saveinfo);
	sender->Response(200, "text/json", strRes.GetString(), strRes.GetLength());
	return;
}

static void httpProcess_UserSaveSave(IHttpSession* sender, INT type)
{
	std::string token;
	auto uid = GetTokenFromHeader(sender, token);
	auto ptr = sender->GetQueryParam("rid", nullptr);
	const auto rid = ptr ? strtoul(ptr, nullptr, 10) : 0;
	if (0 == uid) {
		sender->Response(200, "text/json", R"({"code":1,"msg":"invalid params"})", 33);
		return;
	}

	std::string taskIdStr;
	auto r = UserSave::AddSave(type, uid, rid, taskIdStr);
	if (r < 0) {
		sender->Response(200, "text/json", R"({"code":2,"msg":"error"})", 24);
		return;
	}

	yyjson_mut json(false);
	json.Add("code", 0);
	json.Add("msg", "ok");
	auto data = json.AddObject("data");
	data.Add("task_id", taskIdStr.c_str());

	size_t strLen = 0;
	auto str = json.stringfy(&strLen);

	sender->Response(200, "text/json", str, strLen);

	json.free(str);
}

static void httpProcess_UserSaveSaveTask(IHttpSession* sender)
{
	std::string token;
	auto uid = GetTokenFromHeader(sender, token);
	auto pTaskId = sender->GetQueryParam("task_id", nullptr);
	if (0 == uid && !pTaskId) {
		sender->Response(200, "text/json", R"({"code":1,"msg":"invalid params"})", 33);
		return;
	}

	yyjson_mut json(false);
	json.Add("code", 0);
	json.Add("msg", "ok");
	auto data = json.AddArray("data");

	std::shared_ptr<SAVETASK> task = nullptr;
	{
		std::lock_guard<std::mutex> lock(g_save_tasks_lock);
		if (pTaskId) {
			auto it = g_save_tasks.find(pTaskId);
			if (it != g_save_tasks.end()) {
				pTaskId = it->first.c_str();
				task = it->second;
			}
		}
		else {
			for (auto&& [task_id, t] : g_save_tasks) {
				if (uid == task->uid) {
					task = t;
					pTaskId = task_id.c_str();
					break;
				}
			}
		}
	}
	
	if (task) {
		auto item = data.AddObject();
		item.Add("task_id", (strptr)pTaskId);
		item.Add("status", task->status);
		item.Add("err", (strptr)task->msg.c_str());
	}
	size_t jsonLen = 0;
	auto jsonStr = json.stringfy(&jsonLen);
	sender->Response(200, "text/json", jsonStr, jsonLen);
	json.free(jsonStr);
	return;
}


static void httpProcess_UserSaveServer(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen)
{
	std::string url("application/json; charset=utf-8\r\nlocation: http://data.yunqidong.com:8866");
	//url = "/url/http://data.yunqidong.com:8866";
	url.append(Target, TargetLen);

	time_t t = 0;
	time(&t);
	t += 60;

	std::string token;
	auto uid = GetTokenFromHeader(sender, token);

	if (url.find('?', 93) == std::string::npos) {
		url.push_back('?');
	}
	else {
		url.push_back('&');
	}
	url += "token=" + token;
	url += "&cache_t=" + std::to_string(t);

	if (!StrStrIA(Target, "/share_list")) {
		url += "&uid=" + std::to_string(uid);
	}
	else {
		url += "&query_uid=" + std::to_string(uid);
	}

	sender->Response(302, url.c_str(), nullptr, 0);
}

void httpProcess_UserSave(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen)
{
	//"/UserSave/";
	Target += 10;
	TargetLen -= 10;

	if (IsUriPath(Target, TargetLen, "list", 4))
		return httpProcess_UserSaveList(sender);

	if (IsUriPath(Target, TargetLen, "history", 7))
		return httpProcess_UserSaveHistory(sender);

	if (IsUriPath(Target, TargetLen, "ArchivePic", 10))
		return httpProcess_UserSaveArchivePic(sender, hVerb, Target + 10, TargetLen - 10);
	
	if (IsUriPath(Target, TargetLen, "delete", 6))
		return httpProcess_UserSaveDelete(sender);

	if (IsUriPath(Target, TargetLen, "name", 4))
		return httpProcess_UserSaveName(sender);

	if (IsUriPath(Target, TargetLen, "share", 5))
		return httpProcess_UserSaveShare(sender, hVerb);

	if (IsUriPath(Target, TargetLen, "shareTask", 9))
		return httpProcess_UserSaveShareTask(sender);

	if (IsUriPath(Target, TargetLen, "use", 3))
		return httpProcess_UserSaveUse(sender);

	if (IsUriPath(Target, TargetLen, "useTask", 7))
		return httpProcess_UserSaveUseTask(sender);

	if (IsUriPath(Target, TargetLen, "SaveInfo", 8))//只查询数据库
		return httpProcess_UserSaveSaveInfo(sender);
	if (IsUriPath(Target, TargetLen, "UnSaveInfo", 10))//只查询临时目录
		return httpProcess_UserSaveUnSaveInfo(sender);

	if (IsUriPath(Target, TargetLen, "save", 4))
		return httpProcess_UserSaveSave(sender, 0);

	if (IsUriPath(Target, TargetLen, "unsave", 6))
		return httpProcess_UserSaveSave(sender, 1);

	if (IsUriPath(Target, TargetLen, "saveTask", 8))
		return httpProcess_UserSaveSaveTask(sender);

	if (IsUriPath(Target, TargetLen, "server", 6) && TargetLen > 7)
		return httpProcess_UserSaveServer(sender, hVerb, --Target, ++TargetLen);

	sender->Response(404, "text/json", nullptr, 0);
}


static void httpProcess_UserDataUploadSave(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen)
{
	struct {
		LARGE_INTEGER FileSize;
		LARGE_INTEGER LastWriteTime;
		BYTE Sha[20];
	} file_info;
	FILE_BASIC_INFO basicInfo;

	auto hash = sender->GetQueryParam("hash", nullptr);
	if (nullptr == hash || strlen(hash) != 40) {
#ifdef _DEBUG
		_log.errorU(u8"[%s]code:1 hash is invalid, url:%.*s", __FUNCTION__, TargetLen, Target);
#endif // _DEBUG
		sender->Response(405, "text/json", R"({"code":1,"msg":"Bad Request"})", 30);
		return;
	}

	auto name = sender->GetQueryParam("uid", nullptr);
	const auto uid = name ? strtoul(name, nullptr, 10) : 0;
	name = sender->GetQueryParam("rid", nullptr);
	const auto rid = name ? strtoul(name, nullptr, 10) : 0;
	name = sender->GetQueryParam("attr", nullptr);
	const auto attr = name ? strtoul(name, nullptr, 10) : 0;

	auto path = (char*)sender->GetQueryParam("path", nullptr);
	if (!path || !path[0] || !uid || !rid) {
#ifdef _DEBUG
		_log.errorU(u8"[%s]code:2 param is invalid, url:%.*s", __FUNCTION__, TargetLen, Target);
#endif // _DEBUG
		sender->Response(405, "text/json", R"({"code":2,"msg":"invaild param"})", 32);
		return;
	}
	if (path[1] == ':') path[1] = '$';

	unsigned char sha1[20];
	FILE_INDEX fid; 

	size_t dataLen = 0;
	auto postData = sender->GetPostData(&dataLen);
	if (nullptr == postData && dataLen) {//放开0数据有可能空文件
#ifdef _DEBUG
		_log.errorU(u8"[%s]code:405 PostData is empty, url:%.*s", __FUNCTION__, TargetLen, Target);
#endif // _DEBUG
		sender->Response(405, "text/json", R"({"code":1,"msg":"Bad Request"})", 30);
		return;
	}

	name = sender->GetQueryParam("size", nullptr);
	const auto size = name ? strtoull(name, nullptr, 10) : 0;
	if (size != dataLen/*|| size > 1ULL * 1024 * 1024 * 1024*/) {
		_log.errorU(u8"[%s]dataLen:%Iu/%llu url:%.*s", __FUNCTION__, dataLen, size, TargetLen, Target);
		sender->Response(405, "text/json", R"({"code":3,"msg":"invalid data len"})", 35);
		return;
	}

	if (dataLen) {
		SHA1_CTX ctx;
		SHA1Init(&ctx);
		SHA1Update(&ctx, (const unsigned char*)postData, (uint32_t)dataLen);
		SHA1Final(sha1, &ctx);

		HexToBinA(hash, &fid, 40);
		if (0 != memcmp(&fid, sha1, sizeof(fid))) {
#ifdef _DEBUG
			_log.errorU(u8"[%s]code:4 hash is not equal, url:%.*s", __FUNCTION__, TargetLen, Target);
#endif // _DEBUG
			sender->Response(405, "text/json", R"({"code":4,"msg":"Invaild hash"})", 31);
			return;
		}
	}

	auto file = CDataFactory::Get()->GetUserTmpDir(uid, TRUE);
	file /= std::to_wstring(rid);
	file /= std::filesystem::u8path(path);

	std::error_code ec;
	std::filesystem::create_directories(file.parent_path(), ec);
	DWORD err = 0;
	HANDLE hFile = CreateFileW(
		file.c_str(),
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		auto Error = GetLastError();
		CStringA str;
		str.Format(u8R"({"code":5,"msg":"Save file failed(%d)."})", Error);
		sender->Response(500, "text/json", str.GetString(), str.GetLength());
		_log.errorW(L"[%s]open file failed %u %s", __FUNCTIONW__, Error, file.c_str());
		return;
	}

	if (dataLen) {
		DWORD dwWrite = (DWORD)dataLen;
		if (!WriteFile(hFile, postData, dwWrite, &dwWrite, nullptr)) {
			auto Error = GetLastError();
			CStringA str;
			str.Format(u8R"({"code":5,"msg":"Save file failed(%d)."})", Error);
			sender->Response(500, "text/json", str.GetString(), str.GetLength());
			CloseHandle(hFile);
			_log.errorW(L"[%s]write file failed %u %s", __FUNCTIONW__, Error, file.c_str());
			return;
		}

		BY_HANDLE_FILE_INFORMATION fi_;
		auto fi = &fi_;
		GetFileInformationByHandle(hFile, &fi_);

		// 保存SHA信息
		file_info.FileSize.LowPart = fi->nFileSizeLow;
		file_info.FileSize.HighPart = fi->nFileSizeHigh;
		file_info.LastWriteTime.QuadPart = *(LONGLONG*)&fi->ftLastWriteTime;
		memcpy(file_info.Sha, sha1, sizeof(file_info.Sha));

		SetEaFile(hFile, "SHAINFO", &file_info, sizeof(file_info));
	}

	if (attr) {
		ZeroMemory(&basicInfo, sizeof(basicInfo));
		basicInfo.FileAttributes = attr | FILE_ATTRIBUTE_NORMAL;
		SetFileInformationByHandle(hFile, FileBasicInfo, &basicInfo, sizeof(basicInfo));
	}

	CloseHandle(hFile);

	sender->Response(200, "text/json", R"({"code":0,"msg":"ok"})", 21);
}

static void httpProcess_UserDataDeleteFiles(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen)
{
	size_t dataLen = 0;
	auto postData = sender->GetPostData(&dataLen);
	if (nullptr == postData || 0 == dataLen) {
		sender->Response(405, "text/json", R"({"code":1,"msg":"Bad Request"})", 30);
		return;
	}

	auto name = sender->GetQueryParam("uid", nullptr);
	const auto uid = name ? strtoul(name, nullptr, 10) : 0;
	name = sender->GetQueryParam("rid", nullptr);
	const auto rid = name ? strtoul(name, nullptr, 10) : 0;
	if (0 == uid || 0 == rid) {
		sender->Response(405, "text/json;charset=utf-8", R"({"code":1,"msg":"Bad params"})", 29);
		return;
	}

	yyjson json(postData, dataLen);
	auto fs = json["files"];
	auto FileCount = fs.GetCount();
	if (0 == FileCount) {
		sender->Response(405, "text/json;charset=utf-8", R"({"code":2,"msg":"Empty Array"})", 30);
		return;
	}

	auto files = fs.iter();
	UINT FailedCount = UserSave::DeleteTempFiles(uid, rid, files);

	CStringA strMsg;
	strMsg.Format(R"({"code":0,"msg":"ok","TotleFilesCount":%Iu,"FailedCount":%u})", FileCount, FailedCount);
	sender->Response(200, "text/json;charset=utf-8", strMsg.GetString(), strMsg.GetLength());
}

static void httpProcess_UserDataUploadSavePic(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen)
{
	size_t dataLen = 0;
	auto postData = sender->GetPostData(&dataLen);
	if (nullptr == postData || 0 == dataLen) {
		sender->Response(405, "text/json", R"({"code":1,"msg":"Bad Request"})", 30);
		return;
	}

	auto name = sender->GetQueryParam("uid", nullptr);
	const auto uid = name ? strtoul(name, nullptr, 10) : 0;
	name = sender->GetQueryParam("rid", nullptr);
	const auto rid = name ? strtoul(name, nullptr, 10) : 0;
	name = sender->GetQueryParam("size", nullptr);
	const auto size = name ? strtoull(name, nullptr, 10) : 0;

	if (!uid || !rid || !size) {
		sender->Response(405, "text/json", R"({"code":1,"msg":"Bad Request"})", 30);
		return;
	}
	if (size != dataLen || size > 1ULL * 1024 * 1024) {
		_log.errorU(u8"[%s]dataLen:%Iu/%llu url:%.*s", __FUNCTION__, dataLen, size, TargetLen, Target);
		sender->Response(405, "text/json", R"({"code":3,"msg":"invalid data len"})", 35);
		return;
	}

	auto file = CDataFactory::Get()->GetUserTmpDir(uid, TRUE);
	file /= std::to_wstring(rid) + L".jpg";

	QHFile::WriteAll(file.c_str(), postData, (DWORD)dataLen);
	sender->Response(200, "text/json", R"({"code":0,"msg":"ok"})", 21);
}

static void httpProcess_UserDataList(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen)
{
	auto name = sender->GetQueryParam("uid", nullptr);
	const auto uid = name ? strtoul(name, nullptr, 10) : 0;
	if (0 == uid) {
		sender->Response(405, "text/json;charset=utf-8", R"({"code":1,"msg":"Bad params"})", 29);
		return;
	}

	if (UserSave::MergeTempFiles(uid) == 0) {
		UserSave::MakeFilesList(uid);
	}

	auto strUid = std::to_wstring(uid);
	auto newList = g_current_dir / USER_LIST_DIR;
	newList /= strUid;
	newList /= strUid + L"." + std::to_wstring(APPID_SAVEDATA);
	newList += L".list";

	std::string strListData; // 清单数据
	DWORD err = 0;
	if (FALSE == QHFile::ReadAll(newList.c_str(), &strListData, &err)) {
		strListData.clear();
	}

	if (!strListData.empty()) {
		sender->Response(200, "stream/fileslist", strListData.c_str(), strListData.size());
		return;
	}

	sender->Response(404, "text/json;charset=utf-8", R"({"code":2,"msg":"Not Found"})", 28);
	return;
}

static void httpProcess_LostFile(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen)
{
	auto name = sender->GetQueryParam("uid", nullptr);
	const auto uid = name ? strtoul(name, nullptr, 10) : 0;
	if (0 == uid) {
		name = sender->GetQueryParam("hash", nullptr);
		if (nullptr == name || 40 != strlen(name)) {
			sender->Response(405, "text/json;charset=utf-8", R"({"code":1,"msg":"Bad params"})", 29);
			return;
		}

		WCHAR szChildName[64];
		wcscpy_s(szChildName, ARRAYSIZE(szChildName), ARCH_PREFIX);
		DataFilePath::HashToName(name, &szChildName[9]);
		if (CDataFactory::Get()->IsFileExist(szChildName, 9 + 46UL, FileKeepTimeType::Arch)) {//缓存中存在文件
			sender->Response(200, "text/json;charset=utf-8", R"({"code":2,"msg":"File is exist"})", 32);
			return;
		}

		CStringA strRes;
		auto ret = UserSave::Process_LostFile(name, strRes);
		_log.infoU(u8"[%s]del hash(%s)", __FUNCTION__, name, ret);
		if (ret < 0) {
			sender->Response(500, "text/json;charset=utf-8", R"({"code":3,"msg":"sqlite prepare failed"})", 40);
			return;
		}
		
		if (0 == ret) {
			sender->Response(200, "text/json;charset=utf-8", R"({"code":4,"msg":"uid is empty"})", 31);
			return;
		}

		sender->Response(200, "text/json;charset=utf-8", strRes.GetString(), strRes.GetLength());
		return;
	}

	_log.infoU(u8"[%s]refresh uid(%u)", __FUNCTION__, uid);
	auto ret = CheckFileList(uid, nullptr);
	CStringA strRes;
	strRes.Format(R"({"code":0,"data":{"%u":%d}})", uid, ret);
	sender->Response(200, "text/json;charset=utf-8", strRes.GetString(), strRes.GetLength());
	return;
}

void httpProcess_UserData(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen)
{
	//"/UserData/"
	Target += 10;
	TargetLen -= 10;

	if (IsUriPath(Target, TargetLen, "UploadUserSave", 14))
		return httpProcess_UserDataUploadSave(sender, hVerb, Target + 14, TargetLen - 14);

	if (IsUriPath(Target, TargetLen, "DeleteFiles", 11))
		return httpProcess_UserDataDeleteFiles(sender, hVerb, Target + 11, TargetLen - 11);

	if (IsUriPath(Target, TargetLen, "UploadSavePic", 13))
		return httpProcess_UserDataUploadSavePic(sender, hVerb, Target + 13, TargetLen - 13);

	if (IsUriPath(Target, TargetLen, "UserSaveList", 12))
		return httpProcess_UserDataList(sender, hVerb, Target + 12, TargetLen - 12);

	if (IsUriPath(Target, TargetLen, "LostFile", 8))
		return httpProcess_LostFile(sender, hVerb, Target + 8, TargetLen - 8);

	if (IsUriPath(Target, TargetLen, "clearup", 7)) {
		CDataFactory::Get()->ReqClearup();
		sender->Response(200, "text/json;charset=utf-8", R"({"code":0,"msg":"ok"})", 21);
		return;
	}

	sender->Response(404, "text/json", R"({"code":1,"msg":"Not Found"})", 28);
}

int UserSave::shared::AddShared(UINT uid, std::string& token, int64_t id, int64_t sid, std::string& params, std::string& task_id)
{
	{
		std::lock_guard<std::mutex> lock(g_shared_tasks_lock);
		for (auto&& [_, task] : g_shared_tasks) {
			if (task->h.id == id) {
				if (2 == task->status || 3 == task->status) {
					task_id = _;
					task->h.sid = sid;
					task->params.swap(params);
					task->token.swap(token);
					task->status = 0;
					task->comp_time = UINT64_MAX - TASKKEEPTIME;
					begin_thread();
					return 1;
				}
				else if (task->status == 1) {
					task_id = _;
					return 0;
				}
				return -1;
			}
		}
	}

	// 生成一个UUID作为任务ID
	UUID taskId = { 0 };
	auto r = UuidCreate(&taskId);
	if (r != RPC_S_OK) {
		_log.errorU(u8"[%s]UuidCreate failed, error: %d", __FUNCTION__, r);
		return -2;
	}

	RPC_CSTR taskIdStr = nullptr;
	r = UuidToStringA(&taskId, &taskIdStr);
	if (r != RPC_S_OK) {
		_log.errorU(u8"[%s]UuidToStringA failed, error: %d", __FUNCTION__, r);
		return -3;
	}

	task_id = (char*)taskIdStr;
	RpcStringFreeA(&taskIdStr);

	auto task = std::make_shared<SHAREDTASK>();
	task->h.uid = uid;
	task->h.sid = sid;
	task->h.id = id;
	task->h.size = 0;
	task->uploaded = 0;
	task->files = 0;
	task->files_uploaded = 0;
	task->status = 0;
	task->comp_time = UINT64_MAX - TASKKEEPTIME;
	task->params.swap(params);
	task->token.swap(token);

	{
		std::lock_guard<std::mutex> lk(g_shared_tasks_lock);
		g_shared_tasks.emplace(task_id, task);
	}

	begin_thread();

	return 0;
}

static int isCanShared(std::shared_ptr<SHAREDTASK> task, std::string& err)
{
	return 0;
}

static int DoUpload(std::shared_ptr<SHAREDTASK> task, std::vector<DB_FILES>& files, std::string& err)
{
	int ret = 0;
	std::error_code ec;
	std::string strResponse;
	std::string strCheck;
	WCHAR szChildName[64];

	wcscpy_s(szChildName, ARRAYSIZE(szChildName), ARCH_PREFIX);

	{
		yyjson_mut jsonCheck(true);
		for (auto&& f : files) {
			auto item = jsonCheck.AddObject();
			item.Add((strptr)"hash", (strptr)f.hash);

			DataFilePath::HashToName(f.hash, &szChildName[9]);
			LONGLONG fileSize = 0;
			CDataProvider* pFile = nullptr;
			ret = CDataFactory::Get()->DoOpenFile(szChildName, 9 + 46UL, &pFile);
			if (pFile) {
				pFile->file_size(&fileSize);
				pFile->OnCloseFile(FALSE);
			}
			item.Add("size", fileSize);
		}

		// 压缩一下。
		CStringA jsonString = jsonCheck.toCStringA();
		if (!jsonString.IsEmpty()) {
			LCD::PCompressData pcd = nullptr;
			size_t nLen = 0;
			if (LCD::Compress(jsonString.GetString(), jsonString.GetLength(), &pcd, &nLen)) {
				strCheck.assign((char*)pcd, nLen);
				LCD::Free(pcd);
			}
		}
	}

	if (strCheck.empty()) {
		err = u8"无可共享的内容";
		return -1;
	}

	auto strUrl = "server/UserSave/check";

	while (true) {
		auto status = http::Post(strUrl, strCheck.c_str(), strCheck.size(), &strResponse);
		if (200 != status) {
			err = u8"共享上传失败! 0x101";
			_log.errorU(u8"[%s]请求失败! status:%d url:%s", __FUNCTION__, status, strUrl);
			return -2;
		}

		yyjson json(strResponse.c_str(), strResponse.size());
		if (json.isNull()) {
			err = u8"共享上传失败! 0x102";
			_log.errorU(u8"[%s]解析失败! %.*s ", __FUNCTION__, (int)strResponse.size(), strResponse.c_str());
			return -3;
		}

		if (0 != json["code"].toInt()) {
			err = u8"共享上传失败! 0x103";
			_log.errorU(u8"[%s]code!=0! json:%.*s", __FUNCTION__, (int)strResponse.size(), strResponse.c_str());
			return -4;
		}

		auto fs = json["files"];
		if (fs.GetCount() == 0) {
			// 上传完成，返回TRUE；
			return 1;
		}
		else {
			// 上传文件
			auto iterFiles = fs.iter();
			yyjson val;
			int nCount = 0;
			while (iterFiles.next(&val)) {
				auto state = val["state"].toInt();
				if (state == 3 || state == 4) {
					// 这些状态表示服务器正在校验中
					continue;
				}

				auto hash = val["hash"].toPChar("");
				if (strlen(hash) != 40)
					continue;

				DataFilePath::HashToName(hash, &szChildName[9]);
				CDataProvider* pFile = nullptr;
				ret = CDataFactory::Get()->DoOpenFile(szChildName, 9 + 46UL, &pFile);
				if (S_OK != ret) {
					err = u8"共享上传失败! 0x104";
					_log.errorW(L"[%s]CreateFileW failed(0x%X):%s", __FUNCTIONW__, ret, szChildName);
					return -5;
				}

				AutoRelease ar([pFile]() { pFile->OnCloseFile(FALSE); });

				LONGLONG fileSize = 0;
				pFile->file_size(&fileSize);

				// 分块上传，每次上传1M
				size_t offset = 0;
				offset = val["size"].toInt();
				if (offset >= (size_t)fileSize) {
					offset = 0;
				}

				CHAR token[33] = { 0 };
				CStringA sign;
				while ((LONGLONG)offset < fileSize) {
					size_t len = (size_t)min(1024 * 1024, fileSize - offset);

					auto SIGN = "0641db64f7701ec8b8333e243e151e44";
					sign.Format("%llu%llu%s%s", fileSize, (ULONG64)offset, hash, SIGN);

					MD5_CTX md5;
					MD5Init(&md5);
					MD5Update(&md5, (unsigned char*)sign.GetString(), (UINT)sign.GetLength());
					MD5Final(&md5);

					BinToHexA(md5.digest, token, 16);

					CStringA strUrl;
					strUrl.Format("server/UserSave/upload?type=USERSAVE&hash=%s&size=%llu&offset=%llu&token=%s", hash, fileSize, (ULONG64)offset, token);

					for (int i = 0; i < 3; ++i) {
						if(i) Sleep(1000);
						status = http::Upload(strUrl.GetString(), pFile->Handle(), offset, len, &strResponse);
						if (200 == status)
							break;
					}
					if (200 != status) {
						err = u8"共享上传失败! 0x105";
						_log.errorU(u8"[%s]上传文件失败! status:%d url:%s", __FUNCTION__, status, strUrl.GetString());
						return -6;
					}
					task->uploaded += len;
					offset += len;
				}

				task->files_uploaded++;
				nCount++;
			}

			if (nCount == 0) {
				Sleep(1000);
			}
		}
	}
	return ret;
}

static int DoShare(std::shared_ptr<SHAREDTASK> task, std::vector<DB_FILES>& vecFiles, std::string& err)
{
	int ret = 0;
	yyjson_mut json(false);
	auto info = json.AddObject("info");
	auto files = json.AddArray("files");

	info.Add("share_id", task->h.sid);
	info.Add("uid", task->h.uid);
	info.Add("token", (strptr)task->token.c_str());
	info.Add("rid", task->h.rid);
	info.Add("name", (strptr)task->h.name.c_str());
	info.Add("ver", task->h.ver);
	info.Add("rec_time", task->h.rec_time);
	info.Add("size", task->h.size);
	info.Add("capture", (strptr)task->h.capture.c_str());
	info.Add("comment", (strptr)task->h.comment.c_str());
	info.Add("add", (strptr)task->h.add.c_str());

	for (auto&& f : vecFiles) {
		auto item = files.AddObject();
		item.Add("file", (strptr)f.file.c_str());
		item.Add("size", f.size);
		item.Add("hash", (strptr)f.hash);
		item.Add("attr", f.attr);
		item.Add("creation", f.creation);
		item.Add("ver", f.ver);
		item.Add("rec_time", f.rec_time);
	}

	size_t strLen = 0;
	auto strJson = json.stringfy(&strLen);
	if (!strJson) {
		err = u8"共享失败! 0x201";
		return -1;
	}

	auto url = "server/UserSave/share";
	std::string strResponse;
	auto status = http::Post(url, strJson, strLen, &strResponse);
	if (status != 200) {
		err = u8"共享失败! 0x202";
		_log.errorU(u8"[%s]提交共享失败! status:%d url:%s", __FUNCTION__, status, url);
		return -2;
	}
	json.free(strJson);

	yyjson jsonRes(strResponse.c_str(), strResponse.size());
	if (jsonRes.isNull()) {
		err = u8"共享失败! 0x203";
		_log.errorU(u8"[%s]JSON解析失败: %s", __FUNCTION__, strResponse.c_str());
		return -3;
	}

	auto code = jsonRes["code"].toInt();
	if (code != 0) {
		err = jsonRes["msg"].toPChar("");
		_log.errorU(u8"[%s]共享失败: %s", __FUNCTION__, strResponse.c_str());
		return -4;
	}

	return ret;
}

static void DoTask(std::shared_ptr<SHAREDTASK> task)
{
	sqlite3stmthelp stmt;
	auto r = g_sh.prepare(stmt, "SELECT * FROM history WHERE uid='%u' AND id='%llu'", task->h.uid, task->h.id);
	if (r != SQLITE_OK) {
		task->status = 3;
		task->msg = u8"数据库错误, 0x1";
		_log.errorU(u8"[%s] prepare failed, %d", __FUNCTION__, r);
		return;
	}

	r = stmt.step();
	if (r == SQLITE_DONE) {
		task->status = 3;
		task->msg = u8"该存档不存在!";
		return;
	}
	else if (r != SQLITE_ROW) {
		task->status = 3;
		task->msg = u8"数据库错误, 0x2";
		_log.errorU(u8"[%s] step failed, %d", __FUNCTION__, r);
		return;
	}

	task->h.rid = stmt.GetInt(1);
	task->h.ver = stmt.GetInt64(3);
	task->h.rec_time = stmt.GetInt64(4);
	task->h.name = stmt.GetText(5, "");
	task->h.size = stmt.GetInt64(6);
	task->h.capture = stmt.GetText(7, "");
	task->h.comment = stmt.GetText(8, "");
	task->h.add = stmt.GetText(9, "");

	if (!task->params.empty()) {
		yyjson jsonParams(task->params.c_str(), task->params.size());

		if (jsonParams["name"].isString())
			task->h.name = jsonParams["name"].toPChar("");

		if (jsonParams["comment"].isString())
			task->h.comment = jsonParams["comment"].toPChar("");

		if (jsonParams["add"].isString())
			task->h.add = jsonParams["add"].toPChar("");
	}

	std::string err;
	r = isCanShared(task, err);
	if (r == 1) {
		task->status = 2;
		return;
	}
	else if (r < 0) {
		_log.errorU(u8"[%s] %s", __FUNCTION__, err.c_str());
		task->status = 3;
		task->msg = err;
		return;
	}

	r = g_sh.prepare(stmt, "SELECT * FROM files WHERE uid='%u' AND ver='%llu' AND rid='%u'", task->h.uid, task->h.ver, task->h.rid);
	if (r != SQLITE_OK) {
		task->status = 3;
		task->msg = u8"数据库错误, 0x3";
		_log.errorU(u8"[%s] prepare failed, %d", __FUNCTION__, r);
		return;
	}

	DB_FILES f;
	f.uid = 0;
	f.rid = 0;
	f.reserved = 0;

	std::vector<DB_FILES> vecFiles;
	int64_t totalSize = 0;
	int64_t totalFiles = 0;
	while (stmt.step() == SQLITE_ROW) {
		f.id = stmt.GetInt64(0);
		f.file = stmt.GetText(3, "");
		f.size = stmt.GetInt64(4);
		auto hash = stmt.GetText(5, "");
		memcpy(f.hash, hash, min(strlen(hash), 40));
		f.creation = stmt.GetInt64(6);
		f.attr = stmt.GetInt(7);
		f.ver = stmt.GetInt64(8);
		f.rec_time = stmt.GetInt64(9);

		totalSize += f.size;
		totalFiles++;

		vecFiles.emplace_back(f);
	}

	task->files = totalFiles;
	task->files_uploaded = 0;
	task->h.size = totalSize;
	task->uploaded = 0;

	r = DoUpload(task, vecFiles, err);
	if (r < 0) {
		_log.errorU(u8"[%s]Upload failed: %s", __FUNCTION__, err.c_str());
		task->status = 3;
		task->msg = err;
		return;
	}

	r = DoShare(task, vecFiles, err);
	if (r < 0) {
		_log.errorU(u8"[%s]Share failed: %s", __FUNCTION__, err.c_str());
		task->status = 3;
		task->msg = err;
		return;
	}

	task->status = 2;
}

void UserSave::ClearupTask()
{
	auto tick = GetTickCount64();

	{
		std::lock_guard<std::mutex> lock(g_use_tasks_lock);
		for (auto it = g_use_tasks.begin(); it != g_use_tasks.end();) {
			if (it->second->comp_time + TASKKEEPTIME < tick) {
				it = g_use_tasks.erase(it);
			}
			else {
				++it;
			}
		}
	}

	{
		std::lock_guard<std::mutex> lock(g_save_tasks_lock);
		for (auto it = g_save_tasks.begin(); it != g_save_tasks.end();) {
			if (it->second->comp_time + TASKKEEPTIME < tick) {
				it = g_save_tasks.erase(it);
			}
			else {
				++it;
			}
		}
	}

	{
		std::lock_guard<std::mutex> lock(g_shared_tasks_lock);
		for (auto it = g_shared_tasks.begin(); it != g_shared_tasks.end();) {
			if (it->second->comp_time + TASKKEEPTIME < tick) {
				it = g_shared_tasks.erase(it);
			}
			else {
				++it;
			}
		}
	}
}

void UserSave::shared::thread_shared_process()
{
	do {
		std::shared_ptr<SHAREDTASK> task = nullptr;

		{
			std::lock_guard<std::mutex> lock(g_shared_tasks_lock);
			for (auto&& [_, t] : g_shared_tasks) {
				if (t->status == 0) {
					task = t;
					task->status = 1;
					break;
				}
			}
		}

		if (task) {
			DoTask(task);
			task->comp_time = GetTickCount64();
		}
		else {
			break;
		}
	} while (true);

	InterlockedDecrement(&g_shared_threads);
}

void UserSave::shared::begin_thread()
{
	auto threads = InterlockedIncrement(&g_shared_threads);
	if (threads < g_shared_threads_max) {
		std::thread(thread_shared_process).detach();
	}
	else {
		InterlockedDecrement(&g_shared_threads);
	}
}
