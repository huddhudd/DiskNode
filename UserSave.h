#pragma once
#ifndef _USERSAVE_H
#define _USERSAVE_H

typedef struct _DB_Files {
	int64_t id;
	UINT uid;
	UINT rid;
	std::string file;
	int64_t size;
	CHAR hash[40];
	DWORD reserved;
	DWORD attr;
	int64_t creation;
	int64_t ver;
	int64_t rec_time;
}DB_FILES, * PDB_FILES, * LPDB_FILES;

typedef struct _DB_History {
	int64_t id;
	int64_t sid;
	UINT uid;
	UINT rid;
	int64_t ver;
	int64_t rec_time;
	int64_t size;
	std::string name;
	std::string capture;
	std::string comment;
	std::string add;
}DB_HISTORY, * PDB_HISTORY, * LPDB_HISTORY;

typedef struct _SharedTask {
	DB_HISTORY h;
	int64_t uploaded;
	int64_t files;
	int64_t files_uploaded;
	int64_t comp_time;//完成时tick
	int status; // 0.未开始 1.上传中 2.完成 3.错误
	std::string msg;
	std::string params;
	std::string token;
}SHAREDTASK, * PSHAREDTASK, * LPSHAREDTASK;

typedef struct _UseTask {
	int64_t id;
	int64_t sid;
	int64_t comp_time;//完成时tick
	int status; // 0.未开始 1.同步中 2.完成 3.错误
	UINT uid;
	std::string token;
	std::string msg;
}USETASK, *PUSETASK, *LPUSETASK;

typedef struct _SaveTask {
	INT type; // 0.保存 1.放弃保存
	INT status; // 0.未开始 1.操作中 2.完成 3.错误
	UINT uid;
	UINT rid;
	int64_t comp_time;//完成时tick
	std::string msg;
}SAVETASK, *PSAVETASK, *LPSAVETASK;

namespace UserSave
{
	void Init();

	struct TempFileInfo {
		size_t size;
		int64_t time;
		UINT rid;
		std::filesystem::path path;
	};
	int GetTempFiles(std::filesystem::path pathUserTemp, UINT rid, std::vector<TempFileInfo>& files);
	int MergeTempFiles(UINT uid, UINT rid = 0);
	int DeleteTempFiles(UINT uid, UINT rid = 0);
	UINT DeleteTempFiles(UINT uid, UINT rid, yyjson::iterator& files);
	int MakeFilesList(UINT uid);
	int GetSaveInfo(UINT uid, UINT rid, const char*& saveinfo);

	void Clearup(const int ArchKeepDays);
	void TempFileHandle(std::vector<CcPath>const& vCcPath, std::set<ULONGLONG>const& sUid);

	int AddUse(UINT uid, std::string& token, int64_t id, int64_t sid, std::string& task_id);
	void thread_use_process();
	void begin_use_process();
	uint64_t GetLastSaveId(UINT uid, UINT rid);

	int Process_LostFile(const char* hash, CStringA& strRes);

	int AddSave(INT type, UINT uid, UINT rid, std::string& task_id);
	void thread_save_process();
	void begin_save_process();

	void ClearupTask();

	namespace shared
	{
		int AddShared(UINT uid, std::string& token, int64_t id, int64_t sid, std::string& params, std::string& task_id);
		void thread_shared_process();
		void begin_thread();
	}
}

// 返回UID
UINT GetTokenFromHeader(IHttpSession* sender, std::string& token);

void httpProcess_UserSave(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen);
void httpProcess_UserData(IHttpSession* sender, http_verb hVerb, const char* Target, size_t TargetLen);

#endif
