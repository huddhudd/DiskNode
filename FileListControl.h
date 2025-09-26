#pragma once
#ifndef FILELISTCONTROL_H
#define FILELISTCONTROL_H

typedef struct _FILEST_LIST_EXT {
	struct {
		DWORD size;
		DWORD type;
	}head;
	CHAR  data[1];
}FILEST_LIST_EXT, * PFILEST_LIST_EXT, * LPFILEST_LIST_EXT;

class FileListControl
{
public:
	FileListControl();
	~FileListControl();

private:
	ULONG	m_appid;
	ULONG	m_fileid;	//自增文件ID
	PCACHE_CONTEXT m_header;
	PFILE_ITEM m_items;
	PFILE_ITEM m_lastest_item;//记录最后一个文件指针
	size_t m_item_size;
	size_t m_item_size_max;

	std::map<CStringW, BOOL> folder_map;
	CRITICAL_SECTION m_cs;

public:
	void set_appid(ULONG appid);
	bool set_header(PCACHE_CONTEXT header);
	bool add_item(PFILE_ITEM item);
	bool modify_item(PFILE_ITEM item);
	bool add_file(
		LPCSTR file_name_src,
		LONGLONG totalsize,
		LONGLONG creation_time,
		CHAR file_hash[20],
		UINT channel_support, 
		UINT channel_index,
		ULONG file_attributes = FILE_ATTRIBUTE_ARCHIVE,
		BOOL modify = FALSE);
	bool add_file(
		LPCWSTR file_name_src, 
		LONGLONG totalsize, 
		LONGLONG creation_time,
		CHAR file_hash[20], 
		UINT channel_support,
		UINT channel_index,
		ULONG file_attributes = FILE_ATTRIBUTE_ARCHIVE,
		BOOL modify = FALSE);
	bool add_folder(
		LPCSTR file_name_src, 
		LONGLONG creation_time,
		ULONG file_attributes = FILE_ATTRIBUTE_DIRECTORY,
		BOOL modify = FALSE);
	bool add_folder(
		LPCWSTR file_name_src, 
		LONGLONG creation_time,
		ULONG file_attributes = FILE_ATTRIBUTE_DIRECTORY,
		BOOL modify = FALSE);
	
	/// <summary>
	/// 添加子应用目录
	/// </summary>
	/// <param name="appid">子应用ID</param>
	/// <param name="file_name_src"></param>
	/// <param name="creation_time"></param>
	/// <param name="channel_support"></param>
	/// <param name="channel_index"></param>
	/// <returns></returns>
	bool add_filelist_folder(
		ULONG appid,
		LPCSTR file_name_src, 
		LONGLONG creation_time,
		UINT channel_support = CSF_TCP,
		UINT channel_index = CHANNEL_SUPPORT_TCP,
		ULONG file_attributes = FILE_ATTRIBUTE_DIRECTORY);
	bool add_filelist_folder(
		ULONG appid,
		LPCWSTR file_name_src, 
		LONGLONG creation_time,
		UINT channel_support = CSF_TCP,
		UINT channel_index = CHANNEL_SUPPORT_TCP,
		ULONG file_attributes = FILE_ATTRIBUTE_DIRECTORY);

	/// <summary>
	/// 将目录添加到清单中,已存在则不做任何处理
	/// </summary>
	/// <param name="file_name_src"></param>
	/// <param name="creation_time"></param>
	/// <returns>无意义</returns>
	bool check_folder(LPCSTR file_name_src, LONGLONG creation_time);
	/// <summary>
	/// 将目录添加到清单中,已存在则不做任何处理
	/// </summary>
	/// <param name="file_name_src"></param>
	/// <param name="creation_time"></param>
	/// <returns>无意义</returns>
	bool check_folder(LPCWSTR file_name_src, LONGLONG creation_time);

	size_t get_result_size();
	bool get_result(LPVOID buf, size_t buf_size);
};

class FileListLoader
{
private:
	PCACHE_CONTEXT m_data;
	HANDLE m_file_handle;
	HANDLE m_map_handle;
	BOOL m_is_file_mapping;

	BOOL _load(LPCTSTR file);
	void Release();

public:
	FileListLoader();
	~FileListLoader();

	BOOL load(LPCTSTR file, PCACHE_CONTEXT *header = NULL, PFILE_ITEM* firstitem = NULL);
	PCACHE_CONTEXT header();
	PFILE_ITEM firstitem();
private:

};

class FilesListReader {
public:
	FilesListReader(LPCVOID filesList) : header((PCACHE_CONTEXT)filesList) {}
	~FilesListReader() {};

	class Iterator
	{
	public:
		Iterator(PFILE_ITEM item, PFILE_ITEM last) : cur(item), end(last) {}
		~Iterator() {};

		PFILE_ITEM& operator*() { return cur; };
		Iterator& operator++() {
			if (cur->NextEntryOffset == 0) {
				cur = end;
			}
			else {
				cur = (PFILE_ITEM)((DWORD_PTR)cur + cur->NextEntryOffset);
			}
			return *this;
		}
		bool operator!=(const Iterator& other) {
			return cur != other.cur;
		}

	private:
		PFILE_ITEM cur;
		PFILE_ITEM end;
	};

	PCACHE_CONTEXT head() {
		return header;
	}

	PFILE_ITEM first() {
		return (PFILE_ITEM)((DWORD_PTR)header + header->SizeOfHeader);
	}

	PFILE_ITEM last() {
		return (PFILE_ITEM)((DWORD_PTR)header + header->FileSize.QuadPart);
	}

	Iterator begin() {
		return Iterator(first(), last());
	}

	Iterator end() {
		return Iterator(last(), last());
	}
private:
	PCACHE_CONTEXT header;
};
#endif // !FILELISTCONTROL_H
