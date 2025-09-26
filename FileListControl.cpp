#include "Common.h"


uLong GetFileId(LPCWSTR file_name_src, BOOL bFolder)
{
    CStringW file_name = file_name_src;
    if (bFolder) {
		file_name += L"\\";
    }
    file_name.MakeLower();
    uLong crc = crc32(0, (const Bytef*)file_name.GetString(), file_name.GetLength() * sizeof(WCHAR));
    return crc | 1; // 舍弃第0位，强制置1，用来保证ID不为0
}

FileListControl::FileListControl():
    m_header(NULL), 
    m_items(NULL), 
    m_lastest_item(NULL), 
    m_item_size(0), 
    m_item_size_max(0)
{
    m_fileid = 0;
    m_appid = 0;
    m_cs = { 0 };
    InitializeCriticalSection(&m_cs);
}

FileListControl::~FileListControl()
{
    if (m_header) {
        free(m_header);
    }
    if (m_items) {
        free(m_items);
    }
}

void FileListControl::set_appid(ULONG appid)
{
    m_appid = appid;
}

bool FileListControl::set_header(PCACHE_CONTEXT header)
{
	if (m_header && m_header->cbSize != header->cbSize) {
		free(m_header);//原内存不可复用，直接释放，随后重新申请
		m_header = NULL;
	}

    if (!m_header) {
		PCACHE_CONTEXT new_header = (PCACHE_CONTEXT)malloc(header->cbSize);
		if (!new_header) {
			return false;
		}
		m_header = new_header;
    }

    memcpy_s(m_header, header->cbSize, header, header->cbSize);

    if (0 != m_header->AppId) {
        m_appid = m_header->AppId;
    }
    //m_id = m_header->FileId;
    return true;
}

bool FileListControl::add_item(PFILE_ITEM item)
{
    EnterCriticalSection(&m_cs);
    if (!m_items) {
        m_item_size = 0;
        m_item_size_max = 0;
        m_lastest_item = NULL;
		size_t new_size = AtlAlignUp(item->NextEntryOffset, 65536);
        m_items = (PFILE_ITEM)malloc(new_size);
        if (!m_items) {
            LeaveCriticalSection(&m_cs);
            return false;
        }
        m_item_size_max = new_size;
        folder_map.clear();
    }

    size_t need_size = m_item_size + item->NextEntryOffset;
    if (need_size > m_item_size_max) {
		size_t new_size = AtlAlignUp(need_size, 65536);//64K对齐
        PFILE_ITEM new_items = (PFILE_ITEM)realloc(m_items, new_size);
        if (!new_items) {
            LeaveCriticalSection(&m_cs);
            return false;
        }
        m_items = new_items;
        m_item_size_max = new_size;
    }

    m_lastest_item = (PFILE_ITEM)((DWORD_PTR)m_items + m_item_size);

    memcpy_s(m_lastest_item, m_item_size_max - m_item_size,
        item, item->NextEntryOffset);

    m_item_size = need_size;
    LeaveCriticalSection(&m_cs);
    return true;
}

bool FileListControl::modify_item(PFILE_ITEM item)
{
    auto fileName = item->FileName();
    auto cur = m_items;
    auto end = (PFILE_ITEM)((DWORD_PTR)m_items + m_item_size);
    while (cur < end) {
        if (0 == _wcsicmp(fileName, cur->FileName())) {
            memcpy_s(cur, sizeof(FILE_ITEM) + cur->FileNameLength, item, sizeof(FILE_ITEM) + item->FileNameLength);
            return true;
        }
        if (cur->NextEntryOffset == 0) {
            break;
        }
        cur = (PFILE_ITEM)((DWORD_PTR)cur + cur->NextEntryOffset);
    }
    return false;
}

bool FileListControl::add_file(
    LPCSTR file_name_src, 
    LONGLONG totalsize, 
    LONGLONG creation_time, 
    CHAR file_hash[20], 
    UINT channel_support, 
    UINT channel_index,
    ULONG file_attributes,
    BOOL modify)
{
    WCHAR file_name[LONG_PATH];
    wsprintfW(file_name, L"%S", file_name_src);
    return add_file(file_name, totalsize, creation_time, file_hash, channel_support, channel_index, file_attributes, modify);
}

bool FileListControl::add_file(
    LPCWSTR file_name_src, 
    LONGLONG totalsize, 
    LONGLONG creation_time, 
    CHAR file_hash[20], 
    UINT channel_support,
    UINT channel_index,
    ULONG file_attributes,
    BOOL modify)
{
    if (false == check_folder(file_name_src, creation_time)) {
        return false;
    }
    
    ULONG file_id = GetFileId(file_name_src, FALSE);
    if (file_id == 0) {
        file_id = InterlockedIncrement(&m_fileid);
    }

    size_t pathLen = (wcslen(file_name_src) + 1) * sizeof(WCHAR);
    size_t itemSize = sizeof(FILE_ITEM) + pathLen;
    std::string itemBuf;
    itemBuf.resize(itemSize);

    FILE_ITEM_WITH_FILENAME& item_ = *(FILE_ITEM_WITH_FILENAME*)itemBuf.data();
    int char_count = wsprintfW(item_.file_name, L"%s", file_name_src) + 1;

    PFILE_ITEM item = &item_.item;
    item->DataOffset = 0;
    item->FileNameOffset = sizeof(FILE_ITEM);
    item->FileNameLength = (USHORT)(char_count * sizeof(WCHAR));
    item->Flags = 0;
    item->FileAttributes = file_attributes;
    item->CreationTime.QuadPart = creation_time;
    item->NextEntryOffset = (USHORT)(sizeof(FILE_ITEM) + item->FileNameLength);

    memset(&item->CcInfo, 0, sizeof(item->CcInfo));
    item->CcInfo.cbSize = sizeof(CACHE_CONTEXT);
    item->CcInfo.LocalFlags = 0;
    item->CcInfo.ChannelSupport = (UCHAR)channel_support;
    item->CcInfo.ChannelIndex = channel_index;
    item->CcInfo.Flags = 0;
    item->CcInfo.SignOrLen = FILEIOCTL_SIGN;
    item->CcInfo.AppId = m_appid;
    item->CcInfo.FileId = file_id;
    item->CcInfo.FileSize.QuadPart = totalsize;
    item->CcInfo.SizeOfHeader = 0;
    memcpy_s(&item->CcInfo.Sha, sizeof(FILE_ITEM::CcInfo.Sha), file_hash, 20);

    if (modify) {
        return modify_item(item);
    }
    return add_item(item);
}

bool FileListControl::add_filelist_folder(
    ULONG appid,
    LPCWSTR file_name_src, 
    LONGLONG creation_time,
    UINT channel_support,
    UINT channel_index, 
    ULONG file_attributes)
{
    if (false == check_folder(file_name_src, creation_time)) {
        return false;
    }

    //客户端的相对路径的MD5作为清单ID
    MD5_CTX md5_ctx;
    MD5Init(&md5_ctx);
    CStringW client_path = file_name_src;
    client_path.MakeLower();
    MD5Update(&md5_ctx, (unsigned char*)client_path.GetString(), client_path.GetLength() * sizeof(WCHAR));
    MD5Final(&md5_ctx);

    size_t pathLen = (wcslen(file_name_src) + 1) * sizeof(WCHAR);
    size_t itemSize = sizeof(FILE_ITEM) + pathLen;
    std::string itemBuf;
    itemBuf.resize(itemSize);

    FILE_ITEM_WITH_FILENAME& item_ = *(FILE_ITEM_WITH_FILENAME*)itemBuf.data();
    int char_count = wsprintfW(item_.file_name, L"%s", file_name_src) + 1;

    PFILE_ITEM item = &item_.item;
    item->DataOffset = 0;
    item->FileNameOffset = sizeof(FILE_ITEM);
    item->FileNameLength = (USHORT)(char_count * sizeof(WCHAR));
    item->Flags = 0;
    item->FileAttributes = file_attributes | FILE_ATTRIBUTE_DIRECTORY;
    item->CreationTime.QuadPart = creation_time;
    item->NextEntryOffset = (USHORT)(sizeof(FILE_ITEM) + item->FileNameLength);

    memset(&item->CcInfo, 0, sizeof(item->CcInfo));
    item->CcInfo.cbSize = sizeof(CACHE_CONTEXT);
    item->CcInfo.LocalFlags = 0;
    item->CcInfo.ChannelSupport = channel_support;
    item->CcInfo.Flags = 0;
    item->CcInfo.ChannelIndex = channel_index;
    item->CcInfo.SignOrLen = FILEIOCTL_SIGN;
    item->CcInfo.AppId = appid;
    item->CcInfo.FileId = 0; //InterlockedIncrement(&m_fileid);
    item->CcInfo.FileSize.QuadPart = 0;
    item->CcInfo.SizeOfHeader = 0;

    memcpy_s(item->CcInfo.Sha.md5, 16, md5_ctx.digest, 16);
    item->CcInfo.Sha.Ver = 0;

    if (add_item(item)) {
        EnterCriticalSection(&m_cs);
        folder_map[file_name_src] = TRUE;
        LeaveCriticalSection(&m_cs);
        return true;
    }
    return false;
}

bool FileListControl::add_filelist_folder(
    ULONG appid,
    LPCSTR file_name_src, 
    LONGLONG creation_time,
    UINT channel_support,
    UINT channel_index,
    ULONG file_attributes)
{
    WCHAR file_name[LONG_PATH];
    wsprintfW(file_name, L"%S", file_name_src);
    return add_filelist_folder(appid, file_name, creation_time, channel_support, channel_index);
}

bool FileListControl::add_folder(
    LPCSTR file_name_src, 
    LONGLONG creation_time,
    ULONG file_attributes,
    BOOL modify)
{
    WCHAR file_name[LONG_PATH];
    wsprintfW(file_name, L"%S", file_name_src);
    return add_folder(file_name, creation_time, modify);
}

bool FileListControl::add_folder(
    LPCWSTR file_name_src, 
    LONGLONG creation_time,
    ULONG file_attributes,
    BOOL modify)
{
    if (false == check_folder(file_name_src, creation_time)) {
        return false;
    }

    ULONG file_id = GetFileId(file_name_src, TRUE);
	if (file_id == 0) {
        file_id = InterlockedIncrement(&m_fileid);
    }

    size_t pathLen = (wcslen(file_name_src) + 1) * sizeof(WCHAR);
    size_t itemSize = sizeof(FILE_ITEM) + pathLen;
    std::string itemBuf;
    itemBuf.resize(itemSize);

    FILE_ITEM_WITH_FILENAME& item_ = *(FILE_ITEM_WITH_FILENAME*)itemBuf.data();
    int char_count = wsprintfW(item_.file_name, L"%s", file_name_src) + 1;

    PFILE_ITEM item = &item_.item;
    item->DataOffset = 0;
    item->FileNameOffset = sizeof(FILE_ITEM);
    item->FileNameLength = (USHORT)(char_count * sizeof(WCHAR));
    item->Flags = 0;
    item->FileAttributes = file_attributes | FILE_ATTRIBUTE_DIRECTORY;
    item->CreationTime.QuadPart = creation_time;
    item->NextEntryOffset = (USHORT)(sizeof(FILE_ITEM) + item->FileNameLength);

    memset(&item->CcInfo, 0, sizeof(item->CcInfo));
    item->CcInfo.cbSize = sizeof(CACHE_CONTEXT);
    item->CcInfo.LocalFlags = 0;
    item->CcInfo.ChannelSupport = CSF_TCP;
    item->CcInfo.ChannelIndex = 0;
    item->CcInfo.Flags = 0;
    item->CcInfo.SignOrLen = FILEIOCTL_SIGN;
    item->CcInfo.AppId = m_appid;
    item->CcInfo.FileId = file_id;
    item->CcInfo.FileSize.QuadPart = 0;
    item->CcInfo.SizeOfHeader = 0;

    bool bRet;
    if (modify) {
        bRet = modify_item(item);
    }
    else {
        bRet = add_item(item);
    }

    if (bRet) {
        EnterCriticalSection(&m_cs);
        folder_map[file_name_src] = TRUE;
        LeaveCriticalSection(&m_cs);
        return true;
    }
    return false;
}

bool FileListControl::check_folder(LPCSTR file_name_src, LONGLONG creation_time)
{
    WCHAR file_name[LONG_PATH];
    wsprintfW(file_name, L"%S", file_name_src);
    return check_folder(file_name, creation_time);
}

bool FileListControl::check_folder(LPCWSTR file_name_src, LONGLONG creation_time)
{
    auto find = StrRChr(file_name_src, NULL, L'\\');
    if (find) {
        size_t size = find - file_name_src;
        if (size > 0) {
            CStringW path(file_name_src, (int)size);
            EnterCriticalSection(&m_cs);
            auto fit = folder_map.find(path);
            if (fit == folder_map.end()) {
                add_folder(path.GetString(), creation_time);
                folder_map[path] = TRUE;
            }
            LeaveCriticalSection(&m_cs);
        }
    }
    return true;
}

size_t FileListControl::get_result_size()
{
    return size_t(m_item_size + (m_header ? m_header->cbSize : 0));
}

bool FileListControl::get_result(LPVOID buf, size_t buf_size)
{
    auto p = buf;
    long long s = (long long)buf_size;
    if (m_header && m_items) {
        size_t total_size = m_header->cbSize + m_item_size;
        if (total_size <= buf_size) {
            memcpy_s(p, s, m_header, m_header->cbSize);
            s -= m_header->cbSize;
            p = (LPVOID)((DWORD_PTR)p + m_header->cbSize);

            if (s > 0) {
                memcpy_s(p, s, m_items, m_item_size);
                s -= m_item_size;
            }

            PCACHE_CONTEXT(buf)->FileSize.QuadPart = total_size;
            if (m_lastest_item) {
                auto lastest_item  = (PFILE_ITEM)((DWORD_PTR)p + ((DWORD_PTR)m_lastest_item - (DWORD_PTR)m_items));
                lastest_item->NextEntryOffset = 0;
            }
            return true;
        }
    }
    return false;
}

FileListLoader::FileListLoader()
    : m_data(NULL), 
    m_is_file_mapping(FALSE), 
    m_file_handle(NULL), 
    m_map_handle(NULL)
{
}

FileListLoader::~FileListLoader()
{
    Release();
}

void FileListLoader::Release()
{
    if (m_data) {
        // 如果m_data来自文件映射，则使用UnmapViewOfFile释放
        if (m_is_file_mapping) {
            UnmapViewOfFile(m_data);
        }
        else {
            // 否则使用free释放
            free(m_data);
        }
        m_data = NULL;
        m_is_file_mapping = FALSE;
    }
    if (m_map_handle) {
        // 释放内存映射句柄
        CloseHandle(m_map_handle);
        m_map_handle = NULL;
    }
    if (m_file_handle && INVALID_HANDLE_VALUE != m_file_handle) {
        // 释放文件句柄
        CloseHandle(m_file_handle);
        m_file_handle = NULL;
    }
}

BOOL FileListLoader::_load(LPCTSTR file)
{
    Release();

    m_file_handle = CreateFile(file, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (INVALID_HANDLE_VALUE == m_file_handle) {
        return FALSE;
    }

    LARGE_INTEGER file_size;
    file_size.QuadPart = 0;
    file_size.LowPart = GetFileSize(m_file_handle, (LPDWORD)&file_size.QuadPart);

    if (file_size.QuadPart < sizeof(CACHE_CONTEXT) && file_size.QuadPart < sizeof(LF::CompressInfo)) {
        return FALSE;
    }

    m_map_handle = CreateFileMapping(m_file_handle, NULL, FILE_MAP_READ, file_size.HighPart, file_size.LowPart, NULL);
    if (!m_map_handle) {
        return FALSE;
    }

    m_data = (PCACHE_CONTEXT)MapViewOfFile(m_map_handle, FILE_MAP_READ, 0, 0, file_size.QuadPart);
    if (!m_data) {
        return FALSE;
    }
    m_is_file_mapping = TRUE;

    if (((LF::PCompressInfo)m_data)->type == LF::FILESLIST_COMPRESS_TYPE) {
        size_t size = ((LF::PCompressInfo)m_data)->uncompress_size;
        PCACHE_CONTEXT buf = (PCACHE_CONTEXT)malloc(size);
        if (!buf) {
            return FALSE;
        }
        if (FALSE == LF::Decompress((LF::PLzmaFilesList)m_data, buf, size)) {
            free(buf);
            return FALSE;
        }

        UnmapViewOfFile(m_data);
        m_data = buf;
        m_is_file_mapping = FALSE;

        CloseHandle(m_map_handle);
        CloseHandle(m_file_handle);

        m_map_handle = m_file_handle = NULL;

        if (m_data->FileSize.QuadPart > (LONGLONG)size) {
            return FALSE;
        }
        return TRUE;
    }
    else if (m_data->cbSize == sizeof(CACHE_CONTEXT)) {
        if (m_data->FileSize.QuadPart >  file_size.QuadPart) {
            return FALSE;
        }
        return TRUE;
    }
    return FALSE;
}

BOOL FileListLoader::load(LPCTSTR file, PCACHE_CONTEXT* header, PFILE_ITEM* firstitem)
{
    if (_load(file)) {
        if (header) {
            *header = this->header();
        }
        if (firstitem) {
            *firstitem = this->firstitem();
        }
        return TRUE;
    }
    else {
        Release();
    }
    return FALSE;
}

PCACHE_CONTEXT FileListLoader::header()
{
    return m_data;
}

PFILE_ITEM FileListLoader::firstitem()
{
    return (PFILE_ITEM)((DWORD_PTR)m_data + m_data->SizeOfHeader);;
}
