package listdata

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/ulikunitz/xz/lzma"
)

const (
	FileAttributeDirectory = 0x10
	FileAttributeArchive   = 0x20

	cacheCtxSize  = 48
	fileItemFixed = 24

	fileIoctlSign = 0x620495FE
	appIDNvCache  = 0x40000000 | 91

	listExNVName = 911

	fileListMagic      = 0x4C33
	fileListHeaderSize = 40
	lzmaHeaderLen      = 13

	channelSupportCDN = 1 << 1
	channelIndexCDN   = 1

	ticksPerSecond            = int64(10_000_000)
	unixToWindowsEpochSeconds = int64(11644473600)
)

type Entry struct {
	Path         string
	Attributes   uint32
	CreationTime int64
	Size         int64
	Hash         [20]byte
}

type File struct {
	Header       cacheContext
	Entries      map[string]*Entry
	Ordered      []string
	Uncompressed []byte
	RawBytes     []byte
}

type cacheContext struct {
	CBSize         uint8
	LocalFlags     uint8
	ChannelSupport uint8
	DataProp       uint8
	SignOrLen      uint32
	AppID          uint32
	FileID         uint32
	FileSize       uint64
	Sha            [20]byte
	SizeOfHeader   uint32
}

type fileListHeader struct {
	Type            uint16
	Checksum        uint16
	UncompressedLen uint32
	CompressedLen   uint32
	Prop            [6]byte
	Reserved        uint16
	Sha             [20]byte
}

type fileItemHeader struct {
	NextEntryOffset uint16
	DataOffset      uint16
	FileNameOffset  uint16
	FileNameLength  uint16
	Flags           uint32
	FileAttributes  uint32
	CreationTime    int64
}

func ParseFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func Parse(blob []byte) (*File, error) {
	if len(blob) >= fileListHeaderSize {
		var hdr fileListHeader
		if err := binary.Read(bytes.NewReader(blob[:fileListHeaderSize]), binary.LittleEndian, &hdr); err == nil {
			if hdr.Type == fileListMagic {
				return parseCompressed(blob, &hdr)
			}
		}
	}
	return parseUncompressed(blob, nil)
}

func ParseRaw(blob []byte) (*File, error) {
	return parseUncompressed(blob, nil)
}

func parseCompressed(blob []byte, hdr *fileListHeader) (*File, error) {
	if len(blob) < fileListHeaderSize {
		return nil, fmt.Errorf("compressed list truncated")
	}
	compLen := int(hdr.CompressedLen)
	if compLen < 0 || fileListHeaderSize+compLen > len(blob) {
		return nil, fmt.Errorf("compressed payload truncated: want %d bytes, have %d", hdr.CompressedLen, len(blob)-fileListHeaderSize)
	}

	comp := blob[fileListHeaderSize : fileListHeaderSize+compLen]

	header := make([]byte, lzmaHeaderLen)
	header[0] = hdr.Prop[0]
	copy(header[1:5], hdr.Prop[1:5])
	binary.LittleEndian.PutUint64(header[5:], uint64(hdr.UncompressedLen))

	reader, err := lzma.NewReader(io.MultiReader(bytes.NewReader(header), bytes.NewReader(comp)))
	if err != nil {
		return nil, fmt.Errorf("init lzma reader: %w", err)
	}
	var out bytes.Buffer
	if hdr.UncompressedLen > 0 {
		out.Grow(int(hdr.UncompressedLen))
	}
	if _, err := io.Copy(&out, reader); err != nil {
		return nil, fmt.Errorf("decompress file list: %w", err)
	}
	data := out.Bytes()
	if hdr.UncompressedLen != 0 && len(data) != int(hdr.UncompressedLen) {
		return nil, fmt.Errorf("unexpected file list size: expect %d, got %d", hdr.UncompressedLen, len(data))
	}

	file, err := parseUncompressed(data, blob)
	if err != nil {
		return nil, err
	}
	file.Uncompressed = data
	return file, nil
}

func parseUncompressed(blob []byte, compressed []byte) (*File, error) {
	if len(blob) < cacheCtxSize {
		return nil, fmt.Errorf("nv list too small: %d", len(blob))
	}

	var hdr cacheContext
	if err := binary.Read(bytes.NewReader(blob[:cacheCtxSize]), binary.LittleEndian, &hdr); err != nil {
		return nil, fmt.Errorf("read cache context: %w", err)
	}
	if hdr.SizeOfHeader != cacheCtxSize {
		return nil, fmt.Errorf("unexpected header size %d", hdr.SizeOfHeader)
	}
	if hdr.SignOrLen != fileIoctlSign {
		return nil, fmt.Errorf("invalid signature 0x%X", hdr.SignOrLen)
	}

	limit := int(hdr.FileSize)
	if limit == 0 {
		limit = len(blob)
	}
	if limit > len(blob) {
		return nil, fmt.Errorf("file size %d exceeds payload %d", limit, len(blob))
	}

	entries := make(map[string]*Entry)
	offset := cacheCtxSize
	for offset < limit {
		if offset+fileItemFixed > limit {
			return nil, errors.New("truncated FILE_ITEM header")
		}
		var fi fileItemHeader
		if err := binary.Read(bytes.NewReader(blob[offset:offset+fileItemFixed]), binary.LittleEndian, &fi); err != nil {
			return nil, fmt.Errorf("read file item header: %w", err)
		}

		itemEnd := offset + int(fi.NextEntryOffset)
		if fi.NextEntryOffset == 0 {
			itemEnd = limit
		}
		if itemEnd > limit {
			return nil, fmt.Errorf("file item overruns payload: end=%d limit=%d", itemEnd, limit)
		}

		ctxOffset := offset + fileItemFixed
		if ctxOffset+cacheCtxSize > limit {
			return nil, errors.New("embedded cache context truncated")
		}
		var itemCtx cacheContext
		if err := binary.Read(bytes.NewReader(blob[ctxOffset:ctxOffset+cacheCtxSize]), binary.LittleEndian, &itemCtx); err != nil {
			return nil, fmt.Errorf("read embedded cache context: %w", err)
		}

		nameOffset := offset + int(fi.FileNameOffset)
		nameEnd := nameOffset + int(fi.FileNameLength)
		if nameOffset < 0 || nameEnd > itemEnd {
			return nil, fmt.Errorf("file name range [%d:%d] out of bounds", nameOffset, nameEnd)
		}
		name, err := decodeUTF16(blob[nameOffset:nameEnd])
		if err != nil {
			return nil, fmt.Errorf("decode file name: %w", err)
		}

		lower := strings.ToLower(name)
		entry := &Entry{
			Path:         name,
			Attributes:   fi.FileAttributes,
			CreationTime: fi.CreationTime,
			Size:         int64(itemCtx.FileSize),
		}
		copy(entry.Hash[:], itemCtx.Sha[:])
		entries[lower] = entry

		if fi.NextEntryOffset == 0 {
			offset = limit
		} else {
			offset += int(fi.NextEntryOffset)
		}
	}

	ordered := make([]string, 0, len(entries))
	for k := range entries {
		ordered = append(ordered, k)
	}
	sort.Slice(ordered, func(i, j int) bool { return lessPath(ordered[i], ordered[j]) })

	raw := blob
	if compressed != nil {
		raw = append([]byte(nil), compressed...)
	}

	return &File{
		Header:       hdr,
		Entries:      entries,
		Ordered:      ordered,
		Uncompressed: append([]byte(nil), blob...),
		RawBytes:     raw,
	}, nil
}

func (f *File) CloneEntries() map[string]*Entry {
	clone := make(map[string]*Entry, len(f.Entries))
	for k, v := range f.Entries {
		if v == nil {
			continue
		}
		copyEntry := *v
		clone[k] = &copyEntry
	}
	return clone
}

func (f *File) Counts() map[string]int {
	counts := make(map[string]int)
	if f == nil {
		return counts
	}
	for _, key := range f.Ordered {
		entry := f.Entries[key]
		if entry == nil || entry.Attributes&FileAttributeDirectory != 0 {
			continue
		}
		counts[hex.EncodeToString(entry.Hash[:])]++
	}
	return counts
}

func Build(listName string, entries map[string]*Entry, template *File) (*File, error) {
	normalized := make(map[string]*Entry, len(entries))
	ordered := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		normPath := NormalizePath(entry.Path)
		if normPath == "" {
			continue
		}
		lower := strings.ToLower(normPath)
		clone := *entry
		clone.Path = normPath
		normalized[lower] = &clone
		ordered = append(ordered, lower)
	}
	sort.Slice(ordered, func(i, j int) bool { return lessPath(ordered[i], ordered[j]) })

	header := defaultHeader()
	if template != nil {
		header.LocalFlags = template.Header.LocalFlags
		header.ChannelSupport = template.Header.ChannelSupport
		header.DataProp = template.Header.DataProp
		header.AppID = template.Header.AppID
	}

	items := make([][]byte, 0, len(ordered))
	for _, key := range ordered {
		entry := normalized[key]
		item, err := buildFileItem(entry)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	for i := range items {
		if i == len(items)-1 {
			binary.LittleEndian.PutUint16(items[i][0:], 0)
		} else {
			binary.LittleEndian.PutUint16(items[i][0:], uint16(len(items[i])))
		}
	}

	now := time.Now().UTC()
	filetime := unixToFiletime(now)
	binary.LittleEndian.PutUint64(header.Sha[8:16], uint64(filetime))

	buf := &bytes.Buffer{}
	if err := binary.Write(buf, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("write header: %w", err)
	}
	for _, item := range items {
		if _, err := buf.Write(item); err != nil {
			return nil, fmt.Errorf("write item: %w", err)
		}
	}
	raw := buf.Bytes()
	binary.LittleEndian.PutUint64(raw[16:], uint64(len(raw)))

	if listName != "" {
		ext := buildExtension(listName)
		raw = append(raw, ext...)
		binary.LittleEndian.PutUint64(raw[16:], uint64(len(raw)))
	}

	var finalHeader cacheContext
	if err := binary.Read(bytes.NewReader(raw[:cacheCtxSize]), binary.LittleEndian, &finalHeader); err != nil {
		return nil, fmt.Errorf("read final header: %w", err)
	}

	compressed, err := compress(raw)
	if err != nil {
		return nil, err
	}

	file := &File{
		Header:       finalHeader,
		Entries:      normalized,
		Ordered:      ordered,
		Uncompressed: append([]byte(nil), raw...),
		RawBytes:     compressed,
	}

	return file, nil
}

func compress(raw []byte) ([]byte, error) {
	cfg := lzma.WriterConfig{
		DictCap:    1 << 24,
		Properties: &lzma.Properties{LC: 3, LP: 0, PB: 2},
		Size:       int64(len(raw)),
	}
	buf := &bytes.Buffer{}
	w, err := cfg.NewWriter(buf)
	if err != nil {
		return nil, fmt.Errorf("init lzma writer: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return nil, fmt.Errorf("compress list: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finish compression: %w", err)
	}
	stream := buf.Bytes()
	if len(stream) < lzmaHeaderLen {
		return nil, errors.New("lzma stream too small")
	}

	header := stream[:lzmaHeaderLen]
	body := stream[lzmaHeaderLen:]

	var hdr fileListHeader
	hdr.Type = fileListMagic
	hdr.Checksum = checksum(raw)
	hdr.UncompressedLen = uint32(len(raw))
	hdr.CompressedLen = uint32(len(body))
	copy(hdr.Prop[:5], header[:5])
	copy(hdr.Sha[:], raw[24:44])

	out := &bytes.Buffer{}
	if err := binary.Write(out, binary.LittleEndian, &hdr); err != nil {
		return nil, fmt.Errorf("write list header: %w", err)
	}
	out.Write(body)
	return out.Bytes(), nil
}

func checksum(data []byte) uint16 {
	var sum uint32
	i := 0
	for ; i+1 < len(data); i += 2 {
		sum += uint32(binary.LittleEndian.Uint16(data[i : i+2]))
	}
	if i < len(data) {
		sum += uint32(data[i])
	}
	return uint16(sum & 0xFFFF)
}

func NormalizePath(path string) string {
	path = strings.ReplaceAll(path, "/", "\\")
	path = strings.TrimSpace(path)
	path = strings.Trim(path, "\\")
	return path
}

func defaultHeader() cacheContext {
	return cacheContext{
		CBSize:         cacheCtxSize,
		LocalFlags:     0,
		ChannelSupport: channelSupportCDN,
		DataProp:       channelIndexCDN,
		SignOrLen:      fileIoctlSign,
		AppID:          appIDNvCache,
		FileID:         0,
		FileSize:       cacheCtxSize,
		SizeOfHeader:   cacheCtxSize,
	}
}

func buildFileItem(entry *Entry) ([]byte, error) {
	if entry == nil {
		return nil, errors.New("nil entry")
	}

	name := NormalizePath(entry.Path)
	if name == "" {
		return nil, errors.New("empty entry path")
	}

	u16 := utf16.Encode([]rune(name))
	u16 = append(u16, 0)
	fileNameLenBytes := len(u16) * 2

	itemSize := fileItemFixed + cacheCtxSize + fileNameLenBytes
	if itemSize%2 != 0 {
		itemSize++
	}
	if itemSize >= math.MaxUint16 {
		return nil, fmt.Errorf("item too large: %d bytes", itemSize)
	}

	buf := make([]byte, itemSize)
	binary.LittleEndian.PutUint16(buf[0:], 0)
	binary.LittleEndian.PutUint16(buf[2:], 0)
	binary.LittleEndian.PutUint16(buf[4:], uint16(fileItemFixed+cacheCtxSize))
	binary.LittleEndian.PutUint16(buf[6:], uint16(fileNameLenBytes))
	binary.LittleEndian.PutUint32(buf[8:], 0)
	binary.LittleEndian.PutUint32(buf[12:], entry.Attributes)
	binary.LittleEndian.PutUint64(buf[16:], uint64(entry.CreationTime))

	ctxOffset := fileItemFixed
	ctx := cacheContext{
		CBSize:         cacheCtxSize,
		LocalFlags:     0,
		ChannelSupport: channelSupportCDN,
		DataProp:       channelIndexCDN,
		SignOrLen:      fileIoctlSign,
		AppID:          appIDNvCache,
		FileID:         computeFileID(entry.Path, entry.Attributes&FileAttributeDirectory != 0),
		FileSize:       uint64(entry.Size),
	}
	copy(ctx.Sha[:], entry.Hash[:])

	var ctxBuf bytes.Buffer
	if err := binary.Write(&ctxBuf, binary.LittleEndian, &ctx); err != nil {
		return nil, err
	}
	copy(buf[ctxOffset:ctxOffset+cacheCtxSize], ctxBuf.Bytes())

	nameBytes := encodeUTF16(u16)
	copy(buf[fileItemFixed+cacheCtxSize:], nameBytes)

	return buf, nil
}

func buildExtension(listName string) []byte {
	data := []byte(listName)
	ext := make([]byte, 8+len(data))
	binary.LittleEndian.PutUint32(ext[0:4], uint32(len(data)))
	binary.LittleEndian.PutUint32(ext[4:8], listExNVName)
	copy(ext[8:], data)
	return ext
}

func decodeUTF16(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", errors.New("invalid utf16 byte length")
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	if n := len(u16); n > 0 && u16[n-1] == 0 {
		u16 = u16[:n-1]
	}
	return string(utf16.Decode(u16)), nil
}

func encodeUTF16(u16 []uint16) []byte {
	out := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	return out
}

func lessPath(a, b string) bool {
	if a == b {
		return false
	}
	ra := []rune(a)
	rb := []rune(b)
	na := len(ra)
	nb := len(rb)
	for i := 0; i < na && i < nb; i++ {
		ca, cb := ra[i], rb[i]
		if ca == '\\' {
			ca = 0
		}
		if cb == '\\' {
			cb = 0
		}
		if ca != cb {
			return ca < cb
		}
	}
	return na < nb
}

func computeFileID(path string, isDir bool) uint32 {
	lower := strings.ToLower(NormalizePath(path))
	u16 := utf16.Encode([]rune(lower))
	buf := encodeUTF16(u16)
	crc := crc32.ChecksumIEEE(buf)
	if isDir {
		extra := []byte{'\\', 0}
		crc = crc32.Update(crc, crc32.IEEETable, extra)
	}
	return crc
}

func unixToFiletime(t time.Time) int64 {
	secs := t.Unix() + unixToWindowsEpochSeconds
	return secs*ticksPerSecond + int64(t.Nanosecond()/100)
}
