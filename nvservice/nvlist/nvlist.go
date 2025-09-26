package nvlist

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/ulikunitz/xz/lzma"
)

const (
	fileListMagic      = 0x4C33 // "L3"
	fileListHeaderSize = 40
	lzmaHeaderLen      = 13
	cacheContextLen    = 48

	fileAttributeDirectory = 0x10
)

type CacheContext struct {
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

func (c CacheContext) ChannelIndex() uint8 { return c.DataProp & 0x7 }
func (c CacheContext) FlagsValue() uint8   { return c.DataProp >> 3 }

type FileItem struct {
	NextEntryOffset uint16
	DataOffset      uint16
	FileNameOffset  uint16
	FileNameLength  uint16
	Flags           uint32
	FileAttributes  uint32
	CreationTime    int64
	Context         CacheContext
	Name            string
	ExtraData       []byte
}

type FileListExtension struct {
	Type uint32
	Data []byte
}

type FileList struct {
	Header     CacheContext
	Items      []FileItem
	Extensions []FileListExtension
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

func ParseFile(path string) (*FileList, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

func Parse(blob []byte) (*FileList, error) {
	payload, err := decompress(blob)
	if err != nil {
		return nil, err
	}

	fl := &FileList{}
	header, err := parseCacheContext(payload)
	if err != nil {
		return nil, fmt.Errorf("parse cache context: %w", err)
	}
	fl.Header = header

	items, nextOffset, err := parseFileItems(payload, header)
	if err != nil {
		return nil, err
	}
	fl.Items = items

	exts, err := parseExtensions(payload, nextOffset)
	if err != nil {
		return nil, err
	}
	fl.Extensions = exts

	return fl, nil
}

func (fl *FileList) HashCounts() map[string]int {
	counts := make(map[string]int)
	if fl == nil {
		return counts
	}
	for _, item := range fl.Items {
		if item.FileAttributes&fileAttributeDirectory != 0 {
			continue
		}
		hash := hex.EncodeToString(item.Context.Sha[:])
		counts[hash]++
	}
	return counts
}

func decompress(raw []byte) ([]byte, error) {
	if len(raw) < fileListHeaderSize {
		return nil, fmt.Errorf("file list too small: %d bytes", len(raw))
	}

	var hdr fileListHeader
	if err := binary.Read(bytes.NewReader(raw[:fileListHeaderSize]), binary.LittleEndian, &hdr); err != nil {
		return nil, fmt.Errorf("parse file list header: %w", err)
	}

	if hdr.Type != fileListMagic {
		return nil, fmt.Errorf("unsupported file list type 0x%04X", hdr.Type)
	}

	if int(hdr.CompressedLen) > len(raw)-fileListHeaderSize {
		return nil, fmt.Errorf("compressed payload truncated: want %d bytes, have %d", hdr.CompressedLen, len(raw)-fileListHeaderSize)
	}

	comp := raw[fileListHeaderSize : fileListHeaderSize+int(hdr.CompressedLen)]

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

	return data, nil
}

func parseCacheContext(buf []byte) (CacheContext, error) {
	if len(buf) < cacheContextLen {
		return CacheContext{}, fmt.Errorf("cache context truncated: need %d bytes, have %d", cacheContextLen, len(buf))
	}

	var ctx CacheContext
	ctx.CBSize = buf[0]
	ctx.LocalFlags = buf[1]
	ctx.ChannelSupport = buf[2]
	ctx.DataProp = buf[3]
	ctx.SignOrLen = binary.LittleEndian.Uint32(buf[4:8])
	ctx.AppID = binary.LittleEndian.Uint32(buf[8:12])
	ctx.FileID = binary.LittleEndian.Uint32(buf[12:16])
	ctx.FileSize = binary.LittleEndian.Uint64(buf[16:24])
	copy(ctx.Sha[:], buf[24:44])
	ctx.SizeOfHeader = binary.LittleEndian.Uint32(buf[44:48])
	return ctx, nil
}

func parseFileItems(buf []byte, header CacheContext) ([]FileItem, int, error) {
	items := make([]FileItem, 0)
	if int(header.SizeOfHeader) > len(buf) {
		return nil, 0, fmt.Errorf("sizeOfHeader %d exceeds payload length %d", header.SizeOfHeader, len(buf))
	}

	if int(header.FileSize) > len(buf) {
		return nil, 0, fmt.Errorf("fileSize %d exceeds payload length %d", header.FileSize, len(buf))
	}

	offset := int(header.SizeOfHeader)
	limit := int(header.FileSize)
	for offset < limit {
		if offset+24 > limit {
			return nil, 0, fmt.Errorf("file item header truncated at offset %d", offset)
		}

		item := FileItem{}
		item.NextEntryOffset = binary.LittleEndian.Uint16(buf[offset : offset+2])
		item.DataOffset = binary.LittleEndian.Uint16(buf[offset+2 : offset+4])
		item.FileNameOffset = binary.LittleEndian.Uint16(buf[offset+4 : offset+6])
		item.FileNameLength = binary.LittleEndian.Uint16(buf[offset+6 : offset+8])
		item.Flags = binary.LittleEndian.Uint32(buf[offset+8 : offset+12])
		item.FileAttributes = binary.LittleEndian.Uint32(buf[offset+12 : offset+16])
		item.CreationTime = int64(binary.LittleEndian.Uint64(buf[offset+16 : offset+24]))

		ctxOffset := offset + 24
		if ctxOffset+cacheContextLen > limit {
			return nil, 0, fmt.Errorf("embedded cache context truncated at offset %d", ctxOffset)
		}
		ctx, err := parseCacheContext(buf[ctxOffset : ctxOffset+cacheContextLen])
		if err != nil {
			return nil, 0, err
		}
		item.Context = ctx

		nameOffset := offset + int(item.FileNameOffset)
		nameEnd := nameOffset + int(item.FileNameLength)
		if nameOffset < 0 || nameEnd > limit {
			return nil, 0, fmt.Errorf("file name range [%d:%d] out of bounds (limit %d)", nameOffset, nameEnd, limit)
		}
		nameBytes := buf[nameOffset:nameEnd]
		runes := make([]rune, 0, len(nameBytes)/2)
		for i := 0; i+1 < len(nameBytes); i += 2 {
			r := rune(binary.LittleEndian.Uint16(nameBytes[i : i+2]))
			if r == 0 {
				break
			}
			runes = append(runes, r)
		}
		item.Name = string(runes)

		if item.DataOffset != 0 {
			extraStart := offset + int(item.DataOffset)
			extraEnd := offset + int(item.NextEntryOffset)
			if item.NextEntryOffset == 0 {
				extraEnd = limit
			}
			if extraStart >= extraEnd || extraEnd > limit {
				return nil, 0, fmt.Errorf("invalid extra data range [%d:%d]", extraStart, extraEnd)
			}
			item.ExtraData = append([]byte(nil), buf[extraStart:extraEnd]...)
		}

		items = append(items, item)

		if item.NextEntryOffset == 0 {
			offset = limit
			break
		}
		offset += int(item.NextEntryOffset)
	}

	return items, limit, nil
}

func parseExtensions(buf []byte, offset int) ([]FileListExtension, error) {
	exts := make([]FileListExtension, 0)
	for offset+8 <= len(buf) {
		size := binary.LittleEndian.Uint32(buf[offset : offset+4])
		typ := binary.LittleEndian.Uint32(buf[offset+4 : offset+8])
		dataStart := offset + 8
		dataEnd := dataStart + int(size)
		if dataEnd > len(buf) {
			return nil, fmt.Errorf("extension data truncated: need %d bytes at offset %d, have %d", size, offset, len(buf)-dataStart)
		}
		exts = append(exts, FileListExtension{Type: typ, Data: append([]byte(nil), buf[dataStart:dataEnd]...)})
		offset = dataEnd
	}
	return exts, nil
}
