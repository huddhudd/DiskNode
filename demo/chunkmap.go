package chunkmapparser

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ulikunitz/xz/lzma"
)

const (
	magicCK01              = 0x434B3031 // "CK01"
	magicCK02              = 0x434B3032 // "CK02"
	customDataSignature    = 0x4C32     // 'L2'
	compressFlagNoCompress = 1
	chunkMapMagicDescCK01  = "CK01"
	chunkMapMagicDescCK02  = "CK02"
	customHeaderSize       = 20
)

type customHeader struct {
	Type            uint16
	Checksum        uint16
	UncompressedLen uint32
	CompressedLen   uint32
	Prop            [6]byte
	Flag            byte
	Reserved        byte
}

type ChunkMapVersion uint32

const (
	ChunkMapVersionCK01 ChunkMapVersion = magicCK01
	ChunkMapVersionCK02 ChunkMapVersion = magicCK02
)

func (v ChunkMapVersion) String() string {
	switch uint32(v) {
	case magicCK01:
		return chunkMapMagicDescCK01
	case magicCK02:
		return chunkMapMagicDescCK02
	default:
		return fmt.Sprintf("0x%08X", uint32(v))
	}
}

func (v ChunkMapVersion) Magic() uint32 { return uint32(v) }

type ChunkMap struct {
	Version   ChunkMapVersion
	DepotKeys []DepotKey
	Files     []ChunkMapFile
	Trailing  []byte
}

type DepotKey struct {
	DepotID uint32
	Key     [32]byte
}

type ChunkMapFile struct {
	ID      [20]byte
	RawInfo []byte
	Info    DepotInfo
}

func (f ChunkMapFile) HexID() string {
	return strings.ToLower(hex.EncodeToString(f.ID[:]))
}
func (f ChunkMapFile) IsZeroID() bool {
	for _, b := range f.ID {
		if b != 0 {
			return false
		}
	}
	return true
}

type DepotInfo struct {
	Version   ChunkMapVersion
	DepotID   uint32
	TotalSize uint64
	CK01Extra uint32
	Chunks    []Chunk
}

type Chunk struct {
	Hash         [20]byte
	Checksum     uint32
	Offset       uint64
	Compressed   uint32
	Uncompressed uint32
	OffsetIs32   bool
}

// ParseChunkMap reads a chunk map from path, expands the custom LZMA envelope if
// necessary, and dumps a human readable view to stdout.
func ParseChunkMap(path string) error {
	cm, err := LoadChunkMap(path)
	if err != nil {
		return err
	}
	return dumpChunkMap(cm)
}

// LoadChunkMap parses the chunk map located at path and returns its structured
// representation.
func LoadChunkMap(path string) (*ChunkMap, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read chunk map: %w", err)
	}

	payload, err := ensureDecompressed(raw)
	if err != nil {
		return nil, err
	}

	return parseChunkMapPayload(payload)
}

// SerializeChunkMap builds a binary chunk map from the provided components.
func SerializeChunkMap(version ChunkMapVersion, depotKeys []DepotKey, files []ChunkMapFile) ([]byte, error) {
	if version != ChunkMapVersionCK01 && version != ChunkMapVersionCK02 {
		return nil, fmt.Errorf("unsupported chunk map version 0x%08X", uint32(version))
	}

	buf := &bytes.Buffer{}
	if err := binary.Write(buf, binary.LittleEndian, uint32(version)); err != nil {
		return nil, fmt.Errorf("write chunk map magic: %w", err)
	}

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(depotKeys))); err != nil {
		return nil, fmt.Errorf("write depot key count: %w", err)
	}

	for _, key := range depotKeys {
		if err := binary.Write(buf, binary.LittleEndian, key.DepotID); err != nil {
			return nil, fmt.Errorf("write depot id: %w", err)
		}
		if _, err := buf.Write(key.Key[:]); err != nil {
			return nil, fmt.Errorf("write depot key: %w", err)
		}
	}

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(files))); err != nil {
		return nil, fmt.Errorf("write file count: %w", err)
	}

	for _, file := range files {
		if _, err := buf.Write(file.ID[:]); err != nil {
			return nil, fmt.Errorf("write file id: %w", err)
		}
		infoLen := len(file.RawInfo)
		if infoLen > int(^uint32(0)) {
			return nil, fmt.Errorf("info blob too large: %d", infoLen)
		}
		if err := binary.Write(buf, binary.LittleEndian, uint32(infoLen)); err != nil {
			return nil, fmt.Errorf("write depot info size: %w", err)
		}
		if _, err := buf.Write(file.RawInfo); err != nil {
			return nil, fmt.Errorf("write depot info blob: %w", err)
		}
	}

	return buf.Bytes(), nil
}

// DepotKeyByID returns the depot key associated with depotID, if present.
func (cm *ChunkMap) DepotKeyByID(depotID uint32) (DepotKey, bool) {
	for _, key := range cm.DepotKeys {
		if key.DepotID == depotID {
			return key, true
		}
	}
	return DepotKey{}, false
}

func parseChunkMapPayload(payload []byte) (*ChunkMap, error) {
	reader := &byteReader{data: payload}

	magic, err := reader.readUint32()
	if err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}

	var version ChunkMapVersion
	switch magic {
	case magicCK01:
		version = ChunkMapVersionCK01
	case magicCK02:
		version = ChunkMapVersionCK02
	default:
		return nil, fmt.Errorf("invalid chunk map magic 0x%08X", magic)
	}

	depotKeyCount, err := reader.readUint32()
	if err != nil {
		return nil, fmt.Errorf("read depot key count: %w", err)
	}

	depotKeys := make([]DepotKey, 0, depotKeyCount)
	for i := uint32(0); i < depotKeyCount; i++ {
		depotID, err := reader.readUint32()
		if err != nil {
			return nil, fmt.Errorf("read depot id: %w", err)
		}
		keyBytes, err := reader.read(32)
		if err != nil {
			return nil, fmt.Errorf("read depot key: %w", err)
		}
		var key DepotKey
		key.DepotID = depotID
		copy(key.Key[:], keyBytes)
		depotKeys = append(depotKeys, key)
	}

	fileCount, err := reader.readUint32()
	if err != nil {
		return nil, fmt.Errorf("read file count: %w", err)
	}

	files := make([]ChunkMapFile, 0, fileCount)
	for i := uint32(0); i < fileCount; i++ {
		fileIDBytes, err := reader.read(20)
		if err != nil {
			return nil, fmt.Errorf("read file id: %w", err)
		}
		infoSize, err := reader.readUint32()
		if err != nil {
			return nil, fmt.Errorf("read depot info size: %w", err)
		}
		infoBytes, err := reader.read(int(infoSize))
		if err != nil {
			return nil, fmt.Errorf("read depot info blob: %w", err)
		}

		var file ChunkMapFile
		copy(file.ID[:], fileIDBytes)
		file.RawInfo = append([]byte(nil), infoBytes...)
		info, err := parseDepotInfo(version, infoBytes)
		if err != nil {
			return nil, fmt.Errorf("parse depot info for file %d: %w", i, err)
		}
		file.Info = info
		files = append(files, file)
	}

	trailing := payload[reader.pos:]
	var trailingCopy []byte
	if len(trailing) > 0 {
		trailingCopy = append([]byte(nil), trailing...)
	}

	return &ChunkMap{
		Version:   version,
		DepotKeys: depotKeys,
		Files:     files,
		Trailing:  trailingCopy,
	}, nil
}

func parseDepotInfo(version ChunkMapVersion, data []byte) (DepotInfo, error) {
	reader := &byteReader{data: data}
	info := DepotInfo{Version: version}

	switch version {
	case ChunkMapVersionCK01:
		depotID, err := reader.readUint32()
		if err != nil {
			return info, err
		}
		extra, err := reader.readUint32()
		if err != nil {
			return info, err
		}
		totalSizeBytes, err := reader.read(8)
		if err != nil {
			return info, err
		}
		totalSize := binary.LittleEndian.Uint64(totalSizeBytes)
		chunkCount, err := reader.readUint32()
		if err != nil {
			return info, err
		}

		info.DepotID = depotID
		info.CK01Extra = extra
		info.TotalSize = totalSize
		info.Chunks = make([]Chunk, 0, chunkCount)

		for idx := uint32(0); idx < chunkCount; idx++ {
			checksum, err := reader.readUint32()
			if err != nil {
				return info, err
			}
			hashBytes, err := reader.read(20)
			if err != nil {
				return info, err
			}
			offset32, err := reader.readUint32()
			if err != nil {
				return info, err
			}
			compressed, err := reader.readUint32()
			if err != nil {
				return info, err
			}
			uncompressed, err := reader.readUint32()
			if err != nil {
				return info, err
			}

			var hash [20]byte
			copy(hash[:], hashBytes)
			info.Chunks = append(info.Chunks, Chunk{
				Hash:         hash,
				Checksum:     checksum,
				Offset:       uint64(offset32),
				Compressed:   compressed,
				Uncompressed: uncompressed,
				OffsetIs32:   true,
			})
		}

	case ChunkMapVersionCK02:
		totalSize, err := reader.readUint64()
		if err != nil {
			return info, err
		}
		depotID, err := reader.readUint32()
		if err != nil {
			return info, err
		}
		chunkCount, err := reader.readUint32()
		if err != nil {
			return info, err
		}

		info.TotalSize = totalSize
		info.DepotID = depotID
		info.Chunks = make([]Chunk, 0, chunkCount)

		for idx := uint32(0); idx < chunkCount; idx++ {
			hashBytes, err := reader.read(20)
			if err != nil {
				return info, err
			}
			checksum, err := reader.readUint32()
			if err != nil {
				return info, err
			}
			offset, err := reader.readUint64()
			if err != nil {
				return info, err
			}
			compressed, err := reader.readUint32()
			if err != nil {
				return info, err
			}
			uncompressed, err := reader.readUint32()
			if err != nil {
				return info, err
			}

			var hash [20]byte
			copy(hash[:], hashBytes)
			info.Chunks = append(info.Chunks, Chunk{
				Hash:         hash,
				Checksum:     checksum,
				Offset:       offset,
				Compressed:   compressed,
				Uncompressed: uncompressed,
			})
		}

	default:
		return info, errors.New("unknown chunk map version")
	}

	if reader.pos != len(reader.data) {
		return info, fmt.Errorf("%d unread bytes remain in depot info", len(reader.data)-reader.pos)
	}

	return info, nil
}

func ensureDecompressed(raw []byte) ([]byte, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("chunk map payload too small: %d bytes", len(raw))
	}

	magic := binary.LittleEndian.Uint32(raw[:4])
	if magic == magicCK01 || magic == magicCK02 {
		return raw, nil
	}

	if len(raw) < customHeaderSize {
		return nil, fmt.Errorf("custom LZMA header truncated: have %d bytes", len(raw))
	}

	var hdr customHeader
	if err := binary.Read(bytes.NewReader(raw[:customHeaderSize]), binary.LittleEndian, &hdr); err != nil {
		return nil, fmt.Errorf("parse custom header: %w", err)
	}

	if hdr.Type != customDataSignature {
		return nil, fmt.Errorf("unknown chunk map signature 0x%04X", hdr.Type)
	}

	if len(raw) < customHeaderSize+int(hdr.CompressedLen) {
		return nil, fmt.Errorf("compressed data truncated: want %d bytes, have %d", hdr.CompressedLen, len(raw)-customHeaderSize)
	}

	comp := raw[customHeaderSize : customHeaderSize+int(hdr.CompressedLen)]

	if hdr.Flag&compressFlagNoCompress != 0 {
		if int(hdr.UncompressedLen) > len(comp) {
			return nil, fmt.Errorf("no-compress payload too small: want %d bytes, have %d", hdr.UncompressedLen, len(comp))
		}
		return comp[:int(hdr.UncompressedLen)], nil
	}

	header := make([]byte, 13)
	header[0] = hdr.Prop[0]
	copy(header[1:5], hdr.Prop[1:5])
	binary.LittleEndian.PutUint64(header[5:], uint64(hdr.UncompressedLen))

	reader, err := lzma.NewReader(io.MultiReader(bytes.NewReader(header), bytes.NewReader(comp)))
	if err != nil {
		return nil, fmt.Errorf("init lzma reader: %w", err)
	}

	var buf bytes.Buffer
	if hdr.UncompressedLen > 0 {
		buf.Grow(int(hdr.UncompressedLen))
	}

	if _, err := io.Copy(&buf, reader); err != nil {
		return nil, fmt.Errorf("decompress chunk map: %w", err)
	}

	out := buf.Bytes()
	if hdr.UncompressedLen != 0 && len(out) != int(hdr.UncompressedLen) {
		return nil, fmt.Errorf("unexpected decompressed size: expect %d, got %d", hdr.UncompressedLen, len(out))
	}

	return out, nil
}

type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) read(n int) ([]byte, error) {
	if r.pos+n > len(r.data) {
		return nil, io.ErrUnexpectedEOF
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b, nil
}

func (r *byteReader) readUint32() (uint32, error) {
	b, err := r.read(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (r *byteReader) readUint64() (uint64, error) {
	b, err := r.read(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

func dumpChunkMap(cm *ChunkMap) error {
	fmt.Printf("Chunk map version: %s\n", cm.Version.String())

	fmt.Printf("Depot keys: %d\n", len(cm.DepotKeys))
	for i, key := range cm.DepotKeys {
		fmt.Printf("  [%d] depot=%d key=%s\n", i, key.DepotID, toHex(key.Key[:]))
	}

	fmt.Printf("Files: %d\n", len(cm.Files))
	for i, file := range cm.Files {
		fmt.Printf("\nFile %d\n", i)
		fmt.Printf("  id: %s\n", toHex(file.ID[:]))

		switch cm.Version {
		case ChunkMapVersionCK01:
			fmt.Printf("  depot: %d (ck01-extra=%d)\n", file.Info.DepotID, file.Info.CK01Extra)
		case ChunkMapVersionCK02:
			fmt.Printf("  depot: %d\n", file.Info.DepotID)
		default:
			return errors.New("unknown chunk map version")
		}

		fmt.Printf("  total size: %d\n", file.Info.TotalSize)
		fmt.Printf("  chunks: %d\n", len(file.Info.Chunks))

		for idx, chunk := range file.Info.Chunks {
			fmt.Printf("    chunk %d: offset=%d compressed=%d uncompressed=%d checksum=0x%08X hash=%s\n",
				idx,
				chunk.Offset,
				chunk.Compressed,
				chunk.Uncompressed,
				chunk.Checksum,
				toHex(chunk.Hash[:]),
			)
		}
	}

	if len(cm.Trailing) > 0 {
		fmt.Printf("\nWarning: %d trailing bytes not parsed\n", len(cm.Trailing))
	}

	return nil
}

func toHex(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}
