package listdata

import (
	"encoding/hex"
	"testing"
)

func TestBuildAndParse(t *testing.T) {
	fileHash, err := hex.DecodeString("00112233445566778899aabbccddeeff00112233")
	if err != nil {
		t.Fatalf("decode hash: %v", err)
	}
	var hashArr [20]byte
	copy(hashArr[:], fileHash)

	entries := map[string]*Entry{
		"file1.txt": {
			Path:         "file1.txt",
			Attributes:   FileAttributeArchive,
			CreationTime: 123456789,
			Size:         42,
			Hash:         hashArr,
		},
		"Folder": {
			Path:         "Folder",
			Attributes:   FileAttributeDirectory,
			CreationTime: 987654321,
		},
	}

	built, err := Build("sample", entries, nil)
	if err != nil {
		t.Fatalf("build list: %v", err)
	}
	if len(built.RawBytes) < fileListHeaderSize {
		t.Fatalf("compressed payload too small: %d", len(built.RawBytes))
	}

	parsed, err := Parse(built.RawBytes)
	if err != nil {
		t.Fatalf("parse compressed list: %v", err)
	}

	if len(parsed.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(parsed.Entries))
	}

	fileEntry := parsed.Entries["file1.txt"]
	if fileEntry == nil {
		t.Fatalf("file entry missing")
	}
	if fileEntry.Size != 42 {
		t.Fatalf("expected file size 42, got %d", fileEntry.Size)
	}

	dirEntry := parsed.Entries["folder"]
	if dirEntry == nil {
		t.Fatalf("directory entry missing")
	}
	if dirEntry.Attributes&FileAttributeDirectory == 0 {
		t.Fatalf("directory attributes missing flag")
	}
	if dirEntry.Size != 0 {
		t.Fatalf("expected directory size 0, got %d", dirEntry.Size)
	}

	if len(built.Uncompressed) == 0 {
		t.Fatalf("uncompressed buffer empty")
	}
	if len(parsed.Uncompressed) == 0 {
		t.Fatalf("parsed uncompressed buffer empty")
	}
	if len(built.Uncompressed) != len(parsed.Uncompressed) {
		t.Fatalf("uncompressed length mismatch: %d vs %d", len(built.Uncompressed), len(parsed.Uncompressed))
	}
}
