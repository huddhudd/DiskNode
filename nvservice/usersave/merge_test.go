package usersave

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"saveserver/nvservice/listdata"
	"saveserver/nvservice/storage"

	"strings"
)

func TestMergeTempFiles(t *testing.T) {
	svc := newTestService(t)

	fixed := time.Unix(1_700_000_000, 123*int64(time.Millisecond))
	svc.now = func() time.Time { return fixed }

	ctx := context.Background()
	uid := uint32(42)
	rid := uint32(7)

	tempDir, err := svc.storage.UserTempDir(uid, true)
	if err != nil {
		t.Fatalf("user temp dir: %v", err)
	}
	ridDir := filepath.Join(tempDir, "7", "folder")
	if err := os.MkdirAll(ridDir, 0o755); err != nil {
		t.Fatalf("mkdir rid dir: %v", err)
	}
	payload := []byte("payload-data")
	filePath := filepath.Join(ridDir, "save.dat")
	if err := os.WriteFile(filePath, payload, 0o644); err != nil {
		t.Fatalf("write save file: %v", err)
	}

	reqDel := filepath.Join(tempDir, "7"+deleteRequestExt)
	if err := os.WriteFile(reqDel, []byte("folder\\old.txt|\r\n"), 0o644); err != nil {
		t.Fatalf("write reqdel: %v", err)
	}

	screenshot := filepath.Join(tempDir, "7.jpg")
	if err := os.WriteFile(screenshot, []byte("jpg"), 0o644); err != nil {
		t.Fatalf("write screenshot: %v", err)
	}

	oldTS := fixed.Add(-time.Hour).UnixMilli()
	err = svc.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO history (uid, rid, ver, rec_time, name, size, inuse) VALUES (?, ?, ?, ?, ?, ?, 1)`, uid, rid, oldTS, oldTS, "default", 123); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO files (uid, rid, file, size, hash, creation, attr, ver, rec_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			uid, rid, "7\\folder\\old.txt", 12, emptySHA1, oldTS, uint32(fileAttributeArchive), oldTS, oldTS); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed history: %v", err)
	}

	code, err := svc.MergeTempFiles(ctx, uid, rid)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if code != 0 {
		t.Fatalf("unexpected code %d", code)
	}

	hash := sha1.Sum(payload)
	hashHex := hex.EncodeToString(hash[:])
	archiveRoot := filepath.Join(filepath.Dir(filepath.Dir(tempDir)), storage.ArchiveDirName)
	archivePath := filepath.Join(archiveRoot, hashHex[:2], hashHex[2:4], hashHex)
	if _, err := os.Stat(archivePath); err != nil {
		t.Fatalf("archive file missing: %v", err)
	}

	err = svc.withTx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRow(`SELECT inuse FROM history WHERE uid=? AND rid=? AND ver=?`, uid, rid, oldTS)
		var inuseOld int
		if err := row.Scan(&inuseOld); err != nil {
			return err
		}
		if inuseOld != 0 {
			t.Fatalf("old version still in use")
		}

		newVer := fixed.UnixMilli()
		row = tx.QueryRow(`SELECT size FROM history WHERE uid=? AND rid=? AND ver=?`, uid, rid, newVer)
		var size int64
		if err := row.Scan(&size); err != nil {
			return err
		}
		if size != int64(len(payload)) {
			t.Fatalf("unexpected history size %d", size)
		}

		row = tx.QueryRow(`SELECT hash FROM files WHERE uid=? AND rid=? AND ver=? AND file=?`, uid, rid, newVer, "7\\folder\\save.dat")
		var storedHash string
		if err := row.Scan(&storedHash); err != nil {
			return err
		}
		if storedHash != hashHex {
			t.Fatalf("hash mismatch: %s", storedHash)
		}

		row = tx.QueryRow(`SELECT COUNT(*) FROM files WHERE uid=? AND rid=? AND ver=? AND file=?`, uid, rid, newVer, "7\\folder\\old.txt")
		var count int
		if err := row.Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatalf("old file still present")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("verify db: %v", err)
	}

	built, err := svc.BuildFilesList(ctx, uid)
	if err != nil {
		t.Fatalf("build list: %v", err)
	}
	if !built {
		t.Fatalf("expected list to be built")
	}

	listPath := svc.userListPath(uid)
	data, err := os.ReadFile(listPath)
	if err != nil {
		t.Fatalf("read list: %v", err)
	}
	listFile, err := listdata.Parse(data)
	if err != nil {
		t.Fatalf("parse list: %v", err)
	}
	key := strings.ToLower(listdata.NormalizePath("7\\folder\\save.dat"))
	entry := listFile.Entries[key]
	if entry == nil {
		t.Fatalf("list entry missing")
	}
	if entry.Size != int64(len(payload)) {
		t.Fatalf("unexpected list entry size %d", entry.Size)
	}

	infoBytes, err := svc.GetSaveInfo(ctx, uid, 0)
	if err != nil {
		t.Fatalf("get save info: %v", err)
	}
	var payloadInfo saveInfo
	if err := json.Unmarshal(infoBytes, &payloadInfo); err != nil {
		t.Fatalf("unmarshal save info: %v", err)
	}
	lv, ok := payloadInfo.LastVersion["7"]
	if !ok {
		t.Fatalf("lastVersion missing rid 7")
	}
	if lv.TotalFiles != 1 {
		t.Fatalf("unexpected total files %d", lv.TotalFiles)
	}
	if len(payloadInfo.History.Versions["7"]) == 0 {
		t.Fatalf("history versions empty")
	}

	singleRidInfo, err := svc.GetSaveInfo(ctx, uid, rid)
	if err != nil {
		t.Fatalf("get save info (rid): %v", err)
	}
	var singlePayload saveInfo
	if err := json.Unmarshal(singleRidInfo, &singlePayload); err != nil {
		t.Fatalf("unmarshal save info (rid): %v", err)
	}
	if len(singlePayload.LastVersion) != 1 {
		t.Fatalf("unexpected rid count %d", len(singlePayload.LastVersion))
	}

	if _, err := os.Stat(reqDel); !os.IsNotExist(err) {
		t.Fatalf("reqdel not removed: %v", err)
	}
	if _, err := os.Stat(screenshot); !os.IsNotExist(err) {
		t.Fatalf("temp screenshot not removed: %v", err)
	}

	destPic := filepath.Join(svc.userListDir, "42", fmt.Sprintf("7.%d.jpg", fixed.UnixMilli()))
	if _, err := os.Stat(destPic); err != nil {
		t.Fatalf("dest screenshot missing: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tempDir, "7")); !os.IsNotExist(err) {
		t.Fatalf("rid directory not cleaned: %v", err)
	}
}

func TestBuildFilesListEmpty(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	built, err := svc.BuildFilesList(ctx, 99)
	if err != nil {
		t.Fatalf("build list: %v", err)
	}
	if built {
		t.Fatalf("expected no list to be built")
	}
}
