package usersave

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"saveserver/nvfiles"
	"saveserver/nvservice/storage"
)

const (
	archDatabaseRelativePath = "Data/Arch.db"
	userListRelativePath     = "Data/UserList"
	tmpDirPrefix             = "TmpData"
	archiveDirName           = "ArchData"
	deleteRequestExt         = ".reqdel"
	taskKeepTime             = 30 * time.Minute
)

type Service struct {
	baseDir     string
	userListDir string
	archDBPath  string

	store   *nvfiles.Store
	storage *storage.DataFactory

	db              *sql.DB
	mu              sync.RWMutex
	dbMu            sync.Mutex
	reqdelMu        sync.Mutex
	now             func() time.Time
	once            sync.Once
	taskMu          sync.Mutex
	tasks           map[string]*task
	taskQueue       chan *task
	taskStopCh      chan struct{}
	taskWG          sync.WaitGroup
	shareClient     ShareClient
	shareDownloader ShareDownloader
}

func New(ctx context.Context, baseDir string, store *nvfiles.Store, dataFactory *storage.DataFactory) (*Service, error) {
	if store == nil {
		return nil, errors.New("nvfiles store is nil")
	}
	if dataFactory == nil {
		return nil, errors.New("data factory is nil")
	}

	baseDir = filepath.Clean(baseDir)
	if baseDir == "" {
		return nil, errors.New("base dir is empty")
	}

	svc := &Service{
		baseDir:     baseDir,
		userListDir: filepath.Join(baseDir, userListRelativePath),
		archDBPath:  filepath.Join(baseDir, archDatabaseRelativePath),
		store:       store,
		storage:     dataFactory,
		now:         time.Now,
	}
	svc.shareClient = NoopShareClient{}
	svc.shareDownloader = nil

	if err := svc.initDatabase(ctx); err != nil {
		return nil, err
	}
	svc.initTaskManager()
	return svc, nil
}

func (s *Service) Close() error {
	s.shutdownTaskManager()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

func (s *Service) initDatabase(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(s.archDBPath), 0o755); err != nil {
		return fmt.Errorf("create archive db dir: %w", err)
	}

	db, err := sql.Open("sqlite", s.archDBPath)
	if err != nil {
		return fmt.Errorf("open archive db: %w", err)
	}
	db.SetMaxOpenConns(1)

	if err := applyPragmas(ctx, db); err != nil {
		db.Close()
		return err
	}
	if err := ensureSchema(ctx, db); err != nil {
		db.Close()
		return err
	}

	s.mu.Lock()
	s.db = db
	s.mu.Unlock()
	return nil
}

func (s *Service) dbConn() (*sql.DB, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil, errors.New("usersave database not initialised")
	}
	return s.db, nil
}
func (s *Service) Exec(ctx context.Context, query string, args ...any) error {
	if query == "" {
		return errors.New("empty query")
	}
	db, err := s.dbConn()
	if err != nil {
		return err
	}
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	_, err = db.ExecContext(ctx, query, args...)
	return err
}

func (s *Service) UserTempDir(uid uint32, create bool) (string, error) {
	dir, err := s.storage.UserTempDir(uid, create)
	if err != nil {
		return "", err
	}
	if dir == "" {
		return "", os.ErrNotExist
	}
	return dir, nil
}

func (s *Service) UserListFilePath(uid uint32) string {
	return s.userListPath(uid)
}
func (s *Service) SetShareClient(client ShareClient) {
	if client == nil {
		client = NoopShareClient{}
	}
	s.shareClient = client
}

func (s *Service) ShareClient() ShareClient {
	if s.shareClient == nil {
		return NoopShareClient{}
	}
	return s.shareClient
}

func (s *Service) SetShareDownloader(downloader ShareDownloader) {
	s.shareDownloader = downloader
}

func (s *Service) ShareDownloader() ShareDownloader {
	return s.shareDownloader
}
