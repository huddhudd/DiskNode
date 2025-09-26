package integration

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	BaseURL string
	Token   string
	UID     uint32
	RID     uint32
	TempDir string
}

type TaskStatus struct {
	TaskID        string `json:"task_id"`
	Status        int    `json:"status"`
	Err           string `json:"err"`
	UID           uint32 `json:"uid"`
	RID           uint32 `json:"rid"`
	DBID          int64  `json:"db_id"`
	ShareID       int64  `json:"sid"`
	Version       int64  `json:"ver"`
	RecTime       int64  `json:"rec_time"`
	Name          string `json:"name"`
	Size          int64  `json:"size"`
	Capture       string `json:"capture"`
	Comment       string `json:"comment"`
	Add           string `json:"add"`
	Uploaded      int64  `json:"uploaded"`
	Files         int64  `json:"files"`
	FilesUploaded int64  `json:"files_uploaded"`
}

type RunnerOption func(*flowRunner)

func WithLogger(logf func(string, ...any)) RunnerOption {
	return func(r *flowRunner) {
		r.logf = logf
	}
}

func WithHTTPClient(client *http.Client) RunnerOption {
	return func(r *flowRunner) {
		r.client = client
	}
}

type flowRunner struct {
	ctx       context.Context
	cfg       Config
	client    *http.Client
	logf      func(string, ...any)
	shareID   int64
	historyID int64
}

func RunFullFlow(ctx context.Context, cfg Config, opts ...RunnerOption) error {
	if ctx == nil {
		ctx = context.Background()
	}

	runner := &flowRunner{
		ctx:    ctx,
		cfg:    cfg,
		client: &http.Client{Timeout: 5 * time.Second},
		logf:   func(string, ...any) {},
	}

	for _, opt := range opts {
		opt(runner)
	}

	if runner.client == nil {
		runner.client = &http.Client{Timeout: 5 * time.Second}
	}
	if runner.logf == nil {
		runner.logf = func(string, ...any) {}
	}

	if runner.cfg.TempDir == "" {
		dir, err := os.MkdirTemp("", "usersave-rt-*")
		if err != nil {
			return fmt.Errorf("allocate temp dir: %w", err)
		}
		runner.cfg.TempDir = dir
	} else {
		if err := os.MkdirAll(runner.cfg.TempDir, 0o755); err != nil {
			return fmt.Errorf("create temp dir: %w", err)
		}
	}

	return runner.run()
}

func (r *flowRunner) run() error {
	if err := r.step("UserData/uploadSave", r.runUploadSave); err != nil {
		return err
	}
	if err := r.step("UserSave/save -> saveTask", r.runSaveAndWait); err != nil {
		return err
	}
	if err := r.step("UserSave/list / history / saveInfo", r.runQueries); err != nil {
		return err
	}
	if err := r.step("UserSave/share -> shareTask", r.runShareAndWait); err != nil {
		return err
	}
	if err := r.step("UserSave/use (from share)", r.runUseAndWait); err != nil {
		return err
	}
	if err := r.step("UserData/clearup", r.runClearup); err != nil {
		return err
	}
	return nil
}

func (r *flowRunner) step(name string, fn func() error) error {
	r.logf("=== %s ===", name)
	if err := fn(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func (r *flowRunner) runUploadSave() error {
	data := []byte("integration test file contents")
	sum := sha1.Sum(data)
	hashHex := hex.EncodeToString(sum[:])

	q := url.Values{}
	q.Set("uid", strconv.Itoa(int(r.cfg.UID)))
	q.Set("rid", strconv.Itoa(int(r.cfg.RID)))
	q.Set("hash", hashHex)
	q.Set("path", "slot1\\save.dat")
	q.Set("size", strconv.Itoa(len(data)))
	q.Set("attr", "32")

	req, err := http.NewRequestWithContext(r.ctx, http.MethodPost, r.cfg.BaseURL+"/UserData/uploadSave?"+q.Encode(), bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("uploadSave request: %w", err)
	}
	resp, err := r.doRequest(req)
	if err != nil {
		return err
	}
	return r.expectCode(resp, 0)
}

func (r *flowRunner) runSaveAndWait() error {
	taskID, err := r.runStartSave()
	if err != nil {
		return err
	}
	_, err = r.waitTask("/UserSave/saveTask", taskID)
	return err
}

func (r *flowRunner) runQueries() error {
	paths := []string{
		"/UserSave/list",
		fmt.Sprintf("/UserSave/history?rid=%d", r.cfg.RID),
		fmt.Sprintf("/UserSave/saveInfo?rid=%d", r.cfg.RID),
	}

	for _, p := range paths {
		req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.cfg.BaseURL+p, nil)
		if err != nil {
			return fmt.Errorf("query request %s: %w", p, err)
		}
		req.Header.Set("Authorization", r.cfg.Token)

		resp, err := r.doRequest(req)
		if err != nil {
			return err
		}
		if err := r.expectCode(resp, 0); err != nil {
			return err
		}
	}

	return nil
}

func (r *flowRunner) runShareAndWait() error {
	taskID, err := r.runStartShare()
	if err != nil {
		return err
	}
	status, err := r.waitTask("/UserSave/shareTask", taskID)
	if err != nil {
		return err
	}
	if err := ensureShareFields(status); err != nil {
		return err
	}
	r.shareID = status.ShareID
	r.historyID = status.DBID
	return nil
}

func (r *flowRunner) runUseAndWait() error {
	shareID := r.shareID
	historyID := r.historyID

	var (
		taskID string
		err    error
	)

	switch {
	case shareID > 0:
		taskID, err = r.runStartUse(0, shareID)
	case historyID > 0:
		taskID, err = r.runStartUse(historyID, 0)
	default:
		return fmt.Errorf("share task did not return sid or history id")
	}
	if err != nil {
		return err
	}
	_, err = r.waitTask("/UserSave/useTask", taskID)
	return err
}

func (r *flowRunner) runClearup() error {
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, fmt.Sprintf("%s/UserData/clearup?keep_days=%d", r.cfg.BaseURL, 1), nil)
	if err != nil {
		return fmt.Errorf("clearup request: %w", err)
	}
	resp, err := r.doRequest(req)
	if err != nil {
		return err
	}
	return r.expectCode(resp, 0)
}

func (r *flowRunner) runStartSave() (string, error) {
	reqURL := fmt.Sprintf("%s/UserSave/save?rid=%d", r.cfg.BaseURL, r.cfg.RID)
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("start save request: %w", err)
	}
	req.Header.Set("Authorization", r.cfg.Token)

	resp, err := r.doRequest(req)
	if err != nil {
		return "", err
	}
	return r.readTaskID(resp)
}

func (r *flowRunner) runStartShare() (string, error) {
	params := url.Values{}
	params.Set("rid", strconv.Itoa(int(r.cfg.RID)))
	params.Set("id", "0")
	params.Set("sid", "0")

	body := strings.NewReader(`{"comment":"integration","name":"case"}`)
	req, err := http.NewRequestWithContext(r.ctx, http.MethodPost, r.cfg.BaseURL+"/UserSave/share?"+params.Encode(), body)
	if err != nil {
		return "", fmt.Errorf("start share request: %w", err)
	}
	req.Header.Set("Authorization", r.cfg.Token)

	resp, err := r.doRequest(req)
	if err != nil {
		return "", err
	}
	return r.readTaskID(resp)
}

func (r *flowRunner) runStartUse(histID, shareID int64) (string, error) {
	q := url.Values{}
	if histID > 0 {
		q.Set("id", strconv.FormatInt(histID, 10))
	}
	if shareID > 0 {
		q.Set("sid", strconv.FormatInt(shareID, 10))
	}

	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.cfg.BaseURL+"/UserSave/use?"+q.Encode(), nil)
	if err != nil {
		return "", fmt.Errorf("start use request: %w", err)
	}
	req.Header.Set("Authorization", r.cfg.Token)

	resp, err := r.doRequest(req)
	if err != nil {
		return "", err
	}
	return r.readTaskID(resp)
}

func (r *flowRunner) waitTask(endpoint, taskID string) (TaskStatus, error) {
	path := fmt.Sprintf("%s?task_id=%s", endpoint, url.QueryEscape(taskID))
	var last TaskStatus

	for start := time.Now(); time.Since(start) < 30*time.Second; time.Sleep(500 * time.Millisecond) {
		req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.cfg.BaseURL+path, nil)
		if err != nil {
			return TaskStatus{}, fmt.Errorf("task status request: %w", err)
		}
		if r.cfg.Token != "" {
			req.Header.Set("Authorization", r.cfg.Token)
		}

		resp, err := r.doRequest(req)
		if err != nil {
			return TaskStatus{}, err
		}

		var env taskListEnvelope
		if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
			resp.Body.Close()
			return TaskStatus{}, fmt.Errorf("decode %s response: %w", endpoint, err)
		}
		resp.Body.Close()

		if env.Code != 0 {
			return TaskStatus{}, fmt.Errorf("%s returned code=%d msg=%s", endpoint, env.Code, env.Msg)
		}
		if len(env.Data) == 0 {
			continue
		}
		st := env.Data[0]
		last = st
		if st.Status == 2 || st.Status == 3 {
			return st, nil
		}
	}

	return TaskStatus{}, fmt.Errorf("task %s timed out, last status=%+v", taskID, last)
}

func ensureShareFields(st TaskStatus) error {
	if st.DBID == 0 {
		return fmt.Errorf("missing db_id: %+v", st)
	}
	if st.Name == "" || st.Comment == "" {
		return fmt.Errorf("missing share metadata: %+v", st)
	}
	if st.Files == 0 || st.FilesUploaded != st.Files {
		return fmt.Errorf("files progress mismatch: %+v", st)
	}
	if st.Uploaded < 0 {
		return fmt.Errorf("uploaded bytes negative: %+v", st)
	}
	return nil
}

type taskListEnvelope struct {
	Code int          `json:"code"`
	Msg  string       `json:"msg"`
	Data []TaskStatus `json:"data"`
}

type startTaskEnvelope struct {
	Code int            `json:"code"`
	Msg  string         `json:"msg"`
	Data map[string]any `json:"data"`
}

type genericEnvelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

func (r *flowRunner) readTaskID(resp *http.Response) (string, error) {
	defer resp.Body.Close()

	var env startTaskEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return "", fmt.Errorf("decode task start response: %w", err)
	}
	if env.Code != 0 {
		return "", fmt.Errorf("task start failed: code=%d msg=%s", env.Code, env.Msg)
	}
	if env.Data == nil {
		return "", fmt.Errorf("task response missing data")
	}
	id, _ := env.Data["task_id"].(string)
	if id == "" {
		return "", fmt.Errorf("task_id missing in response: %+v", env.Data)
	}
	return id, nil
}

func (r *flowRunner) doRequest(req *http.Request) (*http.Response, error) {
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request %s %s: %w", req.Method, req.URL, err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("http status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return resp, nil
}

func (r *flowRunner) expectCode(resp *http.Response, want int) error {
	defer resp.Body.Close()

	var env genericEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if env.Code != want {
		return fmt.Errorf("unexpected code %d (%s)", env.Code, env.Msg)
	}
	return nil
}
