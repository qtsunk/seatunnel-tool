package main

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	_ "github.com/glebarez/sqlite"
)

//go:embed index.html
var embeddedFiles embed.FS

const (
	configRowID      = 1
	defaultTimeout   = 60 * time.Second
	maxBodySize      = 16 << 20 // 16 MiB
	sqliteDataSource = "file:seatunnel_tool.db?_foreign_keys=on"
)

// config 存储 SeaTunnel 接口的基础访问配置。
type config struct {
	BaseURL string `json:"baseUrl"`
	Timeout int    `json:"timeout"`
}

// proxyResponse 为前端展示准备的响应载体。
type proxyResponse struct {
	Ok          bool    `json:"ok"`
	Status      int     `json:"status"`
	StatusText  string  `json:"statusText"`
	DurationMs  float64 `json:"durationMs"`
	ContentType string  `json:"contentType"`
	Body        string  `json:"body"`
	URL         string  `json:"url"`
}

// ProxyRequestPayload 定义了前端发送的请求参数，用于代理到 SeaTunnel RESTful API V2。
type ProxyRequestPayload struct {
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	Query        map[string]string `json:"query"`
	Headers      map[string]string `json:"headers"`
	Body         string            `json:"body"`
	BodyEncoding string            `json:"bodyEncoding"`
}

// server 管理 HTTP 请求处理，包含数据库连接。
type server struct {
	db *sql.DB
}

func main() {
	// 初始化 SQLite 存储，并启动内置 HTTP 服务。
	db, err := sql.Open("sqlite", sqliteDataSource)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer db.Close()

	if err := initDB(db); err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}

	srv := &server{db: db}
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/index.html", srv.handleIndex)
	mux.HandleFunc("/api/config", srv.handleConfig)
	mux.HandleFunc("/api/request", srv.handleProxyRequest)
	mux.HandleFunc("/api/upload", srv.handleUpload)

	addr := ":8080"
	log.Printf("SeaTunnel 工具已启动，访问 http://127.0.0.1%v 即可打开页面", addr)
	if err := http.ListenAndServe(addr, withSecurityHeaders(mux)); err != nil {
		log.Fatalf("HTTP 服务异常退出: %v", err)
	}
}

// initDB 初始化配置表，并确保存在默认行。
func initDB(db *sql.DB) error {
	const ddl = `CREATE TABLE IF NOT EXISTS config (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        base_url TEXT NOT NULL DEFAULT '',
        timeout_ms INTEGER NOT NULL DEFAULT 0
    )`
	if _, err := db.Exec(ddl); err != nil {
		return err
	}
	// Ensure default row exists
	const insert = `INSERT INTO config (id, base_url, timeout_ms)
        SELECT ?, '', 0 WHERE NOT EXISTS (SELECT 1 FROM config WHERE id = ?)`
	_, err := db.Exec(insert, configRowID, configRowID)
	return err
}

// withSecurityHeaders 为所有响应增加基础安全首部。
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// handleIndex 输出内置的单页应用。
func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	data, err := embeddedFiles.ReadFile("index.html")
	if err != nil {
		http.Error(w, "无法读取页面资源", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// handleConfig 负责读取/写入基础配置。
func (s *server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := s.loadConfig(r.Context())
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("读取配置失败: %v", err))
			return
		}
		respondJSON(w, http.StatusOK, cfg)
	case http.MethodPost:
		var incoming config
		if err := json.NewDecoder(io.LimitReader(r.Body, maxBodySize)).Decode(&incoming); err != nil {
			respondError(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
			return
		}
		trimmed, err := sanitizeBaseURL(incoming.BaseURL)
		if err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		if incoming.Timeout < 0 {
			respondError(w, http.StatusBadRequest, "超时时间必须大于等于 0")
			return
		}
		incoming.BaseURL = trimmed
		if err := s.saveConfig(r.Context(), incoming); err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("保存配置失败: %v", err))
			return
		}
		respondJSON(w, http.StatusOK, incoming)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// handleProxyRequest 转发 JSON 或表单请求到 SeaTunnel。
func (s *server) handleProxyRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload ProxyRequestPayload
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodySize)).Decode(&payload); err != nil {
		respondError(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	if payload.Path == "" {
		respondError(w, http.StatusBadRequest, "目标路径不能为空")
		return
	}

	cfg, err := s.loadConfig(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("读取配置失败: %v", err))
		return
	}
	if cfg.BaseURL == "" {
		respondError(w, http.StatusBadRequest, "尚未配置 Seatunnel 基础地址")
		return
	}

	targetURL, err := buildTargetURL(cfg.BaseURL, payload.Path, payload.Query)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	var bodyReader io.Reader
	if payload.BodyEncoding == "raw" || payload.BodyEncoding == "json" {
		bodyReader = strings.NewReader(payload.Body)
	}

	ctx, cancel := proxyContext(r.Context(), cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, payload.Method, targetURL, bodyReader)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("构造请求失败: %v", err))
		return
	}
	copyHeaders(req.Header, payload.Headers)

	if payload.BodyEncoding == "json" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	}

	result, err := doProxyRequest(req)
	if err != nil {
		respondError(w, http.StatusBadGateway, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, result)
}

// handleUpload 专门处理上传文件的代理逻辑。
func (s *server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxBodySize); err != nil {
		respondError(w, http.StatusBadRequest, "解析表单失败: "+err.Error())
		return
	}

	metaPath := r.FormValue("__path")
	metaMethod := r.FormValue("__method")
	if metaPath == "" {
		respondError(w, http.StatusBadRequest, "__path 不能为空")
		return
	}
	if metaMethod == "" {
		metaMethod = http.MethodPost
	}

	queryMap := map[string]string{}
	if raw := r.FormValue("__query"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &queryMap); err != nil {
			respondError(w, http.StatusBadRequest, "解析 query 失败: "+err.Error())
			return
		}
	}

	headerMap := map[string]string{}
	if raw := r.FormValue("__headers"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &headerMap); err != nil {
			respondError(w, http.StatusBadRequest, "解析 headers 失败: "+err.Error())
			return
		}
	}

	cfg, err := s.loadConfig(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("读取配置失败: %v", err))
		return
	}
	if cfg.BaseURL == "" {
		respondError(w, http.StatusBadRequest, "尚未配置 Seatunnel 基础地址")
		return
	}

	targetURL, err := buildTargetURL(cfg.BaseURL, metaPath, queryMap)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	for field, values := range r.MultipartForm.Value {
		if strings.HasPrefix(field, "__") {
			continue
		}
		for _, value := range values {
			if err := writer.WriteField(field, value); err != nil {
				respondError(w, http.StatusInternalServerError, "写入表单字段失败")
				return
			}
		}
	}

	for field, files := range r.MultipartForm.File {
		if strings.HasPrefix(field, "__") {
			continue
		}
		for _, fileHeader := range files {
			src, err := fileHeader.Open()
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Sprintf("读取上传文件失败: %v", err))
				return
			}
			defer src.Close()

			part, err := writer.CreateFormFile(field, fileHeader.Filename)
			if err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Sprintf("创建文件字段失败: %v", err))
				return
			}
			if _, err := io.Copy(part, src); err != nil {
				respondError(w, http.StatusInternalServerError, fmt.Sprintf("复制文件内容失败: %v", err))
				return
			}
		}
	}

	if err := writer.Close(); err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("写入表单失败: %v", err))
		return
	}

	ctx, cancel := proxyContext(r.Context(), cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, metaMethod, targetURL, &buf)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("构造上传请求失败: %v", err))
		return
	}
	copyHeaders(req.Header, headerMap)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	result, err := doProxyRequest(req)
	if err != nil {
		respondError(w, http.StatusBadGateway, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, result)
}

// loadConfig 从 SQLite 中读取当前配置。
func (s *server) loadConfig(ctx context.Context) (config, error) {
	row := s.db.QueryRowContext(ctx, "SELECT base_url, timeout_ms FROM config WHERE id = ?", configRowID)
	var cfg config
	if err := row.Scan(&cfg.BaseURL, &cfg.Timeout); err != nil {
		return config{}, err
	}
	return cfg, nil
}

// saveConfig 将配置持久化至 SQLite。
func (s *server) saveConfig(ctx context.Context, cfg config) error {
	_, err := s.db.ExecContext(ctx, "UPDATE config SET base_url = ?, timeout_ms = ? WHERE id = ?", cfg.BaseURL, cfg.Timeout, configRowID)
	return err
}

// buildTargetURL 拼接完整的目标 URL，包含基础地址、路径和查询参数。
func buildTargetURL(base, relPath string, query map[string]string) (string, error) {
	trimmed := strings.TrimSuffix(base, "/")
	cleanedPath := path.Join("/", relPath)
	full := trimmed + cleanedPath
	u, err := url.Parse(full)
	if err != nil {
		return "", fmt.Errorf("目标地址无效: %w", err)
	}
	if len(query) > 0 {
		q := u.Query()
		for k, v := range query {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

// sanitizeBaseURL 校验并清洗用户填写的基础地址。
func sanitizeBaseURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("基础地址格式错误: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("基础地址必须以 http:// 或 https:// 开头")
	}
	if parsed.Host == "" {
		return "", errors.New("基础地址缺少主机名")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	sanitized := parsed.String()
	if strings.HasSuffix(sanitized, "/") && len(sanitized) > len(parsed.Scheme)+3 {
		sanitized = strings.TrimRight(sanitized, "/")
	}
	return sanitized, nil
}

// proxyContext 根据配置超时时间构造上下文，避免代理请求阻塞。
func proxyContext(parent context.Context, timeoutMs int) (context.Context, context.CancelFunc) {
	timeout := defaultTimeout
	if timeoutMs > 0 {
		timeout = time.Duration(timeoutMs) * time.Millisecond
	}
	return context.WithTimeout(parent, timeout)
}

// doProxyRequest 调用下游 SeaTunnel 接口并收集关键信息。
func doProxyRequest(req *http.Request) (proxyResponse, error) {
	client := &http.Client{}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return proxyResponse{}, fmt.Errorf("请求 Seatunnel 服务失败: %w", err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, maxBodySize)
	bodyBytes, err := io.ReadAll(limited)
	if err != nil {
		return proxyResponse{}, fmt.Errorf("读取响应失败: %w", err)
	}

	return proxyResponse{
		Ok:          resp.StatusCode >= 200 && resp.StatusCode < 300,
		Status:      resp.StatusCode,
		StatusText:  http.StatusText(resp.StatusCode),
		DurationMs:  float64(time.Since(start).Milliseconds()),
		ContentType: resp.Header.Get("Content-Type"),
		Body:        string(bodyBytes),
		URL:         req.URL.String(),
	}, nil
}

// copyHeaders 将源映射中的键值对复制到目标 HTTP 头中，忽略 Host 头。
func copyHeaders(dst http.Header, src map[string]string) {
	for k, v := range src {
		if strings.EqualFold(k, "host") {
			continue
		}
		dst.Set(k, v)
	}
}

// respondJSON 以 JSON 格式返回响应体，设置状态码并处理编码错误。
func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("写入响应失败: %v", err)
	}
}

// respondError 以 JSON 格式返回错误响应，设置状态码并记录日志。
func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{
		"error": message,
	})
}
