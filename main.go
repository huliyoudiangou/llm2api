package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// sharedTLSSessionCache：全进程共享的 TLS 会话缓存。
// 冷启动新建连接时走 TLS 会话恢复（session ticket / PSK），省 1 个 RTT 的完整握手。
var sharedTLSSessionCache = tls.NewLRUClientSessionCache(128)

// upstreamDialTimeout 拨号超时。Windows 下直连不可达的上游（SYN 被黑洞丢弃）
// 实测要 ~21s 才失败，30s 偏长；收紧到 10s，让「上游不可达」快速失败并进入
// 重试/报错路径，而不是长时间挂着。
const upstreamDialTimeout = 10 * time.Second

// upstreamResponseHeaderTimeout 限制「请求已发出、但上游迟迟不返回响应头」的等待时间。
// 没有这个上限时，僵死的代理链路或不可达上游会一直挂着：客户端 300s 超时掐断后，
// 网关侧连接与 goroutine 仍滞留，表现为明细里 300s+ 且 0 token 的记录。
const upstreamResponseHeaderTimeout = 45 * time.Second

// maxTransportRetries 传输级错误（拨号失败/连接重置/代理不可达）的总尝试次数上限。
// 此前该循环无上界：上游不可达时会 1s 一次无限重试，直到客户端自己超时，
// 既打爆日志又占满连接，并在客户端自动重试下形成重试风暴。
const maxTransportRetries = 4

// newBaseTransport 构造上游 HTTP 传输层。
// stream=true 时额外设置 ResponseHeaderTimeout：只约束「等到响应头」的时间，
// 一旦开始流式输出就不该再受它限制（长流由 client.Timeout=0 保证不被截断）。
func newBaseTransport(stream bool) *http.Transport {
	t := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   upstreamDialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{ClientSessionCache: sharedTLSSessionCache},
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if stream {
		t.ResponseHeaderTimeout = upstreamResponseHeaderTimeout
	}
	return t
}

var httpClient = &http.Client{
	Timeout:   600 * time.Second,
	Transport: newBaseTransport(false),
}

var streamHTTPClient = &http.Client{
	Timeout:   0,
	Transport: newBaseTransport(true),
}

// ======================== SOCKS5 代理 ========================

type Socks5Proxy struct {
	Addr     string `json:"addr"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Name     string `json:"name,omitempty"`
}

// Billing header regex for stripping Anthropic system message headers
var reBillingHeader = regexp.MustCompile(`(?m)^x-anthropic-billing-header:\s*.*$`)

var (
	socks5Proxies []Socks5Proxy
	socks5Mu      sync.RWMutex
)

type socks5ClientKey struct {
	Addr     string
	Username string
	Password string
	Stream   bool
}

var (
	socks5ClientsMu sync.Mutex
	socks5Clients   = map[socks5ClientKey]*http.Client{}
)

func socks5Dial(proxy Socks5Proxy) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		conn, err := dialer.DialContext(ctx, network, proxy.Addr)
		if err != nil {
			return nil, fmt.Errorf("socks5 connect to %s: %w", proxy.Addr, err)
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}
		fail := func(format string, args ...any) (net.Conn, error) {
			conn.Close()
			return nil, fmt.Errorf(format, args...)
		}

		deadline := time.Now().Add(15 * time.Second)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := conn.SetDeadline(deadline); err != nil {
			return fail("socks5 set deadline: %w", err)
		}

		authMethod := byte(0x00)
		if proxy.Username != "" {
			authMethod = 0x02
		}
		if _, err := conn.Write([]byte{0x05, 0x01, authMethod}); err != nil {
			return fail("socks5 handshake write: %w", err)
		}
		handshake := make([]byte, 2)
		if _, err := io.ReadFull(conn, handshake); err != nil {
			return fail("socks5 handshake read: %w", err)
		}
		if handshake[0] != 0x05 {
			return fail("socks5: unexpected protocol version 0x%02x", handshake[0])
		}
		switch handshake[1] {
		case 0x00:
		case 0x02:
			if proxy.Username == "" {
				return fail("socks5: server requires authentication")
			}
			if len(proxy.Username) > 255 || len(proxy.Password) > 255 {
				return fail("socks5: username or password is too long")
			}
			auth := []byte{0x01, byte(len(proxy.Username))}
			auth = append(auth, proxy.Username...)
			auth = append(auth, byte(len(proxy.Password)))
			auth = append(auth, proxy.Password...)
			if _, err := conn.Write(auth); err != nil {
				return fail("socks5 auth write: %w", err)
			}
			authResponse := make([]byte, 2)
			if _, err := io.ReadFull(conn, authResponse); err != nil {
				return fail("socks5 auth read: %w", err)
			}
			if authResponse[1] != 0x00 {
				return fail("socks5: authentication failed")
			}
		default:
			return fail("socks5: unsupported authentication method 0x%02x", handshake[1])
		}

		host, portText, err := net.SplitHostPort(target)
		if err != nil {
			return fail("socks5: invalid target %s: %w", target, err)
		}
		portNumber, err := strconv.Atoi(portText)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return fail("socks5: invalid target port %q", portText)
		}
		request := []byte{0x05, 0x01, 0x00}
		if ip := net.ParseIP(host); ip != nil {
			if ipv4 := ip.To4(); ipv4 != nil {
				request = append(request, 0x01)
				request = append(request, ipv4...)
			} else {
				request = append(request, 0x04)
				request = append(request, ip.To16()...)
			}
		} else {
			if len(host) == 0 || len(host) > 255 {
				return fail("socks5: invalid target hostname")
			}
			request = append(request, 0x03, byte(len(host)))
			request = append(request, host...)
		}
		request = append(request, byte(portNumber>>8), byte(portNumber))
		if _, err := conn.Write(request); err != nil {
			return fail("socks5 connect write: %w", err)
		}

		response := make([]byte, 4)
		if _, err := io.ReadFull(conn, response); err != nil {
			return fail("socks5 connect read: %w", err)
		}
		if response[0] != 0x05 || response[1] != 0x00 {
			return fail("socks5: connect failed, status 0x%02x", response[1])
		}
		addressLength := 0
		switch response[3] {
		case 0x01:
			addressLength = 4
		case 0x03:
			length := make([]byte, 1)
			if _, err := io.ReadFull(conn, length); err != nil {
				return fail("socks5: read bind hostname length: %w", err)
			}
			addressLength = int(length[0])
		case 0x04:
			addressLength = 16
		default:
			return fail("socks5: unknown bind address type 0x%02x", response[3])
		}
		if _, err := io.ReadFull(conn, make([]byte, addressLength+2)); err != nil {
			return fail("socks5: read bind address: %w", err)
		}
		if err := conn.SetDeadline(time.Time{}); err != nil {
			return fail("socks5 clear deadline: %w", err)
		}
		return conn, nil
	}
}

func configuredSocks5Proxy(addr string) (Socks5Proxy, bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return Socks5Proxy{}, false
	}
	socks5Mu.RLock()
	defer socks5Mu.RUnlock()
	for _, proxy := range socks5Proxies {
		if proxy.Addr == addr {
			return proxy, true
		}
	}
	return Socks5Proxy{}, false
}

func socks5ProxyLabel(proxy Socks5Proxy) string {
	if proxy.Name != "" {
		return proxy.Name + " (" + proxy.Addr + ")"
	}
	return proxy.Addr
}

func getModelHTTPClient(proxyAddr string, stream bool) (*http.Client, string) {
	proxy, ok := configuredSocks5Proxy(proxyAddr)
	if !ok {
		if stream {
			return streamHTTPClient, "direct"
		}
		return httpClient, "direct"
	}
	key := socks5ClientKey{
		Addr:     proxy.Addr,
		Username: proxy.Username,
		Password: proxy.Password,
		Stream:   stream,
	}
	socks5ClientsMu.Lock()
	defer socks5ClientsMu.Unlock()
	if client := socks5Clients[key]; client != nil {
		return client, socks5ProxyLabel(proxy)
	}
	transport := newBaseTransport(stream)
	// SOCKS5 客户端必须直连代理本身：清掉 ProxyFromEnvironment，
	// 避免环境变量里的 HTTP(S)_PROXY 叠加成 socks5→env-proxy 双层链路（多一跳延迟）
	transport.Proxy = nil
	transport.DialContext = socks5Dial(proxy)
	client := &http.Client{Transport: transport, Timeout: 600 * time.Second}
	if stream {
		client.Timeout = 0
	}
	socks5Clients[key] = client
	return client, socks5ProxyLabel(proxy)
}

func modelProxyLabel(proxyAddr string) string {
	if proxy, ok := configuredSocks5Proxy(proxyAddr); ok {
		return socks5ProxyLabel(proxy)
	}
	return "direct"
}

func clearSocks5ClientCache() {
	socks5ClientsMu.Lock()
	defer socks5ClientsMu.Unlock()
	for _, client := range socks5Clients {
		if transport, ok := client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
	socks5Clients = map[socks5ClientKey]*http.Client{}
}

// ======================== 随机 ID ========================

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = letters[b[i]%byte(len(letters))]
	}
	return string(b)
}

// ======================== OpenCode 会话 ========================

var (
	upstreamCfgs = map[string]*UpstreamConfig{}
	requestCount atomic.Int64
)

// ======================== 模型 ========================

type ModelInfo struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

var (
	upstreamKeyCursorMu sync.Mutex
	upstreamKeyCursor   = map[string]int{}
)

func splitUpstreamAPIKeys(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := map[string]struct{}{}
	keys := make([]string, 0, strings.Count(raw, "\n")+1)
	for _, line := range strings.Split(raw, "\n") {
		key := strings.TrimSpace(line)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

func getUpstreamAPIKeys(upstream *UpstreamConfig) []string {
	if upstream == nil {
		return nil
	}
	return splitUpstreamAPIKeys(upstream.APIKey)
}

func nextUpstreamAPIKeyIndex(name string, total int) int {
	if total <= 1 {
		return 0
	}
	resolvedName := effectiveUpstreamName(name)
	upstreamKeyCursorMu.Lock()
	defer upstreamKeyCursorMu.Unlock()
	idx := upstreamKeyCursor[resolvedName] % total
	upstreamKeyCursor[resolvedName] = (idx + 1) % total
	return idx
}

// ======================== 多 Key 缓存亲和 ========================
// 同「上游 + 目标模型」尽量固定使用同一把 API Key，避免多 Key 轮询导致
// 上游 prefix cache / prompt cache 命中率下降。Key 被熔断或 429 后会自动迁移。
var (
	modelKeyAffinityMu sync.Mutex
	modelKeyAffinity   = map[string]string{} // key: upstream|targetModel, value: api key
)

func modelAffinityKey(upstreamName, modelID string) string {
	return effectiveUpstreamName(upstreamName) + "|" + modelID
}

func getModelKeyAffinity(upstreamName, modelID string) string {
	if modelID == "" {
		return ""
	}
	modelKeyAffinityMu.Lock()
	defer modelKeyAffinityMu.Unlock()
	return modelKeyAffinity[modelAffinityKey(upstreamName, modelID)]
}

func setModelKeyAffinity(upstreamName, modelID, apiKey string) {
	if modelID == "" || apiKey == "" {
		return
	}
	modelKeyAffinityMu.Lock()
	defer modelKeyAffinityMu.Unlock()
	modelKeyAffinity[modelAffinityKey(upstreamName, modelID)] = apiKey
}

func clearModelKeyAffinity() {
	modelKeyAffinityMu.Lock()
	defer modelKeyAffinityMu.Unlock()
	modelKeyAffinity = map[string]string{}
}

func indexOfAPIKey(keys []string, key string) int {
	for i, k := range keys {
		if k == key {
			return i
		}
	}
	return -1
}

// ======================== API Key 熔断与健康池 ========================

type keyHealthStatus struct {
	cooldownUntil time.Time
	failCount     int
	lastError     string
}

var (
	keyHealthMu sync.RWMutex
	keyHealth   = map[string]*keyHealthStatus{}
)

func markAPIKeyFailure(key string, statusCode int, reason string) {
	if key == "" {
		return
	}
	keyHealthMu.Lock()
	defer keyHealthMu.Unlock()
	st, ok := keyHealth[key]
	if !ok {
		st = &keyHealthStatus{}
		keyHealth[key] = st
	}
	st.failCount++
	st.lastError = reason

	cooldown := 30 * time.Second
	switch statusCode {
	case http.StatusTooManyRequests:
		cooldown = 60 * time.Second
	case http.StatusUnauthorized, http.StatusForbidden:
		cooldown = 5 * time.Minute
	default:
		if st.failCount > 2 {
			cooldown = 45 * time.Second
		}
	}
	st.cooldownUntil = time.Now().Add(cooldown)
	keyPrefix := key
	if len(keyPrefix) > 12 {
		keyPrefix = keyPrefix[:12]
	}
	log.Printf("[key health] Key %s... 标记不健康(status=%d), 冷却至 %s", keyPrefix, statusCode, st.cooldownUntil.Format("15:04:05"))
}

func markAPIKeySuccess(key string) {
	if key == "" {
		return
	}
	keyHealthMu.Lock()
	defer keyHealthMu.Unlock()
	if st, ok := keyHealth[key]; ok {
		st.failCount = 0
		st.cooldownUntil = time.Time{}
	}
}

func isAPIKeyHealthy(key string) bool {
	if key == "" {
		return true
	}
	keyHealthMu.RLock()
	defer keyHealthMu.RUnlock()
	st, ok := keyHealth[key]
	if !ok {
		return true
	}
	return time.Now().After(st.cooldownUntil)
}

func selectUpstreamAPIKey(name string, upstream *UpstreamConfig, modelID string) (string, int, []string) {
	keys := getUpstreamAPIKeys(upstream)
	if len(keys) == 0 {
		return "", -1, nil
	}
	total := len(keys)

	// 多 Key 缓存亲和：若该模型已有固定 Key 且当前健康，优先复用同一把 Key。
	if modelID != "" {
		if affKey := getModelKeyAffinity(name, modelID); affKey != "" {
			if idx := indexOfAPIKey(keys, affKey); idx >= 0 && isAPIKeyHealthy(affKey) {
				return affKey, idx, keys
			}
		}
	}

	start := nextUpstreamAPIKeyIndex(name, total)
	// 优先在 healthy 状态的 key 中按轮询顺序选
	for i := 0; i < total; i++ {
		idx := (start + i) % total
		if isAPIKeyHealthy(keys[idx]) {
			if modelID != "" {
				setModelKeyAffinity(name, modelID, keys[idx])
			}
			return keys[idx], idx, keys
		}
	}
	// 若全部 Key 处于冷却中，则回退到原始轮询选中的 Key
	return keys[start], start, keys
}

func rotateUpstreamAPIKey(keys []string, current int, upstreamName, modelID string) (string, int) {
	if len(keys) == 0 {
		return "", -1
	}
	total := len(keys)
	if current < 0 {
		current = 0
	}
	for i := 1; i <= total; i++ {
		next := (current + i) % total
		if isAPIKeyHealthy(keys[next]) {
			if modelID != "" {
				setModelKeyAffinity(upstreamName, modelID, keys[next])
			}
			return keys[next], next
		}
	}
	// 全部都在冷却，降级为下一个
	next := (current + 1) % total
	if modelID != "" {
		setModelKeyAffinity(upstreamName, modelID, keys[next])
	}
	return keys[next], next
}

func formatUpstreamAPIKeySlot(index int, total int) string {
	if index < 0 || total <= 0 {
		return "0/0"
	}
	return fmt.Sprintf("%d/%d", index+1, total)
}

// waitForRetry 在重试前等待退避；ctx 取消时返回错误。
// 取消即代表客户端已断开，这里统一把 usageRecorder 标记为 499：
// 否则调用方直接 `return nil, 0, nil, err` 会让明细落下 status=0，
// 前端把 0 当成功渲染成绿色 200，超时/断开的请求在统计里被误记为成功。
func waitForRetry(ctx context.Context, baseDelay time.Duration) error {
	delay := baseDelay
	if delay <= 0 {
		delay = time.Second
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		rec := usageRecorderFromContext(ctx)
		rec.SetStatus(499)
		rec.SetError("client disconnected")
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func nextRetryDelay(delay time.Duration) time.Duration {
	if delay <= 0 {
		return time.Second
	}
	if delay >= 30*time.Second {
		return 30 * time.Second
	}
	delay *= 2
	if delay > 30*time.Second {
		return 30 * time.Second
	}
	return delay
}

func shouldRetryUpstreamStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusInternalServerError:
		return true
	default:
		return false
	}
}

func cloneUpstreamConfig(cfg *UpstreamConfig) *UpstreamConfig {
	if cfg == nil {
		return nil
	}
	cp := *cfg
	if cfg.CustomModels != nil {
		cp.CustomModels = append([]string(nil), cfg.CustomModels...)
	}
	if cfg.CustomHeaders != nil {
		cp.CustomHeaders = make(map[string]string, len(cfg.CustomHeaders))
		for k, v := range cfg.CustomHeaders {
			cp.CustomHeaders[k] = v
		}
	}
	return &cp
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameUpstreamConfig(a, b *UpstreamConfig) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.BaseURL == b.BaseURL &&
		a.APIKey == b.APIKey &&
		a.APIType == b.APIType &&
		a.ResponsesReasoningFormat == b.ResponsesReasoningFormat &&
		sameStringSlice(a.CustomModels, b.CustomModels) &&
		sameStringMap(a.CustomHeaders, b.CustomHeaders)
}

func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// upstreamsConfigChanged 判断上游连接相关配置是否变化（模型列表依赖这些字段）。
// 别名、推理映射、代理等不影响上游模型列表。
func upstreamsConfigChanged(oldMap map[string]*UpstreamConfig, newMap map[string]*UpstreamConfig) bool {
	if len(oldMap) != len(newMap) {
		return true
	}
	for name, newCfg := range newMap {
		oldCfg, ok := oldMap[name]
		if !ok || !sameUpstreamConfig(oldCfg, newCfg) {
			return true
		}
	}
	return false
}

func normalizeSingleUpstream(cfg *UpstreamConfig) bool {
	if cfg == nil {
		return false
	}
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	cfg.APIKey = strings.TrimSpace(cfg.APIKey)
	if cfg.APIType == "" {
		cfg.APIType = UpstreamOpenAI
	}
	cfg.ResponsesReasoningFormat = strings.TrimSpace(cfg.ResponsesReasoningFormat)
	if len(cfg.CustomModels) > 0 {
		cleaned := make([]string, 0, len(cfg.CustomModels))
		for _, model := range cfg.CustomModels {
			model = strings.TrimSpace(model)
			if model != "" {
				cleaned = append(cleaned, model)
			}
		}
		cfg.CustomModels = cleaned
	}
	if len(cfg.CustomHeaders) > 0 {
		cleaned := make(map[string]string, len(cfg.CustomHeaders))
		for k, v := range cfg.CustomHeaders {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if k == "" || v == "" {
				continue
			}
			cleaned[k] = v
		}
		if len(cleaned) > 0 {
			cfg.CustomHeaders = cleaned
		} else {
			cfg.CustomHeaders = nil
		}
	}
	return cfg.BaseURL != ""
}

func sortedUpstreamNames(m map[string]*UpstreamConfig) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func getUpstreamModelsEndpoint(upstream *UpstreamConfig) string {
	if upstream == nil || upstream.BaseURL == "" {
		return ""
	}
	base := strings.TrimRight(upstream.BaseURL, "/")
	return base + "/models"
}

// connPhase 记录一次请求的建连阶段耗时；命中温热连接池（连接复用）时各阶段为零值，summary 显示 reused
type connPhase struct {
	dnsStart, dnsDone time.Time
	connectStart      time.Time
	connectDone       time.Time
	tlsStart, tlsDone time.Time
}

func (ct *connPhase) summary() string {
	if ct == nil || ct.connectStart.IsZero() || ct.connectDone.IsZero() {
		return "reused"
	}
	parts := make([]string, 0, 3)
	if !ct.dnsStart.IsZero() && !ct.dnsDone.IsZero() {
		parts = append(parts, "dns="+ct.dnsDone.Sub(ct.dnsStart).Round(time.Millisecond).String())
	}
	parts = append(parts, "tcp="+ct.connectDone.Sub(ct.connectStart).Round(time.Millisecond).String())
	if !ct.tlsStart.IsZero() && !ct.tlsDone.IsZero() {
		parts = append(parts, "tls="+ct.tlsDone.Sub(ct.tlsStart).Round(time.Millisecond).String())
	}
	return strings.Join(parts, " ")
}

// ttfbReadCloser wraps an io.ReadCloser and logs the time-to-first-byte
// on the first Read call, then delegates all subsequent calls to the inner ReadCloser.
type ttfbReadCloser struct {
	inner      io.ReadCloser
	once       sync.Once
	start      time.Time
	upstream   string
	model      string
	clientAPI  string
	keySlot    string
	proxyLabel string
	rec        *usageRecorder
	ct         *connPhase
	proto      string
}

func (r *ttfbReadCloser) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)
	r.once.Do(func() {
		ttfb := time.Since(r.start)
		log.Printf("[ttfb] api=%s upstream=%s model=%s key=%s proxy=%s proto=%s conn=%s ttfb=%s", r.clientAPI, r.upstream, r.model, r.keySlot, r.proxyLabel, r.proto, r.ct.summary(), ttfb.Round(time.Millisecond))
		r.rec.MarkFirstToken()
	})
	return n, err
}

func (r *ttfbReadCloser) Close() error {
	return r.inner.Close()
}

func getFirstConfiguredSocks5ProxyAddr() string {
	socks5Mu.RLock()
	defer socks5Mu.RUnlock()
	if len(socks5Proxies) > 0 {
		return socks5Proxies[0].Addr
	}
	return ""
}

func fetchModelsFromUpstream(name string, cfg *UpstreamConfig) ([]ModelInfo, error) {
	if cfg == nil || cfg.BaseURL == "" {
		return []ModelInfo{}, nil
	}
	ownedBy := effectiveUpstreamName(name)
	if len(cfg.CustomModels) > 0 {
		var models []ModelInfo
		now := time.Now().Unix()
		for _, m := range cfg.CustomModels {
			models = append(models, ModelInfo{ID: m, Object: "model", Created: now, OwnedBy: ownedBy})
		}
		return models, nil
	}
	endpoint := getUpstreamModelsEndpoint(cfg)
	if cfg.APIType == UpstreamAnthropic && !strings.Contains(endpoint, "limit=") {
		if strings.Contains(endpoint, "?") {
			endpoint += "&limit=1000"
		} else {
			endpoint += "?limit=1000"
		}
	}
	apiKeys := getUpstreamAPIKeys(cfg)
	if len(apiKeys) == 0 {
		apiKeys = []string{""}
	}
	start := nextUpstreamAPIKeyIndex(name, len(apiKeys))
	var lastErr error
	proxyAddr := getFirstConfiguredSocks5ProxyAddr()
	client, _ := getModelHTTPClient(proxyAddr, false)
	for i := 0; i < len(apiKeys); i++ {
		apiKeyIndex := (start + i) % len(apiKeys)
		apiKey := apiKeys[apiKeyIndex]
		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			return nil, err
		}
		if apiKey != "" {
			if cfg.APIType == UpstreamAnthropic {
				req.Header.Set("x-api-key", apiKey)
				req.Header.Set("anthropic-version", "2023-06-01")
				req.Header.Set("anthropic-beta", "prompt-caching-2025-01-31")
			} else {
				req.Header.Set("Authorization", "Bearer "+apiKey)
			}
		}
		applyCustomHeaders(req, cfg)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var raw map[string]any
			if err := json.Unmarshal(body, &raw); err == nil {
				var models []ModelInfo
				now := time.Now().Unix()
				extractFromSlice := func(slice []any) {
					for _, item := range slice {
						if m, ok := item.(map[string]any); ok {
							id, _ := m["id"].(string)
							if id == "" {
								id, _ = m["name"].(string)
							}
							if id != "" {
								models = append(models, ModelInfo{ID: id, Object: "model", Created: now, OwnedBy: ownedBy})
							}
						} else if s, ok := item.(string); ok && s != "" {
							models = append(models, ModelInfo{ID: s, Object: "model", Created: now, OwnedBy: ownedBy})
						}
					}
				}
				if dataArr, ok := raw["data"].([]any); ok {
					extractFromSlice(dataArr)
				}
				if len(models) == 0 {
					if modelsArr, ok := raw["models"].([]any); ok {
						extractFromSlice(modelsArr)
					}
				}
				if len(models) == 0 {
					if resultArr, ok := raw["result"].([]any); ok {
						extractFromSlice(resultArr)
					}
				}
				if len(models) > 0 {
					return models, nil
				}
			}
			var result struct {
				Data []struct {
					ID string `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				return nil, err
			}
			var models []ModelInfo
			now := time.Now().Unix()
			for _, m := range result.Data {
				models = append(models, ModelInfo{ID: m.ID, Object: "model", Created: now, OwnedBy: ownedBy})
			}
			return models, nil
		}
		if shouldRetryUpstreamStatus(resp.StatusCode) && len(apiKeys) > 1 {
			lastErr = fmt.Errorf("models endpoint retryable status %d on key %s", resp.StatusCode, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)))
			continue
		}
		lastErr = fmt.Errorf("models endpoint status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		break
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("models endpoint request failed")
	}
	return nil, lastErr
}

// emptyCustomModelUpstreams 返回 normalize 后 custom_models 仍为空的上游名（已按名排序）。
// 仅统计 normalize 后保留下来的上游（有名字、有 BaseURL）；custom_models 是模型唯一来源，留空视为未配好。
func emptyCustomModelUpstreams(m map[string]*UpstreamConfig) []string {
	var empty []string
	for _, name := range sortedUpstreamNames(m) {
		if cfg := m[name]; cfg != nil && cfg.BaseURL != "" && len(cfg.CustomModels) == 0 {
			empty = append(empty, name)
		}
	}
	return empty
}

func effectiveUpstreamName(name string) string {
	if strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	return "default"
}

func getConfiguredUpstreams() map[string]*UpstreamConfig {
	configMu.RLock()
	defer configMu.RUnlock()
	upstreams := make(map[string]*UpstreamConfig, len(upstreamCfgs))
	for name, cfg := range upstreamCfgs {
		upstreams[name] = cloneUpstreamConfig(cfg)
	}
	return upstreams
}

func resolveUpstream(name string) (string, *UpstreamConfig) {
	configMu.RLock()
	defer configMu.RUnlock()
	resolvedName := strings.TrimSpace(name)
	if resolvedName == "" {
		return "", nil
	}
	if cfg := cloneUpstreamConfig(upstreamCfgs[resolvedName]); cfg != nil {
		return resolvedName, cfg
	}
	return resolvedName, nil
}

func countConfiguredModels() int {
	upstreams := getConfiguredUpstreams()
	seen := map[string]struct{}{}
	for _, cfg := range upstreams {
		for _, m := range cfg.CustomModels {
			trimmed := strings.TrimSpace(m)
			if trimmed == "" {
				continue
			}
			seen[trimmed] = struct{}{}
		}
	}
	return len(seen)
}

func getAliasModelInfos() []ModelInfo {
	configMu.RLock()
	defer configMu.RUnlock()
	if len(modelAlias) == 0 {
		return []ModelInfo{}
	}
	names := make([]string, 0, len(modelAlias))
	for name := range modelAlias {
		name = strings.TrimSpace(name)
		if name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	now := time.Now().Unix()
	models := make([]ModelInfo, 0, len(names))
	for _, name := range names {
		models = append(models, ModelInfo{
			ID:      name,
			Object:  "model",
			Created: now,
			OwnedBy: "alias",
		})
	}
	return models
}

// ======================== 配置 ========================

var (
	port       string
	configPath = "config.json"
	modelAlias = map[string]ModelAlias{}

	reasoningEffortMap = map[string]string{}
	debugMode          bool
	configMu           sync.RWMutex
)

// ======================== 管理面板认证 ========================

var (
	adminPassword string
	sessions      = map[string]struct{}{}
	sessionsMu    sync.Mutex
)

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if adminPassword == "" {
			next(w, r)
			return
		}
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		sessionsMu.Lock()
		_, ok := sessions[cookie.Value]
		sessionsMu.Unlock()
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if adminPassword == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			renderLoginPage(w, "表单解析失败")
			return
		}
		if r.FormValue("password") != adminPassword {
			renderLoginPage(w, "密码错误")
			return
		}
		token, err := generateToken()
		if err != nil {
			renderLoginPage(w, "创建会话失败")
			return
		}
		sessionsMu.Lock()
		sessions[token] = struct{}{}
		sessionsMu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/", HttpOnly: true})
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	renderLoginPage(w, "")
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		sessionsMu.Lock()
		delete(sessions, cookie.Value)
		sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// ======================== 使用统计（对齐 cc-switch 用量统计口径） ========================

// ModelStats 单个模型的累计用量。
// PromptTokens 沿用历史语义：包含缓存读/写部分（旧 stats.json 可直接读取）。
type ModelStats struct {
	RequestCount        int64   `json:"request_count"`
	PromptTokens        int64   `json:"prompt_tokens"`
	CompletionTokens    int64   `json:"completion_tokens"`
	TotalTokens         int64   `json:"total_tokens"`
	CacheReadTokens     int64   `json:"cache_read_tokens,omitempty"`
	CacheCreationTokens int64   `json:"cache_creation_tokens,omitempty"`
	ReasoningTokens     int64   `json:"reasoning_tokens,omitempty"`
	ErrorCount          int64   `json:"error_count,omitempty"`
	LatencyMsTotal      int64   `json:"latency_ms_total,omitempty"`
	FirstTokenMsTotal   int64   `json:"first_token_ms_total,omitempty"`
	FirstTokenSamples   int64   `json:"first_token_samples,omitempty"`
	CostUSD             float64 `json:"cost_usd,omitempty"`
}

// DailyStats 单日统计，每天0点自动重置（保留旧结构，供 /api/stats 兼容返回）
type DailyStats struct {
	Date          string                 `json:"date"`
	TotalRequests int64                  `json:"total_requests"`
	Models        map[string]*ModelStats `json:"models"`
}

// UsageRow 按「日期 + 上游 + 模型」聚合的用量行，等价于 cc-switch 的 usage_daily_rollups。
// InputTokens 为「非缓存输入」，缓存读/写单独计列，TotalTokens = 输入 + 缓存读 + 缓存写 + 输出。
type UsageRow struct {
	Date                string  `json:"date"`
	Upstream            string  `json:"upstream"`
	Model               string  `json:"model"`
	TargetModel         string  `json:"target_model,omitempty"`
	RequestCount        int64   `json:"request_count"`
	SuccessCount        int64   `json:"success_count"`
	ErrorCount          int64   `json:"error_count"`
	InputTokens         int64   `json:"input_tokens"`
	OutputTokens        int64   `json:"output_tokens"`
	CacheReadTokens     int64   `json:"cache_read_tokens"`
	CacheCreationTokens int64   `json:"cache_creation_tokens"`
	ReasoningTokens     int64   `json:"reasoning_tokens"`
	TotalTokens         int64   `json:"total_tokens"`
	LatencyMsTotal      int64   `json:"latency_ms_total"`
	LatencySamples      int64   `json:"latency_samples"`
	FirstTokenMsTotal   int64   `json:"first_token_ms_total"`
	FirstTokenSamples   int64   `json:"first_token_samples"`
	CostUSD             float64 `json:"cost_usd"`
}

// RequestLogEntry 单次请求明细，等价于 cc-switch 的 proxy_request_logs（仅保留最近若干条）
type RequestLogEntry struct {
	TS                  int64   `json:"ts"`
	API                 string  `json:"api"`
	Upstream            string  `json:"upstream"`
	Model               string  `json:"model"`
	TargetModel         string  `json:"target_model,omitempty"`
	Stream              bool    `json:"stream"`
	Status              int     `json:"status"`
	Error               string  `json:"error,omitempty"`
	InputTokens         int64   `json:"input_tokens"`
	OutputTokens        int64   `json:"output_tokens"`
	CacheReadTokens     int64   `json:"cache_read_tokens"`
	CacheCreationTokens int64   `json:"cache_creation_tokens"`
	ReasoningTokens     int64   `json:"reasoning_tokens"`
	TotalTokens         int64   `json:"total_tokens"`
	LatencyMs           int64   `json:"latency_ms"`
	FirstTokenMs        int64   `json:"first_token_ms,omitempty"`
	CostUSD             float64 `json:"cost_usd"`
}

type TokenStatsData struct {
	TotalRequests int64                  `json:"total_requests"`
	Models        map[string]*ModelStats `json:"models"`
	Daily         *DailyStats            `json:"daily,omitempty"`
	// Rollups 按日期聚合的明细账（保留最近 usageHistoryDays 天），键为 date|upstream|model
	Rollups map[string]*UsageRow `json:"rollups,omitempty"`
	// Log 最近请求明细（最多 usageLogLimit 条，新的在前）
	Log []RequestLogEntry `json:"log,omitempty"`
}

const (
	usageHistoryDays = 90  // 每日聚合保留天数
	usageLogLimit    = 500 // 请求明细保留条数
)

var (
	tokenStats     = &TokenStatsData{Models: map[string]*ModelStats{}, Daily: nil, Rollups: map[string]*UsageRow{}}
	tokenStatsMu   sync.Mutex
	tokenStatsPath = "stats.json"
	statsDate      string // 当前统计日期 YYYY-MM-DD
	usageSaveDirty bool
)

// ======================== 数据模型 ========================

type OpenAIRequest struct {
	Model           string         `json:"model"`
	Messages        []Message      `json:"messages"`
	Stream          bool           `json:"stream"`
	Temperature     *float64       `json:"temperature,omitempty"`
	MaxTokens       int            `json:"max_tokens,omitempty"`
	TopP            *float64       `json:"top_p,omitempty"`
	Thinking        any            `json:"thinking,omitempty"`
	ReasoningEffort string         `json:"reasoning_effort,omitempty"`
	ExtraBody       map[string]any `json:"extra_body,omitempty"`
	StreamOptions   any            `json:"stream_options,omitempty"`
	Tools           []Tool         `json:"tools,omitempty"`
	ToolChoice      any            `json:"tool_choice,omitempty"`
}

type Message struct {
	Role             string     `json:"role,omitempty"`
	Content          any        `json:"content,omitempty"`
	ToolCalls        []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID       string     `json:"tool_call_id,omitempty"`
	Name             string     `json:"name,omitempty"`
	ReasoningContent *string    `json:"reasoning_content,omitempty"`
}

type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

type ToolFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type UpstreamType string

const (
	UpstreamOpenAI    UpstreamType = "openai"
	UpstreamAnthropic UpstreamType = "anthropic"
	UpstreamResponses UpstreamType = "openai-responses"
)

type UpstreamConfig struct {
	BaseURL                  string            `json:"base_url"`
	APIKey                   string            `json:"api_key"`
	APIType                  UpstreamType      `json:"api_type"`
	CustomModels             []string          `json:"custom_models,omitempty"`
	ResponsesReasoningFormat string            `json:"responses_reasoning_format,omitempty"`
	CustomHeaders            map[string]string `json:"custom_headers,omitempty"`
}

type AppConfig struct {
	ModelAlias map[string]ModelAlias `json:"model_alias"`

	ReasoningEffortMap map[string]string          `json:"reasoning_effort_map"`
	Socks5Proxies      []Socks5Proxy              `json:"socks5_proxies,omitempty"`
	Upstreams          map[string]*UpstreamConfig `json:"upstreams,omitempty"`
}

type ModelAlias struct {
	TargetModel   string `json:"target_model"`
	Upstream      string `json:"upstream,omitempty"`
	Socks5Proxy   string `json:"socks5_proxy,omitempty"`
	WithReasoning bool   `json:"with_reasoning,omitempty"`
}

// ======================== Anthropic Messages API 类型 ========================

type AnthropicRequest struct {
	Model       string             `json:"model"`
	Messages    []AnthropicMessage `json:"messages"`
	System      any                `json:"system,omitempty"`
	MaxTokens   int                `json:"max_tokens,omitempty"`
	Temperature *float64           `json:"temperature,omitempty"`
	TopP        *float64           `json:"top_p,omitempty"`
	Stream      bool               `json:"stream,omitempty"`
	Tools       []AnthropicTool    `json:"tools,omitempty"`
	ToolChoice  any                `json:"tool_choice,omitempty"`
	Metadata    any                `json:"metadata,omitempty"`
	Thinking    any                `json:"thinking,omitempty"`
}

type AnthropicMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

type AnthropicContent struct {
	Type      string `json:"type"`
	Text      string `json:"text,omitempty"`
	Thinking  string `json:"thinking,omitempty"`
	Signature string `json:"signature,omitempty"`
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Input     any    `json:"input,omitempty"`
	ToolUseID string `json:"tool_use_id,omitempty"`
	Content   any    `json:"content,omitempty"`
}

type AnthropicTool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	InputSchema any    `json:"input_schema"`
}

type AnthropicResponse struct {
	ID           string             `json:"id"`
	Type         string             `json:"type"`
	Role         string             `json:"role"`
	Content      []AnthropicContent `json:"content"`
	Model        string             `json:"model"`
	StopReason   string             `json:"stop_reason"`
	StopSequence *string            `json:"stop_sequence"`
	Usage        *AnthropicUsage    `json:"usage,omitempty"`
}

type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// ======================== Responses API 类型 ========================

type ResponsesAPIRequest struct {
	Model             string          `json:"model"`
	Input             any             `json:"input"`
	Messages          []Message       `json:"messages,omitempty"`
	Instructions      string          `json:"instructions,omitempty"`
	Stream            bool            `json:"stream,omitempty"`
	Temperature       float64         `json:"temperature,omitempty"`
	MaxTokens         int             `json:"max_output_tokens,omitempty"`
	TopP              float64         `json:"top_p,omitempty"`
	FrequencyPenalty  float64         `json:"frequency_penalty,omitempty"`
	PresencePenalty   float64         `json:"presence_penalty,omitempty"`
	Reasoning         ReasonEffort    `json:"reasoning,omitempty"`
	Include           []string        `json:"include,omitempty"`
	Store             *bool           `json:"store,omitempty"`
	Tools             []ResponsesTool `json:"tools,omitempty"`
	ToolChoice        any             `json:"tool_choice,omitempty"`
	ParallelToolCalls *bool           `json:"parallel_tool_calls,omitempty"`
	Stop              any             `json:"stop,omitempty"`
	User              string          `json:"user,omitempty"`
	StreamOptions     any             `json:"stream_options,omitempty"`
	Metadata          any             `json:"metadata,omitempty"`
}

type ResponsesTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Parameters  map[string]any  `json:"parameters,omitempty"`
	Function    *ToolFunction   `json:"function,omitempty"`
	Tools       []ResponsesTool `json:"tools,omitempty"`
}

type ResponseToolNameMapping struct {
	Namespace string
	Name      string
}

type ReasonEffort struct {
	Effort string `json:"effort,omitempty"`
}

// ======================== 配置管理 ========================

func loadConfig(path string) AppConfig {
	var cfg AppConfig
	data, err := os.ReadFile(path)
	if err != nil {
		normalizeConfig(&cfg)
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("警告: 配置文件解析失败: %v", err)
	}
	normalizeConfig(&cfg)
	return cfg
}

func normalizeConfig(cfg *AppConfig) {
	if cfg.ModelAlias == nil {
		cfg.ModelAlias = map[string]ModelAlias{}
	}
	for key, alias := range cfg.ModelAlias {
		trimmedKey := strings.TrimSpace(key)
		alias.TargetModel = strings.TrimSpace(alias.TargetModel)
		alias.Upstream = strings.TrimSpace(alias.Upstream)
		alias.Socks5Proxy = strings.TrimSpace(alias.Socks5Proxy)
		if trimmedKey == "" {
			delete(cfg.ModelAlias, key)
			continue
		}
		if trimmedKey != key {
			delete(cfg.ModelAlias, key)
		}
		cfg.ModelAlias[trimmedKey] = alias
	}

	if cfg.ReasoningEffortMap == nil {
		cfg.ReasoningEffortMap = map[string]string{}
	}
	normalizedProxies := make([]Socks5Proxy, 0, len(cfg.Socks5Proxies))
	proxyAddresses := make(map[string]struct{}, len(cfg.Socks5Proxies))
	for _, proxy := range cfg.Socks5Proxies {
		proxy.Addr = strings.TrimSpace(proxy.Addr)
		proxy.Name = strings.TrimSpace(proxy.Name)
		if proxy.Addr == "" {
			continue
		}
		if _, exists := proxyAddresses[proxy.Addr]; exists {
			continue
		}
		proxyAddresses[proxy.Addr] = struct{}{}
		normalizedProxies = append(normalizedProxies, proxy)
	}
	cfg.Socks5Proxies = normalizedProxies
	// 不静默清空 alias.Socks5Proxy：保留引用，交由 adminConfigHandler POST 阶段
	// 校验"孤儿代理引用"并返回 400，避免用户不知情地丢失配置。
	if cfg.Upstreams == nil {
		cfg.Upstreams = map[string]*UpstreamConfig{}
	}
	normalizedUpstreams := make(map[string]*UpstreamConfig, len(cfg.Upstreams))
	for name, upstream := range cfg.Upstreams {
		trimmedName := strings.TrimSpace(name)
		copied := cloneUpstreamConfig(upstream)
		if trimmedName == "" || !normalizeSingleUpstream(copied) {
			continue
		}
		normalizedUpstreams[trimmedName] = copied
	}
	cfg.Upstreams = normalizedUpstreams
	if len(cfg.Upstreams) == 0 {
		return
	}
}

func saveConfig(path string, cfg AppConfig) error {
	normalizeConfig(&cfg)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func applyConfig(cfg AppConfig) bool {
	configMu.Lock()
	defer configMu.Unlock()
	if cfg.ModelAlias != nil {
		modelAlias = cfg.ModelAlias
	}

	if cfg.ReasoningEffortMap != nil {
		reasoningEffortMap = cfg.ReasoningEffortMap
	}
	upstreamsChanged := upstreamsConfigChanged(upstreamCfgs, cfg.Upstreams)
	upstreamCfgs = make(map[string]*UpstreamConfig, len(cfg.Upstreams))
	for name, upstream := range cfg.Upstreams {
		upstreamCfgs[name] = cloneUpstreamConfig(upstream)
	}

	socks5Mu.Lock()
	if cfg.Socks5Proxies != nil {
		socks5Proxies = cfg.Socks5Proxies
	}
	socks5Mu.Unlock()
	// Key 列表或上游配置可能变化，清除模型级 Key 亲和，避免继续用已失效的 Key。
	if upstreamsChanged {
		clearModelKeyAffinity()
	}
	clearSocks5ClientCache()

	return upstreamsChanged
}

// isKnownAlias 判断 model 是否为已配置且填写了 target_model 的别名。
// 严格模式下客户端 model 必须是有效别名，否则推理请求将被拒绝。
func isKnownAlias(model string) bool {
	m := strings.TrimSpace(model)
	if m == "" {
		return false
	}
	configMu.RLock()
	alias, ok := modelAlias[m]
	configMu.RUnlock()
	return ok && alias.TargetModel != ""
}

func resolveModel(model string) (string, ModelAlias, string, *UpstreamConfig) {
	m := strings.TrimSpace(model)
	alias := ModelAlias{}
	configMu.RLock()
	if found, ok := modelAlias[m]; ok {
		alias = found
	}
	configMu.RUnlock()
	if alias.TargetModel != "" {
		m = alias.TargetModel
	}
	upstreamName, upstream := resolveUpstream(alias.Upstream)
	if m == "" {
		m = strings.TrimSpace(model)
	}
	return m, alias, upstreamName, upstream
}

func getConfiguredUpstreamCount() int {
	configMu.RLock()
	defer configMu.RUnlock()
	return len(upstreamCfgs)
}

func getReasoningEffortMap() map[string]string {
	configMu.RLock()
	defer configMu.RUnlock()
	cp := make(map[string]string, len(reasoningEffortMap))
	for k, v := range reasoningEffortMap {
		cp[k] = v
	}
	return cp
}

// ======================== Token 统计 ========================

func getToday() string {
	return time.Now().Format("2006-01-02")
}

func checkAndResetDailyStats() {
	today := getToday()
	tokenStatsMu.Lock()
	defer tokenStatsMu.Unlock()
	if statsDate == "" {
		statsDate = today
		if tokenStats.Daily == nil || tokenStats.Daily.Date != today {
			tokenStats.Daily = &DailyStats{Date: today, Models: map[string]*ModelStats{}}
		}
		return
	}
	if statsDate != today {
		log.Printf("[统计] 日期变更 %s -> %s，重置每日统计", statsDate, today)
		statsDate = today
		tokenStats.Daily = &DailyStats{Date: today, Models: map[string]*ModelStats{}}
	}
}

func loadTokenStats() {
	data, err := os.ReadFile(tokenStatsPath)
	if err != nil {
		checkAndResetDailyStats()
		return
	}
	var st TokenStatsData
	if err := json.Unmarshal(data, &st); err != nil {
		checkAndResetDailyStats()
		return
	}
	tokenStatsMu.Lock()
	if st.Models == nil {
		st.Models = map[string]*ModelStats{}
	}
	if st.Rollups == nil {
		st.Rollups = map[string]*UsageRow{}
	}
	today := getToday()
	if st.Daily != nil && st.Daily.Date != today {
		log.Printf("[统计] 每日统计日期 %s 已过期，重置", st.Daily.Date)
		st.Daily = &DailyStats{Date: today, Models: map[string]*ModelStats{}}
	} else if st.Daily == nil {
		st.Daily = &DailyStats{Date: today, Models: map[string]*ModelStats{}}
	}
	statsDate = today
	tokenStats = &st
	migrated := migrateLegacyDailyLocked()
	repaired := repairUsageUpstreamsLocked()
	pruneUsageRollupsLocked(today)
	tokenStatsMu.Unlock()
	if migrated || repaired {
		markUsageDirty()
	}
}

// migrateLegacyDailyLocked 老版本 stats.json 只有 daily 快照、没有每日聚合，
// 首次升级时把当天数据补进 rollups，避免面板"今日"显示为空。
func migrateLegacyDailyLocked() bool {
	if len(tokenStats.Rollups) > 0 || tokenStats.Daily == nil || len(tokenStats.Daily.Models) == 0 {
		return false
	}
	date := tokenStats.Daily.Date
	if date == "" {
		date = getToday()
	}
	for model, ms := range tokenStats.Daily.Models {
		if ms == nil {
			continue
		}
		_, _, upstreamName, _ := resolveModel(model)
		upstream := effectiveUpstreamName(upstreamName)
		key := usageKey(date, upstream, model)
		row, ok := tokenStats.Rollups[key]
		if !ok {
			row = &UsageRow{Date: date, Upstream: upstream, Model: model}
			tokenStats.Rollups[key] = row
		}
		row.RequestCount += ms.RequestCount
		row.SuccessCount += ms.RequestCount
		row.InputTokens += ms.PromptTokens - ms.CacheReadTokens - ms.CacheCreationTokens
		row.OutputTokens += ms.CompletionTokens
		row.CacheReadTokens += ms.CacheReadTokens
		row.CacheCreationTokens += ms.CacheCreationTokens
		row.ReasoningTokens += ms.ReasoningTokens
		row.TotalTokens += ms.TotalTokens
		row.CostUSD += ms.CostUSD
	}
	log.Printf("[统计] 已从旧版每日快照迁移 %d 个模型到每日聚合", len(tokenStats.Daily.Models))
	return true
}

// repairUsageUpstreamsLocked 修复历史统计数据里被误记为“模型名/上游模型名”的上游。
// 旧版 OpenAI Chat 快速透传路径误把 resolveModel 的第一个返回值（目标模型）当作上游名传入，
// 导致 stats.json 的上游列出现 deepseek-v4-flash、minimaxai/minimax-m3 这类伪上游。
// 此函数在加载统计时按当前别名/目标模型映射回真实配置上游，并合并重复行。
func repairUsageUpstreamsLocked() bool {
	configured := map[string]bool{"default": true}
	aliasToUpstream := map[string]string{}
	targetToUpstream := map[string]string{}

	configMu.RLock()
	for name := range upstreamCfgs {
		configured[name] = true
	}
	for alias, info := range modelAlias {
		up := strings.TrimSpace(info.Upstream)
		if up == "" {
			continue
		}
		aliasToUpstream[alias] = up
		if target := strings.TrimSpace(info.TargetModel); target != "" {
			if _, ok := targetToUpstream[target]; !ok {
				targetToUpstream[target] = up
			}
		}
	}
	configMu.RUnlock()

	resolve := func(model, target string) string {
		for _, candidate := range []string{model, target} {
			if up := aliasToUpstream[candidate]; up != "" {
				return up
			}
			if up := targetToUpstream[candidate]; up != "" {
				return up
			}
		}
		return ""
	}

	changed := false

	// 修复每日聚合：先改上游名，再按新 key 合并，避免同一模型拆成多个伪上游行。
	if tokenStats.Rollups != nil {
		merged := make(map[string]*UsageRow, len(tokenStats.Rollups))
		for _, row := range tokenStats.Rollups {
			if row == nil {
				continue
			}
			if !configured[row.Upstream] {
				if up := resolve(row.Model, row.TargetModel); up != "" {
					row.Upstream = up
					changed = true
				}
			}
			key := usageKey(row.Date, row.Upstream, row.Model)
			if existing, ok := merged[key]; ok {
				mergeUsageRow(existing, row)
				changed = true
			} else {
				merged[key] = row
			}
		}
		tokenStats.Rollups = merged
	}

	// 修复请求明细
	for i := range tokenStats.Log {
		e := &tokenStats.Log[i]
		if !configured[e.Upstream] {
			if up := resolve(e.Model, e.TargetModel); up != "" {
				e.Upstream = up
				changed = true
			}
		}
	}

	return changed
}

// mergeUsageRow 把 src 的计数合并到 dst，用于修复后同一 date|upstream|model 的多行归并。
func mergeUsageRow(dst, src *UsageRow) {
	dst.RequestCount += src.RequestCount
	dst.SuccessCount += src.SuccessCount
	dst.ErrorCount += src.ErrorCount
	dst.InputTokens += src.InputTokens
	dst.OutputTokens += src.OutputTokens
	dst.CacheReadTokens += src.CacheReadTokens
	dst.CacheCreationTokens += src.CacheCreationTokens
	dst.ReasoningTokens += src.ReasoningTokens
	dst.TotalTokens += src.TotalTokens
	dst.LatencyMsTotal += src.LatencyMsTotal
	dst.LatencySamples += src.LatencySamples
	dst.FirstTokenMsTotal += src.FirstTokenMsTotal
	dst.FirstTokenSamples += src.FirstTokenSamples
	dst.CostUSD += src.CostUSD
	if dst.TargetModel == "" {
		dst.TargetModel = src.TargetModel
	}
}

func saveTokenStats() {
	tokenStatsMu.Lock()
	data, err := json.MarshalIndent(tokenStats, "", "  ")
	tokenStatsMu.Unlock()
	if err != nil {
		return
	}
	os.WriteFile(tokenStatsPath, data, 0644)
}

// markUsageDirty 由请求路径调用，实际的磁盘写入由 startUsageSaveWorker 合并执行，
// 避免高 QPS 下每个请求都全量重写 stats.json。
func markUsageDirty() {
	tokenStatsMu.Lock()
	usageSaveDirty = true
	tokenStatsMu.Unlock()
}

func startUsageSaveWorker() {
	go func() {
		for range time.Tick(3 * time.Second) {
			tokenStatsMu.Lock()
			dirty := usageSaveDirty
			usageSaveDirty = false
			tokenStatsMu.Unlock()
			if dirty {
				saveTokenStats()
			}
		}
	}()
}

// ======================== 计费单价（pricing.json，口径同 cc-switch：每百万 token） ========================

// ModelPrice 每百万 token 的单价
type ModelPrice struct {
	Input         float64 `json:"input"`
	Output        float64 `json:"output"`
	CacheRead     float64 `json:"cache_read,omitempty"`
	CacheCreation float64 `json:"cache_creation,omitempty"`
}

// PricingConfig 费用估算配置；未配置时统计面板只显示 token，不显示费用
type PricingConfig struct {
	Currency string                `json:"currency,omitempty"`
	Default  *ModelPrice           `json:"default,omitempty"`
	Models   map[string]ModelPrice `json:"models"`
}

var (
	pricingPath   = "pricing.json"
	pricingMu     sync.RWMutex
	pricingConfig = PricingConfig{Currency: "USD", Models: map[string]ModelPrice{}}
)

func loadPricing() {
	data, err := os.ReadFile(pricingPath)
	if err != nil {
		return
	}
	var p PricingConfig
	if err := json.Unmarshal(data, &p); err != nil {
		log.Printf("[统计] pricing.json 解析失败，忽略费用估算: %v", err)
		return
	}
	if p.Models == nil {
		p.Models = map[string]ModelPrice{}
	}
	if p.Currency == "" {
		p.Currency = "USD"
	}
	pricingMu.Lock()
	pricingConfig = p
	pricingMu.Unlock()
}

func savePricing(p PricingConfig) error {
	pricingMu.Lock()
	pricingConfig = p
	pricingMu.Unlock()
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(pricingPath, data, 0644)
}

func getPricingSnapshot() PricingConfig {
	pricingMu.RLock()
	defer pricingMu.RUnlock()
	out := PricingConfig{Currency: pricingConfig.Currency, Default: pricingConfig.Default, Models: map[string]ModelPrice{}}
	for k, v := range pricingConfig.Models {
		out.Models[k] = v
	}
	return out
}

func pricingConfigured() bool {
	pricingMu.RLock()
	defer pricingMu.RUnlock()
	return len(pricingConfig.Models) > 0 || pricingConfig.Default != nil
}

// lookupPrice 依次用候选名匹配单价：完全匹配（忽略大小写）→ 去掉供应商前缀后匹配 → default
func lookupPrice(candidates ...string) (ModelPrice, bool) {
	pricingMu.RLock()
	defer pricingMu.RUnlock()
	if len(pricingConfig.Models) == 0 && pricingConfig.Default == nil {
		return ModelPrice{}, false
	}
	norms := make([]string, 0, len(candidates)*2)
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		norms = append(norms, strings.ToLower(c))
		if i := strings.LastIndex(c, "/"); i >= 0 && i+1 < len(c) {
			norms = append(norms, strings.ToLower(c[i+1:]))
		}
	}
	for _, key := range norms {
		for k, v := range pricingConfig.Models {
			if strings.ToLower(strings.TrimSpace(k)) == key {
				return v, true
			}
		}
	}
	if pricingConfig.Default != nil {
		return *pricingConfig.Default, true
	}
	return ModelPrice{}, false
}

func calcCostUSD(models []string, a usageAmounts) float64 {
	price, ok := lookupPrice(models...)
	if !ok {
		return 0
	}
	const perM = 1000000.0
	cost := float64(a.Input)*price.Input/perM + float64(a.Output)*price.Output/perM +
		float64(a.CacheRead)*price.CacheRead/perM + float64(a.CacheCreation)*price.CacheCreation/perM
	if cost <= 0 {
		return 0
	}
	return float64(int64(cost*1e8+0.5)) / 1e8
}

// ======================== 请求级用量采集 ========================

// usageAmounts 单次请求的 token 拆分（Input 不含缓存部分）
type usageAmounts struct {
	Input         int64
	Output        int64
	CacheRead     int64
	CacheCreation int64
	Reasoning     int64
}

func (a usageAmounts) total() int64     { return a.Input + a.Output + a.CacheRead + a.CacheCreation }
func (a usageAmounts) empty() bool      { return a.total() <= 0 }
func (a usageAmounts) promptAll() int64 { return a.Input + a.CacheRead + a.CacheCreation }

func nestedInt64(u map[string]any, objKeys []string, valKeys ...string) int64 {
	// Some upstreams put cache/reasoning counters in both prompt_tokens_details and
	// input_tokens_details (or completion/output_tokens_details).  Some contain 0 in one
	// place and the real value in the other; scan all candidates and keep the maximum so
	// a zero-valued placeholder cannot hide the actual cached/reasoning count.
	var best int64
	for _, objKey := range objKeys {
		sub, _ := u[objKey].(map[string]any)
		if sub == nil {
			continue
		}
		if v, ok := getFloat(sub, valKeys...); ok {
			if n := int64(v); n > best {
				best = n
			}
		}
	}
	return best
}

// usageFromMap 从上游 usage 对象提取 token 拆分，兼容 OpenAI Chat / Responses / Anthropic 三种口径。
// Anthropic 的 input_tokens 本身不含缓存，OpenAI 的 prompt_tokens 含 cached_tokens（需要扣出）。
// reasoning_tokens 是 completion/output 的子集，只作展示、不参与求和。
func usageFromMap(u map[string]any) usageAmounts {
	var a usageAmounts
	if u == nil {
		return a
	}
	pt, hasPT := getFloat(u, "prompt_tokens")
	it, hasIT := getFloat(u, "input_tokens")
	ct, hasCT := getFloat(u, "completion_tokens")
	ot, hasOT := getFloat(u, "output_tokens")
	input := int64(pt)
	if !hasPT && hasIT {
		input = int64(it)
	}
	output := int64(ct)
	if !hasCT && hasOT {
		output = int64(ot)
	}
	cr, hasCR := getFloat(u, "cache_read_input_tokens")
	cc, hasCC := getFloat(u, "cache_creation_input_tokens")
	if hasCR || hasCC {
		// Anthropic 口径：input_tokens 已排除缓存部分
		a.CacheRead = int64(cr)
		a.CacheCreation = int64(cc)
	} else {
		// OpenAI / Responses 口径：cached_tokens 是 prompt/input 的子集，需要扣出来
		a.CacheRead = nestedInt64(u, []string{"prompt_tokens_details", "input_tokens_details"}, "cached_tokens")
		a.CacheCreation = nestedInt64(u, []string{"prompt_tokens_details", "input_tokens_details"}, "cache_creation_tokens")
		if a.CacheRead > input {
			a.CacheRead = input
		}
		input -= a.CacheRead
		if a.CacheCreation > input {
			a.CacheCreation = input
		}
		input -= a.CacheCreation
	}
	a.Reasoning = nestedInt64(u, []string{"completion_tokens_details", "output_tokens_details"}, "reasoning_tokens")
	if input < 0 {
		input = 0
	}
	if output < 0 {
		output = 0
	}
	a.Input = input
	a.Output = output
	return a
}

// usageRecorder 汇总单次请求的上游、耗时、状态与 token 用量，请求结束时一次性落账。
type usageRecorder struct {
	mu         sync.Mutex
	api        string
	model      string
	target     string
	upstream   string
	stream     bool
	start      time.Time
	firstToken time.Time
	status     int
	errMsg     string
	usage      usageAmounts
	haveUsage  bool
	done       bool
}

func newUsageRecorder(api, model string, stream bool) *usageRecorder {
	target, _, upstreamName, _ := resolveModel(model)
	return &usageRecorder{
		api:      api,
		model:    strings.TrimSpace(model),
		target:   target,
		upstream: effectiveUpstreamName(upstreamName),
		stream:   stream,
		start:    time.Now(),
	}
}

func (rec *usageRecorder) SetUpstream(name string) {
	if rec == nil || name == "" {
		return
	}
	rec.mu.Lock()
	rec.upstream = effectiveUpstreamName(name)
	rec.mu.Unlock()
}

func (rec *usageRecorder) SetStatus(code int) {
	if rec == nil {
		return
	}
	rec.mu.Lock()
	if code > 0 {
		rec.status = code
	}
	rec.mu.Unlock()
}

func (rec *usageRecorder) SetError(msg string) {
	if rec == nil || msg == "" {
		return
	}
	rec.mu.Lock()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	rec.errMsg = msg
	rec.mu.Unlock()
}

func (rec *usageRecorder) MarkFirstToken() {
	if rec == nil {
		return
	}
	rec.mu.Lock()
	if rec.firstToken.IsZero() {
		rec.firstToken = time.Now()
	}
	rec.mu.Unlock()
}

func (rec *usageRecorder) SetUsage(a usageAmounts) {
	if rec == nil || a.empty() {
		return
	}
	rec.mu.Lock()
	rec.usage = a
	rec.haveUsage = true
	rec.mu.Unlock()
}

// MarkUsageFromMap 解析上游 usage 并记账。
// 同一个流式响应可能先给出一个缺少缓存明细的 usage，再来一个带完整 cache_read/cache_creation
// 的 usage；这里不做“首次即冻结”，而是把后续更完整/更大的计数合并进来，避免缓存统计被 0 覆盖。
func (rec *usageRecorder) MarkUsageFromMap(u map[string]any) {
	if rec == nil {
		return
	}
	a := usageFromMap(u)
	if a.empty() {
		return
	}
	rec.mu.Lock()
	if !rec.haveUsage {
		rec.usage = a
		rec.haveUsage = true
		rec.mu.Unlock()
		return
	}
	// 上游流式 usage 通常是针对整次响应的累计值，因此逐字段取最大即可补齐缺失项，
	// 同时不会把同一份累计 usage 重复相加。
	// 注意 Input 是“扣除缓存后的非缓存输入”，不能直接用两次的 Input 比较：
	// 如果后到的 usage 补充了 cache_read，那么同一份 prompt 里应计入缓存的部分要从 Input 中扣除。
	// 所以这里先保留最大的 promptAll（= Input+CacheRead+CacheCreation），再重算非缓存输入。
	maxPromptAll := rec.usage.promptAll()
	if pa := a.promptAll(); pa > maxPromptAll {
		maxPromptAll = pa
	}
	if a.Output > rec.usage.Output {
		rec.usage.Output = a.Output
	}
	if a.CacheRead > rec.usage.CacheRead {
		rec.usage.CacheRead = a.CacheRead
	}
	if a.CacheCreation > rec.usage.CacheCreation {
		rec.usage.CacheCreation = a.CacheCreation
	}
	if a.Reasoning > rec.usage.Reasoning {
		rec.usage.Reasoning = a.Reasoning
	}
	rec.usage.Input = maxPromptAll - rec.usage.CacheRead - rec.usage.CacheCreation
	if rec.usage.Input < 0 {
		rec.usage.Input = 0
	}
	rec.mu.Unlock()
}

// usageCommit 是 usageRecorder 的一次性快照（不含锁，可安全传递）
type usageCommit struct {
	api          string
	model        string
	target       string
	upstream     string
	stream       bool
	status       int
	errMsg       string
	usage        usageAmounts
	haveUsage    bool
	firstTokenMs int64
}

func (rec *usageRecorder) Finish() {
	if rec == nil {
		return
	}
	rec.mu.Lock()
	if rec.done {
		rec.mu.Unlock()
		return
	}
	rec.done = true
	elapsed := time.Since(rec.start).Milliseconds()
	if elapsed < 0 {
		elapsed = 0
	}
	snap := usageCommit{
		api:       rec.api,
		model:     rec.model,
		target:    rec.target,
		upstream:  rec.upstream,
		stream:    rec.stream,
		status:    rec.status,
		errMsg:    rec.errMsg,
		usage:     rec.usage,
		haveUsage: rec.haveUsage,
	}
	if !rec.firstToken.IsZero() {
		snap.firstTokenMs = rec.firstToken.Sub(rec.start).Milliseconds()
		if snap.firstTokenMs < 0 {
			snap.firstTokenMs = 0
		}
	}
	rec.mu.Unlock()
	commitUsage(snap, elapsed)
}

type usageRecorderCtxKey struct{}

func withUsageRecorder(r *http.Request, rec *usageRecorder) *http.Request {
	if r == nil || rec == nil {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), usageRecorderCtxKey{}, rec))
}

func usageRecorderFromContext(ctx context.Context) *usageRecorder {
	if ctx == nil {
		return nil
	}
	rec, _ := ctx.Value(usageRecorderCtxKey{}).(*usageRecorder)
	return rec
}

func usageKey(date, upstream, model string) string {
	return date + "|" + upstream + "|" + model
}

// commitUsage 把一次请求写入：累计表（兼容旧口径）+ 每日聚合 + 请求明细
func commitUsage(snap usageCommit, latencyMs int64) {
	checkAndResetDailyStats()
	today := getToday()

	model, target, upstream := snap.model, snap.target, snap.upstream
	api, errMsg, status := snap.api, snap.errMsg, snap.status
	usage, haveUsage, firstTokenMs := snap.usage, snap.haveUsage, snap.firstTokenMs

	// status==0 表示从未拿到上游 2xx（成功路径都会显式 SetStatus）。
	// 兜底归一化，避免任何未覆盖的分支落下 status=0 被前端当成成功。
	if status == 0 {
		if latencyMs > 0 {
			status = 499 // 已发出请求但未拿到响应：客户端断开或超时
			if errMsg == "" {
				errMsg = "no upstream response (timeout or client disconnect)"
			}
		} else {
			status = 400 // 请求在进入上游前就被拒
			if errMsg == "" {
				errMsg = "request rejected"
			}
		}
	}

	if model == "" {
		model = target
	}
	if model == "" {
		model = "(unknown)"
	}
	if upstream == "" {
		upstream = "(default)"
	}
	ok := status == 0 || (status >= 200 && status < 300)

	tokenStatsMu.Lock()
	if tokenStats.Rollups == nil {
		tokenStats.Rollups = map[string]*UsageRow{}
	}
	row, exists := tokenStats.Rollups[usageKey(today, upstream, model)]
	if !exists {
		row = &UsageRow{Date: today, Upstream: upstream, Model: model, TargetModel: target}
		tokenStats.Rollups[usageKey(today, upstream, model)] = row
	}
	if target != "" && row.TargetModel == "" {
		row.TargetModel = target
	}
	row.RequestCount++
	if ok {
		row.SuccessCount++
	} else {
		row.ErrorCount++
	}
	if latencyMs > 0 {
		row.LatencyMsTotal += latencyMs
		row.LatencySamples++
	}
	if firstTokenMs > 0 {
		row.FirstTokenMsTotal += firstTokenMs
		row.FirstTokenSamples++
	}
	if haveUsage {
		row.InputTokens += usage.Input
		row.OutputTokens += usage.Output
		row.CacheReadTokens += usage.CacheRead
		row.CacheCreationTokens += usage.CacheCreation
		row.ReasoningTokens += usage.Reasoning
		row.TotalTokens += usage.total()
	}

	// 累计表（旧口径：prompt 含缓存），供 /api/stats 与「累计」视图使用
	if tokenStats.Models == nil {
		tokenStats.Models = map[string]*ModelStats{}
	}
	ms, ok2 := tokenStats.Models[model]
	if !ok2 {
		ms = &ModelStats{}
		tokenStats.Models[model] = ms
	}
	ms.ErrorCount += bool2int(!ok)
	if latencyMs > 0 {
		ms.LatencyMsTotal += latencyMs
	}
	if firstTokenMs > 0 {
		ms.FirstTokenMsTotal += firstTokenMs
		ms.FirstTokenSamples++
	}
	if haveUsage {
		ms.RequestCount++
		tokenStats.TotalRequests++
		ms.PromptTokens += usage.promptAll()
		ms.CompletionTokens += usage.Output
		ms.TotalTokens += usage.total()
		ms.CacheReadTokens += usage.CacheRead
		ms.CacheCreationTokens += usage.CacheCreation
		ms.ReasoningTokens += usage.Reasoning
		if tokenStats.Daily == nil {
			tokenStats.Daily = &DailyStats{Date: today, Models: map[string]*ModelStats{}}
		}
		tokenStats.Daily.TotalRequests++
		dms, dok := tokenStats.Daily.Models[model]
		if !dok {
			dms = &ModelStats{}
			tokenStats.Daily.Models[model] = dms
		}
		dms.RequestCount++
		dms.PromptTokens += usage.promptAll()
		dms.CompletionTokens += usage.Output
		dms.TotalTokens += usage.total()
		dms.CacheReadTokens += usage.CacheRead
		dms.CacheCreationTokens += usage.CacheCreation
		dms.ReasoningTokens += usage.Reasoning
		dms.ErrorCount += bool2int(!ok)
		dms.LatencyMsTotal += latencyMs
		dms.FirstTokenMsTotal += firstTokenMs
		if firstTokenMs > 0 {
			dms.FirstTokenSamples++
		}
	}

	// 请求明细（新的在前，超出上限截断）
	entry := RequestLogEntry{
		TS:                  time.Now().Unix(),
		API:                 api,
		Upstream:            upstream,
		Model:               model,
		TargetModel:         target,
		Stream:              snap.stream,
		Status:              status,
		Error:               errMsg,
		InputTokens:         usage.Input,
		OutputTokens:        usage.Output,
		CacheReadTokens:     usage.CacheRead,
		CacheCreationTokens: usage.CacheCreation,
		ReasoningTokens:     usage.Reasoning,
		LatencyMs:           latencyMs,
		FirstTokenMs:        firstTokenMs,
	}
	if haveUsage {
		entry.TotalTokens = usage.total()
	}
	tokenStats.Log = append([]RequestLogEntry{entry}, tokenStats.Log...)
	if len(tokenStats.Log) > usageLogLimit {
		tokenStats.Log = tokenStats.Log[:usageLogLimit]
	}
	pruneUsageRollupsLocked(today)
	tokenStatsMu.Unlock()
	markUsageDirty()
}

// pruneUsageRollupsLocked 删除超出保留期的每日聚合，必须在持有 tokenStatsMu 时调用
func pruneUsageRollupsLocked(today string) {
	if len(tokenStats.Rollups) == 0 {
		return
	}
	t, err := time.Parse("2006-01-02", today)
	if err != nil {
		return
	}
	cutoff := t.AddDate(0, 0, -(usageHistoryDays - 1)).Format("2006-01-02")
	changed := false
	for k, v := range tokenStats.Rollups {
		if v == nil || v.Date < cutoff {
			delete(tokenStats.Rollups, k)
			changed = true
		}
	}
	if changed {
		log.Printf("[统计] 已清理 %s 之前的每日聚合", cutoff)
	}
}

func bool2int(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// ======================== Thinking/Reasoning 判断 ========================

func numberFromAny(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case int32:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func reasoningEffortFromThinking(value any) string {
	switch v := value.(type) {
	case map[string]any:
		t, _ := v["type"].(string)
		switch strings.ToLower(t) {
		case "disabled":
			return "none"
		case "adaptive":
			return "xhigh"
		case "enabled":
			if budget, ok := numberFromAny(v["budget_tokens"]); ok && budget > 0 {
				switch {
				case budget < 4000:
					return "low"
				case budget <= 16000:
					return "medium"
				default:
					return "high"
				}
			}
			return "medium"
		}
	case map[string]string:
		switch strings.ToLower(v["type"]) {
		case "disabled":
			return "none"
		case "adaptive":
			return "xhigh"
		case "enabled":
			return "medium"
		}
	case bool:
		if v {
			return "medium"
		}
		return "none"
	}
	return ""
}

func ensureReasoningEffort(req *OpenAIRequest, alias ModelAlias) {
	if req == nil || req.ReasoningEffort != "" {
		return
	}
	if effort := reasoningEffortFromThinking(req.Thinking); effort != "" {
		if effort != "none" {
			req.ReasoningEffort = effort
		}
		return
	}
	if req.ExtraBody != nil {
		if effort := reasoningEffortFromThinking(req.ExtraBody["thinking"]); effort != "" {
			if effort != "none" {
				req.ReasoningEffort = effort
			}
			return
		}
	}
}

func shouldUseLegacyResponsesReasoningEffort(upstream *UpstreamConfig) bool {
	if upstream == nil {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(upstream.ResponsesReasoningFormat))
	return v == "reasoning_effort" || v == "legacy" || v == "legacy_reasoning_effort"
}

func setResponsesReasoningEffort(req map[string]any, effort string, upstream *UpstreamConfig) {
	if effort == "" || effort == "none" {
		return
	}
	if shouldUseLegacyResponsesReasoningEffort(upstream) {
		req["reasoning_effort"] = effort
		return
	}
	req["reasoning"] = map[string]any{"effort": effort}
}

func mapConfiguredReasoningEffort(effort string) string {
	if effort == "" {
		return ""
	}
	effortMap := getReasoningEffortMap()
	if mapped, ok := effortMap[effort]; ok {
		return mapped
	}
	return effort
}

// ======================== 上游格式转换 ========================

// reasoningEffortToAnthropicThinking maps OpenAI-compatible reasoning_effort
// to Anthropic thinking with a default budget_tokens (required by Anthropic API).
func reasoningEffortToAnthropicThinking(effort string) map[string]any {
	switch strings.ToLower(effort) {
	case "low":
		return map[string]any{"type": "enabled", "budget_tokens": 4000}
	case "medium":
		return map[string]any{"type": "enabled", "budget_tokens": 16000}
	case "high":
		return map[string]any{"type": "enabled", "budget_tokens": 32000}
	case "xhigh":
		return map[string]any{"type": "enabled", "budget_tokens": 64000}
	case "adaptive":
		return map[string]any{"type": "enabled", "budget_tokens": 32000}
	case "":
		return nil
	default:
		return map[string]any{"type": "enabled", "budget_tokens": 16000}
	}
}

// buildAnthropicThinking picks the Anthropic thinking config from an OpenAI-style
// request body: prefer explicit thinking, fall back to reasoning_effort.
func buildAnthropicThinking(req map[string]any) any {
	if thinking, ok := req["thinking"]; ok {
		if tm, ok := thinking.(map[string]any); ok {
			if t, _ := tm["type"].(string); strings.EqualFold(t, "enabled") {
				if _, has := tm["budget_tokens"]; !has {
					tm["budget_tokens"] = 16000
				}
			}
			return tm
		}
		if tm, ok := thinking.(map[string]string); ok {
			switch strings.ToLower(tm["type"]) {
			case "disabled":
				return nil
			case "enabled":
				return map[string]any{"type": "enabled", "budget_tokens": 16000}
			default:
				return map[string]any{"type": tm["type"]}
			}
		}
		return thinking
	}
	if re, ok := req["reasoning_effort"].(string); ok && re != "" && re != "none" {
		return reasoningEffortToAnthropicThinking(re)
	}
	return nil
}

// addAnthropicCacheControl 在 Anthropic 文本块的最后一个 block 上标记 cache_control:
// {"type":"ephemeral"}，帮助 Anthropic 上游最大化 prompt/prefix cache 命中。
func addAnthropicCacheControl(blocks []map[string]any) {
	if len(blocks) == 0 {
		return
	}
	last := blocks[len(blocks)-1]
	if last == nil {
		return
	}
	if last["type"] != "text" {
		return
	}
	if existing, ok := last["cache_control"].(map[string]any); ok {
		existing["type"] = "ephemeral"
		last["cache_control"] = existing
		return
	}
	last["cache_control"] = map[string]any{"type": "ephemeral"}
}

// openAIToAnthropicRequest 将 OpenAI Chat 请求转为 Anthropic Messages 格式
func openAIToAnthropicRequest(body []byte) []byte {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return body
	}

	model, _ := req["model"].(string)
	msgs, _ := req["messages"].([]any)

	var systemTexts []string
	var anthropicMsgs []map[string]any
	handleContent := func(content any, role string) []map[string]any {
		var blocks []map[string]any
		switch c := content.(type) {
		case string:
			if c != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": c})
			}
		case []any:
			for _, item := range c {
				if p, ok := item.(map[string]any); ok {
					switch p["type"] {
					case "text":
						if t, ok := p["text"].(string); ok && t != "" {
							blocks = append(blocks, map[string]any{"type": "text", "text": t})
						}
					case "image_url":
						blocks = append(blocks, convertOpenAIImageToAnthropic(p))
					}
				}
			}
		}
		return blocks
	}

	for _, m := range msgs {
		msg, _ := m.(map[string]any)
		if msg == nil {
			continue
		}
		role, _ := msg["role"].(string)
		content := msg["content"]

		if role == "system" {
			if s, ok := content.(string); ok {
				systemTexts = append(systemTexts, s)
			}
			continue
		}

		if role == "assistant" {
			var blocks []map[string]any

			if rc, ok := msg["reasoning_content"].(string); ok && rc != "" {
				blocks = append(blocks, map[string]any{"type": "thinking", "thinking": rc})
			}

			blocks = append(blocks, handleContent(content, role)...)

			if tcs, ok := msg["tool_calls"].([]any); ok && len(tcs) > 0 {
				for _, tc := range tcs {
					tcMap, _ := tc.(map[string]any)
					id, _ := tcMap["id"].(string)
					fn, _ := tcMap["function"].(map[string]any)
					name, _ := fn["name"].(string)
					var args any = map[string]any{}
					if rawArgs, ok := fn["arguments"]; ok && rawArgs != nil {
						switch v := rawArgs.(type) {
						case string:
							if v != "" {
								var parsed any
								if json.Unmarshal([]byte(v), &parsed) == nil {
									args = parsed
								}
							}
						default:
							b, _ := json.Marshal(v)
							var parsed any
							if json.Unmarshal(b, &parsed) == nil {
								args = parsed
							}
						}
					}
					blocks = append(blocks, map[string]any{
						"type": "tool_use", "id": id, "name": name, "input": args,
					})
				}
			}

			if len(blocks) == 0 {
				blocks = append(blocks, map[string]any{"type": "text", "text": ""})
			}
			anthropicMsgs = append(anthropicMsgs, map[string]any{"role": "assistant", "content": blocks})
			continue
		}

		if role == "tool" {
			toolCallID, _ := msg["tool_call_id"].(string)
			var resultText string
			if s, ok := content.(string); ok {
				resultText = s
			} else {
				b, _ := json.Marshal(content)
				resultText = string(b)
			}
			anthropicMsgs = append(anthropicMsgs, map[string]any{
				"role": "user",
				"content": []map[string]any{
					{"type": "tool_result", "tool_use_id": toolCallID, "content": resultText},
				},
			})
			continue
		}

		if role == "user" {
			blocks := handleContent(content, role)
			if len(blocks) == 0 {
				continue
			}
			anthropicMsgs = append(anthropicMsgs, map[string]any{"role": "user", "content": blocks})
		}
	}

	// 只在最后一个 user 消息上打 cache breakpoint：既能缓存整段稳定前缀，
	// 又避免在每个历史消息上重复打点造成过多 cache 写入/超限。
	for i := len(anthropicMsgs) - 1; i >= 0; i-- {
		if anthropicMsgs[i]["role"] == "user" {
			if blocks, ok := anthropicMsgs[i]["content"].([]map[string]any); ok {
				// addAnthropicCacheControl 内部只处理 text 块；若最后一个 user 的最后块不是 text，
				// 它不会标记，也不会继续往前找更早的 user，避免把缓存断点打错位置。
				addAnthropicCacheControl(blocks)
			}
			break
		}
	}

	if len(anthropicMsgs) == 0 {
		return body
	}

	anthropicReq := map[string]any{
		"model":      model,
		"messages":   anthropicMsgs,
		"max_tokens": 4096,
	}
	if len(systemTexts) > 0 {
		// 系统提示作为稳定前缀，也在首个断点前标记缓存，最大化前缀复用。
		anthropicReq["system"] = []map[string]any{{
			"type":          "text",
			"text":          strings.Join(systemTexts, "\n"),
			"cache_control": map[string]any{"type": "ephemeral"},
		}}
	}
	if stream, _ := req["stream"].(bool); stream {
		anthropicReq["stream"] = true
	}
	// 同 openAIToResponsesRequest：按 key 存在性判断，保留显式传入的 0
	if temp, ok := req["temperature"].(float64); ok {
		anthropicReq["temperature"] = temp
	}
	if topP, ok := req["top_p"].(float64); ok {
		anthropicReq["top_p"] = topP
	}
	if mt, _ := req["max_tokens"].(float64); mt > 0 {
		anthropicReq["max_tokens"] = int(mt)
	}
	if tools, ok := req["tools"].([]any); ok && len(tools) > 0 {
		anthropicReq["tools"] = convertOpenAIToolsToAnthropic(tools)
	}
	if tc, ok := req["tool_choice"]; ok {
		switch v := tc.(type) {
		case string:
			// OpenAI: "auto", "none", "required" -> Anthropic: {type: ...}
			switch v {
			case "auto":
				anthropicReq["tool_choice"] = map[string]any{"type": "auto"}
			case "none":
				anthropicReq["tool_choice"] = map[string]any{"type": "none"}
			case "required":
				anthropicReq["tool_choice"] = map[string]any{"type": "any"}
			default:
				anthropicReq["tool_choice"] = tc
			}
		case map[string]any:
			// OpenAI: {"type": "function", "function": {"name": "xxx"}}
			// Anthropic: {"type": "tool", "name": "xxx"}
			if fn, ok := v["function"].(map[string]any); ok {
				if name, ok := fn["name"].(string); ok && name != "" {
					anthropicReq["tool_choice"] = map[string]any{"type": "tool", "name": name}
				} else {
					anthropicReq["tool_choice"] = map[string]any{"type": "auto"}
				}
			} else {
				anthropicReq["tool_choice"] = tc
			}
		default:
			anthropicReq["tool_choice"] = tc
		}
	}
	if t := buildAnthropicThinking(req); t != nil {
		anthropicReq["thinking"] = t
	}

	result, _ := json.Marshal(anthropicReq)
	return result
}

func convertOpenAIImageToAnthropic(part map[string]any) map[string]any {
	imgURL, _ := part["image_url"].(map[string]any)
	if imgURL == nil {
		return part
	}
	url, _ := imgURL["url"].(string)
	if strings.HasPrefix(url, "data:") {
		parts := strings.SplitN(url, ",", 2)
		if len(parts) == 2 {
			mediaType := strings.TrimPrefix(parts[0], "data:")
			if idx := strings.Index(mediaType, ";"); idx >= 0 {
				mediaType = mediaType[:idx]
			}
			return map[string]any{
				"type": "image",
				"source": map[string]any{
					"type":       "base64",
					"media_type": mediaType,
					"data":       parts[1],
				},
			}
		}
	}
	return map[string]any{
		"type": "image",
		"source": map[string]any{
			"type": "url",
			"url":  url,
		},
	}
}

func convertOpenAIToolsToAnthropic(tools []any) []map[string]any {
	var result []map[string]any
	for _, t := range tools {
		tc, _ := t.(map[string]any)
		if tc == nil {
			continue
		}
		fn, _ := tc["function"].(map[string]any)
		if fn == nil {
			continue
		}
		name, _ := fn["name"].(string)
		desc, _ := fn["description"].(string)
		params := fn["parameters"]
		if params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		result = append(result, map[string]any{
			"name": name, "description": desc, "input_schema": params,
		})
	}
	return result
}

// openAIToResponsesRequest 将 OpenAI Chat 请求转为 OpenAI Responses API 格式
// chatContentToResponsesInput 把 Chat 的 content 转为 Responses 的 content。
// 纯文本返回 string（与历史行为一致）；含图片时返回 Responses parts 数组，
// 避免多模态内容在转发到 Responses 上游时被丢弃。
func chatContentToResponsesInput(content any) any {
	parts, ok := content.([]any)
	if !ok {
		if s, ok := content.(string); ok {
			return s
		}
		return extractTextFromContentParts(content)
	}
	var converted []any
	var textParts []string
	hasImage := false
	for _, p := range parts {
		part, ok := p.(map[string]any)
		if !ok {
			continue
		}
		switch part["type"] {
		case "input_text", "output_text", "summary_text", "text":
			if t, ok := part["text"].(string); ok && t != "" {
				textParts = append(textParts, t)
				converted = append(converted, map[string]any{"type": "input_text", "text": t})
			}
		case "image_url", "input_image":
			imageURL := responsesImageURLFromPart(part)
			if imageURL == nil {
				continue
			}
			hasImage = true
			// Responses 协议的 input_image.image_url 是字符串，不是对象
			image := map[string]any{"type": "input_image", "image_url": imageURL["url"]}
			if detail, ok := imageURL["detail"].(string); ok && detail != "" {
				image["detail"] = detail
			}
			converted = append(converted, image)
		}
	}
	if hasImage {
		return converted
	}
	return strings.Join(textParts, "\n")
}

func openAIToResponsesRequest(body []byte, upstream *UpstreamConfig) []byte {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return body
	}
	if err := normalizeRawMessagesToolCallArguments(req["messages"]); err != nil {
		log.Printf("Warning: normalizeRawMessagesToolCallArguments failed: %v", err)
	}

	msgs, _ := req["messages"].([]any)
	var instructions string
	var input []map[string]any

	for _, m := range msgs {
		msg, _ := m.(map[string]any)
		if msg == nil {
			continue
		}
		role, _ := msg["role"].(string)
		content := msg["content"]

		if role == "system" {
			// content 可能是 string，也可能是 multi-part 数组，两种都要拍平进 instructions
			if s := extractTextFromContentParts(content); s != "" {
				if instructions == "" {
					instructions = s
				} else {
					instructions += "\n" + s
				}
			}
			continue
		}

		if role == "assistant" {
			if rc, ok := msg["reasoning_content"].(string); ok && rc != "" {
				input = append(input, map[string]any{
					"type":    "reasoning",
					"summary": []any{map[string]any{"type": "summary_text", "text": rc}},
				})
			}
			text := extractTextFromContentParts(content)
			if text != "" {
				input = append(input, map[string]any{
					"role":    "assistant",
					"content": text,
				})
			}
			// Responses 协议要求 function_call 作为独立 item，不能挂在 assistant 消息上
			if tcs, ok := msg["tool_calls"].([]any); ok && len(tcs) > 0 {
				for _, tc := range tcs {
					tcMap, _ := tc.(map[string]any)
					id, _ := tcMap["id"].(string)
					fn, _ := tcMap["function"].(map[string]any)
					name, _ := fn["name"].(string)
					args, _ := fn["arguments"].(string)
					input = append(input, map[string]any{
						"type":      "function_call",
						"call_id":   id,
						"name":      name,
						"arguments": args,
					})
				}
			}
			continue
		}

		if role == "tool" {
			// Responses 协议使用 function_call_output 而不是 role=tool 消息
			toolCallID, _ := msg["tool_call_id"].(string)
			input = append(input, map[string]any{
				"type":    "function_call_output",
				"call_id": toolCallID,
				"output":  extractTextFromContentParts(content),
			})
			continue
		}

		// user / 其他角色（保留图片等非文本 part）
		input = append(input, map[string]any{
			"role":    role,
			"content": chatContentToResponsesInput(content),
		})
	}

	respReq := map[string]any{
		"model": req["model"],
	}
	if instructions != "" {
		respReq["instructions"] = instructions
	}
	if len(input) > 0 {
		respReq["input"] = input
	}
	if stream, _ := req["stream"].(bool); stream {
		respReq["stream"] = true
	}
	// key 存在即代表调用方显式设置过（convertRequest 只在非 nil 时写入），
	// 因此按 key 存在性判断，不能用零值判断，否则显式的 0 会被丢掉
	if temp, ok := req["temperature"].(float64); ok {
		respReq["temperature"] = temp
	}
	if topP, ok := req["top_p"].(float64); ok {
		respReq["top_p"] = topP
	}
	if mt, _ := req["max_tokens"].(float64); mt > 0 {
		respReq["max_output_tokens"] = int(mt)
	}
	if tools, ok := req["tools"].([]any); ok && len(tools) > 0 {
		respReq["tools"] = convertChatToolsToResponses(tools)
	}
	if tc, ok := req["tool_choice"]; ok {
		respReq["tool_choice"] = convertChatToolChoiceToResponses(tc)
	}
	if ptc, ok := req["parallel_tool_calls"]; ok {
		respReq["parallel_tool_calls"] = ptc
	}
	if re, ok := req["reasoning_effort"].(string); ok && re != "" {
		setResponsesReasoningEffort(respReq, mapConfiguredReasoningEffort(re), upstream)
	} else if effort := reasoningEffortFromThinking(req["thinking"]); effort != "" && effort != "none" {
		setResponsesReasoningEffort(respReq, mapConfiguredReasoningEffort(effort), upstream)
	}

	result, _ := json.Marshal(respReq)
	return result
}

// convertResponsesToChat 将 OpenAI Responses API 响应转为 OpenAI Chat 格式
func convertResponsesToChat(body []byte, modelID string) []byte {
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return body
	}

	totalText := ""
	totalReasoning := ""
	var toolCalls []map[string]any
	if output, ok := resp["output"].([]any); ok {
		for _, item := range output {
			if m, ok := item.(map[string]any); ok {
				switch m["type"] {
				case "reasoning":
					reasoning := ""
					if summary, ok := m["summary"].([]any); ok {
						for _, s := range summary {
							if sm, ok := s.(map[string]any); ok {
								if t, ok := sm["text"].(string); ok {
									reasoning += t
								}
							}
						}
					}
					if reasoning == "" {
						if ec, ok := m["encrypted_content"].(string); ok && ec != "" {
							reasoning = ec
						}
					}
					if reasoning != "" {
						totalReasoning += reasoning
					}
				case "message":
					if content, ok := m["content"].([]any); ok {
						for _, block := range content {
							if b, ok := block.(map[string]any); ok {
								switch b["type"] {
								case "output_text":
									if t, ok := b["text"].(string); ok {
										totalText += t
									}
								}
							}
						}
					}
				case "function_call":
					callID, _ := m["call_id"].(string)
					name, _ := m["name"].(string)
					args, _ := m["arguments"].(string)
					toolCalls = append(toolCalls, map[string]any{
						"id":   callID,
						"type": "function",
						"function": map[string]any{
							"name":      name,
							"arguments": args,
						},
					})
				}
			}
		}
	}

	finishReason := "stop"
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
	}
	if status, _ := resp["status"].(string); status == "incomplete" {
		finishReason = "length"
	}
	message := map[string]any{
		"role":    "assistant",
		"content": totalText,
	}
	if totalReasoning != "" {
		message["reasoning_content"] = totalReasoning
	}
	choice := map[string]any{
		"index":         0,
		"message":       message,
		"finish_reason": finishReason,
	}
	if resp["id"] == nil {
		resp["id"] = "resp_" + randomString(16)
	}
	if len(toolCalls) > 0 {
		choice["message"].(map[string]any)["tool_calls"] = toolCalls
	}

	chatResp := map[string]any{
		"id":      resp["id"],
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   modelID,
		"choices": []map[string]any{choice},
	}
	if usage, ok := resp["usage"]; ok {
		// Responses 用 input_tokens/output_tokens，Chat 客户端读 prompt_tokens/completion_tokens。
		// 归一成 Chat 字段名，同时保留原始字段（含 *_tokens_details 等细节）供下游转换使用。
		if um, ok := usage.(map[string]any); ok {
			merged := responsesUsageToChatUsage(um)
			for k, v := range um {
				if _, exists := merged[k]; !exists {
					merged[k] = v
				}
			}
			chatResp["usage"] = merged
		} else {
			chatResp["usage"] = usage
		}
	}

	result, _ := json.Marshal(chatResp)
	return result
}

// ======================== 消息处理 ========================
// normalizeContent 是 dumb pipe 透传：保留 string 与 []any 两种入参形状
// （其它非常规类型走 json.Marshal 兜底），不解析或过滤任何 multimodal part。
// 能力协商由 opencode 客户端 + 上游负责；这里既不"硬降级"也不"补全"。
func normalizeContent(content any) any {
	if content == nil {
		return nil
	}
	if s, ok := content.(string); ok {
		return s
	}
	if arr, ok := content.([]any); ok {
		return arr
	}
	b, err := json.Marshal(content)
	if err != nil {
		return nil
	}
	return string(b)
}

func fixToolCallGaps(messages []Message) []Message {
	toolResponses := map[string]*Message{}
	for i := range messages {
		if messages[i].Role == "tool" && messages[i].ToolCallID != "" {
			toolResponses[messages[i].ToolCallID] = &messages[i]
		}
	}
	fixed := make([]Message, 0, len(messages)+len(messages)/4)
	emitted := map[string]bool{}
	for _, msg := range messages {
		if msg.Role == "tool" && msg.ToolCallID != "" {
			if emitted[msg.ToolCallID] {
				continue
			}
		}
		fixed = append(fixed, msg)
		if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			for _, tc := range msg.ToolCalls {
				if resp, found := toolResponses[tc.ID]; found {
					fixed = append(fixed, *resp)
				} else {
					fixed = append(fixed, Message{Role: "tool", ToolCallID: tc.ID, Content: "Tool call result not available"})
				}
				emitted[tc.ID] = true
			}
		}
	}
	return fixed
}

func normalizeToolCallArguments(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "{}", nil
	}
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return "", err
	}
	obj, ok := parsed.(map[string]any)
	if !ok {
		return "", fmt.Errorf("must decode to JSON object, got %T", parsed)
	}
	normalized, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(normalized), nil
}

func toolCallArgumentsPreview(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	return truncatePreview(raw, 160)
}

func truncatePreview(raw string, limit int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	runes := []rune(raw)
	if limit > 0 && len(runes) > limit {
		return string(runes[:limit]) + "..."
	}
	return raw
}

func messageContentPreview(content any) string {
	switch v := content.(type) {
	case nil:
		return ""
	case string:
		return truncatePreview(v, 160)
	case []any:
		return truncatePreview(extractTextFromContentParts(v), 160)
	default:
		b, _ := json.Marshal(v)
		return truncatePreview(string(b), 160)
	}
}

func logToolCallArgumentsValidationFailure(source string, messageIndex, toolCallIndex int, toolCallID, toolName, rawArgs string, content any, err error) {
	log.Printf("[tool-call arguments invalid] source=%s message_index=%d tool_call_index=%d tool_call_id=%q tool_name=%q arguments_len=%d arguments_preview=%q content_preview=%q err=%v",
		source,
		messageIndex,
		toolCallIndex,
		toolCallID,
		toolName,
		len(rawArgs),
		toolCallArgumentsPreview(rawArgs),
		messageContentPreview(content),
		err,
	)
}

func logStreamToolCallArgumentsValidationFailure(source, itemID, callID, toolName, rawArgs string, outputIndex int, err error) {
	log.Printf("[tool-call stream invalid] source=%s item_id=%q output_index=%d tool_call_id=%q tool_name=%q arguments_len=%d arguments_preview=%q err=%v",
		source,
		itemID,
		outputIndex,
		callID,
		toolName,
		len(rawArgs),
		toolCallArgumentsPreview(rawArgs),
		err,
	)
}

func normalizeMessagesToolCallArguments(messages []Message) ([]Message, error) {
	for i := range messages {
		if messages[i].Role != "assistant" || len(messages[i].ToolCalls) == 0 {
			continue
		}
		for j := range messages[i].ToolCalls {
			normalized, err := normalizeToolCallArguments(messages[i].ToolCalls[j].Function.Arguments)
			if err != nil {
				logToolCallArgumentsValidationFailure(
					"normalizeMessagesToolCallArguments",
					i,
					j,
					messages[i].ToolCalls[j].ID,
					messages[i].ToolCalls[j].Function.Name,
					messages[i].ToolCalls[j].Function.Arguments,
					messages[i].Content,
					err,
				)
				return nil, fmt.Errorf("messages[%d].tool_calls[%d].function.arguments invalid JSON object string: %w; preview=%q", i, j, err, toolCallArgumentsPreview(messages[i].ToolCalls[j].Function.Arguments))
			}
			messages[i].ToolCalls[j].Function.Arguments = normalized
		}
	}
	return messages, nil
}

func normalizeRawMessagesToolCallArguments(rawMessages any) error {
	msgs, ok := rawMessages.([]any)
	if !ok {
		return nil
	}
	for i, rawMsg := range msgs {
		msg, ok := rawMsg.(map[string]any)
		if !ok || msg == nil {
			continue
		}
		role, _ := msg["role"].(string)
		if role != "assistant" {
			continue
		}
		rawToolCalls, ok := msg["tool_calls"].([]any)
		if !ok {
			continue
		}
		for j, rawToolCall := range rawToolCalls {
			tc, ok := rawToolCall.(map[string]any)
			if !ok || tc == nil {
				continue
			}
			toolCallID, _ := tc["id"].(string)
			fn, ok := tc["function"].(map[string]any)
			if !ok || fn == nil {
				continue
			}
			toolName, _ := fn["name"].(string)
			var rawArgs string
			switch v := fn["arguments"].(type) {
			case string:
				rawArgs = v
			case nil:
				rawArgs = ""
			default:
				b, _ := json.Marshal(v)
				rawArgs = string(b)
			}
			normalized, err := normalizeToolCallArguments(rawArgs)
			if err != nil {
				logToolCallArgumentsValidationFailure(
					"normalizeRawMessagesToolCallArguments",
					i,
					j,
					toolCallID,
					toolName,
					rawArgs,
					msg["content"],
					err,
				)
				return fmt.Errorf("messages[%d].tool_calls[%d].function.arguments invalid JSON object string: %w; preview=%q", i, j, err, toolCallArgumentsPreview(rawArgs))
			}
			fn["arguments"] = normalized
		}
	}
	return nil
}

func ensureReasoningContent(messages []Message, withReasoning bool) []Message {
	// Only inject empty reasoning_content when WithReasoning is enabled (DeepSeek upstream).
	// Other upstreams don't need this and may reject the unknown field.
	if !withReasoning {
		return messages
	}
	for i := range messages {
		if messages[i].Role == "assistant" && messages[i].ReasoningContent == nil {
			empty := ""
			messages[i].ReasoningContent = &empty
		}
	}
	return messages
}

func convertMessagesForUpstream(messages []Message, withReasoning bool) []map[string]any {
	converted := make([]map[string]any, 0, len(messages))
	for _, msg := range messages {
		clean := map[string]any{}
		// 兼容 OpenAI 新版 `developer` 角色：b.ai/DeepSeek 等上游只接受
		// system/user/assistant/tool，遇到 developer 统一降级为 system
		if msg.Role == "developer" {
			msg.Role = "system"
		}
		if msg.Role != "" {
			clean["role"] = msg.Role
		}
		content := normalizeContent(msg.Content)
		reasoningContent := msg.ReasoningContent
		// Strip x-anthropic-billing-header from system messages
		if msg.Role == "system" {
			if s, ok := content.(string); ok {
				content = strings.TrimSpace(reBillingHeader.ReplaceAllString(s, ""))
				if content == "" {
					continue
				}
			} else if s, ok := content.([]any); ok {
				// Handle multi-part content in system messages
				var cleaned []any
				for _, part := range s {
					p, ok := part.(map[string]any)
					if !ok {
						continue
					}
					if txt, ok := p["text"].(string); ok {
						txt = strings.TrimSpace(reBillingHeader.ReplaceAllString(txt, ""))
						if txt != "" {
							p["text"] = txt
							cleaned = append(cleaned, p)
						}
					}
				}
				if len(cleaned) == 0 {
					continue
				}
				content = cleaned
			}
		}
		shouldSendContent := content != nil
		if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			switch v := content.(type) {
			case string:
				shouldSendContent = strings.TrimSpace(v) != ""
			case []any:
				shouldSendContent = len(v) > 0
			}
		}
		if shouldSendContent {
			clean["content"] = content
		}
		if withReasoning && reasoningContent != nil && *reasoningContent != "" {
			clean["reasoning_content"] = *reasoningContent
		}
		if len(msg.ToolCalls) > 0 {
			clean["tool_calls"] = msg.ToolCalls
		}
		if msg.ToolCallID != "" {
			clean["tool_call_id"] = msg.ToolCallID
		}
		if msg.Name != "" {
			clean["name"] = msg.Name
		}
		converted = append(converted, clean)
	}
	return converted
}

// ======================== 完整请求转换（含 thinking/reasoning_effort/ExtraBody） ========================

func convertRequest(req *OpenAIRequest, withReasoning bool) map[string]any {
	converted := map[string]any{
		"model":    req.Model,
		"messages": convertMessagesForUpstream(req.Messages, withReasoning),
		"stream":   req.Stream,
	}
	if req.Temperature != nil {
		converted["temperature"] = *req.Temperature
	}
	if req.MaxTokens != 0 {
		converted["max_tokens"] = req.MaxTokens
	}
	// Inject stream_options.include_usage for streaming requests.
	if req.Stream {
		streamOptions := map[string]any{"include_usage": true}
		if existing, ok := req.StreamOptions.(map[string]any); ok {
			for k, v := range existing {
				streamOptions[k] = v
			}
			streamOptions["include_usage"] = true
		}
		converted["stream_options"] = streamOptions
	}
	if req.TopP != nil {
		converted["top_p"] = *req.TopP
	}
	if len(req.Tools) > 0 {
		converted["tools"] = req.Tools
	}
	if req.ToolChoice != nil {
		converted["tool_choice"] = req.ToolChoice
	}

	// thinking/reasoning_effort describe the current request and are independent
	// from withReasoning, which only controls replaying historical reasoning_content.
	if req.Thinking != nil {
		converted["thinking"] = req.Thinking
	} else if req.ExtraBody != nil {
		if thinking, ok := req.ExtraBody["thinking"]; ok && thinking != nil {
			converted["thinking"] = thinking
		}
	}
	effort := req.ReasoningEffort
	if effort == "" && req.ExtraBody != nil {
		effort, _ = req.ExtraBody["reasoning_effort"].(string)
	}
	if effort != "" {
		effortMap := getReasoningEffortMap()
		if mapped, ok := effortMap[effort]; ok {
			converted["reasoning_effort"] = mapped
		} else {
			converted["reasoning_effort"] = effort
		}
	}

	if req.ExtraBody != nil {
		for k, v := range req.ExtraBody {
			if k == "thinking" || k == "reasoning_effort" {
				continue
			}
			if _, exists := converted[k]; !exists {
				converted[k] = v
			}
		}
	}
	return converted
}
func buildUpstreamBody(req *OpenAIRequest, withReasoning ...bool) []byte {
	wr := len(withReasoning) > 0 && withReasoning[0]
	converted := convertRequest(req, wr)
	b, err := json.Marshal(converted)
	if err != nil {
		log.Printf("Error marshaling upstream body: %v", err)
	}
	return b
}

// ======================== Anthropic 格式兼容 ========================

func isAnthropicFormat(body []byte) bool {
	var obj map[string]any
	if json.Unmarshal(body, &obj) == nil {
		if typ, _ := obj["type"].(string); typ == "message" {
			return true
		}
	}
	lines := bytes.Split(body, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}
		typ, _ := event["type"].(string)
		switch typ {
		case "message_start", "content_block_start", "content_block_delta",
			"content_block_stop", "message_delta", "message_stop", "ping":
			return true
		}
		return false
	}
	return false
}

func parseAnthropicSSE(body []byte) (map[string]any, string, string, []map[string]any) {
	lines := bytes.Split(body, []byte("\n"))
	var anthropicMsg map[string]any
	var textBuilder, thinkingBuilder, currentToolInputBuilder strings.Builder
	var currentToolUse map[string]any
	var toolUseBlocks []map[string]any
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}
		typ, _ := event["type"].(string)
		switch typ {
		case "message_start":
			if m, ok := event["message"].(map[string]any); ok {
				anthropicMsg = m
			}
		case "content_block_start":
			if cb, ok := event["content_block"].(map[string]any); ok {
				if cbType, _ := cb["type"].(string); cbType == "tool_use" {
					currentToolUse = cb
					currentToolInputBuilder.Reset()
				}
			}
		case "content_block_delta":
			if delta, ok := event["delta"].(map[string]any); ok {
				if t, ok := delta["text"].(string); ok {
					textBuilder.WriteString(t)
				}
				if dt, _ := delta["type"].(string); dt == "thinking_delta" {
					if th, ok := delta["thinking"].(string); ok {
						thinkingBuilder.WriteString(th)
					}
				}
				if dt, _ := delta["type"].(string); dt == "input_json_delta" {
					if partial, ok := delta["partial_json"].(string); ok {
						currentToolInputBuilder.WriteString(partial)
					}
				}
			}
		case "content_block_stop":
			if currentToolUse != nil {
				inputStr := currentToolInputBuilder.String()
				var input any = inputStr
				var parsed any
				if json.Unmarshal([]byte(inputStr), &parsed) == nil {
					input = parsed
				}
				currentToolUse["input"] = input
				toolUseBlocks = append(toolUseBlocks, currentToolUse)
				currentToolUse = nil
			}
		case "message_delta":
			if delta, ok := event["delta"].(map[string]any); ok {
				if anthropicMsg == nil {
					anthropicMsg = map[string]any{}
				}
				if stop, ok := delta["stop_reason"].(string); ok {
					anthropicMsg["stop_reason"] = stop
				}
				if usage, ok := delta["usage"].(map[string]any); ok {
					anthropicMsg["usage"] = usage
				}
			}
		case "message_stop":
		case "error":
			return nil, "", "", nil
		}
	}
	return anthropicMsg, textBuilder.String(), thinkingBuilder.String(), toolUseBlocks
}

func buildOpenAIResponse(anthropicMsg map[string]any, text string, reasoning string, toolUseBlocks []map[string]any, modelID string) []byte {
	if anthropicMsg == nil {
		return nil
	}
	now := time.Now().Unix()
	role, _ := anthropicMsg["role"].(string)
	if role == "" {
		role = "assistant"
	}
	finishReason, _ := anthropicMsg["stop_reason"].(string)
	if finishReason == "tool_use" {
		finishReason = "tool_calls"
	} else if finishReason == "end_turn" {
		finishReason = "stop"
	} else if finishReason == "max_tokens" {
		finishReason = "length"
	}
	message := map[string]any{"role": role, "content": text}
	if reasoning != "" {
		message["reasoning_content"] = reasoning
	}
	choice := map[string]any{
		"index":         0,
		"message":       message,
		"finish_reason": finishReason,
	}
	if len(toolUseBlocks) > 0 {
		var toolCalls []map[string]any
		for _, tb := range toolUseBlocks {
			toolInput := tb["input"]
			argsJSON, _ := json.Marshal(toolInput)
			toolCalls = append(toolCalls, map[string]any{
				"id":   tb["id"],
				"type": "function",
				"function": map[string]any{
					"name":      tb["name"],
					"arguments": string(argsJSON),
				},
			})
		}
		choice["message"].(map[string]any)["tool_calls"] = toolCalls
		if text == "" {
			choice["message"].(map[string]any)["content"] = nil
		}
	}
	resp := map[string]any{
		"id":      anthropicMsg["id"],
		"object":  "chat.completion",
		"created": now,
		"model":   modelID,
		"choices": []map[string]any{choice},
	}
	if usage, ok := anthropicMsg["usage"].(map[string]any); ok {
		openAIUsage := map[string]any{}
		if v, ok := usage["input_tokens"]; ok {
			openAIUsage["prompt_tokens"] = v
		}
		if v, ok := usage["output_tokens"]; ok {
			openAIUsage["completion_tokens"] = v
		}
		if pt, ok1 := openAIUsage["prompt_tokens"]; ok1 {
			if ct, ok2 := openAIUsage["completion_tokens"]; ok2 {
				ptF, _ := pt.(float64)
				ctF, _ := ct.(float64)
				openAIUsage["total_tokens"] = int64(ptF + ctF)
			}
		}
		resp["usage"] = openAIUsage
	}
	result, _ := json.Marshal(resp)
	return result
}

func convertAnthropicMessageToOpenAI(msg map[string]any, modelID string) []byte {
	if msg["model"] == nil {
		msg["model"] = modelID
	}
	var textBuilder strings.Builder
	var thinkingBuilder strings.Builder
	var toolUses []map[string]any
	if content, ok := msg["content"].([]any); ok {
		for _, c := range content {
			if block, ok := c.(map[string]any); ok {
				switch block["type"] {
				case "text":
					if t, ok := block["text"].(string); ok {
						textBuilder.WriteString(t)
					}
				case "thinking":
					if t, ok := block["thinking"].(string); ok {
						thinkingBuilder.WriteString(t)
					}
				case "tool_use":
					toolUses = append(toolUses, block)
				}
			}
		}
	}
	return buildOpenAIResponse(msg, textBuilder.String(), thinkingBuilder.String(), toolUses, modelID)
}

func convertAnthropicToOpenAI(body []byte, modelID string) []byte {
	var singleMsg map[string]any
	if json.Unmarshal(body, &singleMsg) == nil {
		if typ, _ := singleMsg["type"].(string); typ == "message" {
			return convertAnthropicMessageToOpenAI(singleMsg, modelID)
		}
	}
	msg, text, reasoning, toolUses := parseAnthropicSSE(body)
	if msg == nil {
		return body
	}
	if msg["model"] == nil {
		msg["model"] = modelID
	}
	return buildOpenAIResponse(msg, text, reasoning, toolUses, modelID)
}

// ======================== 响应清理 ========================

func cleanNulls(m map[string]any) {
	for k, v := range m {
		if v == nil {
			delete(m, k)
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			delete(m, k)
		}
	}
}

func hasNonEmptyString(value any) bool {
	s, ok := value.(string)
	return ok && s != ""
}

func normalizeReasoningContent(m map[string]any) {
	if m == nil || hasNonEmptyString(m["reasoning_content"]) {
		return
	}
	if v, ok := m["reasoning"]; ok {
		m["reasoning_content"] = v
	}
}

func cleanStreamDelta(delta map[string]any) {
	normalizeReasoningContent(delta)
	if v, ok := delta["content"]; ok && v == nil {
		delete(delta, "content")
	}
	if s, ok := delta["content"].(string); ok && s == "" {
		delete(delta, "content")
	}
	if v, ok := delta["reasoning_content"]; ok && v == nil {
		delete(delta, "reasoning_content")
	}
	if s, ok := delta["reasoning_content"].(string); ok && s == "" {
		delete(delta, "reasoning_content")
	}
	// 删除与 reasoning_content 重复的 reasoning 字段
	if rc, ok := delta["reasoning_content"].(string); ok && rc != "" {
		delete(delta, "reasoning")
	}
	if v, ok := delta["reasoning"]; ok && v == nil {
		delete(delta, "reasoning")
	}
	if s, ok := delta["reasoning"].(string); ok && s == "" {
		delete(delta, "reasoning")
	}
	if s, ok := delta["role"].(string); ok && s == "" {
		delete(delta, "role")
	}
}

// convertStreamChunkWithUsage 转换流式 chunk 并同时提取 usage，避免二次解析
func convertStreamChunkWithUsage(line string) (string, map[string]any) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
		return line, nil
	}
	if !strings.HasPrefix(line, "data: ") {
		return line, nil
	}
	data := line[6:]

	// 极速快道 Fast-Path：如果当前 chunk 不含 usage 且不含需要特殊清洗的扩展字段，直接微秒级原样透传
	if !strings.Contains(data, `"usage"`) &&
		!strings.Contains(data, `"cost"`) &&
		!strings.Contains(data, `"service_tier"`) &&
		!strings.Contains(data, `"prompt_logprobs"`) &&
		!strings.Contains(data, `"kv_transfer_params"`) &&
		!strings.Contains(data, `"stop_reason"`) &&
		!strings.Contains(data, `"token_ids"`) &&
		strings.Contains(data, `"choices"`) {
		return line, nil
	}

	var raw map[string]any
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return line, nil
	}

	// 提取 usage
	var usage map[string]any
	if u, ok := raw["usage"].(map[string]any); ok {
		usage = u
	}

	choices, ok := raw["choices"].([]any)
	if !ok || len(choices) == 0 {
		// choices 为空但有 usage 时，仍需转发给客户端
		if usage != nil {
			raw["choices"] = []any{}
			delete(raw, "cost")
			delete(raw, "service_tier")
			delete(raw, "prompt_logprobs")
			delete(raw, "prompt_token_ids")
			delete(raw, "kv_transfer_params")
			if v, ok := raw["usage"]; ok && v == nil {
				delete(raw, "usage")
			}
			converted, err := json.Marshal(raw)
			if err != nil {
				return "", usage
			}
			return "data: " + string(converted), usage
		}
		return "", usage
	}
	for i, c := range choices {
		choice, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if delta, ok := choice["delta"].(map[string]any); ok {
			cleanStreamDelta(delta)
			choice["delta"] = delta
		}
		if msg, ok := choice["message"].(map[string]any); ok {
			normalizeReasoningContent(msg)
			cleanNulls(msg)
			choice["message"] = msg
		}
		if v, ok := choice["logprobs"]; ok && v == nil {
			delete(choice, "logprobs")
		}
		if v, ok := choice["finish_reason"]; ok && v == nil {
			delete(choice, "finish_reason")
		}
		if s, ok := choice["finish_reason"].(string); ok && s == "" {
			delete(choice, "finish_reason")
		}
		// 清理上游扩展字段
		delete(choice, "stop_reason")
		delete(choice, "token_ids")
		choices[i] = choice
	}
	raw["choices"] = choices
	if v, ok := raw["usage"]; ok && v == nil {
		delete(raw, "usage")
	}
	delete(raw, "cost")
	delete(raw, "service_tier")
	delete(raw, "prompt_logprobs")
	delete(raw, "prompt_token_ids")
	delete(raw, "kv_transfer_params")
	converted, err := json.Marshal(raw)
	if err != nil {
		return line, usage
	}
	return "data: " + string(converted), usage
}

func convertResponse(data []byte) ([]byte, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Printf("Warning: convertResponse unmarshal failed: %v", err)
		return data, nil
	}
	if choices, ok := raw["choices"].([]any); ok {
		for i, c := range choices {
			if choice, ok := c.(map[string]any); ok {
				if msg, ok := choice["message"].(map[string]any); ok {
					normalizeReasoningContent(msg)
					// 删除与 reasoning_content 重复的 reasoning 字段
					if rc, ok := msg["reasoning_content"].(string); ok && rc != "" {
						delete(msg, "reasoning")
					}
					cleanNulls(msg)
					choice["message"] = msg
				}
				if v, ok := choice["logprobs"]; ok && v == nil {
					delete(choice, "logprobs")
				}
				// 清理上游扩展字段
				delete(choice, "stop_reason")
				delete(choice, "token_ids")
				choices[i] = choice
			}
		}
		raw["choices"] = choices
	}
	if usage, ok := raw["usage"].(map[string]any); ok {
		cleanU := map[string]any{}
		if v, ok := usage["prompt_tokens"]; ok && v != nil {
			cleanU["prompt_tokens"] = v
		}
		if v, ok := usage["completion_tokens"]; ok && v != nil {
			cleanU["completion_tokens"] = v
		}
		if v, ok := usage["total_tokens"]; ok && v != nil {
			cleanU["total_tokens"] = v
		}
		if len(cleanU) > 0 {
			raw["usage"] = cleanU
		} else {
			delete(raw, "usage")
		}
	}
	// 清理上游顶层扩展字段
	delete(raw, "cost")
	delete(raw, "service_tier")
	delete(raw, "prompt_logprobs")
	delete(raw, "prompt_token_ids")
	delete(raw, "kv_transfer_params")
	return json.Marshal(raw)
}

// ======================== 上游端点 ========================

func getUpstreamEndpoint(upstream *UpstreamConfig) string {
	if upstream == nil || upstream.BaseURL == "" {
		return ""
	}
	base := strings.TrimRight(upstream.BaseURL, "/")
	switch upstream.APIType {
	case UpstreamOpenAI:
		return base + "/chat/completions"
	case UpstreamAnthropic:
		return base + "/messages"
	case UpstreamResponses:
		return base + "/responses"
	default:
		return base + "/chat/completions"
	}
}

// applyCustomHeaders 将上游配置的自定义请求头写入请求。需在网关默认头之后调用，
// 同名头会覆盖默认值（例如自定义 Authorization、anthropic-version）。
// Host / Content-Length 由传输层管理，忽略。
func applyCustomHeaders(req *http.Request, upstream *UpstreamConfig) {
	if upstream == nil || len(upstream.CustomHeaders) == 0 {
		return
	}
	keys := make([]string, 0, len(upstream.CustomHeaders))
	for k := range upstream.CustomHeaders {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := strings.TrimSpace(upstream.CustomHeaders[k])
		if v == "" || strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		req.Header.Set(k, v)
	}
}

func buildUpstreamRequest(endpoint, apiKey string, body []byte, upstream *UpstreamConfig) (*http.Request, error) {
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		if upstream != nil && upstream.APIType == UpstreamAnthropic {
			req.Header.Set("x-api-key", apiKey)
			req.Header.Set("anthropic-version", "2023-06-01")
			req.Header.Set("anthropic-beta", "prompt-caching-2025-01-31")
		} else {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}
	req.Header.Set("Accept", "application/json")
	applyCustomHeaders(req, upstream)
	return req, nil
}

// extractTopLevelModelString 读取 JSON 对象顶层 "model" 字符串值；找不到返回空串。
func extractTopLevelModelString(data []byte) string {
	dec := json.NewDecoder(bytes.NewReader(data))
	if _, err := dec.Token(); err != nil { // consume '{'
		return ""
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		if d, ok := tok.(json.Delim); ok && d == '}' {
			return ""
		}
		key, ok := tok.(string)
		if !ok {
			return ""
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return ""
		}
		if key == "model" {
			var model string
			if json.Unmarshal(raw, &model) == nil {
				return model
			}
			return ""
		}
	}
}

// extractTopLevelBool 读取 JSON 对象顶层布尔值；找不到返回 false。
func extractTopLevelBool(data []byte, keyName string) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	if _, err := dec.Token(); err != nil {
		return false
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		if d, ok := tok.(json.Delim); ok && d == '}' {
			return false
		}
		key, ok := tok.(string)
		if !ok {
			return false
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return false
		}
		if key == keyName {
			var v bool
			if json.Unmarshal(raw, &v) == nil {
				return v
			}
			return false
		}
	}
}

// injectRawStreamOptionsIncludeUsage 在原始 OpenAI Chat JSON 顶层插入/补齐
// stream_options.include_usage=true。仅在流式透传且客户端未要求 usage 时用于记账。
func injectRawStreamOptionsIncludeUsage(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if d, ok := tok.(json.Delim); ok && d == '}' {
			// 没找到 stream_options：在对象结尾前插入
			insert := []byte(`,"stream_options":{"include_usage":true}`)
			out := make([]byte, 0, len(data)+len(insert))
			out = append(out, data[:len(data)-1]...)
			out = append(out, insert...)
			out = append(out, '}')
			return out, nil
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected token %T", tok)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		if key == "stream_options" {
			// 已存在：确保 include_usage=true，其余保留（这里做一次轻量解析仅针对该字段）
			var so map[string]any
			if json.Unmarshal(raw, &so) != nil {
				return data, nil
			}
			if v, ok := so["include_usage"].(bool); ok && v {
				return data, nil
			}
			so["include_usage"] = true
			newRaw, _ := json.Marshal(so)
			// 替换该值，其他字节不动
			after := int(dec.InputOffset())
			valueStart := after - len(raw)
			out := make([]byte, 0, len(data)+len(newRaw)-len(raw))
			out = append(out, data[:valueStart]...)
			out = append(out, newRaw...)
			out = append(out, data[after:]...)
			return out, nil
		}
	}
}

// replaceTopLevelModelString 只替换 JSON 对象顶层 "model" 字段的值，其余字节原样保留。
// 相比「Unmarshal 整个请求 → 改 model → Marshal」，它不会重排字段、不会改变浮点/字符串格式，
// 也不会把未识别字段丢失；对同协议 OpenAI Chat 透传是真正的零拷贝级透传。
func replaceTopLevelModelString(data []byte, newModel string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if _, err := dec.Token(); err != nil { // consume '{'
		return nil, err
	}
	for {
		start := int(dec.InputOffset())
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("unexpected end of JSON: %w", err)
		}
		end := int(dec.InputOffset())
		if d, ok := tok.(json.Delim); ok && d == '}' {
			// no top-level model present: let caller fall back to full conversion
			return nil, fmt.Errorf("top-level model not found")
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected token %T at top-level", tok)
		}
		_ = start
		_ = end
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		after := int(dec.InputOffset())
		if key == "model" {
			valueStart := after - len(raw)
			newVal, err := json.Marshal(newModel)
			if err != nil {
				return nil, err
			}
			out := make([]byte, 0, len(data)+len(newVal)-(after-valueStart))
			out = append(out, data[:valueStart]...)
			out = append(out, newVal...)
			out = append(out, data[after:]...)
			return out, nil
		}
	}
}

func prepareOpenAIUpstreamBody(reqBody []byte, modelID string, upstream *UpstreamConfig) ([]byte, error) {
	// 同协议 OpenAI Chat 上游：只替换顶层 model 字段，其余字节原样透传。
	// 这既节省 CPU，也尽量保持上游 prompt/prefix cache 所依赖的原始请求字节不变。
	if upstream == nil || upstream.APIType == UpstreamOpenAI {
		if out, err := replaceTopLevelModelString(reqBody, modelID); err == nil {
			return out, nil
		}
		// 若顶层 model 定位失败，退回原有全量转换，保证可用性。
	}

	var bodyMap map[string]any
	if err := json.Unmarshal(reqBody, &bodyMap); err != nil {
		return nil, fmt.Errorf("invalid request body")
	}
	bodyMap["model"] = modelID
	marshaled, _ := json.Marshal(bodyMap)
	tryBody := marshaled
	if upstream != nil {
		switch upstream.APIType {
		case UpstreamAnthropic:
			tryBody = openAIToAnthropicRequest(marshaled)
		case UpstreamResponses:
			tryBody = openAIToResponsesRequest(marshaled, upstream)
		}
	}
	return tryBody, nil
}

func callPreparedUpstream(ctx context.Context, preparedBody []byte, upstreamName, modelID, clientAPI string, upstream *UpstreamConfig, proxyAddr string, rawResponse ...bool) ([]byte, int, http.Header, error) {
	if upstream == nil || upstream.BaseURL == "" {
		return nil, 500, nil, fmt.Errorf("upstream not configured")
	}

	apiKey, apiKeyIndex, apiKeys := selectUpstreamAPIKey(upstreamName, upstream, modelID)
	retryDelay := 1 * time.Second
	fastRetries := 0 // 传输级错误的 0ms 快速重试计数（仅前 2 次，之后回落 1s 退避）
	proxyLabel := modelProxyLabel(proxyAddr)
	for {
		select {
		case <-ctx.Done():
			log.Printf("[client disconnect] api=%s upstream=%s model=%s key=%s proxy=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), proxyLabel)
			dRec := usageRecorderFromContext(ctx)
			dRec.SetStatus(499)
			dRec.SetError("client disconnected")
			return nil, 0, nil, ctx.Err()
		default:
		}
		up, err := buildUpstreamRequest(getUpstreamEndpoint(upstream), apiKey, preparedBody, upstream)
		if err != nil {
			if err := waitForRetry(ctx, retryDelay); err != nil {
				return nil, 0, nil, err
			}
			// Refresh upstream config on build error too
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return nil, 500, nil, fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream, modelID)
			retryDelay = 1 * time.Second
			continue
		}
		var c *http.Client
		c, proxyLabel = getModelHTTPClient(proxyAddr, false)
		log.Printf("[upstream request] api=%s upstream=%s model=%s key=%s proxy=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), proxyLabel)
		startTTFB := time.Now()
		resp, err := c.Do(up)
		if err != nil {
			// 传输级错误：前两次 0ms 立即重试（等 1 秒对连接错误毫无意义）
			fastRetries++
			if fastRetries > maxTransportRetries {
				// 上游持续不可达：明确放弃并返回 502，避免无限重试占满连接与日志
				log.Printf("[upstream retry exhausted] api=%s upstream=%s model=%s proxy=%s attempts=%d err=%v", clientAPI, effectiveUpstreamName(upstreamName), modelID, proxyLabel, fastRetries, err)
				stopRec := usageRecorderFromContext(ctx)
				stopRec.SetStatus(http.StatusBadGateway)
				stopRec.SetError("upstream unreachable")
				return nil, http.StatusBadGateway, nil, fmt.Errorf("upstream unreachable after %d attempts: %w", fastRetries, err)
			}
			if fastRetries <= 2 {
				log.Printf("[upstream fast-retry] api=%s upstream=%s model=%s proxy=%s err=%v (第%d次,0ms 立即重试)", clientAPI, effectiveUpstreamName(upstreamName), modelID, proxyLabel, err, fastRetries)
			} else if err := waitForRetry(ctx, retryDelay); err != nil {
				return nil, 0, nil, err
			}
			// Refresh upstream config on connection error too
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return nil, 500, nil, fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream, modelID)
			retryDelay = 1 * time.Second
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			markAPIKeySuccess(apiKey)
			setModelKeyAffinity(upstreamName, modelID, apiKey)
			ttfb := time.Since(startTTFB)
			log.Printf("[ttfb] api=%s upstream=%s model=%s key=%s proxy=%s ttfb=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), proxyLabel, ttfb.Round(time.Millisecond))
			rec := usageRecorderFromContext(ctx)
			rec.SetUpstream(upstreamName)
			rec.SetStatus(resp.StatusCode)
			rec.MarkFirstToken()
			b, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				return nil, 0, nil, readErr
			}
			if len(rawResponse) > 0 && rawResponse[0] {
				// rawResponse: skip conversion, return as-is
			} else if upstream != nil && upstream.APIType == UpstreamResponses {
				b = convertResponsesToChat(b, modelID)
			} else if isAnthropicFormat(b) {
				b = convertAnthropicToOpenAI(b, modelID)
			}
			return b, resp.StatusCode, resp.Header, nil
		}
		errBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		markAPIKeyFailure(apiKey, resp.StatusCode, string(errBody))
		errRec := usageRecorderFromContext(ctx)
		errRec.SetUpstream(upstreamName)
		errRec.SetStatus(resp.StatusCode)
		if shouldRetryUpstreamStatus(resp.StatusCode) {
			log.Printf("[upstream retry] api=%s upstream=%s model=%s key=%s proxy=%s status=%d retry_after=%q body=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), proxyLabel, resp.StatusCode, resp.Header.Get("Retry-After"), string(errBody))
			manyKeys := len(apiKeys) > 1
			if manyKeys {
				// 多 key：429/5xx 时立即切到下一把 key 轮询，不退避、不等待
				apiKey, apiKeyIndex = rotateUpstreamAPIKey(apiKeys, apiKeyIndex, upstreamName, modelID)
			} else {
				// 单 key：按指数退避，下一轮用更长的退避等待
				if err := waitForRetry(ctx, retryDelay); err != nil {
					return nil, 0, nil, err
				}
			}
			// Refresh upstream config: user may have re-mapped or deleted this upstream
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return errBody, resp.StatusCode, resp.Header.Clone(), fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			if manyKeys {
				// 多 key：沿用 rotate 选定的 key，不重新按游标选（保留 429 切 key 的意图）
				apiKeys = getUpstreamAPIKeys(upstream)
			} else {
				// 单 key：按指数退避，下一轮用更长的退避等待
				apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream, modelID)
				retryDelay = nextRetryDelay(retryDelay)
			}
			if manyKeys {
				retryDelay = 1 * time.Second
			}
			continue
		}
		// Non-retryable error: return immediately
		errBody = mapUpstreamErrorBody(errBody, upstream.APIType)
		return errBody, resp.StatusCode, resp.Header.Clone(), fmt.Errorf("upstream error: %s", string(errBody))
	}
}

func callUpstream(ctx context.Context, reqBody []byte, upstreamName, modelID, clientAPI string, upstream *UpstreamConfig, proxyAddr string, rawResponse ...bool) ([]byte, int, http.Header, error) {
	tryBody, err := prepareOpenAIUpstreamBody(reqBody, modelID, upstream)
	if err != nil {
		return nil, 500, nil, err
	}
	return callPreparedUpstream(ctx, tryBody, upstreamName, modelID, clientAPI, upstream, proxyAddr, rawResponse...)
}

func callPreparedUpstreamStream(ctx context.Context, preparedBody []byte, upstreamName, modelID, clientAPI string, upstream *UpstreamConfig, proxyAddr string) (io.ReadCloser, int, http.Header, error) {
	if upstream == nil || upstream.BaseURL == "" {
		return nil, 500, nil, fmt.Errorf("upstream not configured")
	}

	apiKey, apiKeyIndex, apiKeys := selectUpstreamAPIKey(upstreamName, upstream, modelID)
	retryDelay := 1 * time.Second
	fastRetries := 0 // 传输级错误的 0ms 快速重试计数（仅前 2 次，之后回落 1s 退避）
	proxyLabel := modelProxyLabel(proxyAddr)
	for {
		select {
		case <-ctx.Done():
			log.Printf("[client disconnect] api=%s upstream=%s model=%s key=%s proxy=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), proxyLabel)
			dRec := usageRecorderFromContext(ctx)
			dRec.SetStatus(499)
			dRec.SetError("client disconnected")
			return nil, 0, nil, ctx.Err()
		default:
		}
		up, err := buildUpstreamRequest(getUpstreamEndpoint(upstream), apiKey, preparedBody, upstream)
		if err != nil {
			if err := waitForRetry(ctx, retryDelay); err != nil {
				return nil, 0, nil, err
			}
			// Refresh upstream config on build error too
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return nil, 500, nil, fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream, modelID)
			retryDelay = 1 * time.Second
			continue
		}
		var c *http.Client
		c, proxyLabel = getModelHTTPClient(proxyAddr, true)
		log.Printf("[upstream request] api=%s upstream=%s model=%s key=%s proxy=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), proxyLabel)
		startTTFB := time.Now()
		// httptrace 建连阶段观测：命中温热池时 tcp/tls 回调不触发，[ttfb] 日志显示 conn=reused
		ct := &connPhase{}
		trace := &httptrace.ClientTrace{
			DNSStart:          func(httptrace.DNSStartInfo) { ct.dnsStart = time.Now() },
			DNSDone:           func(httptrace.DNSDoneInfo) { ct.dnsDone = time.Now() },
			ConnectStart:      func(network, addr string) { ct.connectStart = time.Now() },
			ConnectDone:       func(network, addr string, err error) { ct.connectDone = time.Now() },
			TLSHandshakeStart: func() { ct.tlsStart = time.Now() },
			TLSHandshakeDone:  func(state tls.ConnectionState, err error) { ct.tlsDone = time.Now() },
		}
		up = up.WithContext(httptrace.WithClientTrace(up.Context(), trace))
		resp, err := c.Do(up)
		if err != nil {
			// 传输级错误（拨号失败/连接被重置/代理抖动等）：等 1 秒毫无意义，前两次 0ms 立即重试
			fastRetries++
			if fastRetries > maxTransportRetries {
				// 上游持续不可达：明确放弃并返回 502，避免无限重试占满连接与日志
				log.Printf("[upstream retry exhausted] api=%s upstream=%s model=%s proxy=%s attempts=%d err=%v", clientAPI, effectiveUpstreamName(upstreamName), modelID, proxyLabel, fastRetries, err)
				stopRec := usageRecorderFromContext(ctx)
				stopRec.SetStatus(http.StatusBadGateway)
				stopRec.SetError("upstream unreachable")
				return nil, http.StatusBadGateway, nil, fmt.Errorf("upstream unreachable after %d attempts: %w", fastRetries, err)
			}
			if fastRetries <= 2 {
				log.Printf("[upstream fast-retry] api=%s upstream=%s model=%s proxy=%s err=%v (第%d次,0ms 立即重试)", clientAPI, effectiveUpstreamName(upstreamName), modelID, proxyLabel, err, fastRetries)
			} else if err := waitForRetry(ctx, retryDelay); err != nil {
				return nil, 0, nil, err
			}
			// Refresh upstream config on connection error too
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return nil, 500, nil, fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream, modelID)
			retryDelay = 1 * time.Second
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			markAPIKeySuccess(apiKey)
			setModelKeyAffinity(upstreamName, modelID, apiKey)
			proto := "http/1.1"
			if resp.TLS != nil && resp.TLS.NegotiatedProtocol != "" {
				proto = resp.TLS.NegotiatedProtocol
			}
			wrappedBody := &ttfbReadCloser{
				inner:      resp.Body,
				start:      startTTFB,
				upstream:   effectiveUpstreamName(upstreamName),
				model:      modelID,
				clientAPI:  clientAPI,
				keySlot:    formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)),
				proxyLabel: proxyLabel,
				rec:        usageRecorderFromContext(ctx),
				ct:         ct,
				proto:      proto,
			}
			rec := usageRecorderFromContext(ctx)
			rec.SetUpstream(upstreamName)
			rec.SetStatus(resp.StatusCode)
			return wrappedBody, resp.StatusCode, resp.Header, nil
		}
		errBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		markAPIKeyFailure(apiKey, resp.StatusCode, string(errBody))
		errRec := usageRecorderFromContext(ctx)
		errRec.SetUpstream(upstreamName)
		errRec.SetStatus(resp.StatusCode)
		if shouldRetryUpstreamStatus(resp.StatusCode) {
			log.Printf("[upstream retry] api=%s upstream=%s model=%s key=%s proxy=%s status=%d retry_after=%q body=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), proxyLabel, resp.StatusCode, resp.Header.Get("Retry-After"), string(errBody))
			manyKeys := len(apiKeys) > 1
			if manyKeys {
				// 多 key：429/5xx 时立即切到下一把 key 轮询，不退避、不等待
				apiKey, apiKeyIndex = rotateUpstreamAPIKey(apiKeys, apiKeyIndex, upstreamName, modelID)
			} else {
				// 单 key：按指数退避，下一轮用更长的退避等待
				if err := waitForRetry(ctx, retryDelay); err != nil {
					return nil, 0, nil, err
				}
			}
			// Refresh upstream config: user may have re-mapped or deleted this upstream
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return io.NopCloser(bytes.NewReader(errBody)), resp.StatusCode, resp.Header.Clone(), fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			if manyKeys {
				// 多 key：沿用 rotate 选定的 key，不重新按游标选（保留 429 切 key 的意图）
				apiKeys = getUpstreamAPIKeys(upstream)
			} else {
				// 单 key：按指数退避，下一轮用更长的退避等待
				apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream, modelID)
				retryDelay = nextRetryDelay(retryDelay)
			}
			if manyKeys {
				retryDelay = 1 * time.Second
			}
			continue
		}
		// Non-retryable error: return immediately
		errBody = mapUpstreamErrorBody(errBody, upstream.APIType)
		return io.NopCloser(bytes.NewReader(errBody)), resp.StatusCode, resp.Header.Clone(), fmt.Errorf("upstream error")
	}
}

func callUpstreamStream(ctx context.Context, reqBody []byte, upstreamName, modelID, clientAPI string, upstream *UpstreamConfig, proxyAddr string) (io.ReadCloser, int, http.Header, error) {
	tryBody, err := prepareOpenAIUpstreamBody(reqBody, modelID, upstream)
	if err != nil {
		return nil, 500, nil, err
	}
	return callPreparedUpstreamStream(ctx, tryBody, upstreamName, modelID, clientAPI, upstream, proxyAddr)
}

func stripBillingHeaderText(s string) string {
	return strings.TrimSpace(reBillingHeader.ReplaceAllString(s, ""))
}

func stripBillingHeaderFromResponsesItems(items any) {
	arr, ok := items.([]any)
	if !ok {
		return
	}
	for _, item := range arr {
		msg, ok := item.(map[string]any)
		if !ok {
			continue
		}
		role, _ := msg["role"].(string)
		if role != "system" && role != "developer" {
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			msg["content"] = stripBillingHeaderText(content)
		case []any:
			for _, part := range content {
				pm, ok := part.(map[string]any)
				if !ok {
					continue
				}
				if text, ok := pm["text"].(string); ok {
					pm["text"] = stripBillingHeaderText(text)
				}
			}
		}
	}
}

func ensureResponsesIncludeUsage(req map[string]any) {
	stream, _ := req["stream"].(bool)
	if !stream {
		return
	}
	if so, ok := req["stream_options"].(map[string]any); ok {
		so["include_usage"] = true
		req["stream_options"] = so
		return
	}
	req["stream_options"] = map[string]any{"include_usage": true}
}

// addAnthropicCacheControlToRaw 在已格式化/反序列化的 Anthropic 请求体上，
// 给每个 user 消息的最后一个 content block 添加 ephemeral cache_control。
// 仅用于 Anthropic 同协议透传，尽量不影响其他字段。
func addAnthropicCacheControlToRaw(msgs []any) {
	// 只处理最后一个 user 消息，避免在全部历史消息上重复创建缓存断点。
	// 如果最后一个 user 的最后一个块不是 text，则不强行打点（避免把断点标到更早消息上）。
	for i := len(msgs) - 1; i >= 0; i-- {
		m := msgs[i]
		msg, _ := m.(map[string]any)
		if msg == nil {
			continue
		}
		role, _ := msg["role"].(string)
		if role != "user" {
			continue
		}
		content, ok := msg["content"].([]any)
		if !ok || len(content) == 0 {
			return
		}
		last, ok := content[len(content)-1].(map[string]any)
		if !ok || last == nil || last["type"] != "text" {
			return
		}
		if existing, ok := last["cache_control"].(map[string]any); ok {
			existing["type"] = "ephemeral"
			last["cache_control"] = existing
			return
		}
		last["cache_control"] = map[string]any{"type": "ephemeral"}
		return
	}
}

// addAnthropicSystemCacheControl 给 Anthropic 请求的 system（字符串或 block 数组）
// 最后一个 text block 加 ephemeral cache_control。
func addAnthropicSystemCacheControl(req map[string]any) {
	sys, ok := req["system"]
	if !ok || sys == nil {
		return
	}
	switch v := sys.(type) {
	case string:
		if v == "" {
			return
		}
		req["system"] = []map[string]any{{
			"type":          "text",
			"text":          v,
			"cache_control": map[string]any{"type": "ephemeral"},
		}}
	case []any:
		if len(v) == 0 {
			return
		}
		last, ok := v[len(v)-1].(map[string]any)
		if !ok || last == nil || last["type"] != "text" {
			return
		}
		if existing, ok := last["cache_control"].(map[string]any); ok {
			existing["type"] = "ephemeral"
			last["cache_control"] = existing
			return
		}
		last["cache_control"] = map[string]any{"type": "ephemeral"}
	}
}

func prepareAnthropicPassthroughBody(body []byte, modelID string) ([]byte, error) {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	req["model"] = modelID
	if err := normalizeRawMessagesToolCallArguments(req["messages"]); err != nil {
		return nil, err
	}
	// Anthropic 同协议透传时自动标记 user 消息的 cache_control，提升上游 prefix cache 命中。
	if msgs, ok := req["messages"].([]any); ok {
		addAnthropicCacheControlToRaw(msgs)
	}
	addAnthropicSystemCacheControl(req)
	return json.Marshal(req)
}

func proxyAnthropicPassthroughStream(w http.ResponseWriter, body io.ReadCloser, model string, rec *usageRecorder) error {
	defer body.Close()
	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(body)
	currentEvent := ""
	var inputTokens, outputTokens, cacheCreationInputTokens, cacheReadInputTokens float64
	recordedUsage := false

	updateAnthropicUsage := func(usage map[string]any) {
		if usage == nil {
			return
		}
		if v, ok := getFloat(usage, "input_tokens"); ok && v > 0 {
			inputTokens = v
		}
		if v, ok := getFloat(usage, "cache_creation_input_tokens"); ok && v > 0 {
			cacheCreationInputTokens = v
		}
		if v, ok := getFloat(usage, "cache_read_input_tokens"); ok && v > 0 {
			cacheReadInputTokens = v
		}
		if v, ok := getFloat(usage, "output_tokens"); ok && v >= 0 {
			outputTokens = v
		}
	}

	recordAnthropicUsage := func() {
		if recordedUsage {
			return
		}
		promptTokens := inputTokens + cacheCreationInputTokens + cacheReadInputTokens
		totalTokens := promptTokens + outputTokens
		if totalTokens <= 0 {
			return
		}
		recordedUsage = true
		rec.SetUsage(usageAmounts{
			Input:         int64(inputTokens),
			Output:        int64(outputTokens),
			CacheRead:     int64(cacheReadInputTokens),
			CacheCreation: int64(cacheCreationInputTokens),
		})
	}
	defer func() {
		// If the stream ended after message_delta but before message_stop, still
		// keep the gateway stats consistent. Claude Code receives the raw stream;
		// this only affects this gateway's admin stats.
		if outputTokens > 0 {
			recordAnthropicUsage()
		}
	}()

	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			if _, writeErr := io.WriteString(w, line); writeErr != nil {
				return writeErr
			}
			if strings.HasPrefix(line, "event:") {
				currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			} else if strings.HasPrefix(line, "data:") {
				data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				// 只有记账相关事件需要解析 JSON；content_block_delta 等大块直接透传，省掉逐 token 的解析开销
				if data != "" && data != "[DONE]" &&
					(currentEvent == "message_start" || currentEvent == "message_delta" || currentEvent == "message_stop") {
					var payload map[string]any
					if json.Unmarshal([]byte(data), &payload) == nil {
						switch currentEvent {
						case "message_start":
							if msg, ok := payload["message"].(map[string]any); ok {
								if usage, ok := msg["usage"].(map[string]any); ok {
									updateAnthropicUsage(usage)
								}
							}
						case "message_delta":
							if usage, ok := payload["usage"].(map[string]any); ok {
								updateAnthropicUsage(usage)
							}
						case "message_stop":
							recordAnthropicUsage()
						}
					}
				}
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func prepareResponsesPassthroughBody(body []byte, modelID string, alias ModelAlias) ([]byte, error) {
	// Responses 同协议快速透传：仅替换顶层 model，并补齐 stream_options.include_usage。
	// 对不含 tool_calls / 计费头清洗需求的请求，跳过 Unmarshal/Marshal。
	if !bytes.Contains(body, []byte(`"tool_calls"`)) &&
		!bytes.Contains(body, []byte(`"function_call"`)) &&
		!bytes.Contains(body, []byte(`"x-anthropic-billing-header"`)) {
		if out, err := replaceTopLevelModelString(body, modelID); err == nil {
			if stream := extractTopLevelBool(out, "stream"); stream {
				if injected, err := injectRawStreamOptionsIncludeUsage(out); err == nil {
					return injected, nil
				}
			}
			return out, nil
		}
	}

	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	req["model"] = modelID
	if err := normalizeRawMessagesToolCallArguments(req["messages"]); err != nil {
		return nil, err
	}
	if instructions, ok := req["instructions"].(string); ok {
		req["instructions"] = stripBillingHeaderText(instructions)
	}
	stripBillingHeaderFromResponsesItems(req["input"])
	stripBillingHeaderFromResponsesItems(req["messages"])
	ensureResponsesIncludeUsage(req)

	return json.Marshal(req)
}

func proxyResponsesPassthroughStream(w http.ResponseWriter, body io.ReadCloser, model string, rec *usageRecorder) error {
	defer body.Close()
	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(body)
	currentEvent := ""
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			if _, writeErr := io.WriteString(w, line); writeErr != nil {
				return writeErr
			}
			if strings.HasPrefix(line, "event:") {
				currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			} else if strings.HasPrefix(line, "data:") {
				data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				if data != "" && data != "[DONE]" && (currentEvent == "response.completed" || currentEvent == "response.incomplete") {
					var payload map[string]any
					if json.Unmarshal([]byte(data), &payload) == nil {
						if u := extractResponsesUsage(payload); u != nil {
							rec.MarkUsageFromMap(u)
						}
					}
				}
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func extractResponsesUsage(payload map[string]any) map[string]any {
	if u, ok := payload["usage"].(map[string]any); ok {
		return u
	}
	if resp, ok := payload["response"].(map[string]any); ok {
		if u, ok := resp["usage"].(map[string]any); ok {
			return u
		}
	}
	return nil
}

func responsesUsageToChatUsage(u map[string]any) map[string]any {
	if u == nil {
		return nil
	}
	pt, _ := getFloat(u, "prompt_tokens", "input_tokens")
	ct, _ := getFloat(u, "completion_tokens", "output_tokens")
	tt, _ := getFloat(u, "total_tokens")
	if tt == 0 && pt+ct > 0 {
		tt = pt + ct
	}
	return map[string]any{
		"prompt_tokens":     int64(pt),
		"completion_tokens": int64(ct),
		"total_tokens":      int64(tt),
	}
}

func responsesStreamToChatHandler(w http.ResponseWriter, respBody io.ReadCloser, model string, recordUsage bool, rec *usageRecorder) {
	defer respBody.Close()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(respBody)
	chunkID := "chatcmpl-" + randomString(16)
	created := time.Now().Unix()
	currentEvent := ""
	roleSent := false
	doneSent := false
	hasToolCalls := false
	toolIndexes := map[string]int{}
	nextToolIndex := 0

	emit := func(delta map[string]any, finishReason any, usage map[string]any) {
		if !roleSent {
			chunk := map[string]any{
				"id":      chunkID,
				"object":  "chat.completion.chunk",
				"created": created,
				"model":   model,
				"choices": []map[string]any{{"index": 0, "delta": map[string]any{"role": "assistant"}, "finish_reason": nil}},
			}
			b, _ := json.Marshal(chunk)
			w.Write([]byte("data: " + string(b) + "\n\n"))
			roleSent = true
		}
		if delta == nil {
			delta = map[string]any{}
		}
		chunk := map[string]any{
			"id":      chunkID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   model,
			"choices": []map[string]any{{"index": 0, "delta": delta, "finish_reason": finishReason}},
		}
		if usage != nil {
			chunk["usage"] = usage
		}
		b, _ := json.Marshal(chunk)
		w.Write([]byte("data: " + string(b) + "\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}

	// arguments.delta 事件可能用 item_id 回指，也可能用 call_id，
	// 因此两个 key 都登记到同一个索引，避免同一个工具调用被拆成两个索引
	getToolIndex := func(item map[string]any) int {
		itemID, _ := item["id"].(string)
		callID, _ := item["call_id"].(string)
		if itemID != "" {
			if idx, ok := toolIndexes[itemID]; ok {
				return idx
			}
		}
		if callID != "" {
			if idx, ok := toolIndexes[callID]; ok {
				return idx
			}
		}
		idx := nextToolIndex
		nextToolIndex++
		if itemID != "" {
			toolIndexes[itemID] = idx
		}
		if callID != "" {
			toolIndexes[callID] = idx
		}
		if itemID == "" && callID == "" {
			toolIndexes[fmt.Sprintf("tool_%d", idx)] = idx
		}
		return idx
	}

	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "event:") {
				currentEvent = strings.TrimSpace(strings.TrimPrefix(trimmed, "event:"))
			} else if strings.HasPrefix(trimmed, "data:") {
				data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
				if data == "[DONE]" {
					doneSent = true
					break
				}
				if data != "" {
					var payload map[string]any
					if json.Unmarshal([]byte(data), &payload) == nil {
						eventType, _ := payload["type"].(string)
						if eventType == "" {
							eventType = currentEvent
						}
						switch eventType {
						case "response.output_text.delta":
							if text, _ := payload["delta"].(string); text != "" {
								emit(map[string]any{"content": text}, nil, nil)
							}
						case "response.reasoning_summary_text.delta", "response.reasoning_text.delta":
							if text, _ := payload["delta"].(string); text != "" {
								emit(map[string]any{"reasoning_content": text}, nil, nil)
							}
						case "response.output_item.added":
							if item, ok := payload["item"].(map[string]any); ok {
								if typ, _ := item["type"].(string); typ == "function_call" {
									idx := getToolIndex(item)
									callID, _ := item["call_id"].(string)
									if callID == "" {
										callID, _ = item["id"].(string)
									}
									name, _ := item["name"].(string)
									hasToolCalls = true
									emit(map[string]any{"tool_calls": []map[string]any{{
										"index": float64(idx),
										"id":    callID,
										"type":  "function",
										"function": map[string]any{
											"name":      name,
											"arguments": "",
										},
									}}}, nil, nil)
								}
							}
						case "response.function_call_arguments.delta":
							itemID, _ := payload["item_id"].(string)
							if itemID == "" {
								itemID, _ = payload["call_id"].(string)
							}
							idx, ok := toolIndexes[itemID]
							if !ok {
								idx = nextToolIndex
								toolIndexes[itemID] = idx
								nextToolIndex++
							}
							if delta, _ := payload["delta"].(string); delta != "" {
								emit(map[string]any{"tool_calls": []map[string]any{{
									"index":    float64(idx),
									"function": map[string]any{"arguments": delta},
								}}}, nil, nil)
							}
						case "response.completed", "response.incomplete":
							usage := responsesUsageToChatUsage(extractResponsesUsage(payload))
							if recordUsage {
								rec.MarkUsageFromMap(extractResponsesUsage(payload))
							}
							finishReason := "stop"
							if hasToolCalls {
								finishReason = "tool_calls"
							}
							if eventType == "response.incomplete" {
								finishReason = "length"
							}
							emit(map[string]any{}, finishReason, usage)
						}
					}
				}
			}
		}
		if err != nil {
			break
		}
	}
	if !doneSent {
		w.Write([]byte("data: [DONE]\n\n"))
	}
	if flusher != nil {
		flusher.Flush()
	}
}

// ======================== 安全响应头过滤 ========================

var safeResponseHeaders = map[string]bool{
	"Content-Type":          true,
	"Retry-After":           true,
	"RateLimit-Limit":       true,
	"RateLimit-Remaining":   true,
	"RateLimit-Reset":       true,
	"X-RateLimit-Limit":     true,
	"X-RateLimit-Remaining": true,
	"X-RateLimit-Reset":     true,
}

func filterResponseHeaders(h http.Header) http.Header {
	filtered := make(http.Header)
	for k, v := range h {
		if safeResponseHeaders[k] {
			filtered[k] = v
		}
	}
	return filtered
}

func copyFilteredResponseHeaders(dst http.Header, src http.Header) {
	for k, values := range filterResponseHeaders(src) {
		dst.Del(k)
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}

func normalizeUpstreamStatus(status int) int {
	if status < 100 || status > 999 {
		return http.StatusBadGateway
	}
	return status
}

func applyUpstreamErrorHeaders(w http.ResponseWriter, upstreamHeaders http.Header, status int) int {
	status = normalizeUpstreamStatus(status)
	copyFilteredResponseHeaders(w.Header(), upstreamHeaders)
	w.Header().Set("X-Upstream-Status", strconv.Itoa(status))
	if status == http.StatusTooManyRequests {
		w.Header().Set("X-Upstream-Rate-Limited", "true")
	}
	return status
}

// mapUpstreamErrorBody converts upstream error responses to standard OpenAI format
func mapUpstreamErrorBody(body []byte, upstreamType UpstreamType) []byte {
	if len(body) == 0 {
		return nil
	}
	trimmed := bytes.TrimSpace(body)
	if bytes.HasPrefix(trimmed, []byte("data:")) {
		for _, line := range bytes.Split(trimmed, []byte{'\n'}) {
			line = bytes.TrimSpace(line)
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
			if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
				continue
			}
			trimmed = payload
			break
		}
	}
	var parsed map[string]any
	if json.Unmarshal(trimmed, &parsed) != nil {
		return trimmed
	}
	// Already has OpenAI-format error
	if errObj, ok := parsed["error"].(map[string]any); ok {
		if _, hasMsg := errObj["message"]; hasMsg {
			return trimmed
		}
	}
	// Anthropic: { "error": { "type": "...", "message": "..." } }
	if errObj, ok := parsed["error"].(map[string]any); ok {
		if msg, ok := errObj["message"].(string); ok {
			b, _ := json.Marshal(map[string]any{
				"error": map[string]any{
					"message": msg,
					"type":    errObj["type"],
				},
			})
			return b
		}
	}
	// Top-level message
	if msg, ok := parsed["message"].(string); ok {
		b, _ := json.Marshal(map[string]any{
			"error": map[string]any{
				"message": msg,
				"type":    parsed["type"],
				"code":    parsed["type"],
			},
		})
		return b
	}
	// msg field
	if msg, ok := parsed["msg"].(string); ok {
		b, _ := json.Marshal(map[string]any{
			"error": map[string]any{
				"message": msg,
			},
		})
		return b
	}
	return trimmed
}

// proxyOpenAIPassthroughStream 是同协议 OpenAI Chat 流式透传：逐行复制上游 SSE，
// 只在出现 "usage" 的块里做一次 JSON 解析用于统计，正常 token 块零解析直接转发。
func proxyOpenAIPassthroughStream(w http.ResponseWriter, body io.ReadCloser, rec *usageRecorder) error {
	defer body.Close()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(body)
	doneSeen := false
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			trimmed := strings.TrimSpace(line)
			if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
				doneSeen = true
			}
			if !doneSeen && strings.Contains(line, `"usage"`) {
				if strings.HasPrefix(line, "data: ") {
					var payload map[string]any
					if json.Unmarshal([]byte(line[6:]), &payload) == nil {
						if u, ok := payload["usage"].(map[string]any); ok {
							rec.MarkUsageFromMap(u)
						}
					}
				}
			}
			if _, writeErr := io.WriteString(w, line); writeErr != nil {
				return writeErr
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// ======================== Chat Completions Handler ========================

func chatCompletionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	cnt := requestCount.Add(1)
	if debugMode {
		log.Printf("[request #%d] POST /v1/chat/completions\n%s", cnt, string(body))
	}

	// 同协议 OpenAI Chat 快速透传：只替换顶层 model，不重建 messages，最大化保留上游缓存前缀。
	// 仅用于没有历史 tool_calls/reasoning/extra_body 这类需要网关归一化的简单请求。
	if rawModel := extractTopLevelModelString(body); rawModel != "" {
		_, rawAlias, rawUpstreamName, rawUpstream := resolveModel(rawModel)
		if isKnownAlias(rawModel) && rawUpstream != nil && rawUpstream.APIType == UpstreamOpenAI &&
			!rawAlias.WithReasoning &&
			!bytes.Contains(body, []byte(`"tool_calls"`)) &&
			!bytes.Contains(body, []byte(`"reasoning_content"`)) &&
			!bytes.Contains(body, []byte(`"extra_body"`)) &&
			// 部分 OpenAI 兼容上游不接受 developer 角色；遇到时回退完整转换，
			// 让 convertMessagesForUpstream 将 developer 降级为 system。
			!bytes.Contains(body, []byte(`"role":"developer"`)) &&
			!bytes.Contains(body, []byte(`"role": "developer"`)) {
			rawStream := extractTopLevelBool(body, "stream")
			rawRec := newUsageRecorder("chat", rawModel, rawStream)
			defer rawRec.Finish()
			r = withUsageRecorder(r, rawRec)
			bodyToSend := body
			if rawStream {
				if injected, err := injectRawStreamOptionsIncludeUsage(body); err == nil {
					bodyToSend = injected
				}
				upResp, status, upHeader, err := callUpstreamStream(r.Context(), bodyToSend, rawUpstreamName, rawAlias.TargetModel, "chat", rawUpstream, rawAlias.Socks5Proxy)
				if err != nil || status < 200 || status >= 300 {
					w.Header().Set("Content-Type", "application/json")
					status = applyUpstreamErrorHeaders(w, upHeader, status)
					w.WriteHeader(status)
					if upResp != nil {
						errBody, _ := io.ReadAll(upResp)
						if len(errBody) > 0 {
							w.Write(errBody)
							return
						}
					}
					json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error", "type": "upstream_error"}})
					return
				}
				defer upResp.Close()
				if err := proxyOpenAIPassthroughStream(w, upResp, rawRec); err != nil && debugMode {
					log.Printf("[openai raw stream passthrough error] %v", err)
				}
				return
			}
			respBody, status, upHeader, err := callUpstream(r.Context(), body, rawUpstreamName, rawAlias.TargetModel, "chat", rawUpstream, rawAlias.Socks5Proxy)
			if err != nil || status < 200 || status >= 300 {
				w.Header().Set("Content-Type", "application/json")
				status = applyUpstreamErrorHeaders(w, upHeader, status)
				w.WriteHeader(status)
				if len(respBody) > 0 {
					w.Write(respBody)
				} else {
					json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error", "type": "upstream_error"}})
				}
				return
			}
			var usageRaw map[string]any
			if json.Unmarshal(respBody, &usageRaw) == nil {
				if u, ok := usageRaw["usage"].(map[string]any); ok {
					rawRec.MarkUsageFromMap(u)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			w.Write(respBody)
			return
		}
	}

	var req OpenAIRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	// 使用统计：以客户端请求的别名（req.Model）为主键记录，请求结束时一次性落账
	rec := newUsageRecorder("chat", req.Model, req.Stream)
	defer rec.Finish()
	r = withUsageRecorder(r, rec)
	resolvedModel, modelAliasInfo, upstreamName, upstream := resolveModel(req.Model)
	if !isKnownAlias(req.Model) {
		rec.SetStatus(http.StatusBadRequest)
		rec.SetError("model not found")
		http.Error(w, `{"error":{"message":"model not found; only configured aliases are accepted","type":"invalid_request_error"}}`, http.StatusBadRequest)
		return
	}
	req.Model = resolvedModel
	if req.Model == "" {
		rec.SetStatus(http.StatusBadRequest)
		rec.SetError("model is required")
		http.Error(w, `{"error":"model is required"}`, http.StatusBadRequest)
		return
	}

	// 多模态路由：检测到图片时转发到配置的上游

	req.Messages = fixToolCallGaps(req.Messages)
	var toolArgsErr error
	req.Messages, toolArgsErr = normalizeMessagesToolCallArguments(req.Messages)
	if toolArgsErr != nil {
		log.Printf("[request invalid] path=/v1/chat/completions model=%q err=%v", req.Model, toolArgsErr)
		rec.SetStatus(http.StatusBadRequest)
		rec.SetError(toolArgsErr.Error())
		http.Error(w, toolArgsErr.Error(), http.StatusBadRequest)
		return
	}
	ensureReasoningEffort(&req, modelAliasInfo)
	req.Messages = ensureReasoningContent(req.Messages, modelAliasInfo.WithReasoning)
	upstreamBody := buildUpstreamBody(&req, modelAliasInfo.WithReasoning)

	if req.Stream {
		upResp, status, upHeader, err := callUpstreamStream(r.Context(), upstreamBody, upstreamName, req.Model, "chat", upstream, modelAliasInfo.Socks5Proxy)
		if err != nil || status < 200 || status >= 300 {
			w.Header().Set("Content-Type", "application/json")
			status = applyUpstreamErrorHeaders(w, upHeader, status)
			w.WriteHeader(status)
			if upResp != nil {
				errBody, _ := io.ReadAll(upResp)
				if len(errBody) > 0 {
					w.Write(errBody)
					return
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error", "type": "upstream_error"}})
			return
		}
		defer upResp.Close()
		// 如果上游是 Anthropic，需要将 Anthropic SSE 流转为 OpenAI Chat SSE 格式
		if upstream != nil && upstream.APIType == UpstreamAnthropic {
			anthropicStreamToChatHandler(w, upResp, req.Model, rec)
			return
		}
		if upstream != nil && upstream.APIType == UpstreamResponses {
			responsesStreamToChatHandler(w, upResp, req.Model, true, rec)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		reader := bufio.NewReader(upResp)
		doneSeen := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					break
				}
				log.Printf("Error reading stream: %v", err)
				// 发送错误事件通知客户端
				w.Write([]byte("data: {\"error\":\"stream read error\"}\n\n"))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				return
			}
			if doneSeen {
				continue
			}
			trimmed := strings.TrimSpace(line)
			if trimmed == "data: [DONE]" {
				doneSeen = true
				w.Write([]byte("data: [DONE]\n\n"))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				continue
			}

			out, usage := convertStreamChunkWithUsage(line)
			if out == "" {
				// 空choices chunk，但可能有 usage
				rec.MarkUsageFromMap(usage)
				continue
			}

			// 提取 usage（已在 convertStreamChunkWithUsage 中解析）
			if !doneSeen {
				rec.MarkUsageFromMap(usage)
			}

			w.Write([]byte(out))
			w.Write([]byte("\n\n"))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		return
	}

	respBody, status, upHeader, err := callUpstream(r.Context(), upstreamBody, upstreamName, req.Model, "chat", upstream, modelAliasInfo.Socks5Proxy)
	if err != nil || status < 200 || status >= 300 {
		w.Header().Set("Content-Type", "application/json")
		status = applyUpstreamErrorHeaders(w, upHeader, status)
		w.WriteHeader(status)
		if len(respBody) > 0 {
			w.Write(respBody)
		} else {
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error", "type": "upstream_error"}})
		}
		return
	}
	outBody := respBody
	convertedResp, err := convertResponse(respBody)
	if err == nil {
		outBody = convertedResp
	}
	// Record token usage
	var usageResp2 map[string]any
	if json.Unmarshal(respBody, &usageResp2) == nil {
		if u, ok := usageResp2["usage"].(map[string]any); ok {
			rec.MarkUsageFromMap(u)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(outBody)
}

// ======================== Models Handler ========================

func listModelsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	models := getAliasModelInfos()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"object": "list",
		"data":   models,
	})
}

// ======================== Anthropic Messages API ========================

func extractAnthropicSystemText(system any) string {
	if system == nil {
		return ""
	}
	switch v := system.(type) {
	case string:
		return v
	case []any:
		var parts []string
		for _, item := range v {
			if block, ok := item.(map[string]any); ok {
				if block["type"] == "text" {
					if text, ok := block["text"].(string); ok {
						parts = append(parts, text)
					}
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func cleanJSONSchema(schema any) any {
	m, ok := schema.(map[string]any)
	if !ok {
		return schema
	}
	delete(m, "$schema")
	delete(m, "title")
	delete(m, "examples")
	delete(m, "additionalProperties")
	if m["type"] == "string" {
		delete(m, "format")
	}
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			m[k] = cleanJSONSchema(sub)
		}
		if arr, ok := v.([]any); ok {
			for i, elem := range arr {
				if sub, ok := elem.(map[string]any); ok {
					arr[i] = cleanJSONSchema(sub)
				}
			}
			m[k] = arr
		}
	}
	return m
}

func anthropicToOpenAIMessages(anthropicMsgs []AnthropicMessage, system any) []Message {
	var messages []Message
	if sysText := extractAnthropicSystemText(system); sysText != "" {
		messages = append(messages, Message{Role: "system", Content: sysText})
	}
	for _, msg := range anthropicMsgs {
		switch content := msg.Content.(type) {
		case string:
			messages = append(messages, Message{Role: msg.Role, Content: content})
		case []any:
			var textParts []string
			var reasoningParts []string
			var toolCalls []ToolCall
			var toolResults []Message
			var imageParts []map[string]any
			for _, item := range content {
				block, ok := item.(map[string]any)
				if !ok {
					continue
				}
				blockType, _ := block["type"].(string)
				switch blockType {
				case "text":
					if text, ok := block["text"].(string); ok && text != "" {
						textParts = append(textParts, text)
					}
				case "image":
					source, _ := block["source"].(map[string]any)
					if source != nil {
						srcType, _ := source["type"].(string)
						mediaType, _ := source["media_type"].(string)
						data, _ := source["data"].(string)
						if srcType == "base64" && data != "" {
							if mediaType == "" {
								mediaType = "image/png"
							}
							imageParts = append(imageParts, map[string]any{
								"type": "image_url",
								"image_url": map[string]string{
									"url": "data:" + mediaType + ";base64," + data,
								},
							})
						} else if srcType == "url" {
							if url, ok := source["url"].(string); ok && url != "" {
								imageParts = append(imageParts, map[string]any{
									"type": "image_url",
									"image_url": map[string]string{
										"url": url,
									},
								})
							}
						}
					}
				case "thinking":
					if thinking, ok := block["thinking"].(string); ok && thinking != "" {
						reasoningParts = append(reasoningParts, thinking)
					}
				case "tool_use":
					id, _ := block["id"].(string)
					name, _ := block["name"].(string)
					var args string
					switch input := block["input"].(type) {
					case string:
						args = input
					default:
						if input != nil {
							b, _ := json.Marshal(input)
							args = string(b)
						}
					}
					if args == "" {
						args = "{}"
					}
					toolCalls = append(toolCalls, ToolCall{
						ID:   id,
						Type: "function",
						Function: FunctionCall{
							Name:      name,
							Arguments: args,
						},
					})
				case "tool_result":
					toolUseID, _ := block["tool_use_id"].(string)
					var resultText string
					switch c := block["content"].(type) {
					case string:
						resultText = c
					case []any:
						var parts []string
						for _, p := range c {
							if pb, ok := p.(map[string]any); ok && pb["type"] == "text" {
								if t, ok := pb["text"].(string); ok {
									parts = append(parts, t)
								}
							}
						}
						resultText = strings.Join(parts, "\n")
					default:
						if c != nil {
							b, _ := json.Marshal(c)
							resultText = string(b)
						}
					}
					toolResults = append(toolResults, Message{
						Role:       "tool",
						ToolCallID: toolUseID,
						Content:    resultText,
					})
				}
			}
			om := Message{Role: msg.Role}
			if len(imageParts) > 0 {
				var contentArr []any
				for _, img := range imageParts {
					contentArr = append(contentArr, img)
				}
				if len(textParts) > 0 {
					contentArr = append(contentArr, map[string]any{
						"type": "text",
						"text": strings.Join(textParts, "\n"),
					})
				}
				om.Content = contentArr
			} else if len(textParts) > 0 {
				om.Content = strings.Join(textParts, "\n")
			} else if len(toolCalls) == 0 {
				om.Content = ""
			}
			if len(reasoningParts) > 0 {
				rc := strings.Join(reasoningParts, "\n")
				om.ReasoningContent = &rc
			}
			if len(toolCalls) > 0 {
				om.ToolCalls = toolCalls
			}
			messages = append(messages, om)
			messages = append(messages, toolResults...)
		default:
			b, _ := json.Marshal(content)
			messages = append(messages, Message{Role: msg.Role, Content: string(b)})
		}
	}
	return messages
}

func anthropicToOpenAITools(anthropicTools []AnthropicTool) []Tool {
	tools := make([]Tool, 0, len(anthropicTools))
	for _, ct := range anthropicTools {
		params := ct.InputSchema
		if params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		params = cleanJSONSchema(params)
		paramsMap, ok := params.(map[string]any)
		if !ok {
			// 非对象类型（如数组、字符串）的 input_schema 退化为空对象
			paramsMap = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		tools = append(tools, Tool{
			Type: "function",
			Function: ToolFunction{
				Name:        ct.Name,
				Description: ct.Description,
				Parameters:  paramsMap,
			},
		})
	}
	return tools
}

func convertAnthropicToolChoice(choice any) any {
	if choice == nil {
		return nil
	}
	switch v := choice.(type) {
	case string:
		// Anthropic 也允许字符串，但标准是对象；直接透传
		return v
	case map[string]any:
		t, _ := v["type"].(string)
		switch t {
		case "auto", "none":
			return t
		case "any":
			// Anthropic any -> OpenAI required
			return "required"
		case "tool":
			name, _ := v["name"].(string)
			if name == "" {
				return "auto"
			}
			return map[string]any{
				"type":     "function",
				"function": map[string]any{"name": name},
			}
		default:
			return choice
		}
	default:
		return choice
	}
}

func buildAnthropicErrorBody(errorType, message string) []byte {
	if strings.TrimSpace(errorType) == "" {
		errorType = "api_error"
	}
	if strings.TrimSpace(message) == "" {
		message = "upstream error"
	}
	b, _ := json.Marshal(map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    errorType,
			"message": message,
		},
	})
	return b
}

func upstreamErrorToAnthropic(errObj any, fallback string) (string, string) {
	errType := "api_error"
	msg := fallback
	if m, ok := errObj.(map[string]any); ok {
		if s, ok := m["type"].(string); ok && strings.TrimSpace(s) != "" {
			errType = s
		}
		if s, ok := m["message"].(string); ok && strings.TrimSpace(s) != "" {
			msg = s
		}
		if code, ok := m["code"]; ok && code != nil {
			msg = fmt.Sprintf("%s (upstream code: %v)", msg, code)
		}
	} else if s, ok := errObj.(string); ok && strings.TrimSpace(s) != "" {
		msg = s
	}
	if strings.TrimSpace(msg) == "" {
		msg = "upstream error"
	}
	return errType, msg
}

func openAIToAnthropicResponse(chatBody []byte, model string) ([]byte, bool) {
	var raw map[string]any
	if err := json.Unmarshal(chatBody, &raw); err == nil {
		if errObj, ok := raw["error"]; ok {
			errType, msg := upstreamErrorToAnthropic(errObj, "upstream returned error")
			log.Printf("Warning: upstream returned error object: type=%s message=%s", errType, msg)
			return buildAnthropicErrorBody(errType, msg), false
		}
	}

	var chat struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Created int64  `json:"created"`
		Choices []struct {
			Message struct {
				Content          string     `json:"content"`
				ReasoningContent string     `json:"reasoning_content"`
				Reasoning        string     `json:"reasoning"`
				ToolCalls        []ToolCall `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage map[string]any `json:"usage"`
	}
	if err := json.Unmarshal(chatBody, &chat); err != nil {
		log.Printf("Warning: openAIToAnthropicResponse unmarshal failed: %v", err)
		return buildAnthropicErrorBody("api_error", "upstream returned invalid JSON: "+err.Error()), false
	}
	if len(chat.Choices) == 0 {
		preview := truncatePreview(string(chatBody), 500)
		log.Printf("Warning: upstream returned chat completion without choices: %s", preview)
		return buildAnthropicErrorBody("api_error", "upstream returned chat completion without choices"), false
	}

	content := []AnthropicContent{}
	stopReason := "end_turn"

	msg := chat.Choices[0].Message
	fr := chat.Choices[0].FinishReason
	reasoning := msg.ReasoningContent
	if reasoning == "" {
		reasoning = msg.Reasoning
	}
	if reasoning != "" {
		content = append(content, AnthropicContent{
			Type:     "thinking",
			Thinking: reasoning,
		})
	}
	if msg.Content != "" {
		content = append(content, AnthropicContent{
			Type: "text",
			Text: msg.Content,
		})
	}
	for _, tc := range msg.ToolCalls {
		var input any
		json.Unmarshal([]byte(tc.Function.Arguments), &input)
		if input == nil {
			input = map[string]any{}
		}
		content = append(content, AnthropicContent{
			Type:  "tool_use",
			ID:    tc.ID,
			Name:  tc.Function.Name,
			Input: input,
		})
	}
	switch fr {
	case "stop":
		stopReason = "end_turn"
	case "length":
		stopReason = "max_tokens"
	case "tool_calls", "function_call":
		stopReason = "tool_use"
	}

	if len(content) == 0 {
		log.Printf("Warning: upstream returned empty assistant message for model %s", model)
		return buildAnthropicErrorBody("api_error", "upstream returned empty assistant message"), false
	}

	resp := AnthropicResponse{
		ID:           fmt.Sprintf("msg_%s", randomString(24)),
		Type:         "message",
		Role:         "assistant",
		Content:      content,
		Model:        model,
		StopReason:   stopReason,
		StopSequence: nil,
	}
	if chat.Usage != nil {
		inputTokens, _ := getFloat(chat.Usage, "input_tokens", "prompt_tokens")
		outputTokens, _ := getFloat(chat.Usage, "output_tokens", "completion_tokens")
		resp.Usage = &AnthropicUsage{
			InputTokens:  int(toFloat64(inputTokens)),
			OutputTokens: int(toFloat64(outputTokens)),
		}
	}
	result, _ := json.Marshal(resp)
	return result, true
}

func toFloat64(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return 0
	}
}

func getFloat(m map[string]any, keys ...string) (float64, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch n := v.(type) {
			case float64:
				return n, true
			case float32:
				return float64(n), true
			case int:
				return float64(n), true
			case int64:
				return float64(n), true
			case int32:
				return float64(n), true
			}
		}
	}
	return 0, false
}

func anthropicMessagesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	cnt := requestCount.Add(1)
	if debugMode {
		log.Printf("[request #%d] POST /v1/messages\n%s", cnt, string(body))
	}

	var anthropicReq AnthropicRequest
	if err := json.Unmarshal(body, &anthropicReq); err != nil {
		http.Error(w, `{"type":"error","error":{"type":"invalid_request_error","message":"Invalid JSON"}}`, http.StatusBadRequest)
		return
	}
	rec := newUsageRecorder("messages", anthropicReq.Model, anthropicReq.Stream)
	defer rec.Finish()
	r = withUsageRecorder(r, rec)
	resolvedModel, modelAliasInfo, upstreamName, upstream := resolveModel(anthropicReq.Model)
	if !isKnownAlias(anthropicReq.Model) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]any{"type": "invalid_request_error", "message": "model not found; only configured aliases are accepted"}})
		return
	}
	anthropicReq.Model = resolvedModel

	// 上游是 Anthropic 类型时，下游入口与上游同为 Anthropic 协议，直接透传
	if upstream != nil && upstream.APIType == UpstreamAnthropic {
		rawBody, err := prepareAnthropicPassthroughBody(body, anthropicReq.Model)
		if err != nil {
			log.Printf("[request invalid] path=/v1/messages mode=passthrough model=%q err=%v", anthropicReq.Model, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": "invalid_request_error", "message": err.Error()}})
			return
		}
		if anthropicReq.Stream {
			upResp, status, upHeader, err := callPreparedUpstreamStream(r.Context(), rawBody, upstreamName, anthropicReq.Model, "messages", upstream, modelAliasInfo.Socks5Proxy)
			if err != nil || status < 200 || status >= 300 {
				errResp := map[string]any{
					"type":  "error",
					"error": map[string]string{"type": "api_error", "message": "upstream error"},
				}
				w.Header().Set("Content-Type", "application/json")
				status = applyUpstreamErrorHeaders(w, upHeader, status)
				w.WriteHeader(status)
				if upResp != nil {
					errBody, _ := io.ReadAll(upResp)
					if len(errBody) > 0 {
						w.Write(errBody)
						return
					}
				}
				json.NewEncoder(w).Encode(errResp)
				return
			}
			defer upResp.Close()
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.WriteHeader(http.StatusOK)
			if err := proxyAnthropicPassthroughStream(w, upResp, anthropicReq.Model, rec); err != nil && debugMode {
				log.Printf("[anthropic raw stream passthrough error] %v", err)
			}
			return
		}

		respBody, status, upHeader, err := callPreparedUpstream(r.Context(), rawBody, upstreamName, anthropicReq.Model, "messages", upstream, modelAliasInfo.Socks5Proxy, true)
		if err != nil || status < 200 || status >= 300 {
			w.Header().Set("Content-Type", "application/json")
			status = applyUpstreamErrorHeaders(w, upHeader, status)
			w.WriteHeader(status)
			if len(respBody) > 0 {
				w.Write(respBody)
			} else {
				json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": "api_error", "message": "upstream error"}})
			}
			return
		}
		// Record token usage
		var usageResp map[string]any
		if json.Unmarshal(respBody, &usageResp) == nil {
			if u, ok := usageResp["usage"].(map[string]any); ok {
				rec.MarkUsageFromMap(u)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if debugMode {
			log.Printf("[client response] (Anthropic passthrough)\n%s", string(respBody))
		}
		w.Write(respBody)
		return
	}

	// 上游非 Anthropic 类型，走 Chat 中间格式转换

	messages := anthropicToOpenAIMessages(anthropicReq.Messages, anthropicReq.System)
	messages = fixToolCallGaps(messages)
	var toolArgsErr error
	messages, toolArgsErr = normalizeMessagesToolCallArguments(messages)
	if toolArgsErr != nil {
		log.Printf("[request invalid] path=/v1/messages model=%q err=%v", anthropicReq.Model, toolArgsErr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": "invalid_request_error", "message": toolArgsErr.Error()}})
		return
	}

	chatReq := OpenAIRequest{
		Model:    anthropicReq.Model,
		Messages: messages,
		Stream:   anthropicReq.Stream,
		Thinking: anthropicReq.Thinking,
	}
	if anthropicReq.MaxTokens > 0 {
		chatReq.MaxTokens = anthropicReq.MaxTokens
	}
	if anthropicReq.Temperature != nil {
		chatReq.Temperature = anthropicReq.Temperature
	}
	if anthropicReq.TopP != nil {
		chatReq.TopP = anthropicReq.TopP
	}
	if len(anthropicReq.Tools) > 0 {
		chatReq.Tools = anthropicToOpenAITools(anthropicReq.Tools)
	}
	if anthropicReq.ToolChoice != nil {
		chatReq.ToolChoice = convertAnthropicToolChoice(anthropicReq.ToolChoice)
	} else if len(chatReq.Tools) > 0 {
		chatReq.ToolChoice = "auto"
	}

	ensureReasoningEffort(&chatReq, modelAliasInfo)
	chatReq.Messages = ensureReasoningContent(chatReq.Messages, modelAliasInfo.WithReasoning)

	upstreamBody := buildUpstreamBody(&chatReq, modelAliasInfo.WithReasoning)

	if anthropicReq.Stream {
		upResp, status, upHeader, err := callUpstreamStream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "messages", upstream, modelAliasInfo.Socks5Proxy)
		if err != nil || status < 200 || status >= 300 {
			errResp := map[string]any{
				"type":  "error",
				"error": map[string]string{"type": "api_error", "message": "upstream error"},
			}
			w.Header().Set("Content-Type", "application/json")
			status = applyUpstreamErrorHeaders(w, upHeader, status)
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(errResp)
			return
		}
		defer upResp.Close()
		// 注：Anthropic 上游已在上方同协议直通处理，此处不会到达。
		// Responses 上游：先转为 Chat SSE 流，再转为 Anthropic SSE 流
		if upstream != nil && upstream.APIType == UpstreamResponses {
			pr2, pw2 := io.Pipe()
			go func() {
				defer pw2.Close()
				chatW2 := &pipeResponseWriter{w: pw2}
				// The outer anthropicStreamHandler records the converted usage.
				// Avoid double-counting gateway stats for Responses -> Anthropic.
				responsesStreamToChatHandler(chatW2, upResp, anthropicReq.Model, false, rec)
			}()
			// 传 pr2 本体（不是 NopCloser）：anthropicStreamHandler 退出时关闭读端，
			// 让阻塞在 pw2.Write 的 goroutine 立刻收到 ErrClosedPipe 退出
			anthropicStreamHandler(w, pr2, anthropicReq.Model, rec)
		} else {
			// OpenAI 上游：Chat SSE 流直接转为 Anthropic SSE 流
			anthropicStreamHandler(w, upResp, anthropicReq.Model, rec)
		}
		return
	}

	respBody, status, upHeader, err := callUpstream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "messages", upstream, modelAliasInfo.Socks5Proxy)
	if err != nil || status < 200 || status >= 300 {
		w.Header().Set("Content-Type", "application/json")
		status = applyUpstreamErrorHeaders(w, upHeader, status)
		w.WriteHeader(status)
		if len(respBody) > 0 {
			w.Write(respBody)
		} else {
			json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": "api_error", "message": "upstream error"}})
		}
		return
	}

	anthropicRespBody, convertedOK := openAIToAnthropicResponse(respBody, anthropicReq.Model)
	if !convertedOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write(anthropicRespBody)
		return
	}

	// Record token usage
	var usageResp2 map[string]any
	if json.Unmarshal(respBody, &usageResp2) == nil {
		if u, ok := usageResp2["usage"].(map[string]any); ok {
			rec.MarkUsageFromMap(u)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if debugMode {
		log.Printf("[client response]\n%s", string(anthropicRespBody))
	}
	w.Write(anthropicRespBody)
}

func anthropicStreamHandler(w http.ResponseWriter, respBody io.ReadCloser, model string, rec *usageRecorder) {
	// 必须关闭：作为 pipe 读端时，提前 return 会让写端 goroutine 永久阻塞
	defer respBody.Close()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(respBody)

	msgID := fmt.Sprintf("msg_%s", randomString(24))
	// blockIndex 是下一个可用的块序号；每个已开启的块都要记住自己拿到的真实序号，
	// 不能用 blockIndex-1 反推——否则块交错时 delta/stop 会打到别的块上。
	blockIndex := 0
	thinkingBlockOpen := false
	textBlockOpen := false
	thinkingBlockIndex := -1
	textBlockIndex := -1
	toolCallAccumulator := map[int]map[string]string{}
	toolBlockIndex := map[int]int{}
	toolCallOrder := []int{}
	messageStartSent := false
	finishSeen := false
	finalStopReason := "end_turn"
	fullUsage := map[string]any{}
	defer func() {
		rec.MarkUsageFromMap(fullUsage)
	}()

	emitAnthropicEvent := func(event string, data any) {
		jsonData, err := json.Marshal(data)
		if err != nil {
			log.Printf("Error marshaling Anthropic SSE event: %v", err)
			return
		}
		w.Write([]byte("event: " + event + "\n"))
		w.Write([]byte("data: " + string(jsonData) + "\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}

	closeThinkingBlock := func() {
		if !thinkingBlockOpen {
			return
		}
		emitAnthropicEvent("content_block_stop", map[string]any{
			"type":          "content_block_stop",
			"index":         thinkingBlockIndex,
			"content_block": map[string]any{"type": "thinking"},
		})
		thinkingBlockOpen = false
	}

	closeTextBlock := func() {
		if !textBlockOpen {
			return
		}
		emitAnthropicEvent("content_block_stop", map[string]any{
			"type":          "content_block_stop",
			"index":         textBlockIndex,
			"content_block": map[string]any{"type": "text"},
		})
		textBlockOpen = false
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading stream: %v", err)
			break
		}
		if debugMode && strings.HasPrefix(line, "data: ") {
			log.Printf("[upstream raw chunk] %s", strings.TrimSpace(line[6:]))
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
			break
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		var chunk map[string]any
		if err := json.Unmarshal([]byte(line[6:]), &chunk); err != nil {
			continue
		}
		if errObj, ok := chunk["error"]; ok {
			errType, msg := upstreamErrorToAnthropic(errObj, "upstream stream returned error")
			emitAnthropicEvent("error", map[string]any{
				"type": "error",
				"error": map[string]any{
					"type":    errType,
					"message": msg,
				},
			})
			return
		}

		choices, ok := chunk["choices"].([]any)
		if !ok || len(choices) == 0 {
			if usage, ok := chunk["usage"].(map[string]any); ok {
				fullUsage = usage
			}
			continue
		}

		choice, _ := choices[0].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		normalizeReasoningContent(delta)
		finishReason, _ := choice["finish_reason"].(string)

		if !messageStartSent {
			messageStartSent = true
			emitAnthropicEvent("message_start", map[string]any{
				"type": "message_start",
				"message": map[string]any{
					"id":            msgID,
					"type":          "message",
					"role":          "assistant",
					"content":       []any{},
					"model":         model,
					"stop_reason":   nil,
					"stop_sequence": nil,
					"usage":         map[string]any{"input_tokens": 0, "output_tokens": 0},
				},
			})
			emitAnthropicEvent("ping", map[string]any{"type": "ping"})
		}

		if rc, ok := delta["reasoning_content"]; ok {
			rcStr, _ := rc.(string)
			if rcStr != "" {
				closeTextBlock()
				if !thinkingBlockOpen {
					emitAnthropicEvent("content_block_start", map[string]any{
						"type":  "content_block_start",
						"index": blockIndex,
						"content_block": map[string]any{
							"type":     "thinking",
							"thinking": "",
						},
					})
					thinkingBlockOpen = true
					thinkingBlockIndex = blockIndex
					blockIndex++
				}
				emitAnthropicEvent("content_block_delta", map[string]any{
					"type":  "content_block_delta",
					"index": thinkingBlockIndex,
					"delta": map[string]any{
						"type":     "thinking_delta",
						"thinking": rcStr,
					},
				})
			}
		}

		if c, ok := delta["content"]; ok && c != nil {
			contentStr, _ := c.(string)
			if contentStr != "" {
				closeThinkingBlock()
				if !textBlockOpen {
					emitAnthropicEvent("content_block_start", map[string]any{
						"type":  "content_block_start",
						"index": blockIndex,
						"content_block": map[string]any{
							"type": "text",
							"text": "",
						},
					})
					textBlockOpen = true
					textBlockIndex = blockIndex
					blockIndex++
				}
				emitAnthropicEvent("content_block_delta", map[string]any{
					"type":  "content_block_delta",
					"index": textBlockIndex,
					"delta": map[string]any{
						"type": "text_delta",
						"text": contentStr,
					},
				})
			}
		}

		if rawToolCalls, ok := delta["tool_calls"].([]any); ok {
			for _, rawTC := range rawToolCalls {
				tc, ok := rawTC.(map[string]any)
				if !ok {
					continue
				}
				idxFloat, _ := tc["index"].(float64)
				upstreamIndex := int(idxFloat)

				closeThinkingBlock()
				closeTextBlock()

				if _, exists := toolCallAccumulator[upstreamIndex]; !exists {
					callID, _ := tc["id"].(string)
					if callID == "" {
						callID = "toolu_" + randomString(12)
					}
					fn, _ := tc["function"].(map[string]any)
					name, _ := fn["name"].(string)
					toolCallAccumulator[upstreamIndex] = map[string]string{
						"id":   callID,
						"name": name,
						"args": "",
					}
					toolCallOrder = append(toolCallOrder, upstreamIndex)
					emitAnthropicEvent("content_block_start", map[string]any{
						"type":  "content_block_start",
						"index": blockIndex,
						"content_block": map[string]any{
							"type":  "tool_use",
							"id":    callID,
							"name":  name,
							"input": map[string]any{},
						},
					})
					toolBlockIndex[upstreamIndex] = blockIndex
					blockIndex++
				}

				fn, _ := tc["function"].(map[string]any)
				if argDelta, ok := fn["arguments"].(string); ok && argDelta != "" {
					toolCallAccumulator[upstreamIndex]["args"] += argDelta
					emitAnthropicEvent("content_block_delta", map[string]any{
						"type":  "content_block_delta",
						"index": toolBlockIndex[upstreamIndex],
						"delta": map[string]any{
							"type":         "input_json_delta",
							"partial_json": argDelta,
						},
					})
				}
			}
		}

		if usage, ok := chunk["usage"].(map[string]any); ok {
			fullUsage = usage
		}

		if finishReason == "stop" || finishReason == "length" || finishReason == "tool_calls" || finishReason == "function_call" || finishReason == "content_filter" {
			closeThinkingBlock()
			closeTextBlock()

			for _, idx := range toolCallOrder {
				acc := toolCallAccumulator[idx]
				emitAnthropicEvent("content_block_stop", map[string]any{
					"type":  "content_block_stop",
					"index": toolBlockIndex[idx],
					"content_block": map[string]any{
						"type":  "tool_use",
						"id":    acc["id"],
						"name":  acc["name"],
						"input": map[string]any{},
					},
				})
			}
			// 已收尾的工具块不再重复 stop（上游异常多发 finish_reason 时会重复）
			toolCallOrder = nil

			switch finishReason {
			case "length":
				finalStopReason = "max_tokens"
			case "tool_calls", "function_call":
				finalStopReason = "tool_use"
			default:
				finalStopReason = "end_turn"
			}
			finishSeen = true
			// continue reading remaining chunks (usage chunk arrives after finish_reason)
		}
	}
	closeThinkingBlock()
	closeTextBlock()
	if !messageStartSent {
		emitAnthropicEvent("error", map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "api_error",
				"message": "upstream stream ended without message_start",
			},
		})
		return
	}

	inputTokens := 0
	if v, ok := fullUsage["prompt_tokens"]; ok {
		inputTokens = int(toFloat64(v))
	}
	outputTokens := 0
	if v, ok := fullUsage["completion_tokens"]; ok {
		outputTokens = int(toFloat64(v))
	}

	if !finishSeen {
		finalStopReason = "end_turn"
	}

	emitAnthropicEvent("message_delta", map[string]any{
		"type": "message_delta",
		"delta": map[string]any{
			"stop_reason":   finalStopReason,
			"stop_sequence": nil,
		},
		"usage": map[string]any{
			"input_tokens":  inputTokens,
			"output_tokens": outputTokens,
		},
	})
	emitAnthropicEvent("message_stop", map[string]any{"type": "message_stop"})
}

// ======================== Anthropic 流式转换 ========================

// pipeResponseWriter 适配 io.Writer 到 http.ResponseWriter 接口
type pipeResponseWriter struct {
	w      io.Writer
	header http.Header
}

func (p *pipeResponseWriter) Header() http.Header {
	if p.header == nil {
		p.header = make(http.Header)
	}
	return p.header
}

func (p *pipeResponseWriter) Write(data []byte) (int, error) {
	return p.w.Write(data)
}

func (p *pipeResponseWriter) WriteHeader(code int) {}

func (p *pipeResponseWriter) Flush() {
	// no-op for pipe; writes are synchronous
}

// anthropicStreamToChatHandler 将上游 Anthropic SSE 流实时转为 OpenAI Chat SSE 格式并写入客户端
func anthropicStreamToChatHandler(w http.ResponseWriter, respBody io.ReadCloser, model string, rec *usageRecorder) {
	// 同 anthropicStreamHandler：作为 pipe 读端时必须关闭，否则写端 goroutine 泄漏
	defer respBody.Close()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(respBody)

	chunkID := "chatcmpl-" + randomString(16)
	created := time.Now().Unix()
	roleSent := false
	toolCallAccumulator := map[int]map[string]string{}
	fullUsage := map[string]any{}

	defer func() {
		rec.MarkUsageFromMap(fullUsage)
	}()

	emitChatChunk := func(delta map[string]any, finishReason any, usage map[string]any) {
		// 清理空 content，避免客户端收到 content:"" 的 chunk
		if c, ok := delta["content"].(string); ok && c == "" {
			delete(delta, "content")
		}
		if finishReason == nil || finishReason == "" {
			finishReason = nil
		}
		chunk := map[string]any{
			"id":      chunkID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   model,
			"choices": []map[string]any{
				{
					"index":         0,
					"delta":         delta,
					"finish_reason": finishReason,
				},
			},
		}
		if usage != nil {
			chunk["usage"] = usage
		}
		jsonData, _ := json.Marshal(chunk)
		w.Write([]byte("data: " + string(jsonData) + "\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading Anthropic stream: %v", err)
			break
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
			break
		}

		// Parse Anthropic SSE data lines
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		var event map[string]any
		if json.Unmarshal([]byte(line[6:]), &event) != nil {
			continue
		}

		eventType, _ := event["type"].(string)

		switch eventType {
		case "message_start":
			if msg, ok := event["message"].(map[string]any); ok {
				if id, ok := msg["id"].(string); ok && id != "" {
					chunkID = "chatcmpl-" + id
				}
				if u, ok := msg["usage"].(map[string]any); ok {
					fullUsage = u
				}
			}
			if !roleSent {
				emitChatChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
				roleSent = true
			}

		case "content_block_start":
			block, _ := event["content_block"].(map[string]any)
			if block != nil {
				blockType, _ := block["type"].(string)
				switch blockType {
				case "tool_use":
					idx := len(toolCallAccumulator)
					callID, _ := block["id"].(string)
					name, _ := block["name"].(string)
					toolCallAccumulator[idx] = map[string]string{
						"id":   callID,
						"name": name,
						"args": "",
					}
					if !roleSent {
						emitChatChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
						roleSent = true
					}
					delta := map[string]any{
						"tool_calls": []map[string]any{
							{
								"index": float64(idx),
								"id":    callID,
								"type":  "function",
								"function": map[string]any{
									"name":      name,
									"arguments": "",
								},
							},
						},
					}
					emitChatChunk(delta, nil, nil)
				}
			}

		case "content_block_delta":
			deltaObj, _ := event["delta"].(map[string]any)
			if deltaObj == nil {
				continue
			}
			deltaType, _ := deltaObj["type"].(string)
			switch deltaType {
			case "thinking_delta":
				thinking, _ := deltaObj["thinking"].(string)
				if thinking != "" {
					if !roleSent {
						emitChatChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
						roleSent = true
					}
					emitChatChunk(map[string]any{"reasoning_content": thinking}, nil, nil)
				}
			case "text_delta":
				text, _ := deltaObj["text"].(string)
				if text != "" {
					if !roleSent {
						emitChatChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
						roleSent = true
					}
					emitChatChunk(map[string]any{"content": text}, nil, nil)
				}
			case "input_json_delta":
				partialJSON, _ := deltaObj["partial_json"].(string)
				index, _ := event["index"].(float64)
				idx := int(index)
				if tc, ok := toolCallAccumulator[idx]; ok {
					tc["args"] += partialJSON
					delta := map[string]any{
						"tool_calls": []map[string]any{
							{
								"index":    float64(idx),
								"function": map[string]any{"arguments": partialJSON},
							},
						},
					}
					emitChatChunk(delta, nil, nil)
				}
			}

		case "message_delta":
			deltaObj, _ := event["delta"].(map[string]any)
			if deltaObj != nil {
				stopReason, _ := deltaObj["stop_reason"].(string)
				finishReason := ""
				switch stopReason {
				case "end_turn":
					finishReason = "stop"
				case "max_tokens":
					finishReason = "length"
				case "tool_use":
					finishReason = "tool_calls"
				default:
					if stopReason != "" {
						finishReason = stopReason
					}
				}
				usage, _ := event["usage"].(map[string]any)
				if usage != nil {
					if ot, ok := usage["output_tokens"].(float64); ok {
						fullUsage["output_tokens"] = ot
					}
				}
				chatUsage := map[string]any{}
				if pt, ok := fullUsage["input_tokens"].(float64); ok {
					chatUsage["prompt_tokens"] = int64(pt)
				}
				if ot, ok := fullUsage["output_tokens"].(float64); ok {
					chatUsage["completion_tokens"] = int64(ot)
				}
				if _, ok := chatUsage["prompt_tokens"]; !ok {
					if u, ok2 := event["usage"].(map[string]any); ok2 {
						if it, ok3 := u["input_tokens"].(float64); ok3 {
							chatUsage["prompt_tokens"] = int64(it)
							fullUsage["input_tokens"] = it
						}
					}
				}
				if _, ok := chatUsage["completion_tokens"]; !ok {
					if u, ok2 := event["usage"].(map[string]any); ok2 {
						if ot, ok3 := u["output_tokens"].(float64); ok3 {
							chatUsage["completion_tokens"] = int64(ot)
							fullUsage["output_tokens"] = ot
						}
					}
				}
				pt := float64(0)
				if v, ok := chatUsage["prompt_tokens"].(int64); ok {
					pt = float64(v)
				}
				ct := float64(0)
				if v, ok := chatUsage["completion_tokens"].(int64); ok {
					ct = float64(v)
				}
				chatUsage["total_tokens"] = int64(pt + ct)
				if !roleSent {
					emitChatChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
					roleSent = true
				}
				emitChatChunk(map[string]any{}, finishReason, chatUsage)
			}

		case "message_stop":
			// nothing extra
		case "ping":
			// ignore
		}
	}

	w.Write([]byte("data: [DONE]\n\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

// ======================== Responses API ========================

func responsesInputToMessages(input any, instructions string) []Message {
	var messages []Message
	if instructions != "" {
		messages = append(messages, Message{Role: "system", Content: instructions})
	}
	switch v := input.(type) {
	case string:
		messages = append(messages, Message{Role: "user", Content: v})
	case []any:
		var pendingAssistant *Message
		ensurePendingAssistant := func() *Message {
			if pendingAssistant == nil {
				pendingAssistant = &Message{Role: "assistant", Content: ""}
			}
			return pendingAssistant
		}
		flushPendingAssistant := func() {
			if pendingAssistant == nil {
				return
			}
			if pendingAssistant.Content == nil {
				pendingAssistant.Content = ""
			}
			messages = append(messages, *pendingAssistant)
			pendingAssistant = nil
		}
		appendPendingReasoning := func(text string) {
			if text == "" {
				return
			}
			msg := ensurePendingAssistant()
			if msg.ReasoningContent == nil || *msg.ReasoningContent == "" {
				rc := text
				msg.ReasoningContent = &rc
				return
			}
			rc := *msg.ReasoningContent + "\n" + text
			msg.ReasoningContent = &rc
		}
		appendPendingText := func(text string) {
			if text == "" {
				return
			}
			msg := ensurePendingAssistant()
			if existing, ok := msg.Content.(string); ok && existing != "" {
				msg.Content = existing + "\n" + text
			} else {
				msg.Content = text
			}
		}
		for _, item := range v {
			switch elem := item.(type) {
			case string:
				flushPendingAssistant()
				messages = append(messages, Message{Role: "user", Content: elem})
			case map[string]any:
				itemType, _ := elem["type"].(string)
				switch itemType {
				case "function_call", "tool_call":
					if pendingAssistant != nil {
						if existing, ok := pendingAssistant.Content.(string); ok && strings.TrimSpace(existing) != "" && len(pendingAssistant.ToolCalls) == 0 {
							flushPendingAssistant()
						}
					}
					if tc, ok := responsesToolCallFromItem(elem); ok {
						msg := ensurePendingAssistant()
						msg.ToolCalls = append(msg.ToolCalls, tc)
					}
				case "function_call_output", "tool_result":
					flushPendingAssistant()
					callID, output := responsesToolOutputFromItem(elem)
					if callID != "" {
						messages = append(messages, Message{Role: "tool", ToolCallID: callID, Content: output})
					}
					continue
				case "reasoning":
					text := extractTextFromContentParts(elem["summary"])
					if text == "" {
						text = extractTextFromContentParts(elem["content"])
					}
					if text == "" {
						text, _ = elem["text"].(string)
					}
					appendPendingReasoning(text)
					continue
				case "message", "":
					role := "user"
					if r, ok := elem["role"].(string); ok && r != "" {
						role = r
					}
					if role == "developer" {
						role = "system"
					}
					if role == "assistant" {
						text := extractTextFromContentParts(elem["content"])
						if pendingAssistant != nil && len(pendingAssistant.ToolCalls) > 0 && text != "" {
							flushPendingAssistant()
						}
						appendPendingText(text)
					} else {
						flushPendingAssistant()
						content := responsesContentToChatContent(elem["content"])
						if role == "system" {
							content = extractTextFromContentParts(elem["content"])
						}
						messages = append(messages, Message{Role: role, Content: content})
					}
				default:
					flushPendingAssistant()
					role := "user"
					if r, ok := elem["role"].(string); ok && r != "" {
						role = r
					}
					content := responsesContentToChatContent(elem["content"])
					if content == "" {
						b, _ := json.Marshal(elem)
						content = string(b)
					}
					messages = append(messages, Message{Role: role, Content: content})
				}
			default:
				flushPendingAssistant()
				b, _ := json.Marshal(elem)
				messages = append(messages, Message{Role: "user", Content: string(b)})
			}
		}
		flushPendingAssistant()
	default:
		b, _ := json.Marshal(v)
		messages = append(messages, Message{Role: "user", Content: string(b)})
	}
	return messages
}

func responsesToolCallFromItem(elem map[string]any) (ToolCall, bool) {
	callID, _ := elem["call_id"].(string)
	if callID == "" {
		callID, _ = elem["id"].(string)
	}
	name, _ := elem["name"].(string)
	args, _ := elem["arguments"].(string)
	if args == "" {
		if rawArgs, ok := elem["arguments"]; ok && rawArgs != nil {
			b, _ := json.Marshal(rawArgs)
			args = string(b)
		}
	}
	if name == "" {
		if tu, ok := elem["tool_use"].(map[string]any); ok {
			name, _ = tu["name"].(string)
			if callID == "" {
				callID, _ = tu["id"].(string)
			}
			if a, ok := tu["arguments"].(string); ok {
				args = a
			} else if inp, ok := tu["input"]; ok {
				b, _ := json.Marshal(inp)
				args = string(b)
			}
		}
	}
	if callID == "" || name == "" {
		return ToolCall{}, false
	}
	if args == "" {
		args = "{}"
	}
	return ToolCall{
		ID:   callID,
		Type: "function",
		Function: FunctionCall{
			Name:      name,
			Arguments: args,
		},
	}, true
}

func responsesToolOutputFromItem(elem map[string]any) (string, any) {
	callID, _ := elem["call_id"].(string)
	if callID == "" {
		callID, _ = elem["tool_use_id"].(string)
	}
	if callID == "" {
		return "", ""
	}
	var output any
	switch o := elem["output"].(type) {
	case string:
		output = o
	case []any:
		if converted := responsesContentToChatContent(o); converted != "" {
			output = converted
		} else {
			b, _ := json.Marshal(o)
			output = string(b)
		}
	default:
		if o != nil {
			b, _ := json.Marshal(o)
			output = string(b)
		}
	}
	switch v := output.(type) {
	case nil:
		output = "[tool output missing]"
	case string:
		if v == "" {
			output = "[tool output missing]"
		}
	case []any:
		if len(v) == 0 {
			output = "[tool output missing]"
		}
	}
	return callID, output
}

// convertChatToolsToResponses 将 OpenAI Chat tools 转为 Responses tools 格式
func convertChatToolsToResponses(tools []any) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, raw := range tools {
		tool, ok := raw.(map[string]any)
		if !ok || tool == nil {
			continue
		}
		t, _ := tool["type"].(string)
		if t == "" {
			t = "function"
		}
		// Chat: {type:function, function:{name,description,parameters}}
		// Responses: {type:function, name, description, parameters}
		if fn, ok := tool["function"].(map[string]any); ok && fn != nil {
			item := map[string]any{"type": "function"}
			if name, ok := fn["name"].(string); ok {
				item["name"] = name
			}
			if desc, ok := fn["description"].(string); ok {
				item["description"] = desc
			}
			if params, ok := fn["parameters"]; ok {
				item["parameters"] = params
			} else {
				item["parameters"] = map[string]any{"type": "object", "properties": map[string]any{}}
			}
			out = append(out, item)
			continue
		}
		// 已是 Responses 形态则尽量保留
		item := map[string]any{"type": t}
		for _, k := range []string{"name", "description", "parameters", "function"} {
			if v, ok := tool[k]; ok {
				item[k] = v
			}
		}
		out = append(out, item)
	}
	return out
}

// convertChatToolChoiceToResponses 将 OpenAI Chat tool_choice 转为 Responses tool_choice
func convertChatToolChoiceToResponses(choice any) any {
	if choice == nil {
		return nil
	}
	switch v := choice.(type) {
	case string:
		return v
	case map[string]any:
		// Chat: {"type":"function","function":{"name":"xxx"}}
		// Responses: {"type":"function","name":"xxx"}
		if t, _ := v["type"].(string); t == "function" {
			if fn, ok := v["function"].(map[string]any); ok {
				if name, ok := fn["name"].(string); ok && name != "" {
					return map[string]any{"type": "function", "name": name}
				}
			}
			if name, ok := v["name"].(string); ok && name != "" {
				return map[string]any{"type": "function", "name": name}
			}
		}
		return v
	default:
		return choice
	}
}

func convertResponsesToolsWithMappings(tools []ResponsesTool) ([]Tool, map[string]ResponseToolNameMapping) {
	converted := make([]Tool, 0, len(tools))
	mappings := map[string]ResponseToolNameMapping{}
	for _, tool := range tools {
		switch tool.Type {
		case "function":
			if fn, ok := responsesToolFunction(tool, ""); ok {
				converted = append(converted, Tool{Type: "function", Function: fn})
			}
		case "namespace":
			namespace := strings.TrimSpace(tool.Name)
			for _, nested := range tool.Tools {
				if nested.Type != "function" {
					continue
				}
				if fn, ok := responsesToolFunction(nested, namespace); ok {
					converted = append(converted, Tool{Type: "function", Function: fn})
					mappings[fn.Name] = ResponseToolNameMapping{
						Namespace: namespace,
						Name:      responseToolName(nested),
					}
				}
			}
		}
	}
	return converted, mappings
}

func responsesToolFunction(tool ResponsesTool, namespace string) (ToolFunction, bool) {
	fn := ToolFunction{
		Name:        tool.Name,
		Description: tool.Description,
		Parameters:  tool.Parameters,
	}
	if tool.Function != nil {
		fn = *tool.Function
	}
	fn.Name = strings.TrimSpace(fn.Name)
	if fn.Name == "" {
		return ToolFunction{}, false
	}
	if namespace != "" {
		fn.Name = flattenNamespaceToolName(namespace, fn.Name)
	}
	if fn.Parameters == nil {
		fn.Parameters = map[string]any{"type": "object", "properties": map[string]any{}}
	}
	return fn, true
}

func responseToolName(tool ResponsesTool) string {
	if tool.Function != nil {
		return strings.TrimSpace(tool.Function.Name)
	}
	return strings.TrimSpace(tool.Name)
}

func flattenNamespaceToolName(namespace, toolName string) string {
	ns := strings.TrimSuffix(strings.TrimSpace(namespace), "__")
	name := strings.TrimSpace(toolName)
	if ns == "" {
		return name
	}
	return ns + "__" + name
}

func convertResponsesToolChoice(choice any) any {
	if choice == nil {
		return nil
	}
	choiceMap, ok := choice.(map[string]any)
	if !ok {
		return choice
	}
	if choiceMap["type"] == "function" {
		if name, ok := choiceMap["name"].(string); ok && name != "" {
			return map[string]any{
				"type":     "function",
				"function": map[string]any{"name": name},
			}
		}
	}
	if choiceMap["type"] == "namespace" {
		namespace, _ := choiceMap["name"].(string)
		toolName, _ := choiceMap["tool"].(string)
		if toolName == "" {
			toolName, _ = choiceMap["tool_name"].(string)
		}
		if namespace != "" && toolName != "" {
			return map[string]any{
				"type":     "function",
				"function": map[string]any{"name": flattenNamespaceToolName(namespace, toolName)},
			}
		}
	}
	return choice
}

func responseFunctionCallItem(itemID, status, arguments, callID, name string, mappings map[string]ResponseToolNameMapping) map[string]any {
	item := map[string]any{
		"id":        itemID,
		"type":      "function_call",
		"status":    status,
		"arguments": arguments,
		"call_id":   callID,
		"name":      name,
	}
	if mapping, ok := responseToolNameMapping(name, mappings); ok {
		item["name"] = mapping.Name
		item["namespace"] = mapping.Namespace
	}
	return item
}

func responseToolNameMapping(name string, mappings map[string]ResponseToolNameMapping) (ResponseToolNameMapping, bool) {
	if len(mappings) == 0 {
		return ResponseToolNameMapping{}, false
	}
	if mapping, ok := mappings[name]; ok {
		return mapping, true
	}
	normalized := normalizeResponseToolCallKey(name)
	if mapping, ok := mappings[normalized]; ok {
		return mapping, true
	}
	return ResponseToolNameMapping{}, false
}

func normalizeResponseToolCallKey(name string) string {
	normalized := strings.NewReplacer(":", "__", ".", "__", "/", "__", "-", "_").Replace(strings.TrimSpace(name))
	for strings.Contains(normalized, "___") {
		normalized = strings.ReplaceAll(normalized, "___", "__")
	}
	return normalized
}

func responsesContentToChatContent(content any) any {
	if content == nil {
		return ""
	}
	if s, ok := content.(string); ok {
		return s
	}
	parts, ok := content.([]any)
	if !ok {
		text := extractTextFromContentParts(content)
		if text != "" {
			return text
		}
		return ""
	}

	var converted []any
	var textParts []string
	hasImage := false
	for _, p := range parts {
		part, ok := p.(map[string]any)
		if !ok {
			continue
		}
		partType, _ := part["type"].(string)
		switch partType {
		case "input_text", "output_text", "summary_text", "text":
			if text, ok := part["text"].(string); ok && text != "" {
				textParts = append(textParts, text)
				converted = append(converted, map[string]any{"type": "text", "text": text})
			}
		case "input_image", "image_url":
			imageURL := responsesImageURLFromPart(part)
			if imageURL != nil {
				hasImage = true
				converted = append(converted, map[string]any{"type": "image_url", "image_url": imageURL})
			}
		}
	}
	if len(converted) == 0 {
		return ""
	}
	if hasImage {
		return converted
	}
	return strings.Join(textParts, "\n")
}

func responsesImageURLFromPart(part map[string]any) map[string]any {
	url := ""
	detail := ""
	if v, ok := part["image_url"].(string); ok {
		url = v
	}
	if imageURL, ok := part["image_url"].(map[string]any); ok {
		if u, ok := imageURL["url"].(string); ok {
			url = u
		}
		if d, ok := imageURL["detail"].(string); ok {
			detail = d
		}
	}
	if url == "" {
		if v, ok := part["url"].(string); ok {
			url = v
		}
	}
	if detail == "" {
		detail, _ = part["detail"].(string)
	}
	if url == "" {
		return nil
	}
	imageURL := map[string]any{"url": url}
	if detail != "" {
		imageURL["detail"] = detail
	}
	return imageURL
}

func extractTextFromContentParts(content any) string {
	parts, ok := content.([]any)
	if !ok {
		if s, ok := content.(string); ok {
			return s
		}
		return ""
	}
	var texts []string
	for _, p := range parts {
		if part, ok := p.(map[string]any); ok {
			if part["type"] == "input_text" || part["type"] == "output_text" || part["type"] == "summary_text" || part["type"] == "text" {
				if t, ok := part["text"].(string); ok {
					texts = append(texts, t)
				}
			}
		}
	}
	return strings.Join(texts, "\n")
}

func responsesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	cnt := requestCount.Add(1)
	if debugMode {
		log.Printf("[request #%d] POST /v1/responses\n%s", cnt, string(body))
	}

	var respReq ResponsesAPIRequest
	if err := json.Unmarshal(body, &respReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	rec := newUsageRecorder("responses", respReq.Model, respReq.Stream)
	defer rec.Finish()
	r = withUsageRecorder(r, rec)

	resolvedModel, modelAliasInfo, upstreamName, upstream := resolveModel(respReq.Model)
	if !isKnownAlias(respReq.Model) {
		http.Error(w, `{"error":{"message":"model not found; only configured aliases are accepted","type":"invalid_request_error"}}`, http.StatusBadRequest)
		return
	}
	respReq.Model = resolvedModel
	if respReq.Model == "" {
		http.Error(w, `{"error":"model is required"}`, http.StatusBadRequest)
		return
	}

	if upstream != nil && upstream.APIType == UpstreamResponses {
		rawBody, err := prepareResponsesPassthroughBody(body, respReq.Model, modelAliasInfo)
		if err != nil {
			log.Printf("[request invalid] path=/v1/responses mode=passthrough model=%q err=%v", respReq.Model, err)
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if respReq.Stream {
			upResp, status, upHeader, err := callPreparedUpstreamStream(r.Context(), rawBody, upstreamName, respReq.Model, "responses", upstream, modelAliasInfo.Socks5Proxy)
			if err != nil || status < 200 || status >= 300 {
				w.Header().Set("Content-Type", "application/json")
				status = applyUpstreamErrorHeaders(w, upHeader, status)
				w.WriteHeader(status)
				if upResp != nil {
					errBody, _ := io.ReadAll(upResp)
					if len(errBody) > 0 {
						w.Write(errBody)
						return
					}
				}
				json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error"}})
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.WriteHeader(http.StatusOK)
			if err := proxyResponsesPassthroughStream(w, upResp, respReq.Model, rec); err != nil && debugMode {
				log.Printf("[responses raw stream proxy error] %v", err)
			}
			return
		}

		respBody, status, upHeader, err := callPreparedUpstream(r.Context(), rawBody, upstreamName, respReq.Model, "responses", upstream, modelAliasInfo.Socks5Proxy, true)
		if err != nil || status < 200 || status >= 300 {
			w.Header().Set("Content-Type", "application/json")
			status = applyUpstreamErrorHeaders(w, upHeader, status)
			w.WriteHeader(status)
			if len(respBody) > 0 {
				w.Write(respBody)
			} else {
				json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error"}})
			}
			return
		}
		var usageResp map[string]any
		if json.Unmarshal(respBody, &usageResp) == nil {
			if u, ok := usageResp["usage"].(map[string]any); ok {
				rec.MarkUsageFromMap(u)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if debugMode {
			log.Printf("[responses raw response]\n%s", string(respBody))
		}
		w.Write(respBody)
		return
	}

	// 多模态路由

	messages := respReq.Messages
	if len(messages) == 0 {
		messages = responsesInputToMessages(respReq.Input, respReq.Instructions)
	} else if respReq.Instructions != "" {
		messages = append([]Message{{Role: "system", Content: respReq.Instructions}}, messages...)
	}

	chatReq := OpenAIRequest{
		Model:    respReq.Model,
		Messages: messages,
		Stream:   respReq.Stream,
	}
	toolNameMappings := map[string]ResponseToolNameMapping{}
	if respReq.Temperature != 0 {
		chatReq.Temperature = &respReq.Temperature
	}
	if respReq.MaxTokens != 0 {
		chatReq.MaxTokens = respReq.MaxTokens
	}
	if respReq.TopP != 0 {
		chatReq.TopP = &respReq.TopP
	}
	if len(respReq.Tools) > 0 {
		chatReq.Tools, toolNameMappings = convertResponsesToolsWithMappings(respReq.Tools)
	}
	if respReq.ToolChoice != nil {
		chatReq.ToolChoice = convertResponsesToolChoice(respReq.ToolChoice)
	}
	if respReq.ParallelToolCalls != nil {
		chatReq.ExtraBody = map[string]any{"parallel_tool_calls": *respReq.ParallelToolCalls}
	}
	// reasoning.effort describes the current request and is independent from
	// WithReasoning, which only controls replaying historical reasoning_content.
	if respReq.Reasoning.Effort != "" {
		if respReq.Reasoning.Effort != "none" {
			chatReq.ReasoningEffort = respReq.Reasoning.Effort
		}
	}

	chatReq.Messages = fixToolCallGaps(chatReq.Messages)
	chatReq.Messages, err = normalizeMessagesToolCallArguments(chatReq.Messages)
	if err != nil {
		log.Printf("[request invalid] path=/v1/responses model=%q err=%v", chatReq.Model, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ensureReasoningEffort(&chatReq, modelAliasInfo)
	chatReq.Messages = ensureReasoningContent(chatReq.Messages, modelAliasInfo.WithReasoning)

	upstreamBody := buildUpstreamBody(&chatReq, modelAliasInfo.WithReasoning)

	// callUpstream/callUpstreamStream 内部会根据当前请求选中的 upstream.APIType 自动转换请求格式
	// 不需要在这里手动转换，避免双重转换导致请求体丢失
	// 流式响应需要特殊处理
	if respReq.Stream {
		upResp, status, upHeader, err := callUpstreamStream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "responses", upstream, modelAliasInfo.Socks5Proxy)
		if err != nil || status < 200 || status >= 300 {
			w.Header().Set("Content-Type", "application/json")
			status = applyUpstreamErrorHeaders(w, upHeader, status)
			w.WriteHeader(status)
			if upResp != nil {
				errBody, _ := io.ReadAll(upResp)
				if len(errBody) > 0 {
					w.Write(errBody)
					return
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error"}})
			return
		}
		defer upResp.Close()

		// 注：Responses 上游已在上方同协议直通处理，此处不会到达。
		resp := &http.Response{
			StatusCode: status,
			Body:       upResp,
			Header:     make(http.Header),
		}
		if upstream != nil && upstream.APIType == UpstreamAnthropic {
			// Anthropic 上游：先转为 Chat SSE 流，再转为 Responses SSE 流
			pr, pw := io.Pipe()
			go func() {
				defer pw.Close()
				chatW := &pipeResponseWriter{w: pw}
				anthropicStreamToChatHandler(chatW, upResp, chatReq.Model, rec)
			}()
			chatResp := &http.Response{
				StatusCode: status,
				Body:       pr,
				Header:     make(http.Header),
			}
			responsesStreamHandler(w, r, chatResp, chatReq.Model, chatReq.Tools, chatReq.ToolChoice, toolNameMappings, rec)
		} else {
			// OpenAI 上游：Chat SSE 流直接转为 Responses SSE 流
			responsesStreamHandler(w, r, resp, chatReq.Model, chatReq.Tools, chatReq.ToolChoice, toolNameMappings, rec)
		}
		return
	}

	respBody, status, upHeader, err := callUpstream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "responses", upstream, modelAliasInfo.Socks5Proxy)
	if err != nil || status < 200 || status >= 300 {
		w.Header().Set("Content-Type", "application/json")
		status = applyUpstreamErrorHeaders(w, upHeader, status)
		w.WriteHeader(status)
		if len(respBody) > 0 {
			w.Write(respBody)
		} else {
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error"}})
		}
		return
	}

	// 注：Responses 上游已在上方同协议直通处理，此处不会到达。
	// callUpstream 返回的 respBody 已统一为 Chat 格式，再转为 Responses API 格式
	responsesBody := convertChatToResponses(respBody, chatReq.Model, chatReq.Tools, chatReq.ToolChoice, toolNameMappings)

	var usageResp2 map[string]any
	if json.Unmarshal(respBody, &usageResp2) == nil {
		if u, ok := usageResp2["usage"].(map[string]any); ok {
			rec.MarkUsageFromMap(u)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if debugMode {
		log.Printf("[responses response]\n%s", string(responsesBody))
	}
	w.Write(responsesBody)
}

// ======================== Responses Stream Handler ========================

func responsesStreamHandler(w http.ResponseWriter, _ *http.Request, resp *http.Response, model string, tools []Tool, toolChoice any, toolNameMappings map[string]ResponseToolNameMapping, rec *usageRecorder) {
	// 必须关闭：作为 pipe 读端时，提前 return 会让写端 goroutine 永久阻塞
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(resp.Body)

	responseID := "resp_" + time.Now().Format("20060102150405") + "_" + randomString(8)
	reasoningID := "rs_" + responseID
	msgID := "msg_" + responseID + "_0"
	createdAt := time.Now().Unix()
	seq := 0

	reasoningStarted := false
	reasoningDone := false
	messageStarted := false
	messageDone := false
	isIncomplete := false
	incompleteReason := ""
	terminalFinishSeen := false
	fullReasoning := ""
	fullText := ""
	totalUsage := map[string]any{}
	createdSent := false
	toolCalls := map[int]map[string]any{}
	toolOrder := []int{}

	messageOutputIndex := func() int {
		if reasoningStarted {
			return 1
		}
		return 0
	}

	reasoningItem := func(status string) map[string]any {
		item := map[string]any{
			"id":      reasoningID,
			"type":    "reasoning",
			"summary": []any{},
		}
		if status != "" {
			item["status"] = status
		}
		if status == "completed" {
			item["encrypted_content"] = ""
		}
		if fullReasoning != "" {
			item["summary"] = []any{map[string]any{"type": "summary_text", "text": fullReasoning}}
		}
		return item
	}

	messageItem := func(status string) map[string]any {
		content := []any{map[string]any{
			"type":        "output_text",
			"annotations": []any{},
			"logprobs":    []any{},
			"text":        fullText,
		}}
		return map[string]any{
			"id":      msgID,
			"type":    "message",
			"status":  status,
			"content": content,
			"role":    "assistant",
		}
	}

	emitReasoningDone := func() {
		if !reasoningStarted || reasoningDone {
			return
		}
		seq++
		emitSSEEvent(w, flusher, "response.reasoning_summary_text.done", map[string]any{
			"type":            "response.reasoning_summary_text.done",
			"sequence_number": seq,
			"item_id":         reasoningID,
			"output_index":    0,
			"summary_index":   0,
			"text":            fullReasoning,
		})
		seq++
		emitSSEEvent(w, flusher, "response.reasoning_summary_part.done", map[string]any{
			"type":            "response.reasoning_summary_part.done",
			"sequence_number": seq,
			"item_id":         reasoningID,
			"output_index":    0,
			"summary_index":   0,
			"part":            map[string]any{"type": "summary_text", "text": fullReasoning},
		})
		seq++
		emitSSEEvent(w, flusher, "response.output_item.done", map[string]any{
			"type":            "response.output_item.done",
			"sequence_number": seq,
			"output_index":    0,
			"item":            reasoningItem("completed"),
		})
		reasoningDone = true
	}

	emitMessageDone := func() {
		if !messageStarted || messageDone {
			return
		}
		idx := messageOutputIndex()
		seq++
		emitSSEEvent(w, flusher, "response.output_text.done", map[string]any{
			"type":            "response.output_text.done",
			"sequence_number": seq,
			"item_id":         msgID,
			"output_index":    idx,
			"content_index":   0,
			"text":            fullText,
			"logprobs":        []any{},
		})
		seq++
		emitSSEEvent(w, flusher, "response.content_part.done", map[string]any{
			"type":            "response.content_part.done",
			"sequence_number": seq,
			"item_id":         msgID,
			"output_index":    idx,
			"content_index":   0,
			"part":            map[string]any{"type": "output_text", "annotations": []any{}, "logprobs": []any{}, "text": fullText},
		})
		seq++
		emitSSEEvent(w, flusher, "response.output_item.done", map[string]any{
			"type":            "response.output_item.done",
			"sequence_number": seq,
			"output_index":    idx,
			"item":            messageItem("completed"),
		})
		messageDone = true
	}

	emitToolCallDone := func(idx int, call map[string]any) {
		if done, _ := call["done"].(bool); done {
			return
		}
		itemID, _ := call["item_id"].(string)
		callID, _ := call["call_id"].(string)
		name, _ := call["name"].(string)
		args, _ := call["arguments"].(string)
		normalizedArgs, err := normalizeToolCallArguments(args)
		if err != nil {
			logStreamToolCallArgumentsValidationFailure("responsesStreamHandler.emitToolCallDone", itemID, callID, name, args, idx, err)
			isIncomplete = true
			if incompleteReason == "" {
				incompleteReason = "tool_call_arguments_incomplete"
			}
			return
		}
		call["arguments"] = normalizedArgs
		call["done"] = true
		seq++
		emitSSEEvent(w, flusher, "response.function_call_arguments.done", map[string]any{
			"type":            "response.function_call_arguments.done",
			"sequence_number": seq,
			"item_id":         itemID,
			"output_index":    idx,
			"arguments":       normalizedArgs,
		})
		seq++
		emitSSEEvent(w, flusher, "response.output_item.done", map[string]any{
			"type":            "response.output_item.done",
			"sequence_number": seq,
			"output_index":    idx,
			"item":            responseFunctionCallItem(itemID, "completed", normalizedArgs, callID, name, toolNameMappings),
		})
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading stream: %v", err)
			return
		}
		if debugMode && strings.HasPrefix(line, "data: ") {
			log.Printf("[upstream raw chunk] %s", strings.TrimSpace(line[6:]))
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
			break
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		var chunk map[string]any
		if err := json.Unmarshal([]byte(line[6:]), &chunk); err != nil {
			continue
		}
		if !createdSent {
			if id, ok := chunk["id"].(string); ok && id != "" {
				responseID = id
				reasoningID = "rs_" + responseID + "_0"
				msgID = "msg_" + responseID + "_0"
			}
			if created, ok := chunk["created"].(float64); ok {
				createdAt = int64(created)
			}
			seq++
			emitSSEEvent(w, flusher, "response.created", map[string]any{
				"type":            "response.created",
				"sequence_number": seq,
				"response":        map[string]any{"id": responseID, "object": "response", "created_at": createdAt, "status": "in_progress", "background": false, "error": nil, "output": []any{}},
			})
			seq++
			emitSSEEvent(w, flusher, "response.in_progress", map[string]any{
				"type":            "response.in_progress",
				"sequence_number": seq,
				"response":        map[string]any{"id": responseID, "object": "response", "created_at": createdAt, "status": "in_progress"},
			})
			createdSent = true
		}
		choices, ok := chunk["choices"].([]any)
		if !ok || len(choices) == 0 {
			if usage, ok := chunk["usage"].(map[string]any); ok {
				totalUsage = usage
			}
			continue
		}

		choice, _ := choices[0].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		normalizeReasoningContent(delta)
		finishReason, _ := choice["finish_reason"].(string)

		if rc, ok := delta["reasoning_content"]; ok {
			rcStr, _ := rc.(string)
			if rcStr != "" {
				if !reasoningStarted {
					seq++
					emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
						"type":            "response.output_item.added",
						"sequence_number": seq,
						"output_index":    0,
						"item":            reasoningItem("in_progress"),
					})
					seq++
					emitSSEEvent(w, flusher, "response.reasoning_summary_part.added", map[string]any{
						"type":            "response.reasoning_summary_part.added",
						"sequence_number": seq,
						"item_id":         reasoningID,
						"output_index":    0,
						"summary_index":   0,
						"part":            map[string]any{"type": "summary_text", "text": ""},
					})
					reasoningStarted = true
				}
				fullReasoning += rcStr
				seq++
				emitSSEEvent(w, flusher, "response.reasoning_summary_text.delta", map[string]any{
					"type":            "response.reasoning_summary_text.delta",
					"sequence_number": seq,
					"item_id":         reasoningID,
					"output_index":    0,
					"summary_index":   0,
					"delta":           rcStr,
				})
			}
		}

		contentStr := ""
		if c, ok := delta["content"]; ok && c != nil {
			contentStr, _ = c.(string)
		}
		if contentStr != "" {
			emitReasoningDone()
			if !messageStarted {
				idx := messageOutputIndex()
				seq++
				emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
					"type":            "response.output_item.added",
					"sequence_number": seq,
					"output_index":    idx,
					"item":            map[string]any{"id": msgID, "type": "message", "status": "in_progress", "content": []any{}, "role": "assistant"},
				})
				seq++
				emitSSEEvent(w, flusher, "response.content_part.added", map[string]any{
					"type":            "response.content_part.added",
					"sequence_number": seq,
					"item_id":         msgID,
					"output_index":    idx,
					"content_index":   0,
					"part":            map[string]any{"type": "output_text", "annotations": []any{}, "logprobs": []any{}, "text": ""},
				})
				messageStarted = true
			}
			fullText += contentStr
			seq++
			emitSSEEvent(w, flusher, "response.output_text.delta", map[string]any{
				"type":            "response.output_text.delta",
				"sequence_number": seq,
				"item_id":         msgID,
				"output_index":    messageOutputIndex(),
				"content_index":   0,
				"delta":           contentStr,
				"logprobs":        []any{},
			})
		}

		rawToolCalls, _ := delta["tool_calls"].([]any)
		for _, rawToolCall := range rawToolCalls {
			tc, ok := rawToolCall.(map[string]any)
			if !ok {
				continue
			}
			idxFloat, _ := tc["index"].(float64)
			upstreamIndex := int(idxFloat)
			call, exists := toolCalls[upstreamIndex]
			if !exists {
				outputIndex := messageOutputIndex()
				if messageStarted {
					outputIndex++
				}
				outputIndex += len(toolOrder)
				callID, _ := tc["id"].(string)
				if callID == "" {
					callID = "call_" + randomString(12)
				}
				fn, _ := tc["function"].(map[string]any)
				name, _ := fn["name"].(string)
				call = map[string]any{
					"output_index": outputIndex,
					"item_id":      "fc_" + callID,
					"call_id":      callID,
					"name":         name,
					"arguments":    "",
					"done":         false,
				}
				toolCalls[upstreamIndex] = call
				toolOrder = append(toolOrder, upstreamIndex)
				seq++
				emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
					"type":            "response.output_item.added",
					"sequence_number": seq,
					"output_index":    outputIndex,
					"item":            responseFunctionCallItem(call["item_id"].(string), "in_progress", "", callID, name, toolNameMappings),
				})
			}
			fn, _ := tc["function"].(map[string]any)
			if name, _ := fn["name"].(string); name != "" {
				call["name"] = name
			}
			if argDelta, _ := fn["arguments"].(string); argDelta != "" {
				call["arguments"] = call["arguments"].(string) + argDelta
				seq++
				emitSSEEvent(w, flusher, "response.function_call_arguments.delta", map[string]any{
					"type":            "response.function_call_arguments.delta",
					"sequence_number": seq,
					"item_id":         call["item_id"],
					"output_index":    call["output_index"],
					"delta":           argDelta,
				})
			}
		}

		if usage, ok := chunk["usage"].(map[string]any); ok {
			totalUsage = usage
		}
		if finishReason == "stop" || finishReason == "length" || finishReason == "tool_calls" || finishReason == "function_call" || finishReason == "content_filter" {
			terminalFinishSeen = true
			if finishReason == "length" {
				isIncomplete = true
				incompleteReason = "max_output_tokens"
			}
			emitReasoningDone()
			if !messageStarted && len(toolCalls) == 0 {
				idx := messageOutputIndex()
				seq++
				emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
					"type":            "response.output_item.added",
					"sequence_number": seq,
					"output_index":    idx,
					"item":            map[string]any{"id": msgID, "type": "message", "status": "in_progress", "content": []any{}, "role": "assistant"},
				})
				seq++
				emitSSEEvent(w, flusher, "response.content_part.added", map[string]any{
					"type":            "response.content_part.added",
					"sequence_number": seq,
					"item_id":         msgID,
					"output_index":    idx,
					"content_index":   0,
					"part":            map[string]any{"type": "output_text", "annotations": []any{}, "logprobs": []any{}, "text": ""},
				})
				messageStarted = true
			}
			emitMessageDone()
			for _, idx := range toolOrder {
				emitToolCallDone(toolCalls[idx]["output_index"].(int), toolCalls[idx])
			}
		}
	}

	if !terminalFinishSeen {
		isIncomplete = true
		if incompleteReason == "" {
			incompleteReason = "stream_ended_early"
		}
		log.Printf("[responses stream incomplete] model=%q reason=%s message_started=%t tool_calls=%d", model, incompleteReason, messageStarted, len(toolOrder))
	}

	emitReasoningDone()
	emitMessageDone()
	if terminalFinishSeen {
		for _, idx := range toolOrder {
			emitToolCallDone(toolCalls[idx]["output_index"].(int), toolCalls[idx])
		}
	}

	output := []any{}
	if reasoningStarted {
		output = append(output, reasoningItem("completed"))
	}
	if messageStarted {
		output = append(output, messageItem("completed"))
	}
	for _, idx := range toolOrder {
		call := toolCalls[idx]
		args, _ := call["arguments"].(string)
		normalizedArgs, err := normalizeToolCallArguments(args)
		if err != nil {
			itemID, _ := call["item_id"].(string)
			callID, _ := call["call_id"].(string)
			name, _ := call["name"].(string)
			logStreamToolCallArgumentsValidationFailure("responsesStreamHandler.output", itemID, callID, name, args, call["output_index"].(int), err)
			isIncomplete = true
			if incompleteReason == "" {
				incompleteReason = "tool_call_arguments_incomplete"
			}
			continue
		}
		call["arguments"] = normalizedArgs
		itemStatus := "completed"
		if !terminalFinishSeen {
			itemStatus = "in_progress"
		}
		output = append(output, responseFunctionCallItem(
			call["item_id"].(string),
			itemStatus,
			normalizedArgs,
			call["call_id"].(string),
			call["name"].(string),
			toolNameMappings,
		))
	}

	responseStatus := "completed"
	incompleteDetails := any(nil)
	if isIncomplete {
		responseStatus = "incomplete"
		reason := incompleteReason
		if reason == "" {
			reason = "max_output_tokens"
		}
		incompleteDetails = map[string]any{"reason": reason}
	}
	completedResponse := map[string]any{
		"id":                 responseID,
		"object":             "response",
		"created_at":         createdAt,
		"status":             responseStatus,
		"background":         false,
		"error":              nil,
		"incomplete_details": incompleteDetails,
		"model":              model,
		"output":             output,
	}
	if len(tools) > 0 {
		rawTools := make([]any, 0, len(tools))
		for _, t := range tools {
			rawTools = append(rawTools, map[string]any{
				"type": t.Type,
				"function": map[string]any{
					"name":        t.Function.Name,
					"description": t.Function.Description,
					"parameters":  t.Function.Parameters,
				},
			})
		}
		completedResponse["tools"] = convertChatToolsToResponses(rawTools)
	}
	if toolChoice != nil {
		completedResponse["tool_choice"] = convertChatToolChoiceToResponses(toolChoice)
	}

	usage := map[string]any{}
	if len(totalUsage) > 0 {
		if v, ok := totalUsage["prompt_tokens"]; ok {
			usage["input_tokens"] = v
		}
		if v, ok := totalUsage["prompt_tokens_details"]; ok {
			usage["input_tokens_details"] = v
		} else {
			usage["input_tokens_details"] = map[string]any{"cached_tokens": 0}
		}
		if v, ok := totalUsage["completion_tokens"]; ok {
			usage["output_tokens"] = v
		}
		if v, ok := totalUsage["completion_tokens_details"]; ok {
			usage["output_tokens_details"] = v
		}
		if v, ok := totalUsage["total_tokens"]; ok {
			usage["total_tokens"] = v
		}
		if v, ok := totalUsage["input_tokens"]; ok && usage["input_tokens"] == nil {
			usage["input_tokens"] = v
		}
		if v, ok := totalUsage["output_tokens"]; ok && usage["output_tokens"] == nil {
			usage["output_tokens"] = v
		}
	}
	// Always ensure total_tokens is present
	if _, ok := usage["total_tokens"]; !ok {
		pt := float64(0)
		ct := float64(0)
		if v, ok := usage["input_tokens"].(float64); ok {
			pt = v
		} else if v, ok := usage["input_tokens"].(int64); ok {
			pt = float64(v)
		}
		if v, ok := usage["output_tokens"].(float64); ok {
			ct = v
		} else if v, ok := usage["output_tokens"].(int64); ok {
			ct = float64(v)
		}
		usage["total_tokens"] = pt + ct
	}
	// 确保 usage 字段完整
	if _, ok := usage["input_tokens"]; !ok {
		usage["input_tokens"] = float64(0)
	}
	if _, ok := usage["output_tokens"]; !ok {
		usage["output_tokens"] = float64(0)
	}
	completedResponse["usage"] = usage

	rec.MarkUsageFromMap(totalUsage)

	emitSSEEvent(w, flusher, "response."+responseStatus, map[string]any{
		"type":     "response." + responseStatus,
		"response": completedResponse,
	})

	if flusher != nil {
		flusher.Flush()
	}
}

func convertChatToResponses(chatBody []byte, model string, tools []Tool, toolChoice any, toolNameMappings map[string]ResponseToolNameMapping) []byte {
	var chat struct {
		ID      string `json:"id"`
		Created int64  `json:"created"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content          string     `json:"content"`
				ReasoningContent string     `json:"reasoning_content"`
				Reasoning        string     `json:"reasoning"`
				ToolCalls        []ToolCall `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Usage map[string]any `json:"usage"`
	}
	if err := json.Unmarshal(chatBody, &chat); err != nil {
		log.Printf("Warning: convertChatToResponses unmarshal failed: %v", err)
	}

	text := ""
	reasoning := ""
	finishReason := ""
	var toolCalls []ToolCall
	if len(chat.Choices) > 0 {
		text = chat.Choices[0].Message.Content
		reasoning = chat.Choices[0].Message.ReasoningContent
		if reasoning == "" {
			reasoning = chat.Choices[0].Message.Reasoning
		}
		toolCalls = chat.Choices[0].Message.ToolCalls
		finishReason = chat.Choices[0].FinishReason
	}

	status := "completed"
	if finishReason == "length" {
		status = "incomplete"
	}

	responses := map[string]any{
		"id":                 chat.ID,
		"object":             "response",
		"status":             status,
		"background":         false,
		"error":              nil,
		"incomplete_details": nil,
		"model":              model,
		"created_at":         chat.Created,
	}
	if len(tools) > 0 {
		// 回显时使用 Responses tools 形态
		rawTools := make([]any, 0, len(tools))
		for _, t := range tools {
			rawTools = append(rawTools, map[string]any{
				"type": t.Type,
				"function": map[string]any{
					"name":        t.Function.Name,
					"description": t.Function.Description,
					"parameters":  t.Function.Parameters,
				},
			})
		}
		responses["tools"] = convertChatToolsToResponses(rawTools)
	}
	if toolChoice != nil {
		responses["tool_choice"] = convertChatToolChoiceToResponses(toolChoice)
	}
	outputID := "msg_" + chat.ID + "_0"
	output := []any{}
	if reasoning != "" {
		output = append(output, map[string]any{
			"id":                "rs_" + chat.ID,
			"type":              "reasoning",
			"encrypted_content": "",
			"summary":           []any{map[string]any{"type": "summary_text", "text": reasoning}},
		})
	}
	// 有文本时输出 message；仅有 tool_calls 时不注入空 message（与流式路径一致）
	if text != "" || len(toolCalls) == 0 {
		output = append(output, map[string]any{
			"id":     outputID,
			"type":   "message",
			"status": "completed",
			"role":   "assistant",
			"content": []any{map[string]any{
				"type":        "output_text",
				"text":        text,
				"annotations": []any{},
				"logprobs":    []any{},
			}},
		})
	}
	for _, tc := range toolCalls {
		output = append(output, responseFunctionCallItem("fc_"+tc.ID, "completed", tc.Function.Arguments, tc.ID, tc.Function.Name, toolNameMappings))
	}
	responses["output"] = output
	usage := map[string]any{}
	if chat.Usage != nil {
		if v, ok := chat.Usage["prompt_tokens"]; ok {
			usage["input_tokens"] = v
		}
		if v, ok := chat.Usage["prompt_tokens_details"]; ok {
			usage["input_tokens_details"] = v
		} else {
			usage["input_tokens_details"] = map[string]any{"cached_tokens": 0}
		}
		if v, ok := chat.Usage["completion_tokens"]; ok {
			usage["output_tokens"] = v
		}
		if v, ok := chat.Usage["completion_tokens_details"]; ok {
			usage["output_tokens_details"] = v
		}
		if v, ok := chat.Usage["total_tokens"]; ok {
			usage["total_tokens"] = v
		}
		if v, ok := chat.Usage["input_tokens"]; ok && usage["input_tokens"] == nil {
			usage["input_tokens"] = v
		}
		if v, ok := chat.Usage["output_tokens"]; ok && usage["output_tokens"] == nil {
			usage["output_tokens"] = v
		}
	}
	// Always ensure total_tokens is present
	if _, ok := usage["total_tokens"]; !ok {
		pt := float64(0)
		ct := float64(0)
		if v, ok := usage["input_tokens"].(float64); ok {
			pt = v
		} else if v, ok := usage["input_tokens"].(int64); ok {
			pt = float64(v)
		}
		if v, ok := usage["output_tokens"].(float64); ok {
			ct = v
		} else if v, ok := usage["output_tokens"].(int64); ok {
			ct = float64(v)
		}
		usage["total_tokens"] = pt + ct
	}
	// 确保 usage 字段完整
	if _, ok := usage["input_tokens"]; !ok {
		usage["input_tokens"] = float64(0)
	}
	if _, ok := usage["output_tokens"]; !ok {
		usage["output_tokens"] = float64(0)
	}
	responses["usage"] = usage

	// 非流式 Responses API 直接返回 response 对象，不包成 SSE 事件外壳
	result, _ := json.Marshal(responses)
	return result
}

func emitSSEEvent(w http.ResponseWriter, flusher http.Flusher, event string, data map[string]any) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshaling SSE event: %v", err)
		return
	}
	w.Write([]byte("event: " + event + "\n"))
	w.Write([]byte("data: " + string(jsonData) + "\n\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

// ======================== Admin 管理页面 ========================

func upstreamModelsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	var probe *UpstreamConfig
	if r.Method == http.MethodPost && r.Body != nil {
		// 优先用请求体里的临时配置(未保存也能拉取),实现"填好 URL+key 直接试拉"。
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body failed", http.StatusBadRequest)
			return
		}
		if len(strings.TrimSpace(string(data))) > 0 {
			probe = &UpstreamConfig{}
			if err := json.Unmarshal(data, probe); err != nil {
				http.Error(w, "invalid config json", http.StatusBadRequest)
				return
			}
		}
	}
	if probe == nil {
		// 没传请求体时回退用已保存配置(name 必填)。
		if name == "" {
			http.Error(w, "missing name", http.StatusBadRequest)
			return
		}
		_, up := resolveUpstream(name)
		if up == nil || up.BaseURL == "" {
			http.Error(w, "upstream not found", http.StatusNotFound)
			return
		}
		probe = cloneUpstreamConfig(up)
	}
	if probe.BaseURL == "" {
		http.Error(w, "missing base_url", http.StatusBadRequest)
		return
	}
	if name == "" {
		name = "preview"
	}
	// 始终向上游 /models 实时拉取,忽略已配置的 custom_models 快照。
	probe.CustomModels = nil
	models, err := fetchModelsFromUpstream(name, probe)
	if err != nil {
		log.Printf("上游 %s 模型拉取失败: %v", name, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	ids := make([]string, 0, len(models))
	seen := map[string]struct{}{}
	for _, m := range models {
		trimmed := strings.TrimSpace(m.ID)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		ids = append(ids, trimmed)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"upstream": name,
		"models":   ids,
		"count":    len(ids),
	})
}

func reloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 模型完全由用户在 custom_models 中配置，无需联网拉取。
	// 顺手修复历史统计中被误记成“模型名”的上游，面板刷新后即可看到真实上游。
	tokenStatsMu.Lock()
	repaired := repairUsageUpstreamsLocked()
	tokenStatsMu.Unlock()
	if repaired {
		markUsageDirty()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":    "ok",
		"upstreams": getConfiguredUpstreamCount(),
		"models":    countConfiguredModels(),
	})
}

func adminConfigHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		configMu.RLock()
		cfg := AppConfig{
			ModelAlias:         modelAlias,
			ReasoningEffortMap: reasoningEffortMap,
			Upstreams:          map[string]*UpstreamConfig{},
		}
		for name, upstream := range upstreamCfgs {
			cfg.Upstreams[name] = cloneUpstreamConfig(upstream)
		}
		configMu.RUnlock()
		socks5Mu.RLock()
		cfg.Socks5Proxies = socks5Proxies
		socks5Mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"model_alias":          cfg.ModelAlias,
			"reasoning_effort_map": cfg.ReasoningEffortMap,
			"socks5_proxies":       cfg.Socks5Proxies,
			"upstreams":            cfg.Upstreams,
		}
		json.NewEncoder(w).Encode(resp)
	case http.MethodPost:
		var cfg AppConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}
		normalizeConfig(&cfg)
		if empty := emptyCustomModelUpstreams(cfg.Upstreams); len(empty) > 0 {
			msg := "以下上游未配置模型，请点击\"获取模型列表\"或手动填写：" + strings.Join(empty, "、")
			http.Error(w, `{"error":"`+msg+`"}`, http.StatusBadRequest)
			return
		}
		// 校验别名引用的上游是否存在（前端已拦空 key/重复 key，这里后端兜底孤儿上游）
		for aliasKey, alias := range cfg.ModelAlias {
			if aliasUpstream := strings.TrimSpace(alias.Upstream); aliasUpstream != "" {
				if _, ok := cfg.Upstreams[aliasUpstream]; !ok {
					http.Error(w, `{"error":"别名 `+aliasKey+` 引用的上游 `+aliasUpstream+` 不存在"}`, http.StatusBadRequest)
					return
				}
			}
		}
		// 校验别名引用的 SOCKS5 代理是否存在（不再静默清空，避免用户不知情丢失配置）
		proxyAddrSet := make(map[string]struct{}, len(cfg.Socks5Proxies))
		for _, proxy := range cfg.Socks5Proxies {
			proxyAddrSet[strings.TrimSpace(proxy.Addr)] = struct{}{}
		}
		for aliasKey, alias := range cfg.ModelAlias {
			if aliasProxy := strings.TrimSpace(alias.Socks5Proxy); aliasProxy != "" {
				if _, ok := proxyAddrSet[aliasProxy]; !ok {
					http.Error(w, `{"error":"别名 `+aliasKey+` 引用的代理 `+aliasProxy+` 不存在"}`, http.StatusBadRequest)
					return
				}
			}
		}
		if err := saveConfig(configPath, cfg); err != nil {
			http.Error(w, `{"error":"Failed to save config"}`, http.StatusInternalServerError)
			return
		}
		upstreamsChanged := applyConfig(cfg)
		if upstreamsChanged {
			// 配置变更后立即后台预热新上游/新代理的连接池，避免第一条请求付握手开销
			go warmUpstreamConnections()
		}
		if debugMode {
			log.Printf("Config updated: aliases=%d, effort_map=%d, upstreams=%d, upstreams_changed=%v", len(cfg.ModelAlias), len(cfg.ReasoningEffortMap), len(cfg.Upstreams), upstreamsChanged)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ======================== 使用统计查询（管理面板「使用统计」板块） ========================

// UsageSummary 汇总指标，对应面板顶部的统计卡片
type UsageSummary struct {
	Requests            int64   `json:"requests"`
	SuccessCount        int64   `json:"success_count"`
	ErrorCount          int64   `json:"error_count"`
	InputTokens         int64   `json:"input_tokens"`
	OutputTokens        int64   `json:"output_tokens"`
	CacheReadTokens     int64   `json:"cache_read_tokens"`
	CacheCreationTokens int64   `json:"cache_creation_tokens"`
	ReasoningTokens     int64   `json:"reasoning_tokens"`
	TotalTokens         int64   `json:"total_tokens"`
	CostUSD             float64 `json:"cost_usd"`
	AvgLatencyMs        int64   `json:"avg_latency_ms"`
	AvgFirstTokenMs     int64   `json:"avg_first_token_ms"`
	CacheHitRate        float64 `json:"cache_hit_rate"`
}

// UsageGroupRow 分组行（按模型 / 按上游 / 按天）
type UsageGroupRow struct {
	Key       string   `json:"key"`
	Upstreams []string `json:"upstreams,omitempty"`
	Models    []string `json:"models,omitempty"`
	Targets   []string `json:"targets,omitempty"`
	UsageSummary
	latencyTotal  int64
	latencySample int64
	ttfbTotal     int64
	ttfbSample    int64
}

// rowCost 用当前单价把一行 token 拆分换算成费用（模型匹配：别名 → 上游真实模型）
func rowCost(candidates []string, in, out, cr, cw int64) float64 {
	return calcCostUSD(candidates, usageAmounts{Input: in, Output: out, CacheRead: cr, CacheCreation: cw})
}

func rowCostCandidates(r *UsageRow) []string {
	names := []string{r.Model, r.TargetModel}
	return names
}

func (g *UsageGroupRow) add(r *UsageRow) {
	g.Requests += r.RequestCount
	g.SuccessCount += r.SuccessCount
	g.ErrorCount += r.ErrorCount
	g.InputTokens += r.InputTokens
	g.OutputTokens += r.OutputTokens
	g.CacheReadTokens += r.CacheReadTokens
	g.CacheCreationTokens += r.CacheCreationTokens
	g.ReasoningTokens += r.ReasoningTokens
	g.TotalTokens += r.TotalTokens
	g.CostUSD += r.CostUSD + rowCost(rowCostCandidates(r), r.InputTokens, r.OutputTokens, r.CacheReadTokens, r.CacheCreationTokens)
	g.latencyTotal += r.LatencyMsTotal
	g.latencySample += r.LatencySamples
	g.ttfbTotal += r.FirstTokenMsTotal
	g.ttfbSample += r.FirstTokenSamples
	if r.Upstream != "" && !containsString(g.Upstreams, r.Upstream) {
		g.Upstreams = append(g.Upstreams, r.Upstream)
	}
	if r.Model != "" && !containsString(g.Models, r.Model) {
		g.Models = append(g.Models, r.Model)
	}
	if r.TargetModel != "" && !containsString(g.Targets, r.TargetModel) {
		g.Targets = append(g.Targets, r.TargetModel)
	}
}

func (g *UsageGroupRow) finalize() {
	if g.latencySample > 0 {
		g.AvgLatencyMs = int64(float64(g.latencyTotal) / float64(g.latencySample))
	}
	if g.ttfbSample > 0 {
		g.AvgFirstTokenMs = int64(float64(g.ttfbTotal) / float64(g.ttfbSample))
	}
	if promptAll := g.InputTokens + g.CacheReadTokens + g.CacheCreationTokens; promptAll > 0 {
		g.CacheHitRate = float64(int64(float64(g.CacheReadTokens)/float64(promptAll)*10000+0.5)) / 100
	}
	g.CostUSD = float64(int64(g.CostUSD*1e6+0.5)) / 1e6
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// usageResolveRange 把 range 关键字解析成起止日期（含）；all 返回空 start 表示不限
func usageResolveRange(rangeKey string) (start, end string, days int, label string) {
	today := getToday()
	t, err := time.Parse("2006-01-02", today)
	if err != nil {
		t = time.Now()
		today = t.Format("2006-01-02")
	}
	switch rangeKey {
	case "", "today":
		return today, today, 1, "今日"
	case "yesterday":
		y := t.AddDate(0, 0, -1).Format("2006-01-02")
		return y, y, 1, "昨日"
	case "7d":
		return t.AddDate(0, 0, -6).Format("2006-01-02"), today, 7, "近 7 天"
	case "14d":
		return t.AddDate(0, 0, -13).Format("2006-01-02"), today, 14, "近 14 天"
	case "30d":
		return t.AddDate(0, 0, -29).Format("2006-01-02"), today, 30, "近 30 天"
	case "all":
		return "", today, 0, "全部"
	}
	if strings.HasSuffix(rangeKey, "d") {
		if n, e := strconv.Atoi(strings.TrimSuffix(rangeKey, "d")); e == nil && n > 0 && n <= usageHistoryDays {
			return t.AddDate(0, 0, -(n - 1)).Format("2006-01-02"), today, n, "近 " + strconv.Itoa(n) + " 天"
		}
	}
	return today, today, 1, "今日"
}

// usageRowsInRange 返回区间内的聚合行，按日期升序
func usageRowsInRange(start, end string) []*UsageRow {
	tokenStatsMu.Lock()
	defer tokenStatsMu.Unlock()
	out := make([]*UsageRow, 0, len(tokenStats.Rollups))
	for _, row := range tokenStats.Rollups {
		if row == nil {
			continue
		}
		if start != "" && row.Date < start {
			continue
		}
		if end != "" && row.Date > end {
			continue
		}
		cp := *row
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Date != out[j].Date {
			return out[i].Date < out[j].Date
		}
		return out[i].TotalTokens > out[j].TotalTokens
	})
	return out
}

func aggregateUsageRows(rows []*UsageRow, groupBy string) []UsageGroupRow {
	bucket := map[string]*UsageGroupRow{}
	order := []string{}
	for _, r := range rows {
		var key string
		switch groupBy {
		case "upstream":
			key = r.Upstream
		case "day":
			key = r.Date
		default:
			key = r.Model
		}
		g, ok := bucket[key]
		if !ok {
			g = &UsageGroupRow{Key: key}
			bucket[key] = g
			order = append(order, key)
		}
		g.add(r)
	}
	out := make([]UsageGroupRow, 0, len(order))
	for _, k := range order {
		g := bucket[k]
		g.finalize()
		out = append(out, *g)
	}
	if groupBy == "day" {
		sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	} else {
		sort.Slice(out, func(i, j int) bool {
			if out[i].TotalTokens != out[j].TotalTokens {
				return out[i].TotalTokens > out[j].TotalTokens
			}
			return out[i].Key < out[j].Key
		})
	}
	return out
}

// usageLifetimeRows 全部历史累计（来自旧版累计表，不受 90 天保留期限制）
func usageLifetimeRows() []UsageGroupRow {
	tokenStatsMu.Lock()
	defer tokenStatsMu.Unlock()
	out := make([]UsageGroupRow, 0, len(tokenStats.Models))
	for model, ms := range tokenStats.Models {
		if ms == nil {
			continue
		}
		g := UsageGroupRow{Key: model}
		g.Requests = ms.RequestCount
		g.SuccessCount = ms.RequestCount - ms.ErrorCount
		g.ErrorCount = ms.ErrorCount
		g.InputTokens = ms.PromptTokens - ms.CacheReadTokens - ms.CacheCreationTokens
		g.OutputTokens = ms.CompletionTokens
		g.CacheReadTokens = ms.CacheReadTokens
		g.CacheCreationTokens = ms.CacheCreationTokens
		g.ReasoningTokens = ms.ReasoningTokens
		g.TotalTokens = ms.TotalTokens
		g.CostUSD = ms.CostUSD + rowCost([]string{model}, ms.PromptTokens-ms.CacheReadTokens-ms.CacheCreationTokens, ms.CompletionTokens, ms.CacheReadTokens, ms.CacheCreationTokens)
		g.latencyTotal = ms.LatencyMsTotal
		g.latencySample = ms.RequestCount
		g.ttfbTotal = ms.FirstTokenMsTotal
		g.ttfbSample = ms.FirstTokenSamples
		g.finalize()
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TotalTokens != out[j].TotalTokens {
			return out[i].TotalTokens > out[j].TotalTokens
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// usageLogFilter 请求明细的筛选条件
type usageLogFilter struct {
	Model    string
	Upstream string
	Status   string // ok / err / 空
	Query    string
}

func (f usageLogFilter) match(e *RequestLogEntry) bool {
	if f.Model != "" && e.Model != f.Model {
		return false
	}
	if f.Upstream != "" && e.Upstream != f.Upstream {
		return false
	}
	success := e.Status == 0 || (e.Status >= 200 && e.Status < 300)
	if f.Status == "ok" && !success {
		return false
	}
	if f.Status == "err" && success {
		return false
	}
	if f.Query != "" {
		q := strings.ToLower(f.Query)
		if !strings.Contains(strings.ToLower(e.Model), q) &&
			!strings.Contains(strings.ToLower(e.Upstream), q) &&
			!strings.Contains(strings.ToLower(e.TargetModel), q) &&
			!strings.Contains(strings.ToLower(e.Error), q) &&
			!strings.Contains(strings.ToLower(e.API), q) {
			return false
		}
	}
	return true
}

// adminUsageHandler GET /api/usage?range=7d —— 汇总 + 分组明细
func adminUsageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	start, end, days, label := usageResolveRange(q.Get("range"))
	rows := usageRowsInRange(start, end)

	var summary UsageGroupRow
	summary.Key = "__all__"
	for _, row := range rows {
		summary.add(row)
	}
	summary.finalize()

	pricing := getPricingSnapshot()
	currency := pricing.Currency
	if currency == "" {
		currency = "USD"
	}
	tokenStatsMu.Lock()
	logTotal := len(tokenStats.Log)
	tokenStatsMu.Unlock()

	resp := map[string]any{
		"today":        getToday(),
		"range":        map[string]any{"key": q.Get("range"), "start": start, "end": end, "days": days, "label": label},
		"summary":      summary.UsageSummary,
		"models":       aggregateUsageRows(rows, "model"),
		"upstreams":    aggregateUsageRows(rows, "upstream"),
		"daily":        aggregateUsageRows(rows, "day"),
		"history_days": usageHistoryDays,
		"log_total":    logTotal,
		"lifetime":     usageLifetimeRows(),
		"pricing": map[string]any{
			"configured": pricingConfigured(),
			"currency":   currency,
			"models":     pricing.Models,
			"default":    pricing.Default,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// adminUsageLogHandler GET /api/usage/log?page=1&size=20 —— 请求明细分页
func adminUsageLogHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	size := 20
	if v, err := strconv.Atoi(q.Get("size")); err == nil && v > 0 {
		size = v
	}
	if size > 200 {
		size = 200
	}
	page := 1
	if v, err := strconv.Atoi(q.Get("page")); err == nil && v > 0 {
		page = v
	}
	f := usageLogFilter{Model: q.Get("model"), Upstream: q.Get("upstream"), Status: q.Get("status"), Query: strings.TrimSpace(q.Get("q"))}

	tokenStatsMu.Lock()
	matched := make([]RequestLogEntry, 0, len(tokenStats.Log))
	for i := range tokenStats.Log {
		if f.match(&tokenStats.Log[i]) {
			e := tokenStats.Log[i]
			e.CostUSD = rowCost([]string{e.Model, e.TargetModel}, e.InputTokens, e.OutputTokens, e.CacheReadTokens, e.CacheCreationTokens)
			matched = append(matched, e)
		}
	}
	tokenStatsMu.Unlock()

	total := len(matched)
	pages := (total + size - 1) / size
	if pages == 0 {
		pages = 1
	}
	if page > pages {
		page = pages
	}
	from := (page - 1) * size
	to := from + size
	if from > total {
		from = total
	}
	if to > total {
		to = total
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"total": total, "page": page, "size": size, "pages": pages,
		"rows": matched[from:to],
	})
}

// adminPricingHandler GET/POST /api/pricing —— 费用估算单价（每百万 token）
func adminPricingHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(getPricingSnapshot())
	case http.MethodPost:
		var p PricingConfig
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}
		if p.Models == nil {
			p.Models = map[string]ModelPrice{}
		}
		if p.Currency == "" {
			p.Currency = "USD"
		}
		clean := map[string]ModelPrice{}
		for k, v := range p.Models {
			key := strings.TrimSpace(k)
			if key == "" {
				continue
			}
			clean[key] = v
		}
		p.Models = clean
		if err := savePricing(p); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func adminStatsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tokenStatsMu.Lock()
		data, err := json.Marshal(tokenStats)
		tokenStatsMu.Unlock()
		if err != nil {
			http.Error(w, `{"error":"marshal error"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	case http.MethodDelete:
		tokenStatsMu.Lock()
		tokenStats = &TokenStatsData{
			Models:  map[string]*ModelStats{},
			Daily:   &DailyStats{Date: getToday(), Models: map[string]*ModelStats{}},
			Rollups: map[string]*UsageRow{},
			Log:     nil,
		}
		statsDate = getToday()
		usageSaveDirty = false
		tokenStatsMu.Unlock()
		saveTokenStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func adminPageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(adminHTML))
}

func renderLoginPage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(adminLoginHTML))
	if msg != "" {
		w.Write([]byte("<script>document.addEventListener('DOMContentLoaded',function(){var m=document.getElementById('login-msg');if(m){m.textContent='" + msg + "';m.style.display='block'}})</script>"))
	}
}

const adminLoginHTML = `<!DOCTYPE html>
<html lang="zh" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 — LLM Gateway</title>
<style>
:root{--bg:#f4f6fa;--surface:#fff;--border:#e2e6ed;--text:#1a1d26;--text-sec:#6a7180;--accent:#6c8aff;--accent-hover:#5a78f0;--radius:12px;--radius-sm:8px;--font:'Noto Sans SC',system-ui,-apple-system,sans-serif;--mono:'JetBrains Mono',Consolas,monospace}
[data-theme="dark"]{--bg:#0c0e14;--surface:#14161e;--border:#252835;--text:#e8eaf0;--text-sec:#8b90a5;--accent:#6c8aff;--accent-hover:#5a78f0}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;line-height:1.6;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
body::before{content:'';position:fixed;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(ellipse at 30% 20%,rgba(108,138,255,.04) 0%,transparent 50%),radial-gradient(ellipse at 70% 80%,rgba(61,214,140,.03) 0%,transparent 50%);pointer-events:none;z-index:0}
.container{max-width:400px;width:100%;position:relative;z-index:1}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:36px 32px 32px}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.logo-mark{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#8b6cff);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;color:#fff;flex-shrink:0}
.logo-text{font-size:20px;font-weight:700;letter-spacing:-.5px;background:linear-gradient(135deg,var(--text),var(--text-sec));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-sub{font-size:12px;color:var(--text-sec);margin-top:2px}
.subtitle{font-size:13px;color:var(--text-sec);margin-bottom:28px;margin-top:4px}
.field{margin-bottom:16px}
.field label{display:block;font-size:12px;font-weight:500;color:var(--text-sec);margin-bottom:6px;letter-spacing:.3px}
.field input{width:100%;padding:10px 14px;border:1px solid var(--border);border-radius:var(--radius-sm);font-size:14px;font-family:var(--mono);background:var(--surface);color:var(--text);transition:border-color .15s,box-shadow .15s}
.field input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(108,138,255,.1)}
.msg{display:none;background:rgba(240,96,96,.1);color:#d64545;padding:10px 14px;border-radius:var(--radius-sm);margin-bottom:16px;font-size:13px;text-align:center;border:1px solid rgba(240,96,96,.2)}
[data-theme="dark"] .msg{color:#f06060}
.btn{width:100%;padding:10px;border:none;border-radius:var(--radius-sm);font-size:14px;font-weight:600;cursor:pointer;font-family:var(--font);background:var(--accent);color:#fff;transition:background .15s}
.btn:hover{background:var(--accent-hover)}
.theme-bar{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}
.theme-toggle{background:transparent;border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 12px;cursor:pointer;font-size:13px;color:var(--text-sec);font-family:var(--font);transition:all .15s}
.theme-toggle:hover{border-color:var(--accent);color:var(--accent)}
@media(max-width:500px){.card{padding:24px 20px}}
</style>
</head>
<body>
<div class="container">
<div class="card">
<div class="theme-bar">
<div class="logo">
<div class="logo-mark">⌨</div>
<div>
<div class="logo-text">LLM Gateway</div>
<div class="logo-sub">管理面板</div>
</div>
</div>
<button class="theme-toggle" onclick="toggleTheme()">☀</button>
</div>
<div class="subtitle">请输入管理密码以继续</div>
<div class="msg" id="login-msg"></div>
<form method="post" action="/login">
<div class="field">
<label for="pwd">密码</label>
<input id="pwd" name="password" type="password" placeholder="输入管理密码" autocomplete="current-password" required>
</div>
<button class="btn" type="submit">登录</button>
</form>
</div>
</div>
<script>
(function(){var t=localStorage.getItem('theme');if(t==='dark'){document.documentElement.setAttribute('data-theme','dark')}})();
function toggleTheme(){var d=document.documentElement;var n=d.getAttribute('data-theme')==='dark'?'light':'dark';if(n==='dark')d.setAttribute('data-theme','dark');else d.removeAttribute('data-theme');localStorage.setItem('theme',n);document.querySelector('.theme-toggle').textContent=n==='dark'?'🌙':'☀'}
</script>
</body>
</html>`

const adminHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LLM Gateway 管理面板</title>
<style>
:root {
  --bg: #f4f6fa;
  --surface: #ffffff;
  --surface-2: #f0f2f7;
  --border: #e2e6ed;
  --border-light: #d0d4df;
  --text: #1a1d26;
  --text-sec: #6a7180;
  --text-ter: #9ca3b0;
  --accent: #6c8aff;
  --accent-dim: rgba(108,138,255,.08);
  --accent-hover: #5a78f0;
  --green: #22a85a;
  --green-dim: rgba(34,168,90,.08);
  --green-hover: #1d9850;
  --orange: #d9600a;
  --orange-dim: rgba(217,96,10,.08);
  --orange-hover: #c45507;
  --red: #dc2626;
  --red-dim: rgba(220,38,38,.08);
  --radius: 12px;
  --radius-sm: 8px;
  --font: 'Noto Sans SC', system-ui, -apple-system, sans-serif;
  --mono: 'JetBrains Mono', Consolas, monospace;
  --glow-a: rgba(108,138,255,.03);
  --glow-b: rgba(61,214,140,.02);
  --stats-total-bg: #f0f2f7;
  --zebra: rgba(108,138,255,.05);
}
[data-theme="dark"] {
  --bg: #0c0e14;
  --surface: #14161e;
  --surface-2: #1a1d27;
  --border: #252835;
  --border-light: #2e3142;
  --text: #e8eaf0;
  --text-sec: #8b90a5;
  --text-ter: #5c6080;
  --accent: #6c8aff;
  --accent-dim: rgba(108,138,255,.12);
  --accent-hover: #5a78f0;
  --green: #3dd68c;
  --green-dim: rgba(61,214,140,.12);
  --green-hover: #30c47a;
  --orange: #f0a050;
  --orange-dim: rgba(240,160,80,.12);
  --orange-hover: #e09040;
  --red: #f06060;
  --red-dim: rgba(240,96,96,.12);
  --glow-a: rgba(108,138,255,.04);
  --glow-b: rgba(61,214,140,.03);
  --stats-total-bg: var(--surface-2);
  --zebra: rgba(108,138,255,.07);
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;line-height:1.6;min-height:100vh}
body::before{content:'';position:fixed;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(ellipse at 30% 20%,var(--glow-a) 0%,transparent 50%),radial-gradient(ellipse at 70% 80%,var(--glow-b) 0%,transparent 50%);pointer-events:none;z-index:0}
.container{max-width:1280px;margin:0 auto;padding:32px 24px;position:relative;z-index:1}
header{display:flex;align-items:flex-end;gap:16px;margin-bottom:28px;padding-bottom:20px;border-bottom:1px solid var(--border);justify-content:space-between}
.logo{display:flex;align-items:center;gap:10px}
.logo-mark{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#8b6cff);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;color:#fff;flex-shrink:0}
.logo-text{font-size:22px;font-weight:700;letter-spacing:-.5px;background:linear-gradient(135deg,var(--text),var(--text-sec));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-sub{font-size:12.5px;color:var(--text-ter);margin-bottom:2px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:22px 24px;transition:border-color .2s}
.card:hover{border-color:var(--border-light)}
.card h2{font-size:13px;font-weight:600;margin-bottom:16px;letter-spacing:.2px;display:flex;align-items:center;gap:8px;color:var(--text-sec);text-transform:uppercase}
.card h2 .dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.config-grid{display:grid;grid-template-columns:2fr 3fr;gap:16px;margin-top:16px}
.config-grid .card{margin-bottom:0}
.full-row{grid-column:1/-1}
.form-group{margin-bottom:14px}
.form-group:last-child{margin-bottom:0}
.form-group label{display:block;font-size:11.5px;font-weight:500;color:var(--text-ter);margin-bottom:5px;letter-spacing:.4px;text-transform:uppercase}
.form-group input[type="text"],.form-group input[type="url"],.form-group input[type="password"],.form-group textarea,.form-group select,.m-select{width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius-sm);font-size:13px;font-family:var(--mono);background:var(--surface-2);color:var(--text);transition:border-color .15s,box-shadow .15s}
.form-group input:focus,.form-group textarea:focus,.form-group select:focus,.m-select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-dim)}
.form-group .hint{font-size:11px;color:var(--text-ter);margin-top:4px;line-height:1.4}
.actions{display:flex;gap:8px;margin-top:14px;flex-wrap:wrap}
.btn{padding:8px 16px;border-radius:var(--radius-sm);font-size:12.5px;font-weight:500;cursor:pointer;border:none;transition:all .15s;font-family:var(--font);white-space:nowrap}
.btn-primary{background:var(--accent-dim);color:var(--accent)}
.btn-primary:hover{background:var(--accent);color:#fff}
.btn-default{background:var(--surface-2);color:var(--text-sec);border:1px solid var(--border)}
.btn-default:hover{border-color:var(--border-light);color:var(--text)}
.btn-success{background:var(--green-dim);color:var(--green)}
.btn-success:hover{background:var(--green);color:#fff}
.btn-warning{background:var(--orange-dim);color:var(--orange)}
.btn-warning:hover{background:var(--orange);color:#fff}
.btn-danger{background:var(--red-dim);color:var(--red)}
.btn-danger:hover{background:var(--red);color:#fff}
.btn-secondary{background:var(--surface);color:var(--text-ter);border:1px solid var(--border)}
.btn-secondary:hover{background:var(--accent-dim);color:var(--accent);border-color:var(--accent)}
.tbl{width:100%;border-collapse:collapse;font-size:12.5px}
.tbl th{text-align:left;font-weight:500;color:var(--text-ter);padding:8px 10px;border-bottom:1px solid var(--border);font-size:11px;letter-spacing:.4px;text-transform:uppercase;white-space:nowrap}
.tbl td{padding:7px 10px;border-bottom:1px solid var(--border)}
.tbl tr:last-child td{border-bottom:none}
.tbl input,.tbl textarea{width:100%;padding:6px 10px;border:1px solid var(--border);border-radius:6px;font-size:12.5px;font-family:var(--mono);background:var(--surface-2);color:var(--text);transition:border-color .15s,box-shadow .15s}
.tbl textarea{min-height:72px;resize:vertical;line-height:1.4}
.tbl input:focus,.tbl textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-dim)}
.tbl .m-select{padding:6px 10px;font-size:12.5px}
.tbl th:last-child{width:52px}
.tbl td:last-child{white-space:nowrap;text-align:center}
#statsTable th:last-child{width:auto}
#statsTable td:last-child{text-align:left;white-space:nowrap}
.tbl .btn{padding:4px 10px;font-size:11px;white-space:nowrap}
#statsTable td:first-child{font-weight:500;color:var(--text)}
#statsTable td:not(:first-child){font-family:var(--mono);color:var(--text-sec);text-align:left}
#statsTable tbody tr:hover{background:var(--surface-2)}
#statsTable thead+tbody tr:last-child td{font-weight:600;color:var(--text);background:var(--stats-total-bg);border-top:1px solid var(--border-light)}
#dailyTable th:last-child{width:auto}
#dailyTable td:last-child{text-align:left;white-space:nowrap}
#dailyTable td:first-child{font-weight:500;color:var(--text)}
#dailyTable td:not(:first-child){font-family:var(--mono);color:var(--text-sec);text-align:left}
#dailyTable tbody tr:hover{background:var(--surface-2)}
#dailyTable thead+tbody tr:last-child td{font-weight:600;color:var(--text);background:var(--stats-total-bg);border-top:1px solid var(--border-light)}
.stats-header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.stats-header .btns{display:flex;gap:6px;align-items:center}
.panel-header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.panel-header h2{margin-bottom:0}
.panel-header .btns{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.upstream-list{display:flex;flex-direction:column;gap:10px}
.upstream-item{border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface-2);overflow:hidden;transition:border-color .15s}
.upstream-item:hover{border-color:var(--border-light)}
.upstream-item summary{display:flex;align-items:center;gap:10px;padding:12px 14px;cursor:pointer;list-style:none;user-select:none}
.upstream-item summary::-webkit-details-marker{display:none}
.upstream-item summary::before{content:'›';font-size:19px;line-height:1;color:var(--text-ter);transition:transform .15s;flex-shrink:0}
.upstream-item[open] summary::before{transform:rotate(90deg)}
.upstream-item[open] summary{border-bottom:1px solid var(--border)}
.upstream-summary-name{font-size:13px;font-weight:600;color:var(--text);min-width:110px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.upstream-type-badge{padding:2px 7px;border-radius:999px;font-size:10px;line-height:1.5;white-space:nowrap}
.upstream-type-badge{background:var(--accent-dim);color:var(--accent)}
.upstream-summary-url{min-width:0;flex:1;color:var(--text-ter);font-family:var(--mono);font-size:11.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.upstream-summary-meta{color:var(--text-ter);font-size:10.5px;white-space:nowrap}
.upstream-body{padding:15px 14px 14px}
.upstream-form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.upstream-field{min-width:0}
.upstream-field.full{grid-column:1/-1}
.upstream-field label{display:block;font-size:10.5px;font-weight:500;color:var(--text-ter);margin-bottom:5px;letter-spacing:.35px;text-transform:uppercase}
.upstream-field input,.upstream-field textarea,.upstream-field select{width:100%;padding:8px 10px;border:1px solid var(--border);border-radius:6px;font-size:12.5px;font-family:var(--mono);background:var(--surface);color:var(--text);transition:border-color .15s,box-shadow .15s}
.upstream-field textarea{min-height:92px;resize:vertical;line-height:1.45}
.upstream-field input:focus,.upstream-field textarea:focus,.upstream-field select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-dim)}
.upstream-field .field-hint{margin-top:4px;color:var(--text-ter);font-size:10.5px}
.upstream-item-actions{display:flex;justify-content:flex-end;margin-top:14px;padding-top:12px;border-top:1px solid var(--border)}
.custom-models-row{display:flex;gap:8px}
.custom-models-row input{flex:1;min-width:0}
.custom-models-row .btn{flex:0 0 auto;align-self:flex-end;padding:8px 12px}
.upstream-empty{padding:24px;text-align:center;color:var(--text-ter);font-size:12.5px;border:1px dashed var(--border);border-radius:var(--radius-sm);background:var(--surface-2)}
#toast{position:fixed;top:20px;right:20px;padding:12px 20px;border-radius:var(--radius-sm);font-size:13px;font-weight:500;color:#fff;opacity:0;transition:opacity .25s,transform .25s;z-index:999;transform:translateY(-8px);pointer-events:none;backdrop-filter:blur(8px)}
#toast.success{background:rgba(61,214,140,.85)}
#toast.error{background:rgba(240,96,96,.85)}
#toast.show{opacity:1;transform:translateY(0)}
.empty-hint{color:var(--text-ter);font-size:13px;padding:28px;text-align:center}
.advanced-settings{margin-top:18px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface-2);overflow:hidden;transition:border-color .15s}
.advanced-settings:hover{border-color:var(--border-light)}
.advanced-settings summary{display:flex;align-items:center;gap:9px;padding:11px 14px;cursor:pointer;list-style:none;color:var(--text-sec);font-size:12.5px;font-weight:600;user-select:none}
.advanced-settings summary::-webkit-details-marker{display:none}
.advanced-settings summary::before{content:'›';font-size:18px;line-height:1;color:var(--text-ter);transition:transform .15s}
.advanced-settings[open] summary::before{transform:rotate(90deg)}
.advanced-settings[open] summary{border-bottom:1px solid var(--border)}
.advanced-summary-count{margin-left:auto;color:var(--text-ter);font-size:11px;font-weight:400}
.advanced-content{padding:14px}
.advanced-hint{font-size:11px;color:var(--text-ter);margin-bottom:10px}
.effort-label-row,.effort-row{display:grid;grid-template-columns:minmax(120px,1fr) 28px minmax(120px,1fr) auto;gap:8px;align-items:center}
.effort-label-row{padding:0 1px 5px;color:var(--text-ter);font-size:10.5px;letter-spacing:.3px;text-transform:uppercase}
.effort-row{margin-bottom:8px}
.effort-row input{width:100%;padding:7px 10px;border:1px solid var(--border);border-radius:6px;font-size:12.5px;font-family:var(--mono);background:var(--surface);color:var(--text);transition:border-color .15s,box-shadow .15s}
.effort-row input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-dim)}
.effort-arrow{text-align:center;color:var(--text-ter);font-family:var(--mono)}
.effort-row .btn{padding:6px 10px;font-size:11px}
.effort-empty{padding:16px 8px;color:var(--text-ter);font-size:12px;text-align:center;border:1px dashed var(--border);border-radius:6px}
.effort-actions{margin-top:10px}
.think-row{display:flex;align-items:center;gap:10px;padding:8px 12px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:12px;transition:border-color .15s}
.think-row:hover{border-color:var(--border-light)}
.think-row input[type="checkbox"]{width:16px;height:16px;accent-color:var(--accent);cursor:pointer}
.think-row label{font-size:13px;font-weight:500;cursor:pointer;margin:0;color:var(--text)}
.think-row .hint{font-size:11px;color:var(--text-ter);margin:0 0 0 auto;white-space:nowrap}
@media(max-width:700px){.config-grid{grid-template-columns:1fr}.container{padding:16px 12px}header{flex-direction:column;align-items:flex-start;gap:8px}.effort-label-row,.effort-row{grid-template-columns:minmax(90px,1fr) 22px minmax(90px,1fr) auto}.upstream-form-grid{grid-template-columns:1fr}.upstream-field.full{grid-column:auto}.upstream-summary-url{display:none}.upstream-summary-meta{margin-left:auto}}
.theme-toggle{background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 12px;cursor:pointer;font-size:18px;display:flex;align-items:center;justify-content:center;transition:all .15s;color:var(--text-sec);flex-shrink:0;line-height:1}
.theme-toggle:hover{border-color:var(--border-light);color:var(--text)}
.usage-toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.usage-toolbar .grow{margin-left:auto}
.seg{display:inline-flex;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:2px;gap:2px}
.seg button{padding:5px 11px;border:none;background:transparent;color:var(--text-sec);font-size:12px;font-weight:500;border-radius:6px;cursor:pointer;font-family:var(--font);transition:all .15s;white-space:nowrap}
.seg button:hover{color:var(--text)}
.seg button.on{background:var(--accent);color:#fff}
.u-input{padding:6px 10px;border:1px solid var(--border);border-radius:var(--radius-sm);font-size:12px;font-family:var(--mono);background:var(--surface);color:var(--text)}
.u-input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-dim)}
.u-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:8px;margin-bottom:16px}
.u-card{background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:9px 12px;min-width:0;transition:border-color .15s}
.u-card:hover{border-color:var(--border-light)}
.u-card .k{font-size:10px;color:var(--text-ter);letter-spacing:.4px;text-transform:uppercase;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.u-card .v{font-size:17px;font-weight:700;font-family:var(--mono);margin-top:3px;line-height:1.25;word-break:break-all}
.u-card .s{font-size:10.5px;color:var(--text-ter);margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.u-card.hl{background:var(--accent-dim);border-color:var(--accent)}
.u-card.hl .v{color:var(--accent)}
.u-sec{margin-top:18px}
.u-sec:first-child{margin-top:0}
.u-sec-h{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px}
.u-sec-h h3{font-size:13.5px;font-weight:600;margin:0;color:var(--text);padding-left:9px;border-left:3px solid var(--accent);line-height:1.25}
.u-pager{margin-left:auto;display:flex;align-items:center;gap:5px;font-size:11px;color:var(--text-sec);flex-wrap:wrap}
.u-pager button{min-width:24px;padding:2px 7px;border:1px solid var(--border);background:var(--surface);color:var(--text-sec);border-radius:5px;cursor:pointer;font-size:12px;line-height:1.5;transition:all .15s}
.u-pager button:hover:not(:disabled){border-color:var(--accent);color:var(--accent)}
.u-pager button:disabled{opacity:.35;cursor:default}
.u-pager .pg{font-family:var(--mono);white-space:nowrap}
.u-wrap{overflow-x:auto;overscroll-behavior-x:contain;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface)}
.usage-tbl{border-collapse:separate;border-spacing:0;table-layout:fixed}
.usage-tbl th,.usage-tbl td{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding:6px 8px}
.usage-tbl th:last-child{width:auto}
.usage-tbl thead th{background:var(--surface-2);border-bottom:1px solid var(--border-light)}
.usage-tbl td:last-child{text-align:right;white-space:nowrap}
.usage-tbl th.num{text-align:right}
.usage-tbl td.num{text-align:right;font-family:var(--mono);white-space:nowrap}
.usage-tbl td.pin,.usage-tbl th.pin{position:sticky;left:0;z-index:1;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;background:var(--surface);box-shadow:inset -1px 0 0 var(--border)}
.usage-tbl thead th.pin{background:var(--surface-2)}
.usage-tbl tr.alt td{background:var(--zebra)}
.usage-tbl tr.tot td{font-weight:600;background:var(--stats-total-bg);border-top:1px solid var(--border-light)}
.usage-tbl tr:hover td{background:var(--surface-2)}
.usage-tbl tr:hover td.pin{background:var(--surface-2)}
.u-pill{display:inline-block;text-align:center;padding:0 7px;border-radius:999px;font-size:10.5px;font-weight:600;line-height:17px;letter-spacing:.2px}
.u-pill.ok{background:var(--green-dim);color:var(--green)}
.u-pill.bad{background:var(--red-dim);color:var(--red)}
.u-banner{margin-bottom:14px;padding:11px 16px;background:linear-gradient(120deg,var(--accent),#8b6cff);color:#fff;border-radius:var(--radius-sm);font-size:13px;box-shadow:0 6px 18px -8px rgba(108,138,255,.55)}
.u-banner b{font-family:var(--mono);font-weight:700}
.u-hint{font-size:11px;color:var(--text-ter)}
.u-tag{display:inline-block;padding:0 6px;border-radius:4px;font-size:10.5px;background:var(--accent-dim);color:var(--accent);margin:1px 3px 1px 0;white-space:nowrap}
.u-ok{color:var(--green)}
.u-bad{color:var(--red)}
.u-mut{color:var(--text-ter)}
.pricing-box{margin-top:16px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface-2);overflow:hidden}
.pricing-box summary{display:flex;align-items:center;gap:9px;padding:10px 14px;cursor:pointer;list-style:none;color:var(--text-sec);font-size:12.5px;font-weight:600}
.pricing-box summary::-webkit-details-marker{display:none}
.pricing-box summary::before{content:'\203A';font-size:18px;line-height:1;color:var(--text-ter);transition:transform .15s}
.pricing-box[open] summary::before{transform:rotate(90deg)}
.pricing-box[open] summary{border-bottom:1px solid var(--border)}
.pricing-body{padding:12px 14px}
.pricing-row{display:grid;grid-template-columns:1.6fr repeat(4,1fr) auto;gap:6px;margin-bottom:6px;align-items:center}
.pricing-row input{width:100%;padding:6px 8px;border:1px solid var(--border);border-radius:6px;font-size:12px;font-family:var(--mono);background:var(--surface);color:var(--text)}
.pricing-row input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-dim)}
.pricing-head{font-size:10px;color:var(--text-ter);text-transform:uppercase;letter-spacing:.3px;margin-bottom:4px}
</style>
</head>
<body>
<div class="container">
<header>
<div class="logo">
<div class="logo-mark">⌨</div>
<div>
<div class="logo-text">LLM Gateway</div>
<div class="logo-sub">通用 LLM 代理网关</div>
</div>
</div>
<div style="display:flex;align-items:center;gap:8px">
<button class="theme-toggle" onclick="toggleTheme()" title="切换主题">☀</button>
<form method="post" action="/logout" style="margin:0"><button class="theme-toggle" type="submit" title="退出登录" style="font-size:14px">退出</button></form>
</div>
</header>

<div class="card">
<div class="stats-header">
<h2><span class="dot" style="background:var(--green)"></span>使用统计</h2>
<div class="btns">
<span id="usageMeta" class="u-hint"></span>
<button class="btn btn-success" onclick="loadUsage(true)">刷新</button>
<button class="btn btn-danger" onclick="resetStats()">清空统计</button>
<span id="resetStatus" style="font-size:11px;color:var(--text-ter)"></span>
</div>
</div>
<div class="usage-toolbar">
<div class="seg" id="usageRangeSeg"></div>
<div class="seg" id="usageLogStatusSeg"></div>
<input class="u-input" id="usageLogQ" placeholder="搜索模型 / 上游 / 错误" style="width:190px" oninput="onUsageSearch(this.value)">
<select class="u-input" id="usageLogSize" onchange="onUsageLogSize(this.value)"><option value="10">每页 10 条</option><option value="20" selected>每页 20 条</option><option value="50">每页 50 条</option><option value="100">每页 100 条</option></select>
<select class="u-input" id="usageRowSize" onchange="onUsageRowSize(this.value)"><option value="10">表格每页 10 行</option><option value="20" selected>表格每页 20 行</option><option value="50">表格每页 50 行</option><option value="1000">表格不分页</option></select>
</div>
<div id="statsContent" style="font-size:12.5px">
<div class="empty-hint">加载中...</div>
</div>
<details class="pricing-box" id="pricingBox">
<summary><span>费用估算设置</span><span class="u-hint" id="pricingSummary" style="margin-left:auto">未配置 · 只显示 token</span></summary>
<div class="pricing-body">
<div class="u-hint" style="margin-bottom:10px">按「每百万 token 单价」填写，留空或 0 表示不计费；模型名支持别名或上游真实模型名（不区分大小写，可省略 <code>vendor/</code> 前缀）。数据保存在 pricing.json。</div>
<div class="pricing-row pricing-head"><span>模型</span><span>输入</span><span>输出</span><span>缓存读</span><span>缓存写</span><span></span></div>
<div id="pricingList"></div>
<div class="actions" style="margin-top:10px">
<button class="btn btn-primary" onclick="addPricingRow()">添加单价</button>
<button class="btn btn-success" onclick="savePricing()">保存单价</button>
<span class="u-hint" id="pricingStatus"></span>
</div>
</div>
</details>
</div>

<div class="config-grid">
<div class="card full-row">
<div class="panel-header">
<h2><span class="dot" style="background:var(--green)"></span>多上游配置</h2>
<div class="btns">
<button class="btn btn-primary" onclick="addUpstreamRow()">添加上游</button>
<button class="btn btn-success" onclick="saveConfig('上游配置')">保存上游</button>
</div>
</div>
<div class="upstream-list" id="upstreamList"></div>
</div>
<div class="card full-row">
<h2><span class="dot" style="background:var(--accent)"></span>模型映射</h2>
<div style="margin-bottom:12px">
<table class="tbl" id="aliasTable">
<thead><tr><th style="width:17%">别名（请求名）</th><th style="width:14%">上游</th><th style="width:24%">实际模型（上游名）</th><th style="width:18%">代理出口</th><th style="width:19%">回传 reasoning_content</th><th style="width:8%"></th></tr></thead>
<tbody></tbody>
</table>
</div>
<details class="advanced-settings" id="reasoningEffortDetails">
<summary><span>高级设置 · 推理力度映射</span><span class="advanced-summary-count" id="effortSummary">未配置 · 原值透传</span></summary>
<div class="advanced-content">
<div class="advanced-hint">将客户端传入的 reasoning_effort 映射为上游支持的值；未配置的值保持原样。</div>
<div class="effort-label-row"><span>请求值</span><span></span><span>上游值</span><span></span></div>
<div id="effortList"></div>
<div class="effort-actions"><button class="btn btn-primary" onclick="addEffortRow()">添加映射</button></div>
</div>
</details>
<div class="actions">
<button class="btn btn-primary" onclick="addAliasRow()">添加别名</button>
<button class="btn btn-success" onclick="saveConfig()">保存全部</button>
</div>
</div>

<div class="card full-row">
<h2><span class="dot" style="background:var(--accent)"></span>SOCKS5 代理配置</h2>
<div style="margin-bottom:12px">
<table class="tbl" id="socks5Table">
<thead><tr><th style="width:25%">名称</th><th style="width:28%">地址</th><th style="width:17%">用户名</th><th style="width:17%">密码</th><th style="width:13%"></th></tr></thead>
<tbody></tbody>
</table>
</div>
<div class="actions">
<button class="btn btn-primary" onclick="addSocks5Row()">添加代理</button>
<button class="btn btn-success" onclick="saveConfig()">保存全部</button>
</div>
</div>
</div>
</div>
<div id="toast"></div>
<script>
let aliasData={},effortData={},modelListByUpstream={},upstreamData={},socks5Data=[];
function toggleTheme(){const d=document.documentElement;const cur=d.getAttribute('data-theme');const next=cur==='dark'?null:'dark';if(next)d.setAttribute('data-theme',next);else d.removeAttribute('data-theme');localStorage.setItem('theme',next||'light');document.querySelector('.theme-toggle').textContent=next==='dark'?'🌙':'☀'}
(function(){const t=localStorage.getItem('theme');if(t==='dark'){document.documentElement.setAttribute('data-theme','dark');document.addEventListener('DOMContentLoaded',()=>{const b=document.querySelector('.theme-toggle');if(b)b.textContent='🌙'})}})();
function reloadConfig(){const sy=window.scrollY;fetch('/api/reload',{method:'POST'}).then(r=>r.json()).then(d=>{showToast('会话已刷新，模型 '+d.models+' 个','success')}).catch(()=>{}).finally(()=>{loadConfig();loadUsage();setTimeout(()=>window.scrollTo(0,sy),100)})}
function apiTypeSelectHtml(selected){const v=selected||'openai';return '<select data-field="api_type" onchange="onUpstreamTypeChange(this)"><option value="openai"'+(v==='openai'?' selected':'')+'>OpenAI</option><option value="anthropic"'+(v==='anthropic'?' selected':'')+'>Anthropic</option><option value="openai-responses"'+(v==='openai-responses'?' selected':'')+'>Responses</option></select>'}
function upstreamTypeLabel(value){if(value==='anthropic')return 'Anthropic';if(value==='openai-responses')return 'Responses';return 'OpenAI'}
function nonEmptyLineCount(value){return String(value||'').split(/\r?\n/).map(s=>s.trim()).filter(Boolean).length}
function customModelCount(value){return String(value||'').split(',').map(s=>s.trim()).filter(Boolean).length}
function responsesReasoningFormatHtml(value){const legacy=['reasoning_effort','legacy','legacy_reasoning_effort'].includes(value);return '<select data-field="responses_reasoning_format"><option value=""'+(!legacy?' selected':'')+'>标准 reasoning.effort</option><option value="legacy_reasoning_effort"'+(legacy?' selected':'')+'>兼容 reasoning_effort</option></select>'}
function customHeadersToText(obj){obj=obj||{};return Object.keys(obj).map(k=>k+': '+obj[k]).join('\n')}
function headerLineCount(text){return String(text||'').split(/\r?\n/).map(s=>s.trim()).filter(s=>s&&s.indexOf(':')>0).length}
function parseHeaderText(text){const r={};String(text||'').split(/\r?\n/).forEach(line=>{const t=line.trim();if(!t)return;const i=t.indexOf(':');if(i<=0)return;const k=t.slice(0,i).trim();const v=t.slice(i+1).trim();if(k)r[k]=v});return r}
function upstreamCardHtml(name,up,expanded){up=up||{};const apiType=up.api_type||'openai';const baseURL=up.base_url||'';const apiKey=up.api_key||'';const customModels=(up.custom_models||[]).join(',');const headersText=customHeadersToText(up.custom_headers);const headerCount=Object.keys(up.custom_headers||{}).length;const keyCount=nonEmptyLineCount(apiKey);const modelCount=(up.custom_models||[]).length;let h='<details class="upstream-item" data-original-name="'+esc(name||'')+'"'+(expanded?' open':'')+'>';h+='<summary><span class="upstream-summary-name">'+esc(name||'未命名上游')+'</span><span class="upstream-type-badge">'+upstreamTypeLabel(apiType)+'</span><span class="upstream-summary-url">'+esc(baseURL||'尚未配置 Base URL')+'</span><span class="upstream-summary-meta">'+keyCount+' Key · '+modelCount+' 模型'+(headerCount>0?' · '+headerCount+' 请求头':'')+'</span></summary>';h+='<div class="upstream-body"><div class="upstream-form-grid">';h+='<div class="upstream-field"><label>名称</label><input value="'+esc(name||'')+'" data-field="name" placeholder="例如: main" oninput="updateUpstreamCardSummary(this)" onchange="syncUpstreamOptions()"></div>';h+='<div class="upstream-field"><label>接口类型</label>'+apiTypeSelectHtml(apiType)+'</div>';h+='<div class="upstream-field full"><label>Base URL</label><input value="'+esc(baseURL)+'" data-field="base_url" placeholder="https://example.com/v1" oninput="updateUpstreamCardSummary(this)" onchange="syncUpstreamOptions()"></div>';h+='<div class="upstream-field full"><label>API Key（每行一个）</label><textarea data-field="api_key" placeholder="每行填写一个 API Key" oninput="updateUpstreamCardSummary(this)">'+esc(apiKey)+'</textarea><div class="field-hint">支持填写多个 Key，请求时按顺序轮询。</div></div>';h+='<div class="upstream-field full"><label>自定义请求头（每行一条）</label><textarea data-field="custom_headers" placeholder="X-Custom-Header: value">'+esc(headersText)+'</textarea><div class="field-hint">每行一条，格式 "名称: 值"；发往该上游的所有请求都会附加，同名头覆盖网关默认头（如 Authorization、anthropic-version）。</div></div>';h+='<div class="upstream-field full"><label>自定义模型</label><div class="custom-models-row"><input value="'+esc(customModels)+'" data-field="custom_models" placeholder="model-a, model-b" oninput="updateUpstreamCardSummary(this)" onchange="syncUpstreamOptions()"><button type="button" class="btn btn-secondary" onclick="fetchUpstreamModels(this)">获取模型列表</button></div><div class="field-hint">多个模型使用英文逗号分隔；点"获取模型列表"从上游 /models 实时拉取并填入；填入后启动/刷新不再自动拉取。</div></div>';h+='<div class="upstream-field full responses-format-field"'+(apiType==='openai-responses'?'':' style="display:none"')+'><label>Responses 推理参数格式</label>'+responsesReasoningFormatHtml(up.responses_reasoning_format||'')+'</div>';h+='</div><div class="upstream-item-actions"><button class="btn btn-danger" onclick="delUpstream(this)">删除此上游</button></div></div></details>';return h}
function buildModelListByUpstreamFromCustomModels(){const grouped={};Object.keys(upstreamData).forEach(name=>{const arr=(upstreamData[name]&&Array.isArray(upstreamData[name].custom_models))?upstreamData[name].custom_models:(typeof (upstreamData[name]||{}).custom_models==='string'?(upstreamData[name].custom_models.split(',').map(s=>s.trim()).filter(Boolean)):[]);grouped[name]=Array.from(new Set(arr)).sort()});return grouped}
function normalizeAliasData(){const next={};Object.keys(aliasData||{}).forEach(k=>{const raw=aliasData[k];if(typeof raw==='object'&&raw){next[k]={target_model:raw.target_model||'',upstream:raw.upstream||'',socks5_proxy:raw.socks5_proxy||'',with_reasoning:!!raw.with_reasoning}}else{next[k]={target_model:typeof raw==='string'?raw:'',upstream:'',socks5_proxy:'',with_reasoning:false}}});aliasData=next}
function normalizeUpstreamData(cfg){upstreamData=cfg.upstreams||{}}
async function loadConfig(){const sy=window.scrollY;try{const r=await fetch('/api/config');const cfg=await r.json();aliasData=cfg.model_alias||{};normalizeAliasData();effortData=cfg.reasoning_effort_map||{};socks5Data=cfg.socks5_proxies||[];normalizeUpstreamData(cfg);modelListByUpstream=buildModelListByUpstreamFromCustomModels()
renderUpstreamTable();renderAliasTable();renderEffortTable();renderSocks5Table();setTimeout(()=>window.scrollTo(0,sy),0)}catch(e){showToast('失败: '+e.message,'error')}}
function renderUpstreamTable(){const list=document.getElementById('upstreamList');const names=Object.keys(upstreamData).sort();list.innerHTML=names.length?names.map(name=>upstreamCardHtml(name,upstreamData[name],false)).join(''):'<div class="upstream-empty">暂无上游配置，请先添加一个上游。</div>';}
function addUpstreamRow(){collectUpstreams();const list=document.getElementById('upstreamList');const empty=list.querySelector('.upstream-empty');if(empty)empty.remove();list.insertAdjacentHTML('beforeend',upstreamCardHtml('',{api_type:'openai'},true));const cards=list.querySelectorAll('.upstream-item');const input=cards.length?cards[cards.length-1].querySelector('[data-field="name"]'):null;if(input)input.focus()}
function delUpstream(btn){collectAliases();const card=btn.closest('.upstream-item');if(card)card.remove();collectUpstreams();modelListByUpstream=buildModelListByUpstreamFromCustomModels();const list=document.getElementById('upstreamList');if(!list.querySelector('.upstream-item'))list.innerHTML='<div class="upstream-empty">暂无上游配置，请先添加一个上游。</div>';renderAliasTable()}
function collectUpstreams(){const r={};document.querySelectorAll('#upstreamList .upstream-item').forEach(card=>{const name=(card.querySelector('[data-field="name"]')||{}).value?.trim()||'';const baseURL=(card.querySelector('[data-field="base_url"]')||{}).value?.trim()||'';if(!name||!baseURL)return;const apiKey=(card.querySelector('[data-field="api_key"]')||{}).value?.trim()||'';const apiType=(card.querySelector('[data-field="api_type"]')||{}).value||'openai';const customRaw=(card.querySelector('[data-field="custom_models"]')||{}).value?.trim()||'';const reasoningFormat=(card.querySelector('[data-field="responses_reasoning_format"]')||{}).value||'';const headers=parseHeaderText((card.querySelector('[data-field="custom_headers"]')||{}).value||'');const up={base_url:baseURL,api_type:apiType};if(apiKey)up.api_key=apiKey;if(customRaw)up.custom_models=customRaw.split(',').map(s=>s.trim()).filter(Boolean);if(apiType==='openai-responses'&&reasoningFormat)up.responses_reasoning_format=reasoningFormat;if(Object.keys(headers).length)up.custom_headers=headers;r[name]=up;card.dataset.originalName=name});upstreamData=r;return r}
function updateUpstreamCardSummary(el){const card=el.closest('.upstream-item');if(!card)return;const name=(card.querySelector('[data-field="name"]')||{}).value?.trim()||'';const baseURL=(card.querySelector('[data-field="base_url"]')||{}).value?.trim()||'';const apiType=(card.querySelector('[data-field="api_type"]')||{}).value||'openai';const apiKey=(card.querySelector('[data-field="api_key"]')||{}).value||'';const customRaw=(card.querySelector('[data-field="custom_models"]')||{}).value||'';const headerN=headerLineCount((card.querySelector('[data-field="custom_headers"]')||{}).value||'');card.querySelector('.upstream-summary-name').textContent=name||'未命名上游';card.querySelector('.upstream-summary-url').textContent=baseURL||'尚未配置 Base URL';card.querySelector('.upstream-type-badge').textContent=upstreamTypeLabel(apiType);card.querySelector('.upstream-summary-meta').textContent=nonEmptyLineCount(apiKey)+' Key · '+customModelCount(customRaw)+' 模型'+(headerN>0?' · '+headerN+' 请求头':'')}
function onUpstreamTypeChange(sel){const card=sel.closest('.upstream-item');const field=card?card.querySelector('.responses-format-field'):null;if(field)field.style.display=sel.value==='openai-responses'?'':'none';updateUpstreamCardSummary(sel)}
function syncUpstreamOptions(){collectAliases();collectUpstreams();modelListByUpstream=buildModelListByUpstreamFromCustomModels();renderAliasTable()}function fetchUpstreamModels(btn){const card=btn.closest('.upstream-item');if(!card)return;const name=(card.querySelector('[data-field="name"]')||{}).value?.trim()||'';const baseURL=(card.querySelector('[data-field="base_url"]')||{}).value?.trim()||'';if(!baseURL){alert('请先填写 Base URL');return}const apiKey=(card.querySelector('[data-field="api_key"]')||{}).value||'';const apiType=(card.querySelector('[data-field="api_type"]')||{}).value||'openai';const input=card.querySelector('[data-field="custom_models"]');const body={base_url:baseURL,api_type:apiType};if(apiKey)body.api_key=apiKey;const probeHeaders=parseHeaderText((card.querySelector('[data-field="custom_headers"]')||{}).value||'');if(Object.keys(probeHeaders).length)body.custom_headers=probeHeaders;const orig=btn.textContent;btn.disabled=true;btn.textContent='获取中…';fetch('/api/upstream/models?name='+encodeURIComponent(name),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>{if(!r.ok){return r.text().then(t=>{throw new Error(t||('HTTP '+r.status))})}return r.json()}).then(d=>{const arr=Array.isArray(d.models)?d.models:[];if(arr.length===0){alert('上游未返回任何模型');return}input.value=arr.join(', ');updateUpstreamCardSummary(input);syncUpstreamOptions();btn.textContent='已填充 '+arr.length+' 个'}).catch(e=>{alert('获取失败: '+(e&&e.message?e.message:e))}).finally(()=>{btn.disabled=false;btn.textContent=orig})}

function modelsForUpstream(name){const resolved=(name||'').trim();return modelListByUpstream[resolved]||[]}
function upstreamSelectHtml(selected){const names=Object.keys(upstreamData).sort();if(names.length===0)return '<select data-field="upstream" class="m-select" disabled><option value="">（未配置上游）</option></select>';let h='<select data-field="upstream" class="m-select" onchange="onAliasUpstreamChange(this)">';for(const name of names){h+='<option value="'+esc(name)+'"'+(selected===name?' selected':'')+'>'+esc(name)+'</option>'}h+='</select>';return h}
function modelSelectHtml(selected,upstreamName){const models=modelsForUpstream(upstreamName);if(models.length===0)return '<select data-field="val" class="m-select" disabled><option value="">（未配置模型）</option></select>';let h='<select data-field="val" class="m-select">';let found=!selected;for(const m of models){if(selected===m)found=true;h+='<option value="'+esc(m)+'"'+(selected===m?' selected':'')+'>'+esc(m)+'</option>'}if(selected&&!found)h+='<option value="'+esc(selected)+'" selected>'+esc(selected)+' (自定义)</option>';h+='</select>';return h}
function socks5SelectHtml(selected){let h='<select data-field="socks5_proxy" class="m-select"><option value="">直连</option>';let found=!selected;for(const p of socks5Data){if(!p||!p.addr)continue;const addr=String(p.addr).trim();if(!addr)continue;if(selected===addr)found=true;const label=p.name?String(p.name)+' ('+addr+')':addr;h+='<option value="'+esc(addr)+'"'+(selected===addr?' selected':'')+'>'+esc(label)+'</option>'}if(selected&&!found)h+='<option value="'+esc(selected)+'" selected>'+esc(selected)+' (已失效)</option>';h+='</select>';return h}
function renderAliasTable(){const tb=document.querySelector('#aliasTable tbody');const ks=Object.keys(aliasData);if(!ks.length){tb.innerHTML='<tr><td colspan="6" class="empty-hint">暂无别名配置</td></tr>';return}const sortedUpstreams=Object.keys(upstreamData).sort();const defaultUp=(sortedUpstreams.length&&sortedUpstreams[0])||'';tb.innerHTML=ks.map(k=>{const entry=aliasData[k]||{target_model:'',upstream:'',socks5_proxy:'',with_reasoning:false};const upName=entry.upstream||defaultUp;return '<tr><td><input value="'+esc(k)+'" data-field="key"></td><td>'+upstreamSelectHtml(upName)+'</td><td data-model-cell="1">'+modelSelectHtml(entry.target_model||'',upName)+'</td><td>'+socks5SelectHtml(entry.socks5_proxy||'')+'</td><td><input type="checkbox" data-field="with_reasoning" title="将历史 assistant 消息中的 reasoning_content 回传给上游"'+(entry.with_reasoning?' checked':'')+'></td><td><button class="btn btn-danger" onclick="delAlias(this)">删除</button></td></tr>'}).join('')}
function onAliasUpstreamChange(sel){const row=sel.closest('tr');const holder=row.querySelector('[data-model-cell]');const current=row.querySelector('[data-field="val"]');const currentVal=current?current.value.trim():'';holder.innerHTML=modelSelectHtml(currentVal,sel.value)}
function addAliasRow(){collectUpstreams();collectSocks5();const tb=document.querySelector('#aliasTable tbody');if(tb.querySelector('.empty-hint'))tb.innerHTML='';const sortedUpstreams=Object.keys(upstreamData).sort();const defaultUp=(sortedUpstreams.length&&sortedUpstreams[0])||'';tb.insertAdjacentHTML('beforeend','<tr><td><input value="" placeholder="例如: gpt-5.5" data-field="key"></td><td>'+upstreamSelectHtml(defaultUp)+'</td><td data-model-cell="1">'+modelSelectHtml('', defaultUp)+'</td><td>'+socks5SelectHtml('')+'</td><td><input type="checkbox" data-field="with_reasoning" title="将历史 assistant 消息中的 reasoning_content 回传给上游"></td><td><button class="btn btn-danger" onclick="delAlias(this)">删除</button></td></tr>')}
function delAlias(btn){const row=btn.closest('tr');const ki=row.querySelector('[data-field="key"]');if(ki&&ki.value&&aliasData[ki.value])delete aliasData[ki.value];row.remove();if(!Object.keys(aliasData).length)document.querySelector('#aliasTable tbody').innerHTML='<tr><td colspan="6" class="empty-hint">暂无别名配置</td></tr>'}
function collectAliases(){const r={};document.querySelectorAll('#aliasTable tbody tr').forEach(tr=>{const k=tr.querySelector('[data-field="key"]'),u=tr.querySelector('[data-field="upstream"]'),v=tr.querySelector('[data-field="val"]'),p=tr.querySelector('[data-field="socks5_proxy"]'),w=tr.querySelector('[data-field="with_reasoning"]');if(k&&k.value.trim()){const aliasKey=k.value.trim();let targetModel=v?v.value.trim():'';const upstreamName=u?u.value.trim():'';const socks5Proxy=p?p.value.trim():'';const withReasoning=w?w.checked:false;if(!targetModel&&(upstreamName||socks5Proxy||withReasoning))targetModel=aliasKey;if(targetModel||upstreamName||socks5Proxy||withReasoning){r[aliasKey]={target_model:targetModel,upstream:upstreamName,socks5_proxy:socks5Proxy,with_reasoning:withReasoning}}}});aliasData=r;return r}






function effortRowHtml(key,val){return '<div class="effort-row"><input value="'+esc(key||'')+'" data-field="key" placeholder="例如: low"><span class="effort-arrow">→</span><input value="'+esc(val||'')+'" data-field="val" placeholder="例如: high"><button class="btn btn-danger" onclick="delEffort(this)">删除</button></div>'}
function updateEffortSummary(){const el=document.getElementById('effortSummary');if(!el)return;const count=Object.keys(effortData||{}).length;el.textContent=count?count+' 条映射':'未配置 · 原值透传'}
function renderEffortTable(){const list=document.getElementById('effortList');const ks=Object.keys(effortData);list.innerHTML=ks.length?ks.map(k=>effortRowHtml(k,effortData[k])).join(''):'<div class="effort-empty">未配置，reasoning_effort 将按原值透传</div>';updateEffortSummary()}
function addEffortRow(){collectEfforts();const details=document.getElementById('reasoningEffortDetails');details.open=true;const list=document.getElementById('effortList');const empty=list.querySelector('.effort-empty');if(empty)empty.remove();list.insertAdjacentHTML('beforeend',effortRowHtml('',''));const rows=list.querySelectorAll('.effort-row');const input=rows.length?rows[rows.length-1].querySelector('[data-field="key"]'):null;if(input)input.focus()}
function delEffort(btn){const row=btn.closest('.effort-row');if(row)row.remove();collectEfforts();renderEffortTable()}
function collectEfforts(){const r={};document.querySelectorAll('#effortList .effort-row').forEach(row=>{const k=row.querySelector('[data-field="key"]'),v=row.querySelector('[data-field="val"]');if(k&&k.value.trim())r[k.value.trim()]=v?v.value.trim():''});effortData=r;updateEffortSummary();return r}
function renderSocks5Table(){const tb=document.querySelector('#socks5Table tbody');if(!socks5Data.length){tb.innerHTML='<tr><td colspan="5" class="empty-hint">暂无代理配置</td></tr>';return}tb.innerHTML=socks5Data.map((p,i)=>'<tr><td><input value="'+esc(p.name||'')+'" data-field="name" onchange="syncSocks5AliasOptions()"></td><td><input value="'+esc(p.addr)+'" data-field="addr" placeholder="例如: 127.0.0.1:1080" onchange="syncSocks5AliasOptions()"></td><td><input value="'+esc(p.username||'')+'" data-field="username"></td><td><input value="'+esc(p.password||'')+'" data-field="password" type="password"></td><td><button class="btn btn-danger" onclick="delSocks5('+i+')">删除</button></td></tr>').join('')}
function addSocks5Row(){collectSocks5();socks5Data.push({addr:'',name:''});renderSocks5Table()}
function delSocks5(i){collectAliases();const rows=document.querySelectorAll('#socks5Table tbody tr');if(rows[i])rows[i].remove();collectSocks5();renderSocks5Table();renderAliasTable()}
function collectSocks5(){const r=[];document.querySelectorAll('#socks5Table tbody tr').forEach(tr=>{const a=tr.querySelector('[data-field="addr"]');if(a&&a.value.trim())r.push({addr:a.value.trim(),name:(tr.querySelector('[data-field="name"]')||{}).value?.trim()||'',username:(tr.querySelector('[data-field="username"]')||{}).value?.trim()||'',password:(tr.querySelector('[data-field="password"]')||{}).value?.trim()||''})});socks5Data=r;return r}
function syncSocks5AliasOptions(){collectAliases();collectSocks5();renderAliasTable()}
async function saveConfig(section){const aliasRows=[...document.querySelectorAll('#aliasTable tbody tr')];if(aliasRows.some(tr=>{const k=tr.querySelector('[data-field="key"]');return k&&!k.value.trim()})){showToast('存在别名（请求名）为空的行，请填写后再保存','error');return}const dupCheck={};for(const tr of aliasRows){const k=tr.querySelector('[data-field="key"]');const key=k?k.value.trim():'';if(key){if(dupCheck[key]){showToast('存在重复的别名「'+key+'」，请修改后再保存','error');return}dupCheck[key]=true}}collectAliases();collectUpstreams();collectEfforts();collectSocks5();const cfg={model_alias:aliasData,reasoning_effort_map:effortData,socks5_proxies:socks5Data,upstreams:upstreamData};const label=section||'配置';try{const r=await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)});if(!r.ok)throw new Error(await r.text());showToast(label+'已保存','success');loadConfig()}catch(e){showToast(label+'保存失败: '+e.message,'error')}}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML.replace(/"/g,'&quot;').replace(/'/g,'&#39;')}
function showToast(msg,t){const e=document.getElementById('toast');e.textContent=msg;e.className=t+' show';clearTimeout(e._tid);e._tid=setTimeout(()=>e.classList.remove('show'),2500)}
// ======================== 使用统计（cc-switch 风格） ========================
var U={range:'today',row:{model:0,upstream:0,lifetime:0},rowSize:20,logPage:1,logSize:20,logStatus:'',logQ:'',data:null,log:null,pricing:null};
var U_RANGES=[['today','今日'],['7d','近 7 天'],['30d','近 30 天'],['all','全部']];
var UC_MODEL=[
{k:'key',t:'模型',w:130,pin:1},
{k:'upstreams',t:'上游',w:72},
{k:'targets',t:'上游模型',w:132},
{k:'requests',t:'请求数',w:70,n:1},
{k:'succ',t:'成功率',w:66,n:1},
{k:'errors',t:'失败',w:62,n:1},
{k:'input_tokens',t:'输入',w:100,n:1},
{k:'output_tokens',t:'输出',w:100,n:1},
{k:'cache_read_tokens',t:'缓存读',w:100,n:1},
{k:'cache_creation_tokens',t:'缓存写',w:100,n:1},
{k:'reasoning_tokens',t:'思考',w:100,n:1},
{k:'total_tokens',t:'总计',w:116,n:1},
{k:'cache_hit_rate',t:'缓存命中',w:64,n:1},
{k:'avg_latency_ms',t:'平均耗时',w:60,n:1},
{k:'avg_first_token_ms',t:'首字延迟',w:60,n:1},
{k:'cost_usd',t:'估算费用',w:116,n:1}];
var UC_UPSTREAM=[
{k:'key',t:'上游',w:76,pin:1},
{k:'models',t:'模型',w:146},
{k:'requests',t:'请求数',w:70,n:1},
{k:'succ',t:'成功率',w:66,n:1},
{k:'errors',t:'失败',w:62,n:1},
{k:'input_tokens',t:'输入',w:100,n:1},
{k:'output_tokens',t:'输出',w:100,n:1},
{k:'cache_read_tokens',t:'缓存读',w:100,n:1},
{k:'cache_creation_tokens',t:'缓存写',w:100,n:1},
{k:'total_tokens',t:'总计',w:116,n:1},
{k:'cache_hit_rate',t:'缓存命中',w:64,n:1},
{k:'avg_latency_ms',t:'平均耗时',w:60,n:1},
{k:'cost_usd',t:'估算费用',w:116,n:1}];
var UC_LIFETIME=[
{k:'key',t:'模型',w:130,pin:1},
{k:'requests',t:'请求数',w:70,n:1},
{k:'errors',t:'失败',w:62,n:1},
{k:'input_tokens',t:'输入',w:100,n:1},
{k:'output_tokens',t:'输出',w:100,n:1},
{k:'cache_read_tokens',t:'缓存读',w:100,n:1},
{k:'cache_creation_tokens',t:'缓存写',w:100,n:1},
{k:'reasoning_tokens',t:'思考',w:100,n:1},
{k:'total_tokens',t:'总计',w:116,n:1},
{k:'avg_latency_ms',t:'平均耗时',w:60,n:1},
{k:'cost_usd',t:'估算费用',w:116,n:1}];
var UC_LOG=[
{k:'time',t:'时间',w:124,pin:1,n:1},
{k:'model',t:'模型',w:144},
{k:'upstream',t:'上游',w:72},
{k:'api',t:'接口',w:44},
{k:'stream',t:'流式',w:50,n:1},
{k:'status',t:'状态',w:54,n:1},
{k:'latency_ms',t:'耗时',w:56,n:1},
{k:'first_token_ms',t:'首字',w:56,n:1},
{k:'cost_usd',t:'费用',w:92,n:1},
{k:'input_tokens',t:'输入',w:94,n:1},
{k:'output_tokens',t:'输出',w:94,n:1},
{k:'cache_read_tokens',t:'缓存读',w:94,n:1},
{k:'cache_creation_tokens',t:'缓存写',w:94,n:1},
{k:'total_tokens',t:'总计',w:94,n:1}];

function fmt(n){return (n||0).toString().replace(/\B(?=(\d{3})+(?!\d))/g,',')}
function fmtTok(n){n=n||0;if(n>=100000000)return (n/100000000).toFixed(2)+' 亿';if(n>=10000)return (n/10000).toFixed(1)+' 万';return fmt(n)}
function fmtMs(n){if(!n)return '<span class="u-mut">—</span>';if(n<1000)return n+'ms';var s=n/1000;if(s<9.995)return s.toFixed(2)+'s';if(s<99.95)return s.toFixed(1)+'s';return Math.round(s)+'s'}
function fmtCost(c,meta){if(!meta.configured||!c)return '—';var s=meta.currency==='USD'?'$':(meta.currency+' ');return s+c.toFixed(4)}
function fmtTime(ts){if(!ts)return '—';var d=new Date(ts*1000);function p(x){return x<10?'0'+x:''+x}return p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds())}
function uMeta(){var p=(U.data&&U.data.pricing)||{};return {currency:p.currency||'USD',configured:!!p.configured}}
function uTags(list){list=list||[];if(!list.length)return '<span class="u-mut">—</span>';var show=list.slice(0,3).map(function(x){return '<span class="u-tag">'+esc(x)+'</span>'}).join('');return show+(list.length>3?'<span class="u-mut"> +'+(list.length-3)+'</span>':'')}

function usageCell(c,r,meta,first){
var k=c.k,v;
if(k==='key'||k==='model')return '<td'+(first?' class="pin"':'')+' title="'+esc(String(r[k]||''))+'">'+esc(r[k]||'')+'</td>';
if(k==='upstreams')return '<td title="'+esc((r.upstreams||[]).join(', '))+'">'+uTags(r.upstreams)+'</td>';
if(k==='models')return '<td title="'+esc((r.models||[]).join(', '))+'">'+uTags(r.models)+'</td>';
if(k==='targets')return '<td title="'+esc((r.targets||[]).join(', '))+'">'+uTags(r.targets)+'</td>';
if(k==='time')return '<td class="'+(first?'pin ':'')+'num">'+fmtTime(r.ts)+'</td>';
if(k==='api')return '<td>'+(r.api?esc(r.api):'<span class="u-mut">—</span>')+'</td>';
if(k==='stream')return '<td class="num">'+(r.stream?'<span class="u-pill ok">流</span>':'<span class="u-mut">—</span>')+'</td>';
if(k==='status'){var st=r.status||0;var ok=st>=200&&st<300;var t=r.error?' title="'+esc(r.error)+'"':(ok?'':' title="未收到上游响应（超时/断开/请求被拒）"');return '<td class="num"'+t+'><span class="u-pill '+(ok?'ok':'bad')+'">'+(ok?st:(st?st:'无响应'))+'</span></td>'}
if(k==='succ'){var req=r.requests||0;var err=r.error_count||0;return '<td class="num">'+(req?(((req-err)/req)*100).toFixed(1)+'%':'—')+'</td>'}
if(k==='errors'){v=r.error_count||0;return '<td class="num">'+(v?'<span class="u-bad">'+fmt(v)+'</span>':'<span class="u-mut">0</span>')+'</td>'}
if(k==='cache_hit_rate'){v=r.cache_hit_rate||0;return '<td class="num">'+(v>0?v.toFixed(1)+'%':'<span class="u-mut">—</span>')+'</td>'}
if(k==='avg_latency_ms')return '<td class="num">'+fmtMs(r.avg_latency_ms)+'</td>';
if(k==='avg_first_token_ms')return '<td class="num">'+fmtMs(r.avg_first_token_ms)+'</td>';
if(k==='latency_ms')return '<td class="num">'+fmtMs(r.latency_ms)+'</td>';
if(k==='first_token_ms')return '<td class="num">'+fmtMs(r.first_token_ms)+'</td>';
if(k==='cost_usd'){var cv=fmtCost(r.cost_usd,meta);return '<td class="num"'+(cv==='—'?' title="未配置费用单价"':'')+'>'+(cv==='—'?'<span class="u-mut">—</span>':cv)+'</td>'}
v=r[k]||0;return '<td class="num">'+(v?fmt(v):'<span class="u-mut">0</span>')+'</td>';
}

function usagePager(key,rp,rn,total){
var h='<div class="u-pager">';
if(rn>1)h+='<button '+(rp<=0?'disabled':'')+' onclick="usageRowStep(\''+key+'\',-1)">‹</button><span class="pg">'+(rp+1)+'/'+rn+'</span><button '+(rp>=rn-1?'disabled':'')+' onclick="usageRowStep(\''+key+'\',1)">›</button><span class="u-hint">共 '+fmt(total)+' 行</span>';
h+='</div>';return h;
}

function usageTable(key,cols,rows,meta,totals){
var wrap=document.getElementById('uwrap_'+key);if(!wrap)return;
rows=rows||[];
var size=U.rowSize,rn=Math.max(1,Math.ceil(rows.length/size));
var rp=Math.max(0,Math.min(U.row[key]||0,rn-1));U.row[key]=rp;
var body=rows.slice(rp*size,rp*size+size);
var cw=0,cg='<colgroup>';
for(var i=0;i<cols.length;i++){cg+='<col style="width:'+cols[i].w+'px">';cw+=cols[i].w}
cg+='</colgroup>';
var t='<table class="tbl usage-tbl" style="min-width:'+cw+'px">'+cg+'<thead><tr>';
for(i=0;i<cols.length;i++){var c=cols[i];t+='<th class="'+(c.n?'num ':'')+(i===0&&c.pin?'pin':'')+'">'+c.t+'</th>'}
t+='</tr></thead><tbody>';
if(!body.length)t+='<tr><td colspan="'+cols.length+'" class="empty-hint">该区间暂无数据</td></tr>';
for(var j=0;j<body.length;j++){t+='<tr'+(j%2?' class="alt"':'')+'>';for(i=0;i<cols.length;i++)t+=usageCell(cols[i],body[j],meta,i===0);t+='</tr>'}
if(totals&&rows.length){t+='<tr class="tot">';for(i=0;i<cols.length;i++)t+=usageCell(cols[i],totals,meta,i===0);t+='</tr>'}
t+='</tbody></table>';
wrap.innerHTML=t;
var pg=document.getElementById(key+'_pager');if(pg)pg.innerHTML=usagePager(key,rp,rn,rows.length);
}

function usageLogTable(meta){
var L=U.log||{rows:[],total:0,page:1,pages:1};
var wrap=document.getElementById('uwrap_log');if(!wrap)return;
var cw=0,cg='<colgroup>';
for(var i=0;i<UC_LOG.length;i++){cg+='<col style="width:'+UC_LOG[i].w+'px">';cw+=UC_LOG[i].w}
cg+='</colgroup>';
var t='<table class="tbl usage-tbl" style="min-width:'+cw+'px">'+cg+'<thead><tr>';
for(i=0;i<UC_LOG.length;i++){var c=UC_LOG[i];t+='<th class="'+(c.n?'num ':'')+(i===0&&c.pin?'pin':'')+'">'+c.t+'</th>'}
t+='</tr></thead><tbody>';
if(!L.rows.length)t+='<tr><td colspan="'+UC_LOG.length+'" class="empty-hint">暂无请求明细</td></tr>';
for(var j=0;j<L.rows.length;j++){t+='<tr'+(j%2?' class="alt"':'')+'>';for(i=0;i<UC_LOG.length;i++)t+=usageCell(UC_LOG[i],L.rows[j],meta,i===0);t+='</tr>'}
t+='</tbody></table>';
wrap.innerHTML=t;
var pg=document.getElementById('log_pager');
if(pg){var h2='';
if(L.pages>1)h2='<div class="u-pager"><button '+(L.page<=1?'disabled':'')+' onclick="usageLogStep(-1)">‹</button><span class="pg">'+L.page+'/'+L.pages+'</span><button '+(L.page>=L.pages?'disabled':'')+' onclick="usageLogStep(1)">›</button><span class="u-hint">共 '+fmt(L.total)+' 条</span></div>';
pg.innerHTML=h2}
}

function usageCards(s,meta){
var d=s||{};
function card(k,v,sub,hl){return '<div class="u-card'+(hl?' hl':'')+'"><div class="k">'+k+'</div><div class="v">'+v+'</div><div class="s">'+(sub||'')+'</div></div>'}
var req=d.requests||0,err=d.error_count||0;
var h='';
h+=card('请求数',fmt(req),err?'<span class="u-bad">失败 '+fmt(err)+'</span>':'<span class="u-ok">全部成功</span>',1);
h+=card('总计 Token',fmtTok(d.total_tokens),'输入+输出+缓存');
h+=card('输入 Token',fmtTok(d.input_tokens),'不含缓存部分');
h+=card('输出 Token',fmtTok(d.output_tokens),(d.reasoning_tokens?'含思考 '+fmtTok(d.reasoning_tokens):'completion'));
h+=card('缓存读',fmtTok(d.cache_read_tokens),(d.cache_hit_rate?'命中率 '+d.cache_hit_rate.toFixed(1)+'%':'cache read'));
h+=card('缓存写',fmtTok(d.cache_creation_tokens),'cache creation');
h+=card('平均耗时',fmtMs(d.avg_latency_ms),(d.avg_first_token_ms?'首字 '+fmtMs(d.avg_first_token_ms):'端到端'));
h+=card('估算费用',fmtCost(d.cost_usd,meta),meta.configured?'按 pricing.json':'未配置单价');
return '<div class="u-cards">'+h+'</div>';
}

function renderUsage(){
var d=U.data;if(!d)return;
var meta=uMeta();
var rg=d.range||{};
var banner='<div class="u-banner">📊 使用统计 · '+esc(rg.label||'今日')+' ('+esc(rg.start?rg.start+' ~ ':'')+esc(rg.end||d.today)+')：请求 <b>'+fmt((d.summary||{}).requests||0)+'</b> 次 · 模型 <b>'+((d.models||[]).length)+'</b> 个 · 上游 <b>'+((d.upstreams||[]).length)+'</b> 个</div>';
var h='';
h+='<div class="u-sec">'+banner+usageCards(d.summary,meta)+'</div>';
h+='<div class="u-sec"><div class="u-sec-h"><h3>模型用量</h3><span id="model_pager"></span></div><div class="u-wrap" id="uwrap_model"></div></div>';
h+='<div class="u-sec"><div class="u-sec-h"><h3>上游用量</h3><span id="upstream_pager"></span></div><div class="u-wrap" id="uwrap_upstream"></div></div>';
h+='<div class="u-sec"><div class="u-sec-h"><h3>请求明细</h3><span id="log_pager"></span></div><div class="u-wrap" id="uwrap_log"></div></div>';
h+='<div class="u-sec"><div class="u-sec-h"><h3>累计统计</h3><span class="u-hint">自启用统计以来的全部历史</span><span id="lifetime_pager"></span></div><div class="u-wrap" id="uwrap_lifetime"></div></div>';
document.getElementById('statsContent').innerHTML=h;
var sum=Object.assign({key:'区间合计'},d.summary||{});
usageTable('model',UC_MODEL,d.models,meta,sum);
usageTable('upstream',UC_UPSTREAM,d.upstreams,meta,Object.assign({key:'区间合计'},d.summary||{}));
usageTable('lifetime',UC_LIFETIME,d.lifetime,meta,null);
usageLogTable(meta);
var m=document.getElementById('usageMeta');
if(m)m.textContent='数据保留 '+(d.history_days||90)+' 天聚合 · 明细 '+(d.log_total||0)+' 条 · 每 5 秒自动刷新';
}

async function loadUsage(manual){
var sy=window.scrollY;
try{
var r=await fetch('/api/usage?range='+encodeURIComponent(U.range));
U.data=await r.json();
var lr=await fetch('/api/usage/log?page='+U.logPage+'&size='+U.logSize+'&status='+encodeURIComponent(U.logStatus)+'&q='+encodeURIComponent(U.logQ));
U.log=await lr.json();
U.logPage=U.log.page;
renderUsage();
if(manual)showToast('使用统计已刷新','success');
setTimeout(function(){window.scrollTo(0,sy)},0);
}catch(e){var el=document.getElementById('statsContent');if(el)el.innerHTML='<div class="empty-hint">加载失败: '+esc(e.message)+'</div>'}
}

function setUsageRange(k){U.range=k;U.row={model:0,upstream:0,lifetime:0};initUsageSegs();loadUsage()}
function setLogStatus(k){U.logStatus=k;U.logPage=1;initUsageSegs();loadUsage()}
function onUsageLogSize(v){U.logSize=parseInt(v,10)||20;U.logPage=1;loadUsage()}
function onUsageRowSize(v){U.rowSize=parseInt(v,10)||20;U.row={model:0,upstream:0,lifetime:0};renderUsage()}
var _usageQ=null;
function onUsageSearch(v){clearTimeout(_usageQ);_usageQ=setTimeout(function(){U.logQ=v;U.logPage=1;loadUsage()},350)}
function usageRowStep(k,d){U.row[k]=Math.max(0,(U.row[k]||0)+d);renderUsage()}
function usageLogStep(d){U.logPage=Math.max(1,U.logPage+d);loadUsage()}
function initUsageSegs(){
var rs=document.getElementById('usageRangeSeg');
if(rs)rs.innerHTML=U_RANGES.map(function(x){return '<button class="'+(U.range===x[0]?'on':'')+'" onclick="setUsageRange(\''+x[0]+'\')">'+x[1]+'</button>'}).join('');
var ls=document.getElementById('usageLogStatusSeg');
if(ls)ls.innerHTML=[['','全部状态'],['ok','成功'],['err','失败']].map(function(x){return '<button class="'+(U.logStatus===x[0]?'on':'')+'" onclick="setLogStatus(\''+x[0]+'\')">'+x[1]+'</button>'}).join('');
}

// ---------- 费用单价编辑 ----------
function pricingRowHtml(v){
v=v||{model:'',input:'',output:'',cache_read:'',cache_creation:''};
return '<div class="pricing-row"><input value="'+esc(v.model||'')+'" data-field="model" placeholder="模型名，如 glm-5.3-flash"><input value="'+esc(String(v.input==null?'':v.input))+'" data-field="input" placeholder="0" inputmode="decimal"><input value="'+esc(String(v.output==null?'':v.output))+'" data-field="output" placeholder="0" inputmode="decimal"><input value="'+esc(String(v.cache_read==null?'':v.cache_read))+'" data-field="cache_read" placeholder="0" inputmode="decimal"><input value="'+esc(String(v.cache_creation==null?'':v.cache_creation))+'" data-field="cache_creation" placeholder="0" inputmode="decimal"><button class="btn btn-danger" onclick="delPricingRow(this)">删除</button></div>';
}
function renderPricingList(){
var list=document.getElementById('pricingList');if(!list)return;
var rows=U.pricing&&U.pricing.rows?U.pricing.rows:[];
list.innerHTML=rows.length?rows.map(pricingRowHtml).join(''):'<div class="u-hint" style="padding:6px 0">尚未配置单价，费用列显示为 —。</div>';
var ps=document.getElementById('pricingSummary');
if(ps)ps.textContent=rows.length?rows.length+' 个模型 · '+(U.pricing.currency||'USD'):'未配置 · 只显示 token';
}
async function loadPricing(){
try{var r=await fetch('/api/pricing');var p=await r.json();
var rows=[];var models=p.models||{};
Object.keys(models).sort().forEach(function(k){rows.push(Object.assign({model:k},models[k]))});
U.pricing={currency:p.currency||'USD',rows:rows};
renderPricingList();}catch(e){}
}
function addPricingRow(){collectPricing();var list=document.getElementById('pricingList');var empty=list.querySelector('.u-hint');if(empty)empty.remove();list.insertAdjacentHTML('beforeend',pricingRowHtml({}));var rows=list.querySelectorAll('.pricing-row');if(rows.length)rows[rows.length-1].querySelector('[data-field="model"]').focus()}
function delPricingRow(btn){var row=btn.closest('.pricing-row');if(row)row.remove();collectPricing();renderPricingList()}
function collectPricing(){
var rows=[];
document.querySelectorAll('#pricingList .pricing-row').forEach(function(tr){
var m=(tr.querySelector('[data-field="model"]')||{}).value||'';
if(!m.trim())return;
function num(f){var el=tr.querySelector('[data-field="'+f+'"]');var v=parseFloat(el?el.value:'');return isNaN(v)?0:v}
rows.push({model:m.trim(),input:num('input'),output:num('output'),cache_read:num('cache_read'),cache_creation:num('cache_creation')});
});
if(!U.pricing)U.pricing={currency:'USD',rows:[]};
U.pricing.rows=rows;return rows;
}
async function savePricing(){
collectPricing();
var models={};
(U.pricing.rows||[]).forEach(function(r){models[r.model]={input:r.input,output:r.output,cache_read:r.cache_read,cache_creation:r.cache_creation}});
var st=document.getElementById('pricingStatus');st.textContent='保存中...';
try{var r=await fetch('/api/pricing',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({currency:U.pricing.currency||'USD',models:models})});
if(!r.ok)throw new Error(await r.text());
st.textContent='已保存';showToast('费用单价已保存','success');
loadPricing();loadUsage();setTimeout(function(){st.textContent=''},2000)}catch(e){st.textContent='失败: '+e.message;showToast('保存失败','error')}
}

async function resetStats(){
if(!confirm('确认清空全部使用统计？\n将同时清除每日聚合与请求明细，此操作不可撤销。'))return;
var s=document.getElementById('resetStatus');s.textContent='清空中...';
try{const r=await fetch('/api/stats',{method:'DELETE'});if(!r.ok)throw new Error(await r.text());
U.row={model:0,upstream:0,lifetime:0};U.logPage=1;
await loadUsage();s.textContent='已清空';setTimeout(()=>s.textContent='',2000)}catch(e){s.textContent='失败: '+e.message}
}

window.onload=function(){loadConfig();initUsageSegs();loadPricing();loadUsage()};
setInterval(function(){if(!document.hidden)loadUsage()},5000);
document.addEventListener('visibilitychange',function(){if(!document.hidden)loadUsage()});
</script>
</body>
</html>`

// ======================== 连接保活与预热 Worker ========================

// allConfiguredSocks5ProxyAddrs 返回全部已配置代理地址，外加一个空串代表直连。
func allConfiguredSocks5ProxyAddrs() []string {
	socks5Mu.RLock()
	defer socks5Mu.RUnlock()
	addrs := make([]string, 0, len(socks5Proxies)+1)
	addrs = append(addrs, "") // 直连
	for _, p := range socks5Proxies {
		if p.Addr != "" {
			addrs = append(addrs, p.Addr)
		}
	}
	return addrs
}

// warmUpstreamConnections 对「代理出口 × 流式/非流式连接池 × 上游」做轻量 HEAD 预热，
// 让真正的推理请求命中已建立（TCP+SOCKS5+TLS）的温热连接，免去握手延迟。
// 关键：必须分别预热 stream=true / stream=false 两个独立连接池，
// 流式请求走 stream=true 的池，此前只预热了非流式池等于白做。
func warmUpstreamConnections() {
	upstreams := getConfiguredUpstreams()
	if len(upstreams) == 0 {
		return
	}
	for _, proxyAddr := range allConfiguredSocks5ProxyAddrs() {
		for _, stream := range []bool{true, false} {
			client, _ := getModelHTTPClient(proxyAddr, stream)
			for name, up := range upstreams {
				if up == nil || up.BaseURL == "" {
					continue
				}
				endpoint := getUpstreamModelsEndpoint(up)
				if endpoint == "" {
					continue
				}
				req, err := http.NewRequest("HEAD", endpoint, nil)
				if err != nil {
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				req = req.WithContext(ctx)
				if key, _, _ := selectUpstreamAPIKey(name, up, ""); key != "" {
					req.Header.Set("Authorization", "Bearer "+key)
				}
				applyCustomHeaders(req, up)
				resp, err := client.Do(req)
				if err == nil {
					resp.Body.Close()
				}
				cancel()
			}
		}
	}
}

func startConnectionKeepAliveWorker() {
	go func() {
		// 启动立即预热一次，不等第一个 30s 周期，避免重启后的第一条请求付握手开销
		warmUpstreamConnections()
		// 每 30 秒执行一次空闲长连接保活（< IdleConnTimeout 120s，连接永不过期）
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			warmUpstreamConnections()
		}
	}()
}

// ======================== Main ========================

func main() {
	flag.StringVar(&port, "port", "8000", "服务端口")
	flag.StringVar(&configPath, "config", "config.json", "配置文件路径")
	flag.StringVar(&adminPassword, "password", "", "管理面板密码（留空则不启用登录验证）")
	flag.BoolVar(&debugMode, "debug", false, "启用调试日志")
	flag.Parse()

	cfg := loadConfig(configPath)
	applyConfig(cfg)
	if err := saveConfig(configPath, cfg); err != nil {
		log.Printf("警告: 无法保存配置: %v", err)
	}

	loadTokenStats()
	loadPricing()
	startUsageSaveWorker()
	startConnectionKeepAliveWorker()
	log.Printf("配置已从 %s 加载", configPath)
	log.Printf("LLM Gateway")
	log.Printf("===================")
	log.Printf("端口:     %s", port)
	log.Printf("上游:     %d 个", getConfiguredUpstreamCount())
	log.Printf("模型：  %d 个自定义模型", countConfiguredModels())
	log.Printf("别名：  %d", len(modelAlias))

	if adminPassword != "" {
		log.Printf("管理面板: http://localhost:%s/ （密码认证已启用）", port)
	} else {
		log.Printf("管理面板: http://localhost:%s/ （无密码）", port)
	}
	log.Printf("===================")
	http.HandleFunc("/v1/chat/completions", chatCompletionsHandler)
	http.HandleFunc("/v1/responses", responsesHandler)
	http.HandleFunc("/v1/messages", anthropicMessagesHandler)
	http.HandleFunc("/v1/models", listModelsHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/api/config", requireAuth(adminConfigHandler))
	http.HandleFunc("/api/stats", requireAuth(adminStatsHandler))
	http.HandleFunc("/api/usage", requireAuth(adminUsageHandler))
	http.HandleFunc("/api/usage/log", requireAuth(adminUsageLogHandler))
	http.HandleFunc("/api/pricing", requireAuth(adminPricingHandler))
	http.HandleFunc("/api/reload", requireAuth(reloadHandler))
	http.HandleFunc("/api/upstream/models", requireAuth(upstreamModelsHandler))
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			requireAuth(adminPageHandler)(w, r)
			return
		}
		http.NotFound(w, r)
	})
	addr := ":" + port
	log.Printf("服务器启动在 %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
