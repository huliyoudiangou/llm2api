package main

// ======================== WorkBuddy (CodeBuddy) 上游 ========================
//
// 本文件把 WorkBuddy2API（github.com/Sliverkiss/workbuddy2api，MIT 许可）的核心能力
// 集成为本网关的一种上游类型（upstream.api_type = "workbuddy"）：
//
//   - OAuth 设备授权登录（-wb-login 子命令），凭证落盘 auths/workbuddy-<uid>.json；
//   - 账号池：多账号轮转、单号故障自动换号、在途租约、会话粘性（同对话尽量同账号）；
//   - 分级熔断/冷却：429/限流文案软冷却（指数退避）、402/余额耗尽硬冷却至次日 04:00、
//     6004 模型级限流只冷却该模型、session 失效（12153）禁用、上游故障连败熔断；
//   - access token 临期自动刷新（/v2/plugin/auth/token/refresh），刷新结果原子写回账号文件；
//   - 出站改写：强制 stream:true、tool_choice/developer 角色归一、DeepSeek 思维链注入、
//     reasoning_content 回填、Claude Code/Codex 指纹脱敏；
//   - SSE：流式帧规范化（tool_calls 函数名跨帧回填），非流式客户端请求本地聚合为单个响应；
//   - 模型列表：CN 动态探测（cli agent 过滤）+ 静态兜底；Global 静态名单；
//   - 后台任务：token 保活刷新、CN 账号每日签到（upstream.wb_checkin = true 时）。
//
// 上游协议（端点/请求头/业务错误码）以 workbuddy2api 实测实现为准；两处细节与其一致：
// CN chat 走 copilot.tencent.com，Global 走 www.workbuddy.ai（/console 路径 404/405 回退 /v2）。

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ======================== 常量 ========================

const (
	wbChatBaseCN     = "https://copilot.tencent.com"
	wbChatBaseGlobal = "https://www.workbuddy.ai"
	wbOriginCN       = "https://www.codebuddy.cn"
	wbOriginGlobal   = "https://www.workbuddy.ai"

	wbChatPathCN        = "/v2/chat/completions"
	wbChatPathGlobal    = "/console/chat/completions"
	wbRefreshPath       = "/v2/plugin/auth/token/refresh"
	wbModelsPathCN      = "/console/enterprises/personal/models"
	wbModelsPathGlobal  = "/v2/enterprises/personal/models"
	wbBillingMeterV2    = "/v2/billing/meter/get-user-resource"
	wbBillingMeterPlain = "/billing/meter/get-user-resource"
	wbCheckinV2         = "/v2/billing/meter/daily-checkin"
	wbCheckinPlain      = "/billing/meter/daily-checkin"

	wbDefaultClientVersion = "5.5.4"
	wbDefaultCliVersion    = "2.137.1"
	wbLoginUA              = "CLI/2.63.2 CodeBuddy/2.63.2"

	wbMaxRotate       = 4                 // 单请求最多换号次数
	wbRefreshSkew     = 10 * time.Minute  // token 提前刷新窗口
	wbSoftCooldown    = 600 * time.Second // 软限流冷却基数（连击指数退避）
	wbSoftCooldownMax = 2 * time.Hour     // 软限流冷却封顶
	wbNotFoundCool    = 60 * time.Second  // 404 固定浅冷却
	wbBreakerThresh   = 3                 // 连续 5xx 失败触发熔断
	wbBreakerBase     = 30 * time.Minute  // 熔断冷却基数
	wbBreakerMax      = 6 * time.Hour     // 熔断冷却封顶
	wbStreamIdleMax   = 300 * time.Second // SSE 流中静默超时
	wbStickyTTL       = 30 * time.Minute  // 会话粘性绑定 TTL
	wbRPCDeadline     = 60 * time.Second  // 短 RPC（刷新/签到/余额）超时
)

// wbStaticModelsCN / wbStaticModelsGlobal 为模型探测失败时的静态兜底名单
// （对齐 workbuddy2api handler.staticModels / upstream.GlobalModelNames）。
var wbStaticModelsCN = []string{
	"glm-5.2", "glm-5.1", "glm-5v-turbo", "kimi-k2.7", "minimax-m3",
	"hy3", "hy3-preview", "hy3-preview-agent", "deepseek-v4-pro", "deepseek-v4-flash",
}

var wbStaticModelsGlobal = []string{
	"default-model", "fast-model", "balanced-model", "primary-model", "hy4-preview",
	"gpt-5.6-sol", "gpt-5.6-terra", "deep-model", "deepseek-v4.1-flash", "gpt-6-astra",
	"hy4-preview-f", "hy3", "glm-5.2", "gpt-5.6-luna", "gpt-5.5",
	"gpt-5.4", "gpt-5.3-codex", "gemini-3.5-flash", "glm-5.3", "kimi-k3", "kimi-k2.6",
}

// wbDefaultPrompt 网关自有系统提示词（wb_prompt_mode="custom" 且未配 wb_prompt_text 时使用）。
const wbDefaultPrompt = `你是一名工程助手，帮助用户完成软件工程任务。以下原则指导你的行为。

## 核心立场
- 你的价值是让用户的工程目标更快达成，而非展示你自己的能力边界。
- 当用户的方向有更优解时，直接指出并给出替代方案；不必逢迎。
- 对不确定的事保持诚实：宁可说"我不确定，需要验证"，也不编造看似合理的答案。

## 语言与风格
- 跟随用户的提问语言：用户用中文则用中文，用英文则用英文。
- 简洁直接，不说废话；不用客套开场与总结，不重复用户已说过的内容。
- 技术术语精确，不为了通俗而牺牲准确性。

## 工程行为
- 先看代码再动手：理解上下文、既有模式与约定，避免破坏一致性。
- 最小改动：只改必要的部分，不做无关重构或风格统一。
- 改动后验证闭环：运行测试或构建确认结果，不假设"应该没问题"。
- 遇到不确定的边界，先确认再执行，不擅自扩大范围或假设需求。
- 修改共享代码前，先看它被谁依赖，避免连锁影响。

## 任务分解
- 复杂任务先拆步骤，按依赖顺序推进；每步可独立验证。
- 给出改动清单与影响面，让用户能判断是否继续。
- 失败时如实报告原因，给出下一步建议，不掩盖、不粉饰。

## 边界
- 不臆造未给定的 API、字段或行为；不确定时如实说明并给出验证路径。
- 安全敏感操作（删除、覆盖、发布）先确认，除非已被明确授权。
- 错误与失败如实报告，不为了让结果"好看"而省略或美化。`

// ======================== 错误分类 ========================

type wbErrKind int

const (
	wbErrNone           wbErrKind = iota
	wbErrHardCredit               // 余额不足（402 或文案）→ 硬冷却至次日 04:00
	wbErrSoftRate                 // 429 / 限流文案 → 软冷却（指数退避）
	wbErrSessionDead              // 401 + 12153 offline session → 禁用账号
	wbErrNotFound                 // 404 → 短冷却
	wbErrServer                   // 5xx → 连败计数 → 熔断
	wbErrContentBlocked           // 内容审核拦截 → 不罚账号，直接回错
	wbErrBadParams                // 上游 body 解析失败（11101）→ 不罚账号，仍轮转
	wbErrAccountFault             // 账号级故障（11140 request illegal / 14017 trial）→ 冷却/禁用
	wbErrClient                   // 其他 4xx → 不罚账号，仅轮转
)

func (k wbErrKind) String() string {
	switch k {
	case wbErrHardCredit:
		return "hard_credit"
	case wbErrSoftRate:
		return "soft_rate"
	case wbErrSessionDead:
		return "session_dead"
	case wbErrNotFound:
		return "not_found"
	case wbErrServer:
		return "server"
	case wbErrContentBlocked:
		return "content_blocked"
	case wbErrBadParams:
		return "bad_params"
	case wbErrAccountFault:
		return "account_fault"
	case wbErrClient:
		return "client"
	default:
		return "none"
	}
}

type wbError struct {
	Kind   wbErrKind
	Status int
	Msg    string
}

func (e *wbError) Error() string {
	return fmt.Sprintf("workbuddy upstream %s (http %d): %s", e.Kind, e.Status, e.Msg)
}

var (
	wbHardMarkers = []string{
		"insufficient credit", "no credit", "credit exhausted", "out of credit",
		"quota exceeded", "quota exhaust", "payment required", "credit not enough",
		"not enough credit",
		"积分不足", "额度不足", "余额不足", "积分用完", "额度用尽", "没有积分",
	}
	wbSoftRateMarkers = []string{
		"rate limit", "rate-limiting", "rate-limited",
		"too many requests", "too many", "usage limit",
		"请求过于频繁", "限流",
	}
	wbSessionDeadMarkers  = []string{"Offline user session not found", "12153"}
	wbContentBlockMarkers = []string{
		"blocked by security policy", "unapproved channel", "illegal api invocation",
	}
	wbAccountFaultMarkers = []string{
		"request illegal", "trial not activated", "trial version is not yet activated",
	}
	wbAlreadyCheckinMarkers = []string{"已签到", "already"}
)

// wbClassify 按 HTTP 状态码 + 响应体判定错误类别（判定顺序与 workbuddy2api Classify 一致）。
func wbClassify(status int, body string) wbErrKind {
	if status == http.StatusPaymentRequired {
		return wbErrHardCredit
	}
	lower := strings.ToLower(body)
	for _, m := range wbHardMarkers {
		if strings.Contains(lower, strings.ToLower(m)) || strings.Contains(body, m) {
			return wbErrHardCredit
		}
	}
	for _, m := range wbSessionDeadMarkers {
		if strings.Contains(body, m) {
			return wbErrSessionDead
		}
	}
	for _, m := range wbAccountFaultMarkers {
		if strings.Contains(lower, strings.ToLower(m)) || strings.Contains(body, m) {
			return wbErrAccountFault
		}
	}
	for _, m := range wbSoftRateMarkers {
		if strings.Contains(lower, strings.ToLower(m)) || strings.Contains(body, m) {
			return wbErrSoftRate
		}
	}
	if status == http.StatusTooManyRequests {
		return wbErrSoftRate
	}
	if status == http.StatusNotFound {
		return wbErrNotFound
	}
	if status >= 500 {
		return wbErrServer
	}
	if status >= 400 {
		for _, m := range wbContentBlockMarkers {
			if strings.Contains(lower, strings.ToLower(m)) {
				return wbErrContentBlocked
			}
		}
		if strings.Contains(body, "Unmarshal chat params failed") || strings.Contains(body, `"code":11101`) {
			return wbErrBadParams
		}
		return wbErrClient
	}
	return wbErrNone
}

var (
	wbModelRateLimitRe = regexp.MustCompile(`"code"\s*:\s*"?6004"?`)
	wbSoftRateResetRe  = regexp.MustCompile(`将在 (.+?) 重置`)
	wbSoftRateLoc      = time.FixedZone("UTC+8", 8*3600)
)

// wbIsModelRateLimit 报告 429 body 是否为「模型级用量限流」（业务 code 6004）。
func wbIsModelRateLimit(body string) bool { return wbModelRateLimitRe.MatchString(body) }

// wbParseSoftRateReset 从 6004 文案解析上游给出的重置时刻（固定按 UTC+8 解释）。
func wbParseSoftRateReset(body string) (time.Time, bool) {
	if !wbIsModelRateLimit(body) {
		return time.Time{}, false
	}
	m := wbSoftRateResetRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return time.Time{}, false
	}
	ts := strings.TrimSpace(strings.TrimSuffix(m[1], " UTC+8"))
	t, err := time.ParseInLocation("2006-01-02 15:04:05", ts, wbSoftRateLoc)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// wbContentBlockedMessage 把内容审核拦截改写成对用户友好的网关口径（不含账号/错误码）。
func wbContentBlockedMessage(body string) string {
	key := "违禁词"
	msg := body
	var env struct {
		Msg string `json:"msg"`
	}
	if json.Unmarshal([]byte(body), &env) == nil && strings.TrimSpace(env.Msg) != "" {
		msg = env.Msg
	}
	lower := strings.ToLower(msg)
	for _, kw := range []string{"色情", "porn", "nsfw", "adult", "暴力", "violence", "政治", "politics", "赌博", "gambling", "毒品", "drug"} {
		if strings.Contains(lower, strings.ToLower(kw)) {
			key = kw
			break
		}
	}
	return fmt.Sprintf("触发网站风控违禁词，无法调用模型：内容命中网关内容防火墙规则[%s]，已被拦截。请修改内容后重试。", key)
}

// ======================== 账号凭证 ========================

// wbAccount 一个 WorkBuddy 账号（来自 auth 文件或手写凭证），含运行期健康状态。
type wbAccount struct {
	mu sync.Mutex // 串行化 token 字段读写（刷新 vs 落盘）

	AccessToken  string
	RefreshToken string
	ExpiresAt    int64 // Unix 秒
	Domain       string
	Realm        string // cn / global
	UID          string
	EnterpriseID string
	Nickname     string
	DeviceToken  string
	FilePath     string // 来源文件；刷新后原子写回

	// —— 运行期状态（仅 pool.mu 保护）——
	coolingUntil   time.Time
	coolingModel   string // 非空 = 仅该模型冷却（6004）
	coolingReason  string
	disabled       bool
	disabledReason string
	failStreak     int
	breakerUntil   time.Time
	breakerStreak  int
	softStreak     int
	inFlight       int
	lastUsed       time.Time
	lastError      string
}

// wbResolveRealm 归一化账号域：显式 global 优先，否则按 domain 后缀推断；空 → cn。
func wbResolveRealm(explicit, domain string) string {
	if r := strings.TrimSpace(explicit); r != "" {
		return r
	}
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "workbuddy.ai" || strings.HasSuffix(d, ".workbuddy.ai") {
		return "global"
	}
	return "cn"
}

// realm 读凭证字段（Realm/Domain），加锁避免与后台刷新写入产生数据竞争。
func (a *wbAccount) realm() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return wbResolveRealm(a.Realm, a.Domain)
}

// wbAcctInfo 账号字段的一致性快照：所有出站构造（headers/billing/status）只读快照，
// 不与后台保活刷新（a.mu 写凭证字段）产生数据竞争。
type wbAcctInfo struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64
	Domain       string
	Realm        string // 已归一化（cn/global）
	UID          string
	EnterpriseID string
	Nickname     string
	DeviceToken  string
}

func (a *wbAccount) snapshot() wbAcctInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	return wbAcctInfo{
		AccessToken:  a.AccessToken,
		RefreshToken: a.RefreshToken,
		ExpiresAt:    a.ExpiresAt,
		Domain:       a.Domain,
		Realm:        wbResolveRealm(a.Realm, a.Domain),
		UID:          a.UID,
		EnterpriseID: a.EnterpriseID,
		Nickname:     a.Nickname,
		DeviceToken:  a.DeviceToken,
	}
}

func (a *wbAccount) needsRefresh(within time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ExpiresAt <= 0 {
		return true
	}
	return time.Now().Add(within).Unix() >= a.ExpiresAt
}

// wbParseAuth 兼容两种磁盘形态：嵌套形 {"auth":{...},"account":{...}} 与扁平形。
func wbParseAuth(raw []byte) (*wbAccount, error) {
	raw = stripBOM(raw) // Windows 记事本 BOM 容忍
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty auth storage")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("storage_parse_error: %w", err)
	}
	a := &wbAccount{}
	if _, nested := probe["auth"]; nested {
		var n struct {
			Auth struct {
				AccessToken  string `json:"accessToken"`
				RefreshToken string `json:"refreshToken"`
				ExpiresAt    int64  `json:"expiresAt"`
				Domain       string `json:"domain"`
				Realm        string `json:"realm"`
			} `json:"auth"`
			Account struct {
				UID          string `json:"uid"`
				EnterpriseID string `json:"enterpriseId"`
				Nickname     string `json:"nickname"`
			} `json:"account"`
			DeviceToken string `json:"device_token"`
		}
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, fmt.Errorf("storage_parse_error: %w", err)
		}
		a.AccessToken = n.Auth.AccessToken
		a.RefreshToken = n.Auth.RefreshToken
		a.ExpiresAt = n.Auth.ExpiresAt
		a.Domain = n.Auth.Domain
		a.Realm = n.Auth.Realm
		a.UID = n.Account.UID
		a.EnterpriseID = n.Account.EnterpriseID
		a.Nickname = n.Account.Nickname
		a.DeviceToken = n.DeviceToken
	} else {
		var f struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
			ExpiresAt    int64  `json:"expiresAt"`
			Domain       string `json:"domain"`
			Realm        string `json:"realm"`
			UID          string `json:"uid"`
			EnterpriseID string `json:"enterpriseId"`
			Nickname     string `json:"nickname"`
			DeviceToken  string `json:"device_token"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("storage_parse_error: %w", err)
		}
		a.AccessToken = f.AccessToken
		a.RefreshToken = f.RefreshToken
		a.ExpiresAt = f.ExpiresAt
		a.Domain = f.Domain
		a.Realm = f.Realm
		a.UID = f.UID
		a.EnterpriseID = f.EnterpriseID
		a.Nickname = f.Nickname
		a.DeviceToken = f.DeviceToken
	}
	if strings.TrimSpace(a.AccessToken) == "" {
		return nil, fmt.Errorf("parse_error: missing accessToken")
	}
	if a.Realm == "" {
		a.Realm = wbResolveRealm("", a.Domain)
	}
	return a, nil
}

// wbSaveAuth 以嵌套形原子写回（与插件 OAuth 输出形状一致）。
func wbSaveAuth(a *wbAccount) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if strings.TrimSpace(a.AccessToken) == "" {
		return fmt.Errorf("save refused: empty accessToken (uid=%s)", a.UID)
	}
	if a.FilePath == "" {
		return fmt.Errorf("no FilePath set")
	}
	doc := map[string]any{
		"auth": map[string]any{
			"accessToken":  a.AccessToken,
			"refreshToken": a.RefreshToken,
			"expiresAt":    a.ExpiresAt,
			"domain":       a.Domain,
			"realm":        a.Realm,
		},
		"account": map[string]any{
			"uid":          a.UID,
			"enterpriseId": a.EnterpriseID,
			"nickname":     a.Nickname,
		},
	}
	if a.DeviceToken != "" {
		doc["device_token"] = a.DeviceToken
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(a.FilePath, raw, 0600)
}

// ======================== 账号池 ========================

type wbPool struct {
	mu          sync.Mutex
	dir         string
	accounts    map[string]*wbAccount // uid（或文件路径）→ 账号
	order       []string              // 稳定轮转顺序
	cursor      int
	maxInFlight int
	cfg         *UpstreamConfig // 最近一次配置快照（后台 RPC 用 base/UA 等），写读均持 mu
}

var (
	wbPoolsMu sync.Mutex
	wbPools   = map[string]*wbPool{} // auth dir（绝对路径）→ 池
)

// wbPoolFor 按 auth dir 取（或首次加载）账号池。凭证目录不存在时自动创建（登录命令用）。
func wbPoolFor(cfg *UpstreamConfig) *wbPool {
	dir := wbAuthDirOf(cfg)
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	wbPoolsMu.Lock()
	defer wbPoolsMu.Unlock()
	if p, ok := wbPools[abs]; ok {
		p.mu.Lock()
		p.cfg = cloneUpstreamConfig(cfg)
		if cfg != nil && cfg.WBMaxInFlight > 0 {
			p.maxInFlight = cfg.WBMaxInFlight
		}
		p.mu.Unlock()
		return p
	}
	p := &wbPool{dir: abs, accounts: map[string]*wbAccount{}, maxInFlight: 3, cfg: cloneUpstreamConfig(cfg)}
	if cfg != nil && cfg.WBMaxInFlight > 0 {
		p.maxInFlight = cfg.WBMaxInFlight
	}
	p.reload()
	wbPools[abs] = p
	return p
}

// wbReloadPools 重新扫描所有已加载池的凭证目录（新增/替换账号即时生效）。
func wbReloadPools() {
	wbPoolsMu.Lock()
	defer wbPoolsMu.Unlock()
	for _, p := range wbPools {
		p.reload()
	}
}

// wbPoolCfg 取池绑定的配置快照（后台任务发 RPC 用 base_url/UA 等）。
func (p *wbPool) poolCfg() *UpstreamConfig {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg
}

func wbAuthDirOf(cfg *UpstreamConfig) string {
	dir := "auths"
	if cfg != nil && strings.TrimSpace(cfg.WBAuthDir) != "" {
		dir = strings.TrimSpace(cfg.WBAuthDir)
	}
	// 相对路径以配置文件所在目录为基准。
	if !filepath.IsAbs(dir) && configPath != "" {
		if base := filepath.Dir(configPath); base != "" && base != "." {
			dir = filepath.Join(base, dir)
		}
	}
	return dir
}

// reload 扫描 dir 下 workbuddy*.json，新增/更新账号。
// 已存在的账号**原地更新凭证字段**（对象身份稳定：在途请求的 release/健康回写不会落到
// 被替换的孤儿对象上，避免在途计数泄漏）；凭证内容变化（重新登录）时清除失效/冷却/熔断
// 标记恢复调度；其余运行期状态保留。
func (p *wbPool) reload() {
	p.mu.Lock()
	defer p.mu.Unlock()
	files, _ := filepath.Glob(filepath.Join(p.dir, "workbuddy*.json"))
	parsedByKey := map[string]*wbAccount{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		a, err := wbParseAuth(raw)
		if err != nil {
			log.Printf("[workbuddy] 跳过无法解析的凭证 %s: %v", filepath.Base(f), err)
			continue
		}
		a.FilePath = f
		key := a.UID
		if key == "" {
			key = "file:" + f
		}
		parsedByKey[key] = a
	}
	for key, parsed := range parsedByKey {
		live, ok := p.accounts[key]
		if !ok {
			p.accounts[key] = parsed
			log.Printf("[workbuddy] 新账号入池: uid=%s realm=%s nickname=%s", wbUID8(parsed.UID), parsed.realm(), parsed.Nickname)
			continue
		}
		live.mu.Lock()
		relogged := live.AccessToken != parsed.AccessToken || live.RefreshToken != parsed.RefreshToken
		live.AccessToken = parsed.AccessToken
		live.RefreshToken = parsed.RefreshToken
		live.ExpiresAt = parsed.ExpiresAt
		live.Domain = parsed.Domain
		live.Realm = parsed.Realm
		live.UID = parsed.UID
		live.EnterpriseID = parsed.EnterpriseID
		live.Nickname = parsed.Nickname
		live.DeviceToken = parsed.DeviceToken
		live.FilePath = parsed.FilePath
		live.mu.Unlock()
		if relogged {
			// 凭证被重新登录覆盖：清除各类封锁标记，恢复调度（对齐参考项目"重新登录自动恢复"）
			live.coolingUntil = time.Time{}
			live.coolingModel = ""
			live.coolingReason = ""
			live.disabled = false
			live.disabledReason = ""
			live.breakerUntil = time.Time{}
			live.breakerStreak = 0
			live.softStreak = 0
			live.failStreak = 0
			live.lastError = ""
			log.Printf("[workbuddy] uid=%s 凭证已更新，自动恢复调度", wbUID8(parsed.UID))
		}
	}
	for k := range p.accounts {
		if _, ok := parsedByKey[k]; !ok {
			delete(p.accounts, k)
			log.Printf("[workbuddy] 账号已移出池: %s", k)
		}
	}
	p.order = p.order[:0]
	for k := range p.accounts {
		p.order = append(p.order, k)
	}
	sort.Strings(p.order)
}

// nextLocal4AM 次日凌晨 04:00（本地）——余额耗尽账号的硬冷却终点。
func wbNextLocal4AM(now time.Time) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), 4, 0, 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

// pick 选出一个可用账号：健康（未禁用/未冷却/未熔断/在途未满）、realm 匹配、排除已试过的。
// 候选中取「最久未用」者，天然均匀轮转。
func (p *wbPool) pick(exclude map[string]bool, realm, model string) (*wbAccount, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	var best *wbAccount
	var bestKey string
	for i := 0; i < len(p.order); i++ {
		key := p.order[(p.cursor+i)%len(p.order)]
		if exclude[key] {
			continue
		}
		a := p.accounts[key]
		if a == nil {
			continue
		}
		if realm != "" && a.realm() != realm {
			continue
		}
		if a.disabled {
			continue
		}
		if now.Before(a.breakerUntil) {
			continue
		}
		if now.Before(a.coolingUntil) {
			// 模型级冷却豁免：该冷却只针对 coolingModel，其他模型立即可用（issue #31 语义）。
			if a.coolingModel == "" || a.coolingModel == model {
				continue
			}
		}
		if p.maxInFlight > 0 && a.inFlight >= p.maxInFlight {
			continue
		}
		if best == nil || a.lastUsed.Before(best.lastUsed) {
			best = a
			bestKey = key
		}
	}
	if best == nil {
		return nil, ""
	}
	for i := 0; i < len(p.order); i++ {
		if p.order[(p.cursor+i)%len(p.order)] == bestKey {
			p.cursor = (p.cursor + i + 1) % len(p.order)
			break
		}
	}
	best.lastUsed = now
	best.inFlight++
	return best, bestKey
}

func (p *wbPool) release(a *wbAccount) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if a != nil && a.inFlight > 0 {
		a.inFlight--
	}
}

// noteSuccess 成功后清零连败与各类冷却计数。
func (p *wbPool) noteSuccess(a *wbAccount) {
	p.mu.Lock()
	defer p.mu.Unlock()
	a.failStreak = 0
	a.breakerStreak = 0
	a.softStreak = 0
	a.coolingUntil = time.Time{}
	a.coolingModel = ""
	a.coolingReason = ""
	a.lastError = ""
}

// applyError 按错误类别施加冷却/禁用/熔断（对齐 workbuddy2api applyErrorPolicy 语义）。
func (p *wbPool) applyError(a *wbAccount, kind wbErrKind, body, model string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(body) > 200 {
		body = body[:200]
	}
	a.lastError = body
	now := time.Now()
	switch kind {
	case wbErrHardCredit:
		a.coolingUntil = wbNextLocal4AM(now)
		a.coolingModel = ""
		a.coolingReason = "余额不足"
	case wbErrSoftRate:
		// 模型级 6004 带重置时刻 → 只冷却该模型（切其他模型立即可用）。
		if resetAt, ok := wbParseSoftRateReset(body); ok {
			until := resetAt
			if until.Sub(now) > wbSoftCooldownMax {
				until = now.Add(wbSoftCooldownMax)
			}
			if until.After(a.coolingUntil) {
				a.coolingUntil = until
			}
			a.coolingModel = model
			a.coolingReason = "6004 model rate limit"
			return
		}
		a.softStreak++
		d := wbSoftCooldown
		for i := 1; i < a.softStreak && i < 20; i++ {
			d *= 2
			if d > wbSoftCooldownMax {
				d = wbSoftCooldownMax
				break
			}
		}
		a.coolingUntil = now.Add(d)
		a.coolingModel = ""
		a.coolingReason = "429 rate limit"
	case wbErrSessionDead:
		a.disabled = true
		a.disabledReason = "12153 session dead（需重新登录）"
	case wbErrAccountFault:
		lower := strings.ToLower(body)
		if strings.Contains(lower, "request illegal") {
			a.disabled = true
			a.disabledReason = "account banned by upstream (11140 request illegal), re-login required"
		} else {
			a.coolingUntil = now.Add(wbSoftCooldown)
			a.coolingModel = ""
			a.coolingReason = "account fault (14017)"
		}
	case wbErrNotFound:
		a.coolingUntil = now.Add(wbNotFoundCool)
		a.coolingModel = ""
		a.coolingReason = "upstream 404"
	case wbErrServer:
		a.failStreak++
		if a.failStreak >= wbBreakerThresh {
			a.breakerStreak++
			d := wbBreakerBase
			for i := 1; i < a.breakerStreak && i < 20; i++ {
				d *= 2
				if d > wbBreakerMax {
					d = wbBreakerMax
					break
				}
			}
			a.breakerUntil = now.Add(d)
		}
	case wbErrContentBlocked, wbErrBadParams, wbErrClient, wbErrNone:
		// 内容/参数问题不罚账号：仅换号（或终止）
	}
}

// accountCount 返回池内账号数（状态端点/日志用）。
func (p *wbPool) accountCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.accounts)
}

// snapshotKeys 取当前账号键序快照（避免在持锁状态下发起网络请求）。
func (p *wbPool) snapshotKeys() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.order...)
}

// byKey 按池内键取账号指针（账号对象稳定，reload 原地保留）。
func (p *wbPool) byKey(key string) *wbAccount {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accounts[key]
}

// ======================== 会话粘性 ========================

var (
	wbStickyMu    sync.Mutex
	wbStickyBinds = map[string]struct {
		uid  string
		seen time.Time
	}{}
)

func wbStickyResolve(key string) string {
	if key == "" {
		return ""
	}
	wbStickyMu.Lock()
	defer wbStickyMu.Unlock()
	e, ok := wbStickyBinds[key]
	if !ok || time.Since(e.seen) > wbStickyTTL {
		return ""
	}
	e.seen = time.Now()
	wbStickyBinds[key] = e
	return e.uid
}

func wbStickyBind(key, uid string) {
	if key == "" || uid == "" {
		return
	}
	wbStickyMu.Lock()
	defer wbStickyMu.Unlock()
	wbStickyBinds[key] = struct {
		uid  string
		seen time.Time
	}{uid: uid, seen: time.Now()}
}

func wbStickyUnbind(key string) {
	if key == "" {
		return
	}
	wbStickyMu.Lock()
	defer wbStickyMu.Unlock()
	delete(wbStickyBinds, key)
}

func wbStickyGC() {
	wbStickyMu.Lock()
	defer wbStickyMu.Unlock()
	now := time.Now()
	for k, e := range wbStickyBinds {
		if now.Sub(e.seen) > wbStickyTTL {
			delete(wbStickyBinds, k)
		}
	}
}

// wbExtractSessionKey 从出站 body 提取会话键（对齐 workbuddy2api session.ExtractKey）。
func wbExtractSessionKey(body []byte) string {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return ""
	}
	str := func(v any) string { s, _ := v.(string); return s }
	if meta, ok := obj["metadata"].(map[string]any); ok {
		if v := str(meta["conversation_id"]); v != "" {
			return v
		}
		if v := str(meta["conversationId"]); v != "" {
			return v
		}
		if v := str(meta["user_id"]); v != "" {
			return v
		}
	}
	if v := str(obj["conversation_id"]); v != "" {
		return v
	}
	return str(obj["conversationId"])
}

// ======================== 会话头族 ID ========================

func wbNewMessageID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// 熵源故障（理论不可能）兜底：仍保证 32 位 hex。
		sum := sha256.Sum256([]byte(fmt.Sprint(time.Now().UnixNano())))
		return hex.EncodeToString(sum[:16])
	}
	return hex.EncodeToString(b)
}

var (
	wbRequestIDs sync.Map // 会话键 → conversationRequestID（32 hex）
	wbTurnSalt   = wbNewMessageIDAtInit()
)

func wbNewMessageIDAtInit() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "0123456789abcdef0123456789abcdef"
	}
	return hex.EncodeToString(b)
}

// wbRequestIDForKey 同一会话键稳定映射同一 conversationRequestID（后台按对话聚合）。
func wbRequestIDForKey(key string) string {
	if key == "" {
		return wbNewMessageID()
	}
	if v, ok := wbRequestIDs.Load(key); ok {
		return v.(string)
	}
	id := wbNewMessageID()
	actual, _ := wbRequestIDs.LoadOrStore(key, id)
	return actual.(string)
}

// wbTurnKey 取最后一条 user 消息文本作为轮级聚合键（无 conversationId 的客户端兜底）。
func wbTurnKey(body []byte) string {
	var obj struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return ""
	}
	for i := len(obj.Messages) - 1; i >= 0; i-- {
		if obj.Messages[i].Role != "user" {
			continue
		}
		s := strings.TrimSpace(string(obj.Messages[i].Content))
		if s == "" || s == "null" {
			return ""
		}
		var text string
		switch s[0] {
		case '"':
			_ = json.Unmarshal(obj.Messages[i].Content, &text)
		case '[':
			var parts []struct {
				Text string `json:"text"`
			}
			_ = json.Unmarshal(obj.Messages[i].Content, &parts)
			for _, p := range parts {
				text += p.Text
			}
		}
		if text == "" {
			return ""
		}
		return fmt.Sprintf("u%d:%s", i, text)
	}
	return ""
}

func wbTurnRequestID(turnKey string) string {
	if turnKey == "" {
		return wbNewMessageID()
	}
	sum := sha256.Sum256([]byte(wbTurnSalt + "|" + turnKey))
	return hex.EncodeToString(sum[:16])
}

// wbChatMeta 一次 chat 出站的会话头族元数据。
type wbChatMeta struct {
	ConversationID        string
	ConversationRequestID string
}

// ======================== 请求头 ========================

// wbChatBase 解析某 realm 的 chat base。优先级：显式 wb_chat_base_<realm> >
// base_url（仅当上游 wb_realm 指向该 realm 时生效）> 内置默认。
func wbChatBase(cfg *UpstreamConfig, realm string) string {
	if realm == "global" {
		if cfg != nil {
			if s := strings.TrimSpace(cfg.WBChatBaseGlobal); s != "" {
				return strings.TrimRight(s, "/")
			}
			if s := strings.TrimSpace(cfg.BaseURL); s != "" && cfg.WBRealm == "global" {
				return strings.TrimRight(s, "/")
			}
		}
		return wbChatBaseGlobal
	}
	if cfg != nil {
		if s := strings.TrimSpace(cfg.WBChatBaseCN); s != "" {
			return strings.TrimRight(s, "/")
		}
		if s := strings.TrimSpace(cfg.BaseURL); s != "" {
			return strings.TrimRight(s, "/")
		}
	}
	return wbChatBaseCN
}

func wbBillingBase(cfg *UpstreamConfig, realm string) string {
	// 用户显式配置 base_url 时以其为单一基准（测试/私有网关部署）；
	// CN 默认计费域与 chat 域分离（www.codebuddy.cn vs copilot.tencent.com），global 两者同域。
	if cfg != nil {
		if realm == "global" && cfg.WBRealm == "global" {
			if s := strings.TrimSpace(cfg.BaseURL); s != "" {
				return strings.TrimRight(s, "/")
			}
		}
		if realm == "cn" {
			if s := strings.TrimSpace(cfg.BaseURL); s != "" && s != wbChatBaseCN {
				return strings.TrimRight(s, "/")
			}
		}
	}
	if realm == "global" {
		return wbChatBase(cfg, realm)
	}
	return wbOriginCN
}

func wbOriginFor(realm string) string {
	if realm == "global" {
		return wbOriginGlobal
	}
	return wbOriginCN
}

func wbUserAgent(cfg *UpstreamConfig, realm string) string {
	if cfg != nil && strings.TrimSpace(cfg.WBUserAgent) != "" {
		return strings.TrimSpace(cfg.WBUserAgent)
	}
	cv := wbDefaultClientVersion
	cli := wbDefaultCliVersion
	if cfg != nil {
		if strings.TrimSpace(cfg.WBClientVersion) != "" {
			cv = strings.TrimSpace(cfg.WBClientVersion)
		}
		if strings.TrimSpace(cfg.WBCliVersion) != "" {
			cli = strings.TrimSpace(cfg.WBCliVersion)
		}
	}
	platform := "WorkBuddy"
	if realm == "global" {
		platform = "WorkBuddy AI"
	}
	return "WorkBuddy/" + cv + " " + platform + "/" + cv + " CLI/" + cli
}

func wbAcceptLanguage(realm string) string {
	if realm == "global" {
		return "en-US"
	}
	return "zh-CN"
}

// wbSetCommonHeaders 所有 API 共享的出站头。
func wbSetCommonHeaders(req *http.Request, cfg *UpstreamConfig, realm string) {
	origin := wbOriginFor(realm)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", origin+"/")
	req.Header.Set("User-Agent", wbUserAgent(cfg, realm))
	req.Header.Set("X-CodeBuddy-Request", "1")
	req.Header.Set("Accept-Language", wbAcceptLanguage(realm))
}

// wbSetChatHeaders chat 出站头：通用头 + 账号身份 + 归属 + 会话头族。
func wbSetChatHeaders(req *http.Request, cfg *UpstreamConfig, info wbAcctInfo, meta wbChatMeta) {
	realm := info.Realm
	wbSetCommonHeaders(req, cfg, realm)
	req.Header.Set("Accept", "application/json, text/event-stream")
	if info.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+info.AccessToken)
	} else {
		req.Header.Set("X-No-Authorization", "1")
	}
	if info.UID != "" {
		req.Header.Set("X-User-Id", info.UID)
	} else {
		req.Header.Set("X-No-User-Id", "1")
	}
	if realm == "global" {
		req.Header.Set("X-No-Enterprise-Id", "1")
		req.Header.Set("X-Domain", "www.workbuddy.ai")
	} else {
		if info.EnterpriseID != "" {
			req.Header.Set("X-Enterprise-Id", info.EnterpriseID)
		} else {
			req.Header.Set("X-No-Enterprise-Id", "1")
		}
		if info.Domain != "" {
			req.Header.Set("X-Domain", info.Domain)
		} else {
			req.Header.Set("X-No-Department-Info", "1")
		}
	}
	// 用量归属头
	if cfg != nil && strings.TrimSpace(cfg.WBClientName) != "" {
		name := strings.TrimSpace(cfg.WBClientName)
		cv := wbDefaultClientVersion
		if strings.TrimSpace(cfg.WBClientVersion) != "" {
			cv = strings.TrimSpace(cfg.WBClientVersion)
		}
		req.Header.Set("X-Agent-Purpose", "conversation")
		req.Header.Set("X-IDE-Name", name)
		req.Header.Set("X-IDE-Type", name)
		req.Header.Set("X-IDE-Version", cv)
		req.Header.Set("X-Product", name)
	} else {
		req.Header.Set("X-Product", "SaaS")
	}
	if info.DeviceToken != "" {
		req.Header.Set("X-Device-Token", info.DeviceToken)
	} else if cfg != nil && strings.TrimSpace(cfg.WBDeviceToken) != "" {
		req.Header.Set("X-Device-Token", strings.TrimSpace(cfg.WBDeviceToken))
	}
	// 会话头族（官方客户端按对话轮聚合请求的键族；缺失的 ID 全部补全）。
	convReqID := meta.ConversationRequestID
	if convReqID == "" {
		convReqID = wbNewMessageID()
	}
	if meta.ConversationID != "" {
		req.Header.Set("X-Conversation-ID", meta.ConversationID)
	}
	messageID := wbNewMessageID()
	req.Header.Set("X-Conversation-Request-ID", convReqID)
	req.Header.Set("X-Conversation-Message-ID", messageID)
	req.Header.Set("X-Request-ID", messageID)
	req.Header.Set("X-Root-Request-ID", convReqID)
	req.Header.Set("X-Trace-ID", convReqID)
	b3Trace := convReqID
	if !wbValidHexID(b3Trace) {
		b3Trace = messageID
	}
	req.Header.Set("X-B3-TraceId", b3Trace)
	req.Header.Set("X-B3-SpanId", messageID[:16])
	req.Header.Set("X-B3-Sampled", "1")
}

func wbValidHexID(s string) bool {
	if len(s) != 16 && len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func wbSetBillingHeaders(req *http.Request, cfg *UpstreamConfig, info wbAcctInfo) {
	realm := info.Realm
	req.Header.Set("Authorization", "Bearer "+info.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CodeBuddy-Request", "1")
	req.Header.Set("Accept-Language", wbAcceptLanguage(realm))
	req.Header.Set("User-Agent", wbUserAgent(cfg, realm))
	if info.UID != "" {
		req.Header.Set("X-User-Id", info.UID)
	}
	if info.EnterpriseID != "" {
		req.Header.Set("X-Enterprise-Id", info.EnterpriseID)
		req.Header.Set("X-Tenant-Id", info.EnterpriseID)
	}
	if info.Domain != "" {
		req.Header.Set("X-Domain", info.Domain)
	}
	if info.DeviceToken != "" {
		req.Header.Set("X-Device-Token", info.DeviceToken)
	} else if cfg != nil && strings.TrimSpace(cfg.WBDeviceToken) != "" {
		req.Header.Set("X-Device-Token", strings.TrimSpace(cfg.WBDeviceToken))
	}
}

// wbSetLoginHeaders 设备授权流（state/token/account）出站头。
func wbSetLoginHeaders(req *http.Request, realm, accessToken string) {
	origin := wbOriginFor(realm)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Origin", origin)
	req.Header.Set("Referer", origin+"/")
	req.Header.Set("User-Agent", wbLoginUA)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
}

// ======================== 出站 payload 改写 ========================

// wbPrepareBody 把网关的 OpenAI chat 请求体改写为 CodeBuddy 接受的出站形态。
// 返回 realm（cn/global）、裸模型名与改写后的 body。
func wbPrepareBody(reqBody []byte, modelID string, cfg *UpstreamConfig) (body []byte, realm, bareModel string, err error) {
	realm, bareModel = wbResolveRequestRealm(cfg, modelID)
	var obj map[string]any
	if err := json.Unmarshal(reqBody, &obj); err != nil {
		return nil, realm, bareModel, fmt.Errorf("invalid request body")
	}
	obj["model"] = bareModel
	obj["stream"] = true
	if _, has := obj["stream_options"]; !has {
		obj["stream_options"] = map[string]any{"include_usage": true}
	}
	wbNormalizeToolChoice(obj)
	wbNormalizeRoles(obj)
	wbInjectThinking(obj)
	wbBackfillReasoningContent(obj)
	if cfg == nil || cfg.WBSanitize == nil || *cfg.WBSanitize {
		if msgs, ok := obj["messages"].([]any); ok {
			wbSanitizeMessages(msgs)
		}
	}
	// global 域兜底 system 注入（防 console 端点缺 system 的 code 11-128）。
	if realm == "global" {
		wbEnsureConsoleSystem(obj)
	}
	// 网关自有提示词替换（wb_prompt_mode=custom）。
	mode := "passthrough"
	if cfg != nil && strings.TrimSpace(cfg.WBPromptMode) != "" {
		mode = strings.TrimSpace(cfg.WBPromptMode)
	}
	if mode == "custom" {
		text := ""
		if cfg != nil {
			text = strings.TrimSpace(cfg.WBPromptText)
			if text == "" && strings.TrimSpace(cfg.WBPromptFile) != "" {
				if raw, e := os.ReadFile(strings.TrimSpace(cfg.WBPromptFile)); e == nil {
					text = strings.TrimSpace(string(stripBOM(raw)))
				}
			}
		}
		if text == "" {
			text = wbDefaultPrompt
		}
		wbRewriteSystem(obj, text)
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, realm, bareModel, err
	}
	return out, realm, bareModel, nil
}

// wbSplitModelRealm 解析模型名上的 cn:/global: 路由前缀（workbuddy2api 的协议）。
// 第三个返回值表示前缀是否显式存在——显式前缀的优先级高于上游的 wb_realm 配置。
func wbSplitModelRealm(model string) (realm, bare string, explicit bool) {
	idx := strings.IndexByte(model, ':')
	if idx > 0 {
		prefix := model[:idx]
		if prefix == "cn" || prefix == "global" {
			return prefix, model[idx+1:], true
		}
	}
	return "cn", model, false
}

// wbResolveRequestRealm 决定本次出站域：模型 cn:/global: 前缀 > 上游 wb_realm（非 all）> cn。
func wbResolveRequestRealm(cfg *UpstreamConfig, modelID string) (string, string) {
	realm, bare, explicit := wbSplitModelRealm(modelID)
	if explicit || cfg == nil {
		return realm, bare
	}
	switch strings.ToLower(strings.TrimSpace(cfg.WBRealm)) {
	case "global":
		return "global", bare
	case "cn":
		return "cn", bare
	}
	return realm, bare
}

func wbNormalizeRoles(obj map[string]any) {
	msgs, _ := obj["messages"].([]any)
	for _, m := range msgs {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		if role, ok := msg["role"].(string); ok && strings.EqualFold(strings.TrimSpace(role), "developer") {
			msg["role"] = "system"
		}
	}
}

// wbNormalizeToolChoice 上游 tool_choice 字段是 string，对象形式会 400（11101）。
func wbNormalizeToolChoice(obj map[string]any) {
	suppress := func() {
		delete(obj, "tools")
		delete(obj, "functions")
	}
	tc, present := obj["tool_choice"]
	if !present {
		return
	}
	switch v := tc.(type) {
	case string:
		if strings.EqualFold(strings.TrimSpace(v), "none") {
			delete(obj, "tool_choice")
			suppress()
		}
	case map[string]any:
		typ := strings.ToLower(strings.TrimSpace(wbStrOr(v["type"])))
		switch typ {
		case "none":
			delete(obj, "tool_choice")
			suppress()
		case "auto", "required":
			obj["tool_choice"] = typ
		case "function":
			name := ""
			if fn, ok := v["function"].(map[string]any); ok {
				name = wbStrOr(fn["name"])
			}
			if name == "" {
				name = wbStrOr(v["name"])
			}
			if name = strings.TrimSpace(name); name != "" {
				obj["tool_choice"] = name
			} else {
				obj["tool_choice"] = "auto"
			}
		default:
			delete(obj, "tool_choice")
		}
	default:
		delete(obj, "tool_choice")
	}
}

func wbStrOr(v any) string {
	s, _ := v.(string)
	return s
}

// wbInjectThinking DeepSeek 系模型「开思考」= thinking.type=enabled + effort 档位，
// 否则上游默认不吐思维链（对齐官方客户端行为，issue #43）。
func wbInjectThinking(obj map[string]any) {
	model := wbStrOr(obj["model"])
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(model)), "deepseek") {
		return
	}
	th, ok := obj["thinking"].(map[string]any)
	typ := ""
	if ok {
		typ = strings.TrimSpace(wbStrOr(th["type"]))
	}
	if typ != "" {
		if strings.EqualFold(typ, "disabled") {
			delete(obj, "reasoning_effort")
			delete(obj, "reasoningEffort")
			return
		}
		wbEnsureDeepSeekEffort(obj)
		return
	}
	if !ok {
		obj["thinking"] = map[string]any{"type": "enabled"}
	} else {
		th["type"] = "enabled"
	}
	wbEnsureDeepSeekEffort(obj)
}

func wbEnsureDeepSeekEffort(obj map[string]any) {
	if _, has := obj["reasoning_effort"]; has {
		return
	}
	if _, has := obj["reasoningEffort"]; has {
		return
	}
	obj["reasoning_effort"] = "high"
}

// wbBackfillReasoningContent DeepSeek 多轮一致性：任一 assistant 带 reasoning 痕迹时，
// 所有 assistant 消息补齐 reasoning_content 字段（上游硬性要求）。
func wbBackfillReasoningContent(obj map[string]any) {
	model := wbStrOr(obj["model"])
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(model)), "deepseek") {
		return
	}
	msgs, ok := obj["messages"].([]any)
	if !ok || len(msgs) == 0 {
		return
	}
	hasTrace := false
	for _, mm := range msgs {
		msg, ok := mm.(map[string]any)
		if !ok {
			continue
		}
		if r, ok := msg["reasoning"].(string); ok && r != "" {
			hasTrace = true
			break
		}
		if _, ok := msg["reasoning_content"]; ok {
			hasTrace = true
			break
		}
	}
	if !hasTrace {
		return
	}
	for _, mm := range msgs {
		msg, ok := mm.(map[string]any)
		if !ok {
			continue
		}
		if wbStrOr(msg["role"]) != "assistant" {
			continue
		}
		if _, ok := msg["reasoning_content"]; ok {
			continue
		}
		if r, ok := msg["reasoning"].(string); ok {
			msg["reasoning_content"] = r
		} else {
			msg["reasoning_content"] = ""
		}
	}
}

func wbEnsureConsoleSystem(obj map[string]any) {
	msgs, ok := obj["messages"].([]any)
	if !ok || len(msgs) == 0 {
		return
	}
	if first, ok := msgs[0].(map[string]any); ok {
		if strings.EqualFold(strings.TrimSpace(wbStrOr(first["role"])), "system") {
			return
		}
	}
	obj["messages"] = append([]any{map[string]any{"role": "system", "content": "You are a helpful assistant."}}, msgs...)
}

// wbRewriteSystem 用网关自有提示词替换全部 system 消息（custom 模式，从源头消除模板句误报）。
func wbRewriteSystem(obj map[string]any, prompt string) {
	msgs, ok := obj["messages"].([]any)
	if !ok {
		obj["messages"] = []any{map[string]any{"role": "system", "content": prompt}}
		return
	}
	replaced := false
	out := make([]any, 0, len(msgs))
	for _, mm := range msgs {
		msg, ok := mm.(map[string]any)
		if !ok {
			out = append(out, mm)
			continue
		}
		role := strings.ToLower(strings.TrimSpace(wbStrOr(msg["role"])))
		if role == "system" || role == "developer" {
			if !replaced {
				msg["role"] = "system"
				msg["content"] = prompt
				replaced = true
				out = append(out, msg)
			}
			continue // 多余 system 丢弃
		}
		out = append(out, msg)
	}
	if !replaced {
		out = append([]any{map[string]any{"role": "system", "content": prompt}}, out...)
	}
	obj["messages"] = out
}

// ---------- 指纹脱敏（对齐 workbuddy2api internal/upstream/sanitize.go） ----------

var wbSanitizeFeatures = []string{
	"x-anthropic-billing-header",
	"cc_entrypoint=",
	"You are Claude Code",
	"Main branch (",
	"You are a coding agent running in the Codex CLI",
	"github.com/anthropics/",
	"11128",
}

var (
	wbSanitizeHdrRe = regexp.MustCompile(`(?i)x-anthropic-billing-header:[^;\n]*;?\s*`)
	wbSanitizeKvRe  = regexp.MustCompile(`(?i)\bcc_[a-z0-9_]+=[^;\n]*;?\s*`)
)

var wbSanitizeRewrites = [][2]string{
	{"You are Claude Code, Anthropic's official CLI for Claude",
		"You are Claude Code, Anthropic's official CLI tool for Claude"},
	{"Main branch (you will usually use this for PRs)",
		"Default branch (you will usually use this for PRs)"},
	{"You are a coding agent running in the Codex CLI, a terminal-based coding assistant.",
		"You are a coding agent running in the Codex CLI tool, a terminal-based coding assistant."},
	{"To give feedback, users should report the issue at https://github.com/anthropics/claude-code/issues",
		"To provide feedback, users should report the issue at https://github.com/anthropics/claude-code/issues"},
	{"11128", "11-128"},
}

func wbSanitizeText(text string) string {
	if !wbHasFingerprint(text) {
		return text
	}
	for _, rw := range wbSanitizeRewrites {
		text = strings.ReplaceAll(text, rw[0], rw[1])
	}
	if wbSanitizeHdrRe.MatchString(text) {
		text = wbSanitizeHdrRe.ReplaceAllString(text, "")
	}
	if strings.Contains(text, "cc_") {
		prev := ""
		for prev != text {
			prev = text
			text = wbSanitizeKvRe.ReplaceAllString(text, "")
		}
	}
	return strings.TrimSpace(text)
}

func wbHasFingerprint(text string) bool {
	for _, f := range wbSanitizeFeatures {
		if strings.Contains(text, f) {
			return true
		}
	}
	return wbSanitizeHdrRe.MatchString(text)
}

func wbSanitizeContent(v any) any {
	switch c := v.(type) {
	case string:
		return wbSanitizeText(c)
	case []any:
		for _, p := range c {
			m, ok := p.(map[string]any)
			if !ok {
				continue
			}
			if text, ok := m["text"].(string); ok {
				m["text"] = wbSanitizeText(text)
			}
		}
	}
	return v
}

func wbSanitizeMessages(messages []any) {
	for _, msg := range messages {
		m, ok := msg.(map[string]any)
		if !ok {
			continue
		}
		if c, ok := m["content"]; ok {
			m["content"] = wbSanitizeContent(c)
		}
		if calls, ok := m["tool_calls"].([]any); ok {
			for _, cl := range calls {
				call, ok := cl.(map[string]any)
				if !ok {
					continue
				}
				fn, ok := call["function"].(map[string]any)
				if !ok {
					continue
				}
				if args, ok := fn["arguments"].(string); ok {
					fn["arguments"] = wbSanitizeText(args)
				}
			}
		}
	}
}

// ======================== SSE：聚合与规范化 ========================

// wbAggregateSSE 读取完整 SSE，聚合为单个 OpenAI chat.completion（非流式客户端用）。
func wbAggregateSSE(r io.Reader) (map[string]any, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	var (
		id, model    string
		created      float64
		content      strings.Builder
		reasoning    strings.Builder
		role         = "assistant"
		finishReason = "stop"
		usage        map[string]any
		gotContent   bool
		validEvents  int
		toolCalls    = map[int]map[string]any{}
		toolOrder    []int
	)
	for {
		line, err := br.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "data: ") {
			payload := strings.TrimPrefix(line, "data: ")
			if payload == "[DONE]" {
				break
			}
			var chunk map[string]any
			if json.Unmarshal([]byte(payload), &chunk) == nil {
				validEvents++
				if v, ok := chunk["id"].(string); ok && id == "" {
					id = v
				}
				if v, ok := chunk["model"].(string); ok && model == "" {
					model = v
				}
				if v, ok := chunk["created"].(float64); ok && created == 0 {
					created = v
				}
				if u, ok := chunk["usage"].(map[string]any); ok {
					usage = u
				}
				if ch, ok := chunk["choices"].([]any); ok {
					for _, ci := range ch {
						c, _ := ci.(map[string]any)
						if c == nil {
							continue
						}
						if fr, ok := c["finish_reason"].(string); ok && fr != "" {
							finishReason = fr
						}
						if delta, ok := c["delta"].(map[string]any); ok {
							if r2, ok := delta["role"].(string); ok && r2 != "" {
								role = r2
							}
							if txt, ok := delta["content"].(string); ok {
								content.WriteString(txt)
								gotContent = true
							}
							if rc, ok := delta["reasoning_content"].(string); ok {
								reasoning.WriteString(rc)
							}
							if tcs, ok := delta["tool_calls"].([]any); ok {
								for _, tc := range tcs {
									call, ok := tc.(map[string]any)
									if !ok {
										continue
									}
									idx := 0
									if v, ok := call["index"].(float64); ok {
										idx = int(v)
									}
									merged, seen := toolCalls[idx]
									if !seen {
										merged = map[string]any{"index": idx}
										toolCalls[idx] = merged
										toolOrder = append(toolOrder, idx)
									}
									wbMergeToolCall(merged, call)
								}
							}
						}
						if msg, ok := c["message"].(map[string]any); ok && !gotContent {
							if txt, ok := msg["content"].(string); ok {
								content.WriteString(txt)
							}
						}
					}
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}
	if validEvents == 0 {
		return nil, fmt.Errorf("workbuddy stream contained no valid data events")
	}
	if id == "" {
		id = "chatcmpl-" + wbNewMessageID()[:12]
	}
	if created == 0 {
		created = float64(time.Now().Unix())
	}
	message := map[string]any{"role": role, "content": content.String()}
	if reasoning.Len() > 0 {
		message["reasoning_content"] = reasoning.String()
	}
	if len(toolOrder) > 0 {
		sort.Ints(toolOrder)
		calls := make([]map[string]any, 0, len(toolOrder))
		for _, idx := range toolOrder {
			calls = append(calls, toolCalls[idx])
		}
		message["tool_calls"] = calls
	}
	resp := map[string]any{
		"id":      id,
		"object":  "chat.completion",
		"created": int64(created),
		"model":   model,
		"choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": finishReason}},
	}
	if usage != nil {
		resp["usage"] = usage
	}
	return resp, nil
}

func wbMergeToolCall(merged, delta map[string]any) {
	if v, ok := delta["id"].(string); ok && v != "" {
		merged["id"] = v
	}
	if v, ok := delta["type"].(string); ok && v != "" {
		merged["type"] = v
	}
	df, _ := delta["function"].(map[string]any)
	if df == nil {
		return
	}
	mf, _ := merged["function"].(map[string]any)
	if mf == nil {
		mf = map[string]any{}
		merged["function"] = mf
	}
	if v, ok := df["name"].(string); ok && v != "" {
		mf["name"] = v
	}
	if v, ok := df["arguments"].(string); ok && v != "" {
		if prev, _ := mf["arguments"].(string); prev != "" {
			mf["arguments"] = prev + v
		} else {
			mf["arguments"] = v
		}
	}
}

// wbBackfillToolNames 流式分片中上游常把后续 chunk 的 function.name 置空，
// 按 index 缓存首见非空名并回填（workbuddy2api issue #2 修复）。
func wbBackfillToolNames(obj map[string]any, names map[int]string) {
	choices, _ := obj["choices"].([]any)
	for _, ci := range choices {
		c, _ := ci.(map[string]any)
		if c == nil {
			continue
		}
		delta, _ := c["delta"].(map[string]any)
		if delta == nil {
			continue
		}
		tcs, _ := delta["tool_calls"].([]any)
		for _, tci := range tcs {
			tc, _ := tci.(map[string]any)
			if tc == nil {
				continue
			}
			idx := 0
			if v, ok := tc["index"].(float64); ok {
				idx = int(v)
			}
			fn, _ := tc["function"].(map[string]any)
			name := ""
			if fn != nil {
				name = wbStrOr(fn["name"])
			}
			if name != "" {
				names[idx] = name
				continue
			}
			if cached, ok := names[idx]; ok {
				if fn == nil {
					fn = map[string]any{}
					tc["function"] = fn
				}
				fn["name"] = cached
			}
		}
	}
}

// wbLeaseCloser 把「账号在途租约归还」绑定到流的 Close 上：
// handler 读完 SSE 后 defer Close，此时才 release，避免提前归还使在途计数失真。
type wbLeaseCloser struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (c *wbLeaseCloser) Close() error {
	err := c.ReadCloser.Close()
	c.once.Do(c.release)
	return err
}

// wbStreamFilter 包裹上游 SSE body：逐 data 帧回填 tool_calls 函数名（其余字节透传）。
// 每个 data 帧只输出单换行结束符，帧分隔空行吞掉——网关各消费端（chat/messages/responses）
// 都按行循环并自行补空行，输出双换行会造成多余空白帧间隔。注释心跳行原样透传。
type wbStreamFilter struct {
	inner io.ReadCloser
	br    *bufio.Reader
	buf   bytes.Buffer
	names map[int]string
}

func (f *wbStreamFilter) Read(p []byte) (int, error) {
	for f.buf.Len() == 0 {
		line, err := f.br.ReadString('\n')
		if line != "" {
			trimmed := strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(trimmed, "data: "):
				payload := strings.TrimPrefix(trimmed, "data: ")
				if payload == "[DONE]" {
					f.buf.WriteString("data: [DONE]\n")
				} else {
					var obj map[string]any
					if json.Unmarshal([]byte(payload), &obj) == nil {
						wbBackfillToolNames(obj, f.names)
						if b, merr := json.Marshal(obj); merr == nil {
							f.buf.WriteString("data: ")
							f.buf.Write(b)
							f.buf.WriteString("\n")
						} else {
							f.buf.WriteString(line)
						}
					} else {
						f.buf.WriteString(line)
					}
				}
			case trimmed == "":
				// 帧分隔空行吞掉（消费端自行补）。
			default:
				f.buf.WriteString(line)
			}
		}
		if err != nil {
			if f.buf.Len() > 0 {
				break
			}
			if err == io.EOF {
				return 0, io.EOF
			}
			return 0, err
		}
	}
	return f.buf.Read(p)
}

func (f *wbStreamFilter) Close() error { return f.inner.Close() }

// wbIdleBody SSE 流中静默超时监控：活跃续命，静默超阈值才断流（对齐 workbuddy2api idle.go）。
type wbIdleBody struct {
	rc       io.ReadCloser
	mu       sync.Mutex
	lastRead time.Time
	stopOnce sync.Once
	stopCh   chan struct{}
	cancel   context.CancelFunc
}

func (b *wbIdleBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		b.mu.Lock()
		b.lastRead = time.Now()
		b.mu.Unlock()
	}
	return n, err
}

func (b *wbIdleBody) Close() error {
	b.stopOnce.Do(func() { close(b.stopCh) })
	b.cancel()
	return b.rc.Close()
}

func wbWrapIdle(rc io.ReadCloser, idle time.Duration, cancel context.CancelFunc) io.ReadCloser {
	if idle <= 0 {
		return rc
	}
	b := &wbIdleBody{rc: rc, lastRead: time.Now(), stopCh: make(chan struct{}), cancel: cancel}
	go func() {
		tick := idle / 4
		if tick > time.Second {
			tick = time.Second
		}
		if tick < 10*time.Millisecond {
			tick = 10 * time.Millisecond
		}
		t := time.NewTicker(tick)
		defer t.Stop()
		for {
			select {
			case <-b.stopCh:
				return
			case <-t.C:
				b.mu.Lock()
				idleFor := time.Since(b.lastRead)
				b.mu.Unlock()
				if idleFor > idle {
					cancel()
					return
				}
			}
		}
	}()
	return b
}

// ======================== 上游 HTTP ========================

// wbChatStream 发 chat 请求（始终流式），返回规范化后的 SSE 流或错误 body。
// 凭证经 a.snapshot() 一致性读取，避免与后台保活刷新并发。
func wbChatStream(ctx context.Context, cfg *UpstreamConfig, a *wbAccount, body []byte, meta wbChatMeta, proxyAddr string) (io.ReadCloser, int, []byte, error) {
	info := a.snapshot()
	realm := info.Realm
	var paths []string
	if realm == "global" {
		paths = []string{wbChatPathGlobal, wbChatPathCN}
	} else {
		paths = []string{wbChatPathCN}
	}
	client, _ := getModelHTTPClient(proxyAddr, true)
	for attempt, path := range paths {
		reqCtx, cancel := context.WithCancel(ctx)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, wbChatBase(cfg, realm)+path, bytes.NewReader(body))
		if err != nil {
			cancel()
			return nil, 0, nil, err
		}
		wbSetChatHeaders(req, cfg, info, meta)
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			return nil, 0, nil, fmt.Errorf("workbuddy chat transport: %w", err)
		}
		if resp.StatusCode >= 400 {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamErrorBodyBytes))
			resp.Body.Close()
			cancel()
			// global console 404/405 → 回退 /v2 路径重试
			if attempt < len(paths)-1 && (resp.StatusCode == 404 || resp.StatusCode == 405) {
				continue
			}
			return nil, resp.StatusCode, raw, nil
		}
		filtered := &wbStreamFilter{inner: resp.Body, br: bufio.NewReaderSize(resp.Body, 64*1024), names: map[int]string{}}
		return wbWrapIdle(filtered, wbStreamIdleMax, cancel), resp.StatusCode, nil, nil
	}
	return nil, 0, nil, fmt.Errorf("workbuddy chat: exhausted path candidates")
}

// wbDoJSON 发短 RPC 并解 {code,msg,data} 信封；ctx 由调用方带 deadline。
func wbDoJSON(ctx context.Context, cfg *UpstreamConfig, req *http.Request, proxyAddr string) (json.RawMessage, error) {
	client, _ := getModelHTTPClient(proxyAddr, false)
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, &wbError{Kind: wbClassify(resp.StatusCode, string(raw)), Status: resp.StatusCode, Msg: truncateForLog(string(raw), 200)}
	}
	var env struct {
		Code int             `json:"code"`
		Msg  string          `json:"msg"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("parse failed: %w (body: %s)", err, truncateForLog(string(raw), 120))
	}
	if env.Code != 0 {
		kind := wbClassify(resp.StatusCode, env.Msg)
		if kind == wbErrNone {
			kind = wbErrClient
		}
		return nil, &wbError{Kind: kind, Status: resp.StatusCode, Msg: fmt.Sprintf("code=%d msg=%s", env.Code, truncateForLog(env.Msg, 160))}
	}
	return env.Data, nil
}

// wbRefreshToken 刷新 access token（成功时更新账号字段并由调用方落盘）。全程持账号锁。
func wbRefreshToken(ctx context.Context, cfg *UpstreamConfig, a *wbAccount, proxyAddr string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if strings.TrimSpace(a.RefreshToken) == "" {
		return fmt.Errorf("no refreshToken")
	}
	url := wbChatBase(cfg, wbResolveRealm(a.Realm, a.Domain)) + wbRefreshPath
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	realm := wbResolveRealm(a.Realm, a.Domain)
	wbSetCommonHeaders(req, cfg, realm)
	req.Header.Set("X-Refresh-Token", a.RefreshToken)
	if a.EnterpriseID != "" {
		req.Header.Set("X-Enterprise-Id", a.EnterpriseID)
	}
	req.Header.Set("X-Auth-Refresh-Source", "plugin")
	data, err := wbDoJSON(ctx, cfg, req, proxyAddr)
	if err != nil {
		return err
	}
	var tok struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    int64  `json:"expiresIn"`
		Domain       string `json:"domain"`
	}
	if err := json.Unmarshal(data, &tok); err != nil || tok.AccessToken == "" {
		return fmt.Errorf("refresh_failed: no accessToken in response — re-login required")
	}
	a.AccessToken = tok.AccessToken
	if tok.RefreshToken != "" {
		a.RefreshToken = tok.RefreshToken
	}
	if tok.Domain != "" {
		a.Domain = tok.Domain
	}
	if tok.ExpiresIn > 0 {
		a.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix()
	}
	return nil
}

// wbFetchModels 拉取动态模型列表（cli agent 过滤）。realm 决定端点路径。
func wbFetchModels(ctx context.Context, cfg *UpstreamConfig, a *wbAccount, proxyAddr string) ([]string, error) {
	info := a.snapshot()
	realm := info.Realm
	url := wbChatBase(cfg, realm)
	if realm == "global" {
		url += wbModelsPathGlobal
	} else {
		url += wbModelsPathCN
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	wbSetCommonHeaders(req, cfg, realm)
	req.Header.Set("Authorization", "Bearer "+info.AccessToken)
	client, _ := getModelHTTPClient(proxyAddr, false)
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamModelsBodyBytes))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("workbuddy models status %d: %s", resp.StatusCode, truncateForLog(string(raw), 120))
	}
	var env struct {
		Code int `json:"code"`
		Data struct {
			Models []struct {
				ID       string `json:"id"`
				Disabled bool   `json:"disabled"`
			} `json:"models"`
			Agents []struct {
				Name   string   `json:"name"`
				Models []string `json:"models"`
			} `json:"agents"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("workbuddy models parse: %w", err)
	}
	if env.Code != 0 {
		return nil, fmt.Errorf("workbuddy models code=%d", env.Code)
	}
	byID := map[string]struct{ disabled bool }{}
	for _, m := range env.Data.Models {
		byID[m.ID] = struct{ disabled bool }{m.Disabled}
	}
	var cliIDs []string
	for _, ag := range env.Data.Agents {
		if ag.Name == "cli" {
			cliIDs = ag.Models
			break
		}
	}
	out := make([]string, 0, len(cliIDs))
	for _, id := range cliIDs {
		if m, ok := byID[id]; ok && !m.disabled {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("workbuddy models api returned empty cli list")
	}
	return out, nil
}

// wbUserResource 查询账号剩余可花积分（CN/global 计费端点自动选路）。
func wbUserResource(ctx context.Context, cfg *UpstreamConfig, a *wbAccount, proxyAddr string) (int64, error) {
	info := a.snapshot()
	realm := info.Realm
	base := wbBillingBase(cfg, realm)
	now := time.Now()
	body := map[string]any{
		"PageNumber":               1,
		"PageSize":                 100,
		"ProductCode":              "p_tcaca",
		"Status":                   []int{0, 3},
		"PackageEndTimeRangeBegin": now.Format("2006-01-02 15:04:05"),
		"PackageEndTimeRangeEnd":   now.Add(365 * 101 * 24 * time.Hour).Format("2006-01-02 15:04:05"),
	}
	raw, _ := json.Marshal(body)
	paths := []string{wbBillingMeterV2}
	if realm == "global" {
		paths = []string{wbBillingMeterPlain, wbBillingMeterV2}
	}
	var lastErr error
	for i, path := range paths {
		req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(raw))
		if err != nil {
			return 0, err
		}
		wbSetBillingHeaders(req, cfg, info)
		data, err := wbDoJSON(ctx, cfg, req, proxyAddr)
		if err != nil {
			lastErr = err
			var ue *wbError
			if errors.As(err, &ue) && ue.Kind == wbErrNotFound && i < len(paths)-1 {
				continue
			}
			return 0, err
		}
		var resp struct {
			Response struct {
				Data struct {
					Accounts []struct {
						CapacityRemain      int64 `json:"CapacityRemain"`
						CycleCapacityRemain int64 `json:"CycleCapacityRemain"`
						CycleCapacitySize   int64 `json:"CycleCapacitySize"`
					} `json:"Accounts"`
				} `json:"Data"`
			} `json:"Response"`
		}
		if err := json.Unmarshal(data, &resp); err != nil {
			return 0, fmt.Errorf("resource parse: %w", err)
		}
		var remain int64
		for _, acct := range resp.Response.Data.Accounts {
			r := acct.CapacityRemain
			if acct.CycleCapacitySize > 0 {
				r = acct.CycleCapacityRemain
			}
			if r < 0 {
				r = 0
			}
			remain += r
		}
		return remain, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("resource query failed")
	}
	return 0, lastErr
}

// wbDailyCheckin 每日签到（仅 CN；global 端点未实测，跳过）。幂等：已签到视为成功。
func wbDailyCheckin(ctx context.Context, cfg *UpstreamConfig, a *wbAccount, proxyAddr string) error {
	info := a.snapshot()
	if info.Realm == "global" {
		return fmt.Errorf("global realm 跳过签到")
	}
	req, err := http.NewRequest(http.MethodPost, wbBillingBase(cfg, info.Realm)+wbCheckinV2, bytes.NewReader([]byte("{}")))
	if err != nil {
		return err
	}
	wbSetBillingHeaders(req, cfg, info)
	_, err = wbDoJSON(ctx, cfg, req, proxyAddr)
	if err != nil {
		var ue *wbError
		if errors.As(err, &ue) {
			lower := strings.ToLower(ue.Msg)
			for _, m := range wbAlreadyCheckinMarkers {
				if strings.Contains(ue.Msg, m) || strings.Contains(lower, strings.ToLower(m)) {
					return nil // 今天已签到 → 幂等成功
				}
			}
		}
		return err
	}
	return nil
}

// ======================== 网关调用入口 ========================

// wbAccountSnapshot 管理端点用的账号状态快照。
type wbAccountSnapshot struct {
	UID          string `json:"uid"`
	Nickname     string `json:"nickname"`
	Realm        string `json:"realm"`
	FilePath     string `json:"file"`
	InFlight     int    `json:"in_flight"`
	Disabled     bool   `json:"disabled"`
	DisabledWhy  string `json:"disabled_reason,omitempty"`
	CoolingUntil string `json:"cooling_until,omitempty"`
	CoolingModel string `json:"cooling_model,omitempty"`
	CoolingWhy   string `json:"cooling_reason,omitempty"`
	BreakerUntil string `json:"breaker_until,omitempty"`
	FailStreak   int    `json:"fail_streak"`
	LastError    string `json:"last_error,omitempty"`
	TokenExpires string `json:"token_expires,omitempty"`
}

func wbSnapshotPool(p *wbPool) []wbAccountSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	out := make([]wbAccountSnapshot, 0, len(p.accounts))
	for _, key := range p.order {
		a := p.accounts[key]
		if a == nil {
			continue
		}
		s := wbAccountSnapshot{
			UID: a.UID, Nickname: a.Nickname, Realm: a.realm(),
			FilePath: filepath.Base(a.FilePath), InFlight: a.inFlight,
			Disabled: a.disabled, DisabledWhy: a.disabledReason,
			CoolingModel: a.coolingModel, CoolingWhy: a.coolingReason, FailStreak: a.failStreak,
			LastError: a.lastError,
		}
		if now.Before(a.coolingUntil) {
			s.CoolingUntil = a.coolingUntil.Format(time.RFC3339)
		}
		if now.Before(a.breakerUntil) {
			s.BreakerUntil = a.breakerUntil.Format(time.RFC3339)
		}
		if a.ExpiresAt > 0 {
			s.TokenExpires = time.Unix(a.ExpiresAt, 0).Format(time.RFC3339)
		}
		out = append(out, s)
	}
	return out
}

// wbErrResponse 把终态错误映射成 OpenAI 风格的错误体（状态码已按网关惯例归一）。
func wbErrResponse(kind wbErrKind, status int, body []byte) ([]byte, int) {
	msg := truncateForLog(string(body), 500)
	switch kind {
	case wbErrContentBlocked:
		body, _ := json.Marshal(map[string]any{"error": map[string]any{
			"message": wbContentBlockedMessage(string(body)), "type": "content_blocked", "code": "content_blocked",
		}})
		return body, http.StatusBadRequest
	case wbErrHardCredit, wbErrSessionDead, wbErrAccountFault:
		body, _ := json.Marshal(map[string]any{"error": map[string]any{
			"message": "workbuddy 账号不可用：" + msg, "type": "upstream_error",
		}})
		return body, http.StatusServiceUnavailable
	}
	mapped := mapUpstreamErrorBody(body, UpstreamOpenAI)
	if mapped == nil {
		mapped, _ = json.Marshal(map[string]any{"error": map[string]any{"message": "upstream error", "type": "upstream_error"}})
	}
	return mapped, normalizeUpstreamStatus(status)
}

// wbRoundTrip 账号轮转主循环：挑号→刷新→出站→按分类施罚/换号；成功时以 openai 形态返回响应。
// wantStream=true 返回规范化 SSE 流；false 聚合为单个 chat.completion JSON。
func wbRoundTrip(ctx context.Context, upstreamName, clientAPI string, upstream *UpstreamConfig, reqBody []byte, modelID, proxyAddr string, wantStream bool) ([]byte, io.ReadCloser, int, http.Header, error) {
	rec := usageRecorderFromContext(ctx)
	pool := wbPoolFor(upstream)
	prepared, realm, bareModel, err := wbPrepareBody(reqBody, modelID, upstream)
	if err != nil {
		return nil, nil, 500, nil, err
	}
	sessKey := wbExtractSessionKey(prepared)
	meta := wbChatMeta{}
	if v := wbJSONStringTop(prepared, "conversationId", "conversation_id"); v != "" {
		meta.ConversationID = v
	}
	if sessKey != "" {
		meta.ConversationRequestID = wbRequestIDForKey(sessKey)
	} else {
		meta.ConversationRequestID = wbTurnRequestID(wbTurnKey(prepared))
	}

	tried := map[string]bool{}
	var lastErrBody []byte
	var lastStatus int
	for attempt := 0; attempt < wbMaxRotate; attempt++ {
		select {
		case <-ctx.Done():
			return nil, nil, 0, nil, ctx.Err()
		default:
		}
		var a *wbAccount
		var key string
		if uid := wbStickyResolve(sessKey); uid != "" {
			pool.mu.Lock()
			cand, cok := pool.accounts[uid]
			pool.mu.Unlock()
			if cok && cand != nil && !cand.disabled && cand.realm() == realm {
				pool.mu.Lock()
				now := time.Now()
				ok := now.After(cand.coolingUntil) || (cand.coolingModel != "" && cand.coolingModel != bareModel)
				ok = ok && now.After(cand.breakerUntil)
				if ok && pool.maxInFlight > 0 {
					ok = cand.inFlight < pool.maxInFlight
				}
				if ok && !tried[uid] {
					cand.inFlight++
					cand.lastUsed = now
					a, key = cand, uid
				}
				pool.mu.Unlock()
			}
		}
		if a == nil {
			a, key = pool.pick(tried, realm, bareModel)
		}
		if a == nil {
			break
		}
		tried[key] = true

		// token 临期 → 先刷新（失败按分类施罚后换号）
		if a.needsRefresh(wbRefreshSkew) {
			rctx, rcancel := context.WithTimeout(context.Background(), wbRPCDeadline)
			rerr := wbRefreshToken(rctx, upstream, a, proxyAddr)
			rcancel()
			if rerr == nil {
				if serr := wbSaveAuth(a); serr != nil {
					log.Printf("[workbuddy] uid=%s 刷新后落盘失败: %v", wbUID8(a.UID), serr)
				}
			} else {
				pool.release(a)
				var ue *wbError
				if errors.As(rerr, &ue) {
					pool.applyError(a, ue.Kind, ue.Error(), bareModel)
					lastErrBody, lastStatus = wbErrResponse(ue.Kind, ue.Status, []byte(ue.Msg))
					if ue.Kind == wbErrSessionDead {
						wbStickyUnbind(sessKey)
					}
					continue
				}
				log.Printf("[workbuddy] uid=%s token 刷新失败: %v", wbUID8(a.UID), rerr)
				continue
			}
		}

		if a.snapshot().AccessToken == "" {
			pool.release(a)
			pool.applyError(a, wbErrSessionDead, "empty accessToken", bareModel)
			continue
		}

		chatStart := time.Now()
		rc, status, errBody, terr := wbChatStream(ctx, upstream, a, prepared, meta, proxyAddr)
		if terr != nil {
			// 传输抖动：只换号，不喂熔断（与 workbuddy2api 同策略）
			pool.release(a)
			log.Printf("[workbuddy] upstream=%s uid=%s transport: %v", effectiveUpstreamName(upstreamName), wbUID8(a.UID), terr)
			lastStatus = 0
			lastErrBody = nil
			continue
		}
		if status >= 400 {
			pool.release(a)
			kind := wbClassify(status, string(errBody))
			pool.applyError(a, kind, string(errBody), bareModel)
			if kind == wbErrContentBlocked {
				body, code := wbErrResponse(kind, status, errBody)
				if rec != nil {
					rec.SetUpstream(upstreamName)
					rec.SetStatus(code)
					rec.SetError("content_blocked")
				}
				return body, nil, code, nil, fmt.Errorf("content blocked")
			}
			lastErrBody, lastStatus = errBody, status
			log.Printf("[workbuddy] upstream=%s uid=%s upstream %d %s body=%s",
				effectiveUpstreamName(upstreamName), wbUID8(a.UID), status, kind, truncateForLog(string(errBody), 200))
			if kind == wbErrSessionDead || kind == wbErrAccountFault {
				wbStickyUnbind(sessKey)
			}
			continue
		}

		// 成功
		pool.noteSuccess(a)
		if sessKey != "" {
			wbStickyBind(sessKey, key)
		}
		if rec != nil {
			rec.SetUpstream(upstreamName)
			rec.SetStatus(status)
		}
		if !wantStream {
			resp, aggErr := wbAggregateSSE(rc)
			rc.Close()
			pool.release(a) // 聚合完成，租约即时归还
			if aggErr != nil {
				if rec != nil {
					rec.SetError(aggErr.Error())
				}
				body, _ := json.Marshal(map[string]any{"error": map[string]any{"message": "upstream parse: " + aggErr.Error(), "type": "upstream_error"}})
				return body, nil, http.StatusBadGateway, nil, aggErr
			}
			out, mErr := json.Marshal(resp)
			if mErr != nil {
				return nil, nil, 502, nil, mErr
			}
			if rec != nil {
				rec.MarkFirstToken()
			}
			if u, ok := resp["usage"].(map[string]any); ok && rec != nil {
				rec.MarkUsageFromMap(u)
			}
			return out, nil, http.StatusOK, http.Header{"Content-Type": []string{"application/json"}}, nil
		}
		// 流式：租约随下游 Close（handler defer）归还，避免提前释放导致在途计数漂移。
		leased := &wbLeaseCloser{ReadCloser: rc, release: func() { pool.release(a) }}
		if rec == nil {
			return nil, leased, http.StatusOK, http.Header{"Content-Type": []string{"text/event-stream"}}, nil
		}
		// ttfbReadCloser 在首字节回调里 MarkFirstToken 并打 [ttfb] 日志，与通用上游同口径。
		wrapped := &ttfbReadCloser{
			inner:      leased,
			start:      chatStart,
			upstream:   effectiveUpstreamName(upstreamName),
			model:      bareModel,
			clientAPI:  clientAPI,
			keySlot:    "wb:" + wbUID8(a.UID),
			proxyLabel: modelProxyLabel(proxyAddr),
			rec:        rec,
			ct:         &connPhase{},
			proto:      "",
		}
		return nil, wrapped, http.StatusOK, http.Header{"Content-Type": []string{"text/event-stream"}}, nil
	}

	// 轮转耗尽
	kind := wbErrClient
	status := lastStatus
	if status == 0 {
		status = http.StatusServiceUnavailable
	}
	if lastErrBody == nil {
		msg := "all workbuddy accounts unavailable (cooling/disabled/no match)"
		lastErrBody, _ = json.Marshal(map[string]any{"error": map[string]any{
			"message": msg, "type": "upstream_error", "code": "no_healthy_account",
		}})
		kind = wbErrClient
	} else {
		kind = wbClassify(lastStatus, string(lastErrBody))
	}
	body, code := wbErrResponse(kind, status, lastErrBody)
	if rec != nil {
		rec.SetUpstream(upstreamName)
		rec.SetStatus(code)
		rec.SetError(truncateForLog(string(lastErrBody), 200))
	}
	return body, nil, code, nil, fmt.Errorf("workbuddy: no usable account")
}

func wbJSONStringTop(body []byte, keys ...string) string {
	var obj map[string]any
	if json.Unmarshal(body, &obj) != nil {
		return ""
	}
	for _, k := range keys {
		if v, ok := obj[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func wbUID8(uid string) string {
	if len(uid) > 8 {
		return uid[:8]
	}
	return uid
}

// wbCallUpstream 非流式入口：聚合 SSE → 单个 chat.completion JSON。
func wbCallUpstream(ctx context.Context, reqBody []byte, upstreamName, modelID, clientAPI string, upstream *UpstreamConfig, proxyAddr string) ([]byte, int, http.Header, error) {
	body, _, status, header, err := wbRoundTrip(ctx, upstreamName, clientAPI, upstream, reqBody, modelID, proxyAddr, false)
	return body, status, header, err
}

// wbCallUpstreamStream 流式入口：返回规范化 SSE 流；失败时以 reader 携带错误体（与网关惯例一致，
// 调用方对非 2xx 会读取该 reader 并原样回给客户端）。
func wbCallUpstreamStream(ctx context.Context, reqBody []byte, upstreamName, modelID, clientAPI string, upstream *UpstreamConfig, proxyAddr string) (io.ReadCloser, int, http.Header, error) {
	errBody, rc, status, header, err := wbRoundTrip(ctx, upstreamName, clientAPI, upstream, reqBody, modelID, proxyAddr, true)
	if rc != nil {
		return rc, status, header, err
	}
	if errBody != nil {
		return io.NopCloser(bytes.NewReader(errBody)), status, header, err
	}
	return nil, status, header, err
}

// ======================== 动态模型列表（网关侧） ========================

// wbProbeMaxAccountsPerRealm 每个域最多探测的健康账号数：不同账号模型权限可能不同，
// 取 2 个账号的并集，兼顾「列表尽量全」与「按钮别拖太久」（单账号 8s 超时 ×2 域）。
const wbProbeMaxAccountsPerRealm = 2

// wbListModels 返回 workbuddy 上游可服务的模型（面板「获取模型列表」按钮触发）。
// 探测域按 wb_realm 决定：cn → 仅国内版；global → 仅国际版；all/缺省 → 两域都探并合并。
// 前缀规则与路由协议严格对齐：
//   - all 混池：global 域结果带 "global:" 前缀（路由域无法从上游推断，必须显式标记）；
//   - 显式单域上游（wb_realm=cn/global）：返回裸名——无前缀模型由上游域兜底路由，
//     与用户手填裸名 custom_models 的习惯一致，重探不会产生「裸名/前缀混排」。
//
// 某域无可用账号或全部探测失败时，该域回退静态名单（账号补齐后重启/重载即恢复探测）。
func wbListModels(upstreamName string, cfg *UpstreamConfig) ([]ModelInfo, error) {
	realms := []string{"cn", "global"}
	mixedPool := true
	if cfg != nil {
		switch strings.ToLower(strings.TrimSpace(cfg.WBRealm)) {
		case "cn":
			realms, mixedPool = []string{"cn"}, false
		case "global":
			realms, mixedPool = []string{"global"}, false
		}
	}
	pool := wbPoolFor(cfg)
	proxy := getFirstConfiguredSocks5ProxyAddr()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	var ids []string
	seen := map[string]bool{}
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		ids = append(ids, id)
	}
	for _, realm := range realms {
		found, hasAccount := wbProbeModelsForRealm(ctx, pool, cfg, realm, proxy)
		if !hasAccount {
			// 池内没有该域账号：不列该域模型（列了也必然 503，徒增误导）。
			continue
		}
		if len(found) == 0 {
			log.Printf("[workbuddy] %s 域账号探测全部失败，使用静态兜底名单", realm)
			found = wbStaticFallback(realm)
		}
		for _, id := range found {
			if realm == "global" && mixedPool {
				id = "global:" + id
			}
			add(id)
		}
	}
	return wbToModelInfos(upstreamName, ids), nil
}

// wbProbeModelsForRealm 探测单个域：对最多 wbProbeMaxAccountsPerRealm 个未禁用账号
// 拉取动态模型并取并集（保序去重，保留上游 cli agent 顺序）。
// 返回 (模型并集, 该域是否有账号)。无账号时不做任何网络调用、也不给兜底名单——
// 池里没有该域账号却列出该域模型，只会诱导用户配出必然 503 的别名。
func wbProbeModelsForRealm(ctx context.Context, pool *wbPool, cfg *UpstreamConfig, realm, proxy string) ([]string, bool) {
	pool.mu.Lock()
	var accts []*wbAccount
	for _, key := range pool.order {
		a := pool.accounts[key]
		if a == nil || a.disabled {
			continue
		}
		// 冷却中的账号仍可服务 GET models（不计费、不触发对话风控），纳入并集提升覆盖。
		if a.realm() != realm {
			continue
		}
		accts = append(accts, a)
		if len(accts) >= wbProbeMaxAccountsPerRealm {
			break
		}
	}
	pool.mu.Unlock()
	if len(accts) == 0 {
		return nil, false
	}
	var union []string
	seen := map[string]bool{}
	anyOK := false
	for _, a := range accts {
		if ctx.Err() != nil {
			break
		}
		pctx, pcancel := context.WithTimeout(ctx, 8*time.Second)
		ids, err := wbFetchModels(pctx, cfg, a, proxy)
		pcancel()
		if err != nil {
			log.Printf("[workbuddy] uid=%s %s 域模型探测失败: %v", wbUID8(a.UID), realm, err)
			continue
		}
		anyOK = true
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				union = append(union, id)
			}
		}
	}
	if !anyOK {
		return nil, true
	}
	return union, true
}

func wbStaticFallback(realm string) []string {
	if realm == "global" {
		return append([]string(nil), wbStaticModelsGlobal...)
	}
	return append([]string(nil), wbStaticModelsCN...)
}

func wbToModelInfos(upstreamName string, ids []string) []ModelInfo {
	owned := effectiveUpstreamName(upstreamName)
	now := time.Now().Unix()
	out := make([]ModelInfo, 0, len(ids))
	for _, id := range ids {
		out = append(out, ModelInfo{ID: id, Object: "model", Created: now, OwnedBy: owned})
	}
	return out
}

// ======================== OAuth 设备授权登录 ========================
//
// 登录协议（无 PKCE，state 由服务端签发）三步：
//  1. POST {base}/v2/plugin/auth/state?platform=CLI → {state, authUrl}
//  2. 用户在浏览器打开 authUrl 完成登录（cn 扫码 / global 邮箱验证码 SSO）；
//     期间轮询 GET {base}/v2/plugin/auth/token?state= 返回 code=11217 表示仍在等待
//  3. 轮询成功后 GET {base}/v2/plugin/login/account?state= 取 uid/nickname → 落盘
//
// CLI（-wb-login=url/poll）与管理面板（/api/wb/login）共用本层原语；
// 面板模式下由网关服务器自己轮询接管（浏览器标签页关掉也能完成入库），15 分钟窗口。

const (
	wbLoginTTL       = 15 * time.Minute // state 有效期（对齐参考项目等待窗口）
	wbLoginPollEvery = 2 * time.Second
	wbLoginKeepDone  = 10 * time.Minute // 终态会话保留时长（供面板最后拉一次结果）
)

// wbLoginStatePath realm 对应的登录 state 落盘路径（CLI url/poll 两段之间传递）。
func wbLoginStatePath(realm string) string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("wb-gateway-login-state-%s.json", realm))
}

type wbLoginToken struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int64  `json:"expiresIn"`
	Domain       string `json:"domain"`
}

type wbLoginAccount struct {
	UID          string `json:"uid"`
	EnterpriseID string `json:"enterpriseId"`
	Nickname     string `json:"nickname"`
}

// wbResolveLoginDir 登录凭证目录归一：相对路径以配置文件所在目录为基准。
func wbResolveLoginDir(dir string) string {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		dir = "auths"
	}
	if !filepath.IsAbs(dir) && configPath != "" {
		if base := filepath.Dir(configPath); base != "" && base != "." {
			dir = filepath.Join(base, dir)
		}
	}
	return dir
}

// wbDefaultLoginDir 面板登录默认目录：首个 workbuddy 上游的 wb_auth_dir，否则 auths。
func wbDefaultLoginDir() string {
	ups := getConfiguredUpstreams()
	for _, name := range sortedUpstreamNames(ups) {
		u := ups[name]
		if u != nil && u.APIType == UpstreamWorkBuddy && strings.TrimSpace(u.WBAuthDir) != "" {
			return wbResolveLoginDir(u.WBAuthDir)
		}
	}
	return wbResolveLoginDir("auths")
}

// wbLoginBaseForRealm 登录端点 base：优先取与目标域匹配的 workbuddy 上游的 chat base
// （尊重 wb_chat_base_cn / wb_chat_base_global / base_url 覆盖），未配置则内置默认。
func wbLoginBaseForRealm(realm string) string {
	ups := getConfiguredUpstreams()
	for _, name := range sortedUpstreamNames(ups) {
		u := ups[name]
		if u == nil || u.APIType != UpstreamWorkBuddy {
			continue
		}
		r := strings.ToLower(strings.TrimSpace(u.WBRealm))
		if r == "" || r == "all" || r == realm {
			return wbChatBase(u, realm)
		}
	}
	if realm == "global" {
		return wbChatBaseGlobal
	}
	return wbChatBaseCN
}

// wbLoginClient 登录流 HTTP 客户端：复用网关的 socks5 感知客户端（proxyAddr 须在 socks5_proxies 中）。
func wbLoginClient(proxyAddr string) *http.Client {
	client, _ := getModelHTTPClient(proxyAddr, false)
	return client
}

func wbLoginJSONGet(client *http.Client, url, realm, accessToken string, out any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	wbSetLoginHeaders(req, realm, accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var env struct {
		Code int             `json:"code"`
		Msg  string          `json:"msg"`
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &env) != nil {
		return fmt.Errorf("http %d: %s", resp.StatusCode, truncateForLog(string(raw), 120))
	}
	if env.Code != 0 || resp.StatusCode >= 400 {
		return fmt.Errorf("code=%d msg=%s", env.Code, env.Msg)
	}
	return json.Unmarshal(env.Data, out)
}

// wbLoginFetchState 申请设备授权会话，返回 state 与浏览器授权 URL。
func wbLoginFetchState(client *http.Client, base, realm string) (state, authURL string, err error) {
	req, rerr := http.NewRequest(http.MethodPost, base+"/v2/plugin/auth/state?platform=CLI", bytes.NewReader([]byte("{}")))
	if rerr != nil {
		return "", "", rerr
	}
	wbSetLoginHeaders(req, realm, "")
	resp, derr := client.Do(req)
	if derr != nil {
		return "", "", fmt.Errorf("授权 state 请求失败: %w", derr)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var env struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			State   string `json:"state"`
			AuthURL string `json:"authUrl"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &env) != nil || env.Code != 0 || env.Data.State == "" || env.Data.AuthURL == "" {
		return "", "", fmt.Errorf("授权 state 响应异常: %s", truncateForLog(string(raw), 200))
	}
	return env.Data.State, env.Data.AuthURL, nil
}

// wbLoginPollToken 单次轮询 token；用户尚未完成浏览器授权时返回 error（pending 语义，调用方按重试处理）。
func wbLoginPollToken(client *http.Client, base, realm, state string) (*wbLoginToken, error) {
	var tok wbLoginToken
	if err := wbLoginJSONGet(client, base+"/v2/plugin/auth/token?state="+url.QueryEscape(state), realm, "", &tok); err != nil {
		return nil, err
	}
	if strings.TrimSpace(tok.AccessToken) == "" {
		return nil, fmt.Errorf("pending: 上游未签发 accessToken")
	}
	return &tok, nil
}

// wbLoginFinalize 登录完成后的落库动作：拉账号信息 → 凭证原子落盘 → 账号池热加载 → CN 首次签到。
func wbLoginFinalize(client *http.Client, base, realm, dir, proxy, state string, tok *wbLoginToken) (*wbAccount, *wbLoginAccount, error) {
	var acct wbLoginAccount
	if err := wbLoginJSONGet(client, base+"/v2/plugin/login/account?state="+url.QueryEscape(state), realm, tok.AccessToken, &acct); err != nil {
		return nil, nil, fmt.Errorf("账号信息获取失败: %w", err)
	}
	if strings.TrimSpace(acct.UID) == "" {
		return nil, nil, fmt.Errorf("上游未返回 uid")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, nil, fmt.Errorf("创建凭证目录失败: %w", err)
	}
	a := &wbAccount{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix(),
		Domain:       tok.Domain,
		Realm:        wbResolveRealm(realm, tok.Domain),
		UID:          acct.UID,
		EnterpriseID: acct.EnterpriseID,
		Nickname:     acct.Nickname,
		FilePath:     filepath.Join(dir, fmt.Sprintf("workbuddy-%s.json", acct.UID)),
	}
	if err := wbSaveAuth(a); err != nil {
		return nil, nil, fmt.Errorf("保存凭证失败: %w", err)
	}
	wbReloadPools() // 免重启入池
	if a.realm() == "cn" {
		// 签到走计费域：自定义 base（私有部署/测试）时跟随 base，默认 CN 走 www.codebuddy.cn。
		ctx, cancel := context.WithTimeout(context.Background(), wbRPCDeadline)
		err := wbDailyCheckin(ctx, &UpstreamConfig{BaseURL: base}, a, proxy)
		cancel()
		if err != nil {
			log.Printf("[workbuddy] uid=%s 首次签到: %v", wbUID8(a.UID), err)
		}
	}
	return a, &acct, nil
}

// ---------- 面板登录会话（服务器侧轮询接管） ----------

type wbLoginSession struct {
	ID         string
	Realm      string
	AuthDir    string
	Proxy      string
	Base       string // 登录端点 base（与 state 获取同域，避免轮询重算漂移）
	State      string
	AuthURL    string
	Status     string // pending | success | expired | error
	UID        string
	Nickname   string
	LastError  string
	CreatedAt  time.Time
	FinishedAt time.Time
}

var (
	wbLoginMu       sync.Mutex
	wbLoginSessions = map[string]*wbLoginSession{}
)

// wbLoginGC 清理超时/终态会话，防内存增长。
func wbLoginGC(now time.Time) {
	wbLoginMu.Lock()
	defer wbLoginMu.Unlock()
	for id, s := range wbLoginSessions {
		if s.Status == "pending" {
			if now.Sub(s.CreatedAt) > wbLoginTTL+time.Minute {
				delete(wbLoginSessions, id)
			}
			continue
		}
		if now.Sub(s.FinishedAt) > wbLoginKeepDone {
			delete(wbLoginSessions, id)
		}
	}
}

func wbLoginSessionSnapshot(id string) (map[string]any, bool) {
	wbLoginMu.Lock()
	defer wbLoginMu.Unlock()
	s, ok := wbLoginSessions[id]
	if !ok {
		return nil, false
	}
	out := map[string]any{
		"id":       s.ID,
		"realm":    s.Realm,
		"status":   s.Status,
		"auth_url": s.AuthURL,
		"dir":      s.AuthDir,
	}
	if s.UID != "" {
		out["uid"] = s.UID
	}
	if s.Nickname != "" {
		out["nickname"] = s.Nickname
	}
	if s.LastError != "" {
		out["last_error"] = s.LastError
	}
	return out, true
}

// wbLoginStartSession 面板发起登录：向后端申请 state，建会话并起服务器侧轮询协程。
// proxy 为空=直连，否则必须是 socks5_proxies 里已配置的地址（国际站网络不可达时选代理）。
func wbLoginStartSession(realm, dir, proxy string) (*wbLoginSession, error) {
	if realm != "global" {
		realm = "cn"
	}
	if proxy != "" {
		if _, ok := configuredSocks5Proxy(proxy); !ok {
			return nil, fmt.Errorf("proxy %q 未在 socks5_proxies 中配置", proxy)
		}
	}
	if dir == "" {
		dir = wbDefaultLoginDir()
	} else {
		dir = wbResolveLoginDir(dir)
	}
	base := wbLoginBaseForRealm(realm)
	state, authURL, err := wbLoginFetchState(wbLoginClient(proxy), base, realm)
	if err != nil {
		return nil, err
	}
	wbLoginGC(time.Now())
	s := &wbLoginSession{
		ID: wbNewMessageID()[:16], Realm: realm, AuthDir: dir, Proxy: proxy, Base: base,
		State: state, AuthURL: authURL, Status: "pending", CreatedAt: time.Now(),
	}
	wbLoginMu.Lock()
	wbLoginSessions[s.ID] = s
	wbLoginMu.Unlock()
	go wbLoginRunLoop(s)
	return s, nil
}

// wbLoginRunLoop 服务器侧轮询直到成功/超时——浏览器标签页关闭不影响接管。
func wbLoginRunLoop(s *wbLoginSession) {
	client := wbLoginClient(s.Proxy)
	base := s.Base // 必须与 state 获取同域：state 是签发它的 host 才能兑换 token
	deadline := time.Now().Add(wbLoginTTL)
	for {
		time.Sleep(wbLoginPollEvery)
		if time.Now().After(deadline) {
			wbLoginMu.Lock()
			if s.Status == "pending" {
				s.Status = "expired"
				s.FinishedAt = time.Now()
			}
			wbLoginMu.Unlock()
			return
		}
		tok, err := wbLoginPollToken(client, base, s.Realm, s.State)
		if err != nil {
			continue // code=11217 等待授权
		}
		a, _, ferr := wbLoginFinalize(client, base, s.Realm, s.AuthDir, s.Proxy, s.State, tok)
		wbLoginMu.Lock()
		s.FinishedAt = time.Now()
		if ferr != nil {
			s.Status = "error"
			s.LastError = ferr.Error()
			log.Printf("[workbuddy] 面板登录入库失败: %v", ferr)
		} else {
			s.Status = "success"
			s.UID = a.UID
			s.Nickname = a.Nickname
			log.Printf("[workbuddy] 面板登录成功: uid=%s realm=%s nickname=%s 已入池", wbUID8(a.UID), a.Realm, a.Nickname)
		}
		wbLoginMu.Unlock()
		return
	}
}

// wbLoginHandler /api/wb/login —— 面板登录端点（requireAuth + sameOriginWriteGuard）。
//
//	POST {action:"start", realm, dir?, proxy?} → {id, status, auth_url, dir}
//	GET  ?id=...                                → {status: pending|success|expired|error, uid?, nickname?, last_error?}
func wbLoginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req struct {
			Action string `json:"action"`
			Realm  string `json:"realm"`
			Dir    string `json:"dir"`
			Proxy  string `json:"proxy"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if req.Action != "start" {
			http.Error(w, `{"error":"action 仅支持 start"}`, http.StatusBadRequest)
			return
		}
		s, err := wbLoginStartSession(req.Realm, req.Dir, req.Proxy)
		if err != nil {
			log.Printf("[workbuddy] 面板登录发起失败: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id": s.ID, "status": s.Status, "auth_url": s.AuthURL, "dir": s.AuthDir, "realm": s.Realm,
		})
	case http.MethodGet:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, `{"error":"missing id"}`, http.StatusBadRequest)
			return
		}
		snap, ok := wbLoginSessionSnapshot(id)
		if !ok {
			http.Error(w, `{"error":"session not found or expired"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(snap)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// wbRunLoginCLI 实现 `-wb-login=url|poll` 两段式命令行登录（面板不可用/远程服务器场景）：
//
//	阶段一  llm-gateway -wb-login=url -wb-realm=cn
//	阶段二  浏览器完成登录后  llm-gateway -wb-login=poll -wb-realm=cn
//
// 与面板共用协议原语，落盘后账号池自动热加载。
func wbRunLoginCLI(phase, realm, dir, proxyAddr string) {
	if phase != "url" && phase != "poll" {
		log.Fatalf("workbuddy-login: 阶段参数必须是 url 或 poll（收到 %q）", phase)
	}
	if realm != "global" {
		realm = "cn"
	}
	dir = wbResolveLoginDir(dir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatalf("workbuddy-login: 无法创建凭证目录 %s: %v", dir, err)
	}
	client := wbLoginClient(proxyAddr)
	base := wbLoginBaseForRealm(realm)

	switch phase {
	case "url":
		state, authURL, err := wbLoginFetchState(client, base, realm)
		if err != nil {
			log.Fatalf("workbuddy-login: %v", err)
		}
		// state 由签发它的 host 才能兑换 token：base 一并落盘，poll 阶段原样复用
		raw, _ := json.Marshal(map[string]string{"state": state, "realm": realm, "base": base})
		if werr := os.WriteFile(wbLoginStatePath(realm), raw, 0600); werr != nil {
			log.Fatalf("workbuddy-login: 保存 state 失败: %v", werr)
		}
		fmt.Println()
		fmt.Println("请在浏览器中打开以下链接完成 WorkBuddy 登录：")
		fmt.Println()
		fmt.Println("  " + authURL)
		fmt.Println()
		fmt.Println("完成登录后执行：")
		prog := filepath.Base(os.Args[0])
		fmt.Printf("  %s -wb-login=poll -wb-realm=%s -wb-auth-dir=%s\n", prog, realm, dir)
		fmt.Println()

	case "poll":
		state := ""
		if raw, err := os.ReadFile(wbLoginStatePath(realm)); err == nil {
			var st map[string]string
			if json.Unmarshal(raw, &st) == nil {
				state = st["state"]
			}
			if st["realm"] != "" && st["realm"] != realm {
				log.Fatalf("workbuddy-login: realm 不一致（state=%s，命令=%s）—— url 与 poll 必须同域", st["realm"], realm)
			}
			// url→poll 跨进程：兑换必须走签发 host（两阶段间若改过上游 base 配置也不漂移）
			if st["base"] != "" {
				base = st["base"]
			}
		}
		if state == "" {
			log.Fatalf("workbuddy-login: 未找到登录 state，请先运行 -wb-login=url")
		}
		fmt.Println("正在获取 token（如浏览器尚未完成登录，最长等 3 分钟）…")
		var tok *wbLoginToken
		deadline := time.Now().Add(3 * time.Minute)
		var lastErr error
		for time.Now().Before(deadline) {
			tok, lastErr = wbLoginPollToken(client, base, realm, state)
			if lastErr == nil {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if tok == nil {
			log.Fatalf("workbuddy-login: 登录未完成或 token 获取失败（%v）——请在浏览器完成登录后重试", lastErr)
		}
		a, _, err := wbLoginFinalize(client, base, realm, dir, proxyAddr, state, tok)
		if err != nil {
			log.Fatalf("workbuddy-login: %v", err)
		}
		_ = os.Remove(wbLoginStatePath(realm))
		fmt.Printf("已保存账号: %s (uid=%s, realm=%s, nickname=%s)\n", a.FilePath, a.UID, a.Realm, a.Nickname)
		fmt.Println("完成。运行中的网关已自动热加载该账号（重启亦可）。")
	}
}

// ======================== 后台任务 ========================

var (
	wbTasksOnce   sync.Once
	wbCheckinDone = map[string]string{} // uid → 已签到日期
	wbCheckinMu   sync.Mutex
)

// wbStartBackgroundTasks token 保活 + 定时签到 + 粘性 GC + 凭证目录重扫（幂等，进程级一次）。
func wbStartBackgroundTasks() {
	wbTasksOnce.Do(func() {
		go func() {
			t := time.NewTicker(30 * time.Minute)
			defer t.Stop()
			for range t.C {
				wbReloadPools() // 发现登录命令新增的账号文件（免重启）
				wbKeepAliveTick()
				wbStickyGC()
			}
		}()
	})
}

func wbKeepAliveTick() {
	now := time.Now()
	hour := now.Hour()
	wbPoolsMu.Lock()
	pools := make([]*wbPool, 0, len(wbPools))
	for _, p := range wbPools {
		pools = append(pools, p)
	}
	wbPoolsMu.Unlock()

	for _, p := range pools {
		pcfg := p.poolCfg()
		checkinEnabled := pcfg != nil && pcfg.WBCheckin
		proxy := ""
		if pcfg != nil {
			proxy = getFirstConfiguredSocks5ProxyAddr()
		}
		p.mu.Lock()
		accounts := make([]*wbAccount, 0, len(p.order))
		for _, key := range p.order {
			if a := p.accounts[key]; a != nil && !a.disabled {
				accounts = append(accounts, a)
			}
		}
		p.mu.Unlock()
		for _, a := range accounts {
			if a.needsRefresh(12 * time.Hour) {
				ctx, cancel := context.WithTimeout(context.Background(), wbRPCDeadline)
				err := wbRefreshToken(ctx, pcfg, a, proxy)
				cancel()
				if err == nil {
					if serr := wbSaveAuth(a); serr != nil {
						log.Printf("[workbuddy] uid=%s 保活刷新落盘失败: %v", wbUID8(a.UID), serr)
					}
				} else {
					var ue *wbError
					if errors.As(err, &ue) && (ue.Kind == wbErrSessionDead || ue.Kind == wbErrAccountFault) {
						p.mu.Lock()
						a.disabled = true
						a.disabledReason = "keepalive refresh: " + ue.Msg
						p.mu.Unlock()
						log.Printf("[workbuddy] uid=%s 保活刷新失败，已禁用账号: %v", wbUID8(a.UID), ue.Msg)
					}
				}
			}
			if !checkinEnabled || a.realm() != "cn" {
				continue
			}
			// 签到窗口：09:00–23:59（21 点排程之后兜底补签，幂等）。
			if hour < 9 {
				continue
			}
			today := now.Format("2006-01-02")
			wbCheckinMu.Lock()
			done := wbCheckinDone[a.UID] == today
			wbCheckinMu.Unlock()
			if done {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), wbRPCDeadline)
			err := wbDailyCheckin(ctx, pcfg, a, proxy)
			cancel()
			if err == nil {
				wbCheckinMu.Lock()
				wbCheckinDone[a.UID] = today
				wbCheckinMu.Unlock()
				log.Printf("[workbuddy] uid=%s 每日签到完成", wbUID8(a.UID))
			} else {
				log.Printf("[workbuddy] uid=%s 签到失败: %v", wbUID8(a.UID), err)
			}
		}
	}
}

// ======================== 管理端点 ========================

// wbStatusHandler GET /api/wb/status —— 各 workbuddy 上游的账号池状态（requireAuth 注册）。
// 展示前先重扫凭证目录：手动往 auths/ 拷入/删除的凭据文件即时生效，不必等后台重扫。
func wbStatusHandler(w http.ResponseWriter, r *http.Request) {
	wbReloadPools()
	out := map[string]any{"upstreams": map[string]any{}}
	ups := map[string]any{}
	for name, cfg := range getConfiguredUpstreams() {
		if cfg == nil || cfg.APIType != UpstreamWorkBuddy {
			continue
		}
		p := wbPoolFor(cfg)
		snap := wbSnapshotPool(p)
		entry := map[string]any{
			"auth_dir": wbAuthDirOf(cfg),
			"realm":    cfg.WBRealm,
			"total":    len(snap),
			"accounts": snap,
		}
		if r.URL.Query().Get("credits") == "1" {
			credits := map[string]int64{}
			for _, s := range snap {
				// 快照里的 FilePath 是 base 名，credits 查询按池内账号顺序找。
				p.mu.Lock()
				var a *wbAccount
				for _, key := range p.order {
					if cand := p.accounts[key]; cand != nil && filepath.Base(cand.FilePath) == s.FilePath {
						a = cand
						break
					}
				}
				p.mu.Unlock()
				if a == nil {
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), wbRPCDeadline)
				remain, err := wbUserResource(ctx, cfg, a, "")
				cancel()
				if err != nil {
					credits[s.FilePath] = -1
				} else {
					credits[s.FilePath] = remain
				}
			}
			entry["credits"] = credits
		}
		ups[name] = entry
	}
	out["upstreams"] = ups
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// wbApplyConfig 配置变更钩子：加载/刷新各 workbuddy 上游的账号池。
// 在 applyConfig（持 configMu）内调用——本函数不得触碰 configMu。
func wbApplyConfig(ups map[string]*UpstreamConfig, changed bool) {
	for _, u := range ups {
		if u == nil || u.APIType != UpstreamWorkBuddy {
			continue
		}
		p := wbPoolFor(u)
		if changed {
			p.reload()
			p.mu.Lock()
			if u.WBMaxInFlight > 0 {
				p.maxInFlight = u.WBMaxInFlight
			}
			p.mu.Unlock()
		}
	}
}

// wbCheckinHandler POST /api/wb/checkin?upstream=name —— 手动触发签到（对齐 workbuddy2api signin.sh）。
// 不带 upstream 参数时对全部 workbuddy 上游执行。CN 账号幂等：已签到视为成功。
func wbCheckinHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	want := strings.TrimSpace(r.URL.Query().Get("upstream"))
	type result struct {
		Upstream string `json:"upstream"`
		UID      string `json:"uid"`
		Realm    string `json:"realm"`
		OK       bool   `json:"ok"`
		Msg      string `json:"msg,omitempty"`
	}
	var out []result
	proxy := getFirstConfiguredSocks5ProxyAddr()
	for name, cfg := range getConfiguredUpstreams() {
		if cfg == nil || cfg.APIType != UpstreamWorkBuddy {
			continue
		}
		if want != "" && want != name {
			continue
		}
		pool := wbPoolFor(cfg)
		for _, key := range pool.snapshotKeys() {
			a := pool.byKey(key)
			if a == nil {
				continue
			}
			res := result{Upstream: name, UID: wbUID8(a.snapshot().UID)}
			ctx, cancel := context.WithTimeout(context.Background(), wbRPCDeadline)
			err := wbDailyCheckin(ctx, cfg, a, proxy)
			cancel()
			res.Realm = a.realm()
			if err != nil {
				res.Msg = err.Error()
			} else {
				res.OK = true
			}
			out = append(out, res)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"results": out})
}

// wbPoolSummaryLog 启动时打印 workbuddy 上游的账号概况。
func wbPoolSummaryLog() {
	for name, cfg := range getConfiguredUpstreams() {
		if cfg == nil || cfg.APIType != UpstreamWorkBuddy {
			continue
		}
		p := wbPoolFor(cfg)
		n := p.accountCount()
		log.Printf("WorkBuddy 上游 %q: 账号池 %d 个（auth dir=%s）", name, n, wbAuthDirOf(cfg))
	}
}
