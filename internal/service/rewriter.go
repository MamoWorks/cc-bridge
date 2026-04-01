package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"regexp"
	"strings"

	"cc2api/internal/model"
)

// headerWireCasing maps lowercase header keys to their real wire format
// as observed in Claude CLI traffic captures. Go's HTTP server canonicalizes
// all header keys (e.g. "anthropic-beta" → "Anthropic-Beta"); this map
// restores the original casing when forwarding to upstream.
var headerWireCasing = map[string]string{
	"accept":                                     "Accept",
	"user-agent":                                 "User-Agent",
	"x-stainless-retry-count":                    "X-Stainless-Retry-Count",
	"x-stainless-timeout":                        "X-Stainless-Timeout",
	"x-stainless-lang":                           "X-Stainless-Lang",
	"x-stainless-package-version":                "X-Stainless-Package-Version",
	"x-stainless-os":                             "X-Stainless-OS",
	"x-stainless-arch":                           "X-Stainless-Arch",
	"x-stainless-runtime":                        "X-Stainless-Runtime",
	"x-stainless-runtime-version":                "X-Stainless-Runtime-Version",
	"x-stainless-helper-method":                  "x-stainless-helper-method",
	"anthropic-dangerous-direct-browser-access":   "anthropic-dangerous-direct-browser-access",
	"anthropic-version":                           "anthropic-version",
	"anthropic-beta":                              "anthropic-beta",
	"x-app":                                       "x-app",
	"content-type":                                "content-type",
	"accept-language":                             "accept-language",
	"sec-fetch-mode":                              "sec-fetch-mode",
	"accept-encoding":                             "accept-encoding",
	"authorization":                               "authorization",
	"x-claude-code-session-id":                    "X-Claude-Code-Session-Id",
	"x-client-request-id":                         "x-client-request-id",
	"content-length":                              "content-length",
	"x-anthropic-billing-header":                  "x-anthropic-billing-header",
}

// resolveWireCasing converts a Go canonical key to its real wire casing.
func resolveWireCasing(key string) string {
	if wk, ok := headerWireCasing[strings.ToLower(key)]; ok {
		return wk
	}
	return key
}

// Rewriter handles all anti-detection rewriting for requests.
// Two modes: Replace (CC client) and Inject (pure API).
type Rewriter struct{}

func NewRewriter() *Rewriter { return &Rewriter{} }

// ClientType distinguishes request origin.
type ClientType int

const (
	ClientTypeClaudeCode ClientType = iota
	ClientTypeAPI
)

const defaultVersion = "2.1.81"

// mergeAnthropicBeta merges required beta tokens with incoming client beta tokens,
// deduplicating and preserving order (required first, then extras from client).
func mergeAnthropicBeta(required, incoming string) string {
	seen := make(map[string]bool)
	var tokens []string
	for _, t := range strings.Split(required, ",") {
		t = strings.TrimSpace(t)
		if t != "" && !seen[t] {
			seen[t] = true
			tokens = append(tokens, t)
		}
	}
	for _, t := range strings.Split(incoming, ",") {
		t = strings.TrimSpace(t)
		if t != "" && !seen[t] {
			seen[t] = true
			tokens = append(tokens, t)
		}
	}
	return strings.Join(tokens, ",")
}

// betaHeaderForModel returns the correct anthropic-beta value based on model.
// Haiku models must NOT include claude-code beta.
func betaHeaderForModel(modelID string) string {
	lower := strings.ToLower(modelID)
	if strings.Contains(lower, "haiku") {
		return "oauth-2025-04-20,interleaved-thinking-2025-05-14"
	}
	return "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14"
}

// --- Header rewriting ---

// RewriteHeaders processes outgoing headers for anti-detection.
// Removes hop-by-hop and auth headers, normalizes User-Agent and billing header.
func (rw *Rewriter) RewriteHeaders(headers map[string]string, account *model.Account, clientType ClientType, modelID string, bodyMap map[string]any) map[string]string {
	env := rw.parseEnv(account)
	version := env.Version
	if version == "" {
		version = defaultVersion
	}

	out := make(map[string]string, len(headers))

	if clientType == ClientTypeAPI {
		// API mode: use a fixed set of headers that match real Claude CLI.
		// Now that we inject system prompt, include claude-code beta.
		out["Accept"] = "application/json"
		out["User-Agent"] = fmt.Sprintf("claude-code/%s (external, cli)", version)
		out["anthropic-beta"] = betaHeaderForModel(modelID)
		out["anthropic-version"] = "2023-06-01"
		out["anthropic-dangerous-direct-browser-access"] = "true"
		out["x-app"] = "cli"
		out["content-type"] = "application/json"
		out["accept-encoding"] = "gzip, deflate, br, zstd"
		out["x-anthropic-billing-header"] = fmt.Sprintf("cc_version=%s.000; cc_entrypoint=cli;", version)
		out["X-Stainless-Lang"] = "js"
		out["X-Stainless-Package-Version"] = "0.70.0"
		out["X-Stainless-OS"] = "Linux"
		out["X-Stainless-Arch"] = "arm64"
		out["X-Stainless-Runtime"] = "node"
		out["X-Stainless-Runtime-Version"] = "v24.13.0"
		out["X-Stainless-Retry-Count"] = "0"
		out["X-Stainless-Timeout"] = "600"
		// Use session_id from body metadata for consistency
		sessionID := extractSessionIDFromBody(bodyMap)
		if sessionID == "" {
			sessionID = generateSessionUUID()
		}
		out["X-Claude-Code-Session-Id"] = sessionID
	} else {
		// CC client mode: whitelist + rewrite. The client already sends correct
		// Claude CLI headers, just filter and normalize casing.
		allowedHeaders := map[string]bool{
			"accept": true, "user-agent": true, "content-type": true,
			"accept-encoding": true, "accept-language": true,
			"anthropic-beta": true, "anthropic-version": true,
			"anthropic-dangerous-direct-browser-access": true,
			"x-app": true, "sec-fetch-mode": true,
			"x-stainless-retry-count": true, "x-stainless-timeout": true,
			"x-stainless-lang": true, "x-stainless-package-version": true,
			"x-stainless-os": true, "x-stainless-arch": true,
			"x-stainless-runtime": true, "x-stainless-runtime-version": true,
			"x-stainless-helper-method": true,
			"x-claude-code-session-id": true, "x-client-request-id": true,
			"x-anthropic-billing-header": true,
		}

		for k, v := range headers {
			lower := strings.ToLower(k)
			if !allowedHeaders[lower] {
				continue
			}
			wireKey := resolveWireCasing(k)
			switch lower {
			case "user-agent":
				out[wireKey] = fmt.Sprintf("claude-code/%s (external, cli)", version)
			case "x-anthropic-billing-header":
				out[wireKey] = rewriteBillingHeader(v, version)
			default:
				out[wireKey] = v
			}
		}

		// Ensure OAuth-required headers are present
		if _, ok := out["anthropic-dangerous-direct-browser-access"]; !ok {
			out["anthropic-dangerous-direct-browser-access"] = "true"
		}
		// Merge client beta with required betas, model-aware
		out["anthropic-beta"] = mergeAnthropicBeta(betaHeaderForModel(modelID), out["anthropic-beta"])
	}

	return out
}

var ccVersionRegex = regexp.MustCompile(`cc_version=[\d.]+\.[a-f0-9]{3}`)

func rewriteBillingHeader(v, version string) string {
	return ccVersionRegex.ReplaceAllString(v, fmt.Sprintf("cc_version=%s.000", version))
}

// --- Body rewriting ---

// RewriteBody rewrites the request body based on endpoint and client type.
func (rw *Rewriter) RewriteBody(body []byte, path string, account *model.Account, clientType ClientType) []byte {
	if len(body) == 0 {
		return body
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body // not JSON, pass through
	}

	switch {
	case strings.HasPrefix(path, "/v1/messages"):
		stripEmptyTextBlocks(parsed)
		rw.rewriteMessages(parsed, account, clientType)
	case strings.Contains(path, "/event_logging/batch"):
		rw.rewriteEventBatch(parsed, account)
	default:
		rw.rewriteGenericIdentity(parsed, account)
	}

	out, err := json.Marshal(parsed)
	if err != nil {
		return body
	}
	return out
}

// rewriteMessages handles /v1/messages body.
func (rw *Rewriter) rewriteMessages(body map[string]any, account *model.Account, clientType ClientType) {
	env := rw.parseEnv(account)
	promptEnv := rw.parsePromptEnv(account)

	if clientType == ClientTypeClaudeCode {
		// Replace mode: rewrite existing metadata.user_id
		rw.rewriteMetadataUserID(body, account)
		// Rewrite system prompt <env> block
		rw.rewriteSystemPrompt(body, promptEnv, env.Version)
	} else {
		// Inject mode: transform pure API request to look exactly like Claude Code client.
		// OAuth tokens are scoped to Claude Code — requests must match CC format precisely.

		// 1. Inject metadata.user_id (CC always sends this)
		sessionID := rw.injectMetadataUserID(body, account)
		// Store sessionID for header consistency (caller retrieves via body)
		if sessionID != "" {
			if metadata, ok := body["metadata"].(map[string]any); ok {
				metadata["_session_id"] = sessionID
			}
		}

		// 2. Strip fields that Claude Code never sends
		delete(body, "temperature")
		delete(body, "top_k")
		delete(body, "top_p")
		delete(body, "stop_sequences")
		delete(body, "tool_choice")

		// 3. Ensure tools field exists (Claude Code always sends it, even empty)
		if _, ok := body["tools"]; !ok {
			body["tools"] = []any{}
		}

		// 4. Ensure stream is true (Claude Code always streams)
		body["stream"] = true

		// 5. Strip cache_control from system blocks (CC doesn't send this from API clients)
		stripCacheControl(body)

		// 6. Normalize max_tokens (CC uses specific values, not arbitrary large numbers)
		if maxTokens, ok := body["max_tokens"].(float64); ok && maxTokens > 32768 {
			body["max_tokens"] = float64(16384)
		}

		// 7. Inject Claude Code system prompt if not already present
		rw.injectSystemPrompt(body)
	}
}

// rewriteMetadataUserID replaces device_id in existing metadata.user_id (CC client mode).
func (rw *Rewriter) rewriteMetadataUserID(body map[string]any, account *model.Account) {
	metadata, ok := body["metadata"].(map[string]any)
	if !ok {
		return
	}
	userIDStr, ok := metadata["user_id"].(string)
	if !ok || userIDStr == "" {
		return
	}

	// Try JSON format
	var uid map[string]any
	if err := json.Unmarshal([]byte(userIDStr), &uid); err == nil {
		uid["device_id"] = account.DeviceID
		// Preserve account_uuid and session_id
		newBytes, _ := json.Marshal(uid)
		metadata["user_id"] = string(newBytes)
		return
	}

	// Legacy format: user_{device}_account_{uuid}_session_{uuid}
	// Replace device_id portion
	parts := strings.SplitN(userIDStr, "_account_", 2)
	if len(parts) == 2 {
		metadata["user_id"] = "user_" + account.DeviceID + "_account_" + parts[1]
	}
}

// injectMetadataUserID creates metadata.user_id for pure API calls.
// Returns the session_id used so it can be reused in the X-Claude-Code-Session-Id header.
func (rw *Rewriter) injectMetadataUserID(body map[string]any, account *model.Account) string {
	metadata, ok := body["metadata"].(map[string]any)
	if !ok {
		metadata = make(map[string]any)
		body["metadata"] = metadata
	}

	if _, exists := metadata["user_id"]; exists {
		// Already has user_id, rewrite it instead
		rw.rewriteMetadataUserID(body, account)
		return ""
	}

	sessionID := generateSessionUUID()
	// Derive account_uuid from account email via hashing (same approach as sub2api)
	accountUUID := deriveAccountUUID(account)
	uid := map[string]any{
		"device_id":    account.DeviceID,
		"account_uuid": accountUUID,
		"session_id":   sessionID,
	}
	uidBytes, _ := json.Marshal(uid)
	metadata["user_id"] = string(uidBytes)
	return sessionID
}

// deriveAccountUUID generates a stable UUID-like identifier from account info.
func deriveAccountUUID(account *model.Account) string {
	// Use email as seed if available, otherwise use account ID
	seed := account.Email
	if seed == "" {
		seed = fmt.Sprintf("account-%d", account.ID)
	}
	h := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// claudeCodeSystemPrompt is the canonical Claude Code banner.
// Must match real Claude CLI traffic exactly.
const claudeCodeSystemPrompt = "You are Claude Code, Anthropic's official CLI for Claude."

// injectSystemPrompt prepends the Claude Code system prompt to the body
// if it's not already present. For API mode (inject) only.
func (rw *Rewriter) injectSystemPrompt(body map[string]any) {
	// Check if system prompt already contains Claude Code banner
	switch sys := body["system"].(type) {
	case nil:
		// No system field — inject as a single text block with cache_control
		body["system"] = []any{
			map[string]any{
				"type": "text",
				"text": claudeCodeSystemPrompt,
				"cache_control": map[string]any{
					"type": "ephemeral",
				},
			},
		}
	case string:
		if strings.HasPrefix(sys, claudeCodeSystemPrompt) {
			return // already present
		}
		// Prepend banner to existing string, wrap in array format
		body["system"] = []any{
			map[string]any{
				"type": "text",
				"text": claudeCodeSystemPrompt,
				"cache_control": map[string]any{
					"type": "ephemeral",
				},
			},
			map[string]any{
				"type": "text",
				"text": sys,
			},
		}
	case []any:
		// Check if first block already has the banner
		if len(sys) > 0 {
			if block, ok := sys[0].(map[string]any); ok {
				if text, ok := block["text"].(string); ok && strings.HasPrefix(text, claudeCodeSystemPrompt) {
					return // already present
				}
			}
		}
		// Prepend banner block
		bannerBlock := map[string]any{
			"type": "text",
			"text": claudeCodeSystemPrompt,
			"cache_control": map[string]any{
				"type": "ephemeral",
			},
		}
		body["system"] = append([]any{bannerBlock}, sys...)
	}
}

// --- System prompt rewriting (CC client mode only) ---

var (
	platformRegex   = regexp.MustCompile(`Platform:\s*\S+`)
	shellRegex      = regexp.MustCompile(`Shell:\s*\S+`)
	osVersionRegex  = regexp.MustCompile(`OS Version:\s*[^\n<]+`)
	workingDirRegex = regexp.MustCompile(`((?:Primary )?[Ww]orking directory:\s*)/\S+`)
	homePathRegex   = regexp.MustCompile(`/(?:Users|home)/[^/\s]+/`)
	promptCCVersion = regexp.MustCompile(`cc_version=[\d.]+\.[a-f0-9]{3}`)
)

func (rw *Rewriter) rewriteSystemPrompt(body map[string]any, pe model.CanonicalPromptEnvData, version string) {
	if version == "" {
		version = defaultVersion
	}

	rewrite := func(text string) string {
		text = platformRegex.ReplaceAllString(text, "Platform: "+pe.Platform)
		text = shellRegex.ReplaceAllString(text, "Shell: "+pe.Shell)
		text = osVersionRegex.ReplaceAllString(text, "OS Version: "+pe.OSVersion)
		text = workingDirRegex.ReplaceAllString(text, "${1}"+pe.WorkingDir)
		homePrefix := pe.WorkingDir
		if idx := nthIndex(pe.WorkingDir, '/', 3); idx > 0 {
			homePrefix = pe.WorkingDir[:idx+1]
		}
		text = homePathRegex.ReplaceAllString(text, homePrefix)
		text = promptCCVersion.ReplaceAllString(text, fmt.Sprintf("cc_version=%s.000", version))
		return text
	}

	// Rewrite body.system (string or array of text blocks)
	switch sys := body["system"].(type) {
	case string:
		body["system"] = rewrite(sys)
	case []any:
		for _, item := range sys {
			if block, ok := item.(map[string]any); ok {
				if text, ok := block["text"].(string); ok {
					block["text"] = rewrite(text)
				}
			}
		}
	}

	// Rewrite messages that may contain <system-reminder> with env info
	if messages, ok := body["messages"].([]any); ok {
		for _, msg := range messages {
			if m, ok := msg.(map[string]any); ok {
				rw.rewriteMessageContent(m, rewrite)
			}
		}
	}
}

func (rw *Rewriter) rewriteMessageContent(msg map[string]any, rewriteFn func(string) string) {
	switch content := msg["content"].(type) {
	case string:
		msg["content"] = rewriteFn(content)
	case []any:
		for _, item := range content {
			if block, ok := item.(map[string]any); ok {
				if text, ok := block["text"].(string); ok {
					block["text"] = rewriteFn(text)
				}
			}
		}
	}
}

// --- Event logging batch rewriting ---

func (rw *Rewriter) rewriteEventBatch(body map[string]any, account *model.Account) {
	env := rw.parseEnv(account)
	proc := rw.parseProcess(account)

	events, ok := body["events"].([]any)
	if !ok {
		return
	}

	canonicalEnv := buildCanonicalEnvMap(env)

	for _, event := range events {
		e, ok := event.(map[string]any)
		if !ok {
			continue
		}

		// Replace identity fields
		if _, ok := e["device_id"]; ok {
			e["device_id"] = account.DeviceID
		}
		if _, ok := e["email"]; ok {
			e["email"] = account.Email
		}

		// Delete proxy traces
		delete(e, "baseUrl")
		delete(e, "base_url")
		delete(e, "gateway")

		// Replace env object entirely
		if _, ok := e["env"]; ok {
			e["env"] = canonicalEnv
		}

		// Replace process data
		if p, ok := e["process"]; ok {
			e["process"] = rw.rewriteProcess(p, proc)
		}

		// Rewrite additional_metadata (base64 encoded)
		if am, ok := e["additional_metadata"].(string); ok {
			e["additional_metadata"] = rewriteAdditionalMetadata(am)
		}
	}
}

func buildCanonicalEnvMap(env model.CanonicalEnvData) map[string]any {
	return map[string]any{
		"platform":                 env.Platform,
		"platform_raw":            env.PlatformRaw,
		"arch":                    env.Arch,
		"node_version":            env.NodeVersion,
		"terminal":                env.Terminal,
		"package_managers":        env.PackageManagers,
		"runtimes":                env.Runtimes,
		"is_running_with_bun":     false,
		"is_ci":                   false,
		"is_claubbit":             false,
		"is_claude_code_remote":   false,
		"is_local_agent_mode":     false,
		"is_conductor":            false,
		"is_github_action":        false,
		"is_claude_code_action":   false,
		"is_claude_ai_auth":       env.IsClaudeAIAuth,
		"version":                 env.Version,
		"version_base":            env.VersionBase,
		"build_time":              env.BuildTime,
		"deployment_environment":  env.DeploymentEnvironment,
		"vcs":                     env.VCS,
	}
}

// --- Process (hardware) fingerprint rewriting ---

func (rw *Rewriter) rewriteProcess(original any, proc model.CanonicalProcessData) any {
	// Process can be base64-encoded JSON string or object
	switch p := original.(type) {
	case string:
		decoded, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			return original
		}
		var obj map[string]any
		if err := json.Unmarshal(decoded, &obj); err != nil {
			return original
		}
		rewriteProcessFields(obj, proc)
		out, _ := json.Marshal(obj)
		return base64.StdEncoding.EncodeToString(out)
	case map[string]any:
		rewriteProcessFields(p, proc)
		return p
	default:
		return original
	}
}

func rewriteProcessFields(obj map[string]any, proc model.CanonicalProcessData) {
	obj["constrainedMemory"] = proc.ConstrainedMemory
	obj["rss"] = randomInRange(proc.RSSRange[0], proc.RSSRange[1])
	obj["heapTotal"] = randomInRange(proc.HeapTotalRange[0], proc.HeapTotalRange[1])
	obj["heapUsed"] = randomInRange(proc.HeapUsedRange[0], proc.HeapUsedRange[1])
}

// --- Generic identity rewriting (policy_limits, settings, etc.) ---

func (rw *Rewriter) rewriteGenericIdentity(body map[string]any, account *model.Account) {
	if _, ok := body["device_id"]; ok {
		body["device_id"] = account.DeviceID
	}
	if _, ok := body["email"]; ok {
		body["email"] = account.Email
	}
}

// --- Base64 additional_metadata rewriting ---

func rewriteAdditionalMetadata(encoded string) string {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return encoded
	}
	var obj map[string]any
	if err := json.Unmarshal(decoded, &obj); err != nil {
		return encoded
	}
	delete(obj, "baseUrl")
	delete(obj, "base_url")
	delete(obj, "gateway")
	out, _ := json.Marshal(obj)
	return base64.StdEncoding.EncodeToString(out)
}

// stripCacheControl removes cache_control from system and message content blocks.
// Claude Code clients manage caching server-side; pure API clients may send cache_control
// which is not expected by the CC OAuth endpoint.
func stripCacheControl(body map[string]any) {
	// Strip from system blocks
	if sys, ok := body["system"].([]any); ok {
		for _, item := range sys {
			if block, ok := item.(map[string]any); ok {
				delete(block, "cache_control")
			}
		}
	}
	// Strip from message content blocks
	if messages, ok := body["messages"].([]any); ok {
		for _, msg := range messages {
			if m, ok := msg.(map[string]any); ok {
				if content, ok := m["content"].([]any); ok {
					for _, item := range content {
						if block, ok := item.(map[string]any); ok {
							delete(block, "cache_control")
						}
					}
				}
			}
		}
	}
}

// --- Helpers ---

func (rw *Rewriter) parseEnv(account *model.Account) model.CanonicalEnvData {
	var env model.CanonicalEnvData
	_ = json.Unmarshal(account.CanonicalEnv, &env)
	return env
}

func (rw *Rewriter) parsePromptEnv(account *model.Account) model.CanonicalPromptEnvData {
	var pe model.CanonicalPromptEnvData
	_ = json.Unmarshal(account.CanonicalPrompt, &pe)
	return pe
}

func (rw *Rewriter) parseProcess(account *model.Account) model.CanonicalProcessData {
	var proc model.CanonicalProcessData
	_ = json.Unmarshal(account.CanonicalProcess, &proc)
	return proc
}

func randomInRange(min, max int64) int64 {
	if max <= min {
		return min
	}
	return min + mrand.Int64N(max-min)
}

// extractSessionIDFromBody retrieves the _session_id stashed during inject mode body rewrite.
// This ensures the X-Claude-Code-Session-Id header matches the session_id in metadata.user_id.
func extractSessionIDFromBody(body map[string]any) string {
	if metadata, ok := body["metadata"].(map[string]any); ok {
		if sid, ok := metadata["_session_id"].(string); ok {
			delete(metadata, "_session_id") // clean up internal marker
			return sid
		}
	}
	return ""
}

func generateSessionUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func nthIndex(s string, c byte, n int) int {
	count := 0
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			count++
			if count == n {
				return i
			}
		}
	}
	return -1
}

// stripEmptyTextBlocks removes empty text content blocks ({"type":"text","text":""})
// from messages and system to prevent upstream 400 errors.
func stripEmptyTextBlocks(body map[string]any) {
	var filterBlocks func([]any) []any
	filterBlocks = func(blocks []any) []any {
		result := make([]any, 0, len(blocks))
		for _, item := range blocks {
			block, ok := item.(map[string]any)
			if !ok {
				result = append(result, item)
				continue
			}
			if block["type"] == "text" {
				text, _ := block["text"].(string)
				if text == "" {
					continue // skip empty text block
				}
			}
			// Also check nested content in tool_result blocks
			if block["type"] == "tool_result" {
				if content, ok := block["content"].([]any); ok {
					block["content"] = filterBlocks(content)
				}
			}
			result = append(result, item)
		}
		return result
	}

	// Filter system blocks
	if sys, ok := body["system"].([]any); ok {
		body["system"] = filterBlocks(sys)
	}

	// Filter message content blocks
	if messages, ok := body["messages"].([]any); ok {
		for _, msg := range messages {
			m, ok := msg.(map[string]any)
			if !ok {
				continue
			}
			if content, ok := m["content"].([]any); ok {
				m["content"] = filterBlocks(content)
			}
		}
	}
}

// DetectClientType determines if request is from Claude Code or pure API.
func DetectClientType(userAgent string, body map[string]any) ClientType {
	if strings.HasPrefix(strings.ToLower(userAgent), "claude-cli/") {
		return ClientTypeClaudeCode
	}
	// Check for metadata.user_id presence (CC client marker)
	if metadata, ok := body["metadata"].(map[string]any); ok {
		if _, ok := metadata["user_id"]; ok {
			return ClientTypeClaudeCode
		}
	}
	return ClientTypeAPI
}

