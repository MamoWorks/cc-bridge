package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"cc2api/internal/logger"
	"cc2api/internal/model"
	"cc2api/internal/tlsfp"
)

const upstreamBase = "https://api.anthropic.com"

type GatewayService struct {
	accountSvc *AccountService
	usageSvc   *UsageService
	rewriter   *Rewriter
}

func NewGatewayService(accountSvc *AccountService, usageSvc *UsageService) *GatewayService {
	return &GatewayService{
		accountSvc: accountSvc,
		usageSvc:   usageSvc,
		rewriter:   NewRewriter(),
	}
}

// HandleRequest is the core gateway logic.
func (s *GatewayService) HandleRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Read body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	// Parse body for routing decisions
	var bodyMap map[string]any
	if len(bodyBytes) > 0 {
		_ = json.Unmarshal(bodyBytes, &bodyMap)
	}
	if bodyMap == nil {
		bodyMap = make(map[string]any)
	}

	// Detect client type
	ua := r.Header.Get("User-Agent")
	clientType := DetectClientType(ua, bodyMap)

	// Generate session hash
	sessionHash := GenerateSessionHash(ua, bodyMap, clientType)

	// Select account
	account, err := s.accountSvc.SelectAccount(ctx, sessionHash, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("no available account: %v", err), http.StatusServiceUnavailable)
		return
	}

	// Acquire concurrency slot
	acquired, err := s.accountSvc.AcquireSlot(ctx, account.ID, account.Concurrency)
	if err != nil || !acquired {
		http.Error(w, "account concurrency limit reached", http.StatusTooManyRequests)
		return
	}
	defer s.accountSvc.ReleaseSlot(ctx, account.ID)

	// Rewrite body
	logger.Debug("request body BEFORE rewrite: %s", truncateBody(bodyBytes, 4096))
	rewrittenBody := s.rewriter.RewriteBody(bodyBytes, r.URL.Path, account, clientType)
	logger.Debug("request body AFTER rewrite: %s", truncateBody(rewrittenBody, 4096))

	// Re-parse rewritten body so headers can extract session_id for consistency
	var rewrittenBodyMap map[string]any
	if len(rewrittenBody) > 0 {
		_ = json.Unmarshal(rewrittenBody, &rewrittenBodyMap)
	}
	if rewrittenBodyMap == nil {
		rewrittenBodyMap = make(map[string]any)
	}

	// Rewrite headers
	modelID, _ := bodyMap["model"].(string)
	headers := extractHeaders(r)
	rewrittenHeaders := s.rewriter.RewriteHeaders(headers, account, clientType, modelID, rewrittenBodyMap)

	// Re-marshal body after header extraction (extractSessionIDFromBody cleans up _session_id)
	if clientType == ClientTypeAPI {
		if cleaned, err := json.Marshal(rewrittenBodyMap); err == nil {
			rewrittenBody = cleaned
		}
	}
	rewrittenHeaders["authorization"] = "Bearer " + account.Token

	// Forward to upstream
	startTime := time.Now()
	s.forwardRequest(ctx, w, r.Method, r.URL.Path, r.URL.RawQuery, rewrittenHeaders, rewrittenBody, account)

	// Record usage (extract from response is done in forwardRequest via tee)
	duration := time.Since(startTime)
	s.recordUsageFromBody(ctx, account, bodyMap, duration)
}

func (s *GatewayService) forwardRequest(ctx context.Context, w http.ResponseWriter, method, path, query string, headers map[string]string, body []byte, account *model.Account) {
	targetURL := upstreamBase + path
	if query != "" {
		if !strings.Contains(query, "beta=true") {
			query += "&beta=true"
		}
		targetURL += "?" + query
	} else {
		targetURL += "?beta=true"
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "failed to create upstream request", http.StatusInternalServerError)
		return
	}

	// Use direct map assignment to preserve header casing (e.g. "anthropic-beta" stays lowercase).
	// Go's Header.Set() canonicalizes to Title-Case which Anthropic may reject.
	for k, v := range headers {
		req.Header[k] = []string{v}
	}
	req.Header["Host"] = []string{"api.anthropic.com"}

	// Debug: log all outgoing headers and URL
	logger.Debug("upstream URL: %s", targetURL)
	for k, vs := range req.Header {
		for _, v := range vs {
			logger.Debug("upstream header: %s: %s", k, v)
		}
	}

	client := s.proxyClient(account.ProxyURL)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[gateway] upstream error for account %d: %v", account.ID, err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	logger.Debug("upstream response: %d %s", resp.StatusCode, resp.Status)
	for k, vs := range resp.Header {
		logger.Debug("upstream resp header: %s: %s", k, strings.Join(vs, ", "))
	}

	// Log error response bodies for debugging (peek at body for non-streaming errors)
	if resp.StatusCode >= 400 {
		peekBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		logger.Warn("upstream %d for account %d, path=%s body=%s", resp.StatusCode, account.ID, path, string(peekBody))
		// Reconstruct body so it can still be streamed to client
		resp.Body = io.NopCloser(io.MultiReader(strings.NewReader(string(peekBody)), resp.Body))
	}

	// Handle rate limit: only mark account as rate limited when upstream provides
	// an explicit reset time. Transient 429s (no reset headers) are passed through
	// without marking the account, matching sub2api behavior.
	if resp.StatusCode == 429 {
		retryAfter := resp.Header.Get("Retry-After")
		rateLimitReset := resp.Header.Get("anthropic-ratelimit-requests-reset")
		if rateLimitReset == "" {
			rateLimitReset = resp.Header.Get("anthropic-ratelimit-tokens-reset")
		}

		if retryAfter != "" {
			if d, err := time.ParseDuration(retryAfter + "s"); err == nil {
				resetAt := time.Now().Add(d)
				_ = s.accountSvc.SetRateLimit(ctx, account.ID, resetAt)
				log.Printf("[gateway] account %d rate limited until %s (Retry-After)", account.ID, resetAt.Format(time.RFC3339))
			}
		} else if rateLimitReset != "" {
			if resetAt, err := time.Parse(time.RFC3339, rateLimitReset); err == nil {
				_ = s.accountSvc.SetRateLimit(ctx, account.ID, resetAt)
				log.Printf("[gateway] account %d rate limited until %s (anthropic-ratelimit)", account.ID, resetAt.Format(time.RFC3339))
			}
		} else {
			// No reset time — likely transient overload, do NOT mark account as rate limited
			log.Printf("[gateway] account %d got 429 without reset headers, not marking rate limited", account.ID)
		}
	}

	// Copy response headers
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream response body
	flusher, canFlush := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			if canFlush {
				flusher.Flush()
			}
		}
		if err != nil {
			break
		}
	}
}

func (s *GatewayService) recordUsageFromBody(ctx context.Context, account *model.Account, body map[string]any, duration time.Duration) {
	modelName, _ := body["model"].(string)
	s.usageSvc.Record(ctx, &model.UsageLog{
		AccountID:  account.ID,
		Model:      modelName,
		DurationMS: int(duration.Milliseconds()),
		// Token counts will be extracted from SSE response in a future improvement
	})
}

func truncateBody(b []byte, max int) string {
	if len(b) > max {
		return string(b[:max]) + "...(truncated)"
	}
	return string(b)
}

func (s *GatewayService) proxyClient(proxyURL string) *http.Client {
	return &http.Client{
		Transport: tlsfp.NewTransport(proxyURL),
		Timeout:   5 * time.Minute,
	}
}

func extractHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string, len(r.Header))
	for k, vs := range r.Header {
		if len(vs) > 0 {
			headers[k] = strings.Join(vs, ", ")
		}
	}
	return headers
}
