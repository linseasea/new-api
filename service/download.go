package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/system_setting"
)

// WorkerRequest Worker请求的数据结构
type WorkerRequest struct {
	URL     string            `json:"url"`
	Key     string            `json:"key"`
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    json.RawMessage   `json:"body,omitempty"`
	// FollowRedirects instructs the worker to follow HTTP redirects itself.
	// It must stay false (default) so the worker returns each 3xx response and
	// the gateway re-validates every redirect target with its SSRF policy.
	// The official worker must be updated to honor this field and use
	// `redirect: 'manual'` when it is false.
	FollowRedirects bool `json:"follow_redirects"`
}

// DoWorkerRequest 通过Worker发送请求
func DoWorkerRequest(req *WorkerRequest) (*http.Response, error) {
	if !system_setting.EnableWorker() {
		return nil, fmt.Errorf("worker not enabled")
	}
	if !system_setting.WorkerAllowHttpImageRequestEnabled && !strings.HasPrefix(req.URL, "https") {
		return nil, fmt.Errorf("only support https url")
	}

	workerUrl := system_setting.WorkerUrl
	if !strings.HasSuffix(workerUrl, "/") {
		workerUrl += "/"
	}

	validateURL := func() error {
		// SSRF防护：每个重定向跳点都做一次URL校验
		fetchSetting := system_setting.GetFetchSetting()
		return common.ValidateURLWithFetchSetting(req.URL, fetchSetting.EnableSSRFProtection, fetchSetting.AllowPrivateIp, fetchSetting.DomainFilterMode, fetchSetting.IpFilterMode, fetchSetting.DomainList, fetchSetting.IpList, fetchSetting.AllowedPorts, fetchSetting.ApplyIPFilterForDomain)
	}

	// 显式要求 worker 自行跟随重定向：仅做初始 URL 校验，一次性直传（操作者须信任其 worker）。
	if req.FollowRedirects {
		if err := validateURL(); err != nil {
			return nil, fmt.Errorf("request reject: %v", err)
		}
		workerPayload, err := common.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal worker payload: %v", err)
		}
		return GetHttpClient().Post(workerUrl, "application/json", bytes.NewBuffer(workerPayload))
	}

	// 默认（推荐）：worker 返回每个 3xx（redirect: manual），网关逐跳校验后重新派发，
	// 使重定向目标同样经过 SSRF 策略，等价于直连模式的逐跳防护。
	for hop := 0; hop < maxWorkerRedirectHops; hop++ {
		if err := validateURL(); err != nil {
			return nil, fmt.Errorf("request reject: %v", err)
		}
		workerPayload, err := common.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal worker payload: %v", err)
		}
		resp, err := GetHttpClient().Post(workerUrl, "application/json", bytes.NewBuffer(workerPayload))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 300 || resp.StatusCode > 399 {
			return resp, nil
		}
		nextURL, err := resp.Location()
		resp.Body.Close()
		if err != nil || nextURL == nil {
			return nil, fmt.Errorf("worker returned invalid redirect")
		}
		req.URL = nextURL.String()
	}
	return nil, fmt.Errorf("too many redirects while fetching via worker")
}

const maxWorkerRedirectHops = 10

func DoDownloadRequest(originUrl string, reason ...string) (resp *http.Response, err error) {
	if system_setting.EnableWorker() {
		common.SysLog(fmt.Sprintf("downloading file from worker: %s, reason: %s", originUrl, strings.Join(reason, ", ")))
		req := &WorkerRequest{
			URL: originUrl,
			Key: system_setting.WorkerValidKey,
		}
		return DoWorkerRequest(req)
	} else {
		// SSRF防护：验证请求URL（非Worker模式）
		if err := ValidateSSRFProtectedFetchURL(originUrl); err != nil {
			return nil, fmt.Errorf("request reject: %v", err)
		}

		common.SysLog(fmt.Sprintf("downloading from origin: %s, reason: %s", common.MaskSensitiveInfo(originUrl), strings.Join(reason, ", ")))
		return GetSSRFProtectedHTTPClient().Get(originUrl)
	}
}
