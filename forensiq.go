package forensiq

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/rs/xlog"
	"github.com/rs/xstats"

	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"
)

type (
	// Forensiq represents a forensiq API client.
	Forensiq struct {
		// ClientKey is an authentication key for each client’s account provided by
		// Forensiq. Required.
		ClientKey string
		// Host is the host where the Forensiq API is available at.
		Host string

		httpClient *http.Client
	}

	// CheckRequest represents a request to the Forensiq API
	CheckRequest struct {
		// IP is the visitor’s IP address. Required.
		IP net.IP
		// RequestType based on where the call is performed. Possible values are
		// click or display. Required
		RequestType string
		// URL is the URL  where the ad is placed. Optional
		URL string
		// SellerID is the ID you assign to your traffic sources/publishers.
		// Required
		SellerID string
		// SubID is the sub source or placement ID. Optional
		SubID string
		// Campaign is the campaign or creative ID. Optional
		Campaign string
		// UserAgent is user-agent string captured from the http headers passed by
		// the browser. Optional
		UserAgent string
		// CookieID is the id representing the user of the request.
		CookieID string
	}

	// CheckResponse is returned by Forensiq API.
	CheckResponse struct {
		// RiskScore represents the likelihood that an impression is fraudulent.
		RiskScore int `json:"riskScore"`
		// SellerDomain represents the ratio of impressions with riskScore of 65 or
		// above for a specified seller-domain combination.
		SellerDomain int `json:"sellerDomain"`
		// DomainViewed represents the ratio of ads viewed grouped by domain,
		// ranging from 0 (no ads viewed) to 100 (all ads viewed).
		DomainViewed int `json:"domainViewed"`
		// DomainHidden represents the ratio of ads likely hidden grouped by
		// domain, ranging from 0 (no ads hidden) to 100 (all ads hidden).
		DomainHidden int `json:"domainHidden"`
		// SellerViewed represents the ratio of ads viewed grouped by seller,
		// ranging from 0 (no ads viewed) to 100 (all ads viewed).
		SellerViewed int `json:"sellerViewed"`
		// SellerHidden represents the ratio of ads likely hidden grouped by
		// seller, ranging from 0 (no ads hidden) to 100 (all ads hidden).
		SellerHidden int `json:"sellerHidden"`
		// IPReputation is true if Forensiq have flagged high-risk activity from
		// the IP in the past (e.g. User Agent spoofing, IP manipulation etc.).
		IPReputation bool `json:"ipr"`
		// Proxy is true if IP is a proxy.
		Proxy bool `json:"pxy"`
		// AutomatedTraffic is true if malicious botnet and other types of
		// automated activity identified through real-time traffic pattern
		// analysis.
		AutomatedTraffic bool `json:"atf"`
		// HostingProvider Use of an ISP, which Forensiq recognized as a
		// hosting provider. Servers in hosting providers are used to send spam,
		// host malware, botnet controllers, or engage in other suspect activities.
		HostingProvider bool `json:"hst"`
		// Spoofed is true if Forensiq see patterns of spoofing within the user’s
		// device. This characteristic is limited to analyzing the user agent of
		// the user within the pre-bid environment.
		Spoofed int
		// NonSuspect is true if the client is not suspected of being a bot
		NonSuspect bool `json:"nonSuspect"`
		// TimeMS represents the time it took for the request to complete in
		// Millisecond.
		TimeMS int `json:"timeMs"`
	}
)

var (
	// ErrInvalidClientKey is returned when the client key was not accepted by forensiq
	ErrInvalidClientKey = errors.New("the client key was not accepted by forensiq")
)

// New returns a new Forensiq initialized with given host and clientKey and use
// http.DefaultClient as the HTTP client.
func New(host, clientKey string) *Forensiq {
	return &Forensiq{
		Host:       host,
		ClientKey:  clientKey,
		httpClient: http.DefaultClient,
	}
}

// SetHTTPClient sets a custom HTTP Client to use when sending requests to
// forensiq. By default http.DefaultClient is used.
func (f *Forensiq) SetHTTPClient(hc *http.Client) {
	f.httpClient = hc
}

// Check get the riskScore and aggregate characteristics.
func (f *Forensiq) Check(ctx context.Context, creq CheckRequest) (CheckResponse, error) {
	var (
		uri   *url.URL
		cresp CheckResponse
		err   error
		log   = xlog.FromContext(ctx)
		sts   = xstats.FromContext(ctx)
	)

	var req *http.Request
	{
		uri, err = url.Parse(f.Host)
		if err != nil {
			log.Errorf("error parsing the URL: %s%v", err, xlog.F{"host": f.Host})
			return CheckResponse{}, err
		}
		uri.Path = "/check"
		v := creq.toValues()
		v.Set("ck", f.ClientKey)
		v.Set("output", "JSON")
		uri.RawQuery = v.Encode()
		req, err = http.NewRequest("GET", uri.String(), nil)
		if err != nil {
			return CheckResponse{}, err
		}
		req.Header.Set("Content-Type", "application/json")
	}

	{
		begin := time.Now()
		resp, err := ctxhttp.Do(ctx, f.httpClient, req)
		if err != nil {
			return CheckResponse{}, err
		}
		defer resp.Body.Close()
		sts.Timing("forensiq.request_time", time.Since(begin),
			"request:check",
			"status:"+responseStatus(ctx, resp.StatusCode),
			"status_code:"+strconv.Itoa(resp.StatusCode),
		)
		if resp.StatusCode == http.StatusForbidden {
			log.Errorf("client key is invalid%v", xlog.F{"client_key": f.ClientKey})
			return CheckResponse{}, ErrInvalidClientKey
		}
		if err := json.NewDecoder(resp.Body).Decode(&cresp); err != nil {
			return CheckResponse{}, err
		}
	}

	return cresp, nil
}

// Ready returns true if the API is ready
func (f *Forensiq) Ready(ctx context.Context) (bool, error) {
	var (
		uri *url.URL
		b   []byte
		err error
		sts = xstats.FromContext(ctx)
	)

	{
		uri, err = url.Parse(f.Host)
		if err != nil {
			return false, err
		}
		uri.Path = "/ready"
	}

	{
		begin := time.Now()
		resp, err := ctxhttp.Get(ctx, f.httpClient, uri.String())
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		sts.Timing("forensiq.request_time", time.Since(begin),
			"request:ready",
			"status:"+responseStatus(ctx, resp.StatusCode),
			"status_code:"+strconv.Itoa(resp.StatusCode),
		)

		b, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}
	}

	return string(b) == "1", nil
}

func (cr CheckRequest) toValues() url.Values {
	v := url.Values{}
	v.Set("ip", cr.IP.String())
	v.Set("rt", cr.RequestType)
	v.Set("url", cr.URL)
	v.Set("seller", cr.SellerID)
	v.Set("sub", cr.SubID)
	v.Set("cmp", cr.Campaign)
	v.Set("ua", cr.UserAgent)
	v.Set("id", cr.CookieID)

	return v
}

func responseStatus(ctx context.Context, statusCode int) string {
	if ctx.Err() != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "timeout"
		}
		return "canceled"
	} else if statusCode >= 200 && statusCode < 400 {
		return "ok"
	}
	return "error"
}
