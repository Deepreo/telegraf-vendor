//go:generate ../../../tools/readme_config_includer/generator
package deepmon_uptime

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Deepreo/MonitoringTime-Backend/pkg/monitors"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/internal/choice"
	"github.com/influxdata/telegraf/plugins/inputs"
	"golang.org/x/net/idna"
)

// TODO: Testler ve Auth metotların eklenmesi gerekiyor (Basic, Bearer, JWT, OAuth2)
type Uptime struct {
	URL         string              `toml:"url"`
	Method      string              `toml:"method"`
	Cookies     []map[string]string `toml:"cookies"`
	Headers     []map[string]string `toml:"headers"`
	Queries     url.Values          `toml:"queries"`
	UserAgent   string              `toml:"user_agent"`
	ContentType string              `toml:"content_type"`
	Body        string              `toml:"body"`
	Timeout     config.Duration     `toml:"timeout"`
}

const (
	CONTENT_TYPE_JSON string = "application/json"
	CONTENT_TYPE_XML  string = "application/xml"
	CONTENT_TYPE_Form string = "application/x-www-form-urlencoded"
	CONTENT_TYPE_Text string = "text/plain"
	// CONTENT_TYPE_HTML string = "text/html"
	CONTENT_TYPE_None string = ""
)

var types = []string{
	CONTENT_TYPE_JSON,
	CONTENT_TYPE_XML,
	CONTENT_TYPE_Form,
	CONTENT_TYPE_Text,
	// CONTENT_TYPE_HTML,
	CONTENT_TYPE_None,
}

var methods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
}

//go:embed sample.conf
var sampleConfig string

var pluginName = monitors.MonitorTypes_DEEPMON_UPTIME.String()

func (u *Uptime) SampleConfig() string {
	return sampleConfig
}

func (u *Uptime) Init() error {
	if u.URL == "" {
		return fmt.Errorf("url is missing")
	}
	parsedURL, err := url.Parse(u.URL)
	if err != nil {
		return err
	}
	// Http or Https
	if parsedURL.Scheme == "" {
		return fmt.Errorf("protocol is missing")
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("invalid protocol: %s", parsedURL.Scheme)
	}
	// Domain
	if parsedURL.Hostname() == "" {
		return fmt.Errorf("domain is missing")
	}
	// Burada domain parse edilmiyor bunu düzelt
	// dp, err := tld.Parse(parsedURL.Hostname())
	// if err != nil {
	// 	return err
	// }
	// fmt.Println(dp.Path)
	// if dp.Domain == "" {
	// 	return fmt.Errorf("invalid domain: %s", parsedURL.Host)
	// }
	// Check if the domain is valid
	if _, err := idna.Lookup.ToASCII(parsedURL.Hostname()); err != nil {
		return fmt.Errorf("invalid domain: %s", parsedURL.Host)
	}

	if u.Method == "" {
		u.Method = http.MethodHead
	}
	if err := choice.Check(u.Method, methods); err != nil {
		return err
	}
	if err := choice.Check(u.ContentType, types); err != nil {
		return err
	}
	if len(u.Queries) == 0 {
		u.Queries = parsedURL.Query()
	}
	if u.UserAgent == "" {
		u.UserAgent = "Telegraf"
	}
	if u.Timeout == 0 {
		u.Timeout = config.Duration(5 * time.Second)
	}
	return nil
}

func (u *Uptime) Gather(acc telegraf.Accumulator) error {
	u.sendData(acc)
	return nil
}

func init() {
	inputs.Add(pluginName, func() telegraf.Input {
		return &Uptime{}
	})
}

type uptimeStats struct {
	Latency        float64
	StatusCode     int
	ResponseHeader string
	ResponseBody   string
	ContentLength  int64
	ReqMethod      string
	ReqHost        string
	Protocol       string
}

// If parameter is Get, run this function ???
func (u *Uptime) gohttp() (*uptimeStats, error) {
	us := &uptimeStats{}
	start := time.Now()

	//url kontrolü yaparak başına http veya https ekler
	correctedUrl, err := u.checkProtocol()
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: time.Duration(u.Timeout),
	}
	//http.NewRequest() kullanılacak
	req, err := http.NewRequest(u.Method, correctedUrl, bytes.NewBuffer([]byte(u.Body))) //Body de opsiyonel eğer set edilmişse eklensin
	if err != nil {
		us.Latency = 0
		return us, err
	}
	//Add Cookies
	if len(u.Cookies) > 0 {
		for _, cookie := range u.Cookies {
			for key, value := range cookie {
				req.AddCookie(&http.Cookie{Name: key, Value: value})
			}
		}
	}
	// Add Headers
	if len(u.Headers) > 0 {
		for _, header := range u.Headers {
			for key, value := range header {
				req.Header.Add(key, value)
			}
		}
	}
	// Add Params
	req.URL.RawQuery = u.Queries.Encode()
	// if len(u.Params) > 0 {
	// 	q := req.URL.Query()
	// 	for _, param := range u.Params {
	// 		for key, value := range param {
	// 			q.Add(key, value)
	// 		}
	// 	}
	// 	req.URL.RawQuery = q.Encode()
	// }
	// Add User-Agent
	if u.UserAgent != "" {
		req.Header.Add("User-Agent", u.UserAgent)
	}

	// Set Content-Type
	if u.ContentType != "" {
		req.Header.Add("Content-Type", u.ContentType)
	}

	//Request Datas
	us.ReqMethod = req.Method
	us.ReqHost = req.Host

	// Send the request

	resp, err := client.Do(req)
	if err != nil {
		return us, err
	}
	defer resp.Body.Close()

	// Convert the response headers to a string
	var headersString strings.Builder
	for key, values := range resp.Header {
		for _, value := range values {
			headersString.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}
	us.ResponseHeader = headersString.String()

	//Response Datas
	us.Latency = float64(time.Since(start).Seconds())
	us.StatusCode = resp.StatusCode
	us.ContentLength = resp.ContentLength
	us.Protocol = resp.Proto

	// Read and return the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return us, err
	}

	us.ResponseBody = string(respBody)

	return us, nil
}

func (u *Uptime) sendData(acc telegraf.Accumulator) {
	fields := &monitors.UptimeData{}
	fields.Access = monitors.StatusFailed
	tags := monitors.MonitorData[*monitors.UptimeData]{
		Domain: u.URL,
		Data:   fields,
	}
	stats, err := u.gohttp()
	if err != nil {
		if netErr, ok := err.(*net.OpError); ok && netErr.Timeout() {
			fields.Result = monitors.Timeout //Buraya io error da gelecek
		} else {
			fields.Result = monitors.ConnectionFailed
		}
		acc.AddFields(pluginName, tags.GetFields(), tags.GetTags())
		return
	}

	//resp dataları field'a buradan ekleniyor
	fields.Result = monitors.Success
	fields.Access = monitors.StatusSuccess
	fields.Latency = stats.Latency
	fields.StatusCode = stats.StatusCode
	fields.ResponseHeader = stats.ResponseHeader
	fields.ResponseBody = stats.ResponseBody
	fields.ContentLength = stats.ContentLength
	fields.ReqMethod = stats.ReqMethod
	fields.ReqHost = stats.ReqHost //If empty, the Request.Write method uses the value of URL.Host.
	fields.Protocol = stats.Protocol

	acc.AddFields(pluginName, tags.GetFields(), tags.GetTags())

}

func (u *Uptime) checkProtocol() (string, error) {
	// Define the protocols to check in order
	protocols := []string{"http", "https"}

	// Iterate over each protocol
	for _, protocol := range protocols {
		// Build the full URL
		fullURL := protocol + "://" + u.URL

		// Send the request
		client := &http.Client{
			Timeout: 5 * time.Second, // Set a timeout to avoid hanging
		}
		resp, err := client.Get(fullURL)
		if err != nil {
			continue // If there's an error, try the next protocol
		}

		// Close the response body
		defer resp.Body.Close()

		// Check the status code
		if resp.StatusCode == http.StatusOK {
			return fullURL, nil // Return the URL if accessible
		}
	}

	// If neither HTTPS nor HTTP is accessible, return an error
	return "", fmt.Errorf("neither HTTPS nor HTTP is accessible for %s", u.URL)
}
