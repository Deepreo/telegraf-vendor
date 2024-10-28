//go:generate ../../../tools/readme_config_includer/generator
package deepmon_cert

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Deepreo/MonitoringTime-Backend/pkg/monitors"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
)

type Tls struct {
	Domain string `toml:"domain"`
}

var pluginName = monitors.MonitorTypes_DEEPMON_TLS.String()

//go:embed sample.conf
var sampleConfig string

func (u *Tls) SampleConfig() string {
	return sampleConfig
}

func (u *Tls) Gather(acc telegraf.Accumulator) error {
	u.sendData(acc)
	return nil
}

func init() {
	inputs.Add(pluginName, func() telegraf.Input {
		return &Tls{}
	})
}

type TlsStats struct {
	Latency float64
	tls.ConnectionState
}

func (u *Tls) gotls() (*TlsStats, error) {
	us := &TlsStats{}
	start := time.Now()

	//url kontrolü yaparak başına http veya https ekler
	correctedUrl, err := u.checkProtocol()
	if err != nil {
		return nil, err
	}

	resp, err := http.Get(correctedUrl)
	// Measure TLS handshake time
	if err != nil {
		us.Latency = 0
		return us, err
	}
	defer resp.Body.Close()

	//return all data
	elapsed := time.Since(start) //zaman değerini int64 milisaniye olarak değiştirdim
	us.Latency = float64(elapsed) / float64(time.Millisecond)

	//TLS informations
	us.ConnectionState = *resp.TLS
	//fmt.Println(us.ConnectionState)

	return us, nil
}

func (u *Tls) sendData(acc telegraf.Accumulator) {
	fields := &monitors.TlsData{}
	tags := monitors.MonitorData[*monitors.TlsData]{
		Domain: u.Domain,
		Data:   fields,
	}
	stats, err := u.gotls()
	if err != nil {
		acc.AddFields(pluginName, tags.GetFields(), tags.GetTags())
		return
	}
	//PeerCertificates beginning
	cert := stats.PeerCertificates[0]

	fields.Subject = cert.Subject.String()
	fields.Issuer = cert.Issuer.String()
	fields.NotBefore = cert.NotBefore.Format(time.RFC3339)
	fields.NotAfter = cert.NotAfter.Format(time.RFC3339)
	fields.SerialNumber = cert.SerialNumber.Uint64()
	fields.SignatureAlgorithm = cert.SignatureAlgorithm.String()
	fields.PublicKeyAlgorithm = cert.PublicKeyAlgorithm.String()
	fields.Extensions = len(cert.Extensions)

	// Join DNS Names into a single string
	if len(cert.DNSNames) > 0 {
		dnsNames := strings.Join(cert.DNSNames, ", ")
		fields.DNSNames = dnsNames
	}

	// Join Email Addresses into a single string
	if len(cert.EmailAddresses) > 0 {
		emailAddresses := strings.Join(cert.EmailAddresses, ", ")
		fields.EmailAddresses = emailAddresses
	}

	// Join IP Addresses into a single string (convert each IP to string first)
	if len(cert.IPAddresses) > 0 {
		ipStrings := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ipStrings[i] = ip.String()
		}
		ipAddressString := strings.Join(ipStrings, ", ")
		fields.IPAddresses = ipAddressString
	}
	//PeerCertificates End

	//TLS dataları field'a buradan ekleniyor
	fields.Latency = stats.Latency
	fields.TLSVersion = stats.Version
	fields.HandshakeComplete = stats.HandshakeComplete
	fields.DidResume = stats.DidResume
	fields.CipherSuite = stats.CipherSuite
	fields.NegotiatedProtocol = stats.NegotiatedProtocol
	fields.NegotiatedProtocolIsMutual = stats.NegotiatedProtocolIsMutual
	fields.ServerName = stats.ServerName

	acc.AddFields(pluginName, tags.GetFields(), tags.GetTags())

}

func (u *Tls) checkProtocol() (string, error) {
	// Define the protocols to check in order
	protocols := []string{"http", "https"}

	// Iterate over each protocol
	for _, protocol := range protocols {
		// Build the full URL
		fullURL := protocol + "://" + u.Domain

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
	return "", fmt.Errorf("neither HTTPS nor HTTP is accessible for %s", u.Domain)
}
