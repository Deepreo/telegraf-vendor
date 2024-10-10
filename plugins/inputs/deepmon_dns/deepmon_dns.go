package deepmon_dns

import (
	"crypto/tls"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Deepreo/MonitoringTime-Backend/pkg/monitors"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/plugins/inputs"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

//go:embed sample.conf
var sampleConfig string

var pluginName = monitors.MonitorTypes_DEEPMON_DNS.String()

type DeepmonDNS struct {
	Domain           string          `toml:"domain"`
	ResolverIP       string          `toml:"resolver_ip"` //TODO: Burada birden fazla resolver olabilsin
	ResolverPort     int             `toml:"resolver_port"`
	ResolverProtocol string          `toml:"resolver_protocol"`
	Timeout          config.Duration `toml:"timeout"`
	tlsConfig        *tls.Config
}

var recordTypes []uint16 = []uint16{
	dns.TypeA,
	dns.TypeAAAA,
	dns.TypeCNAME,
	dns.TypeMX,
	dns.TypeNS,
	dns.TypePTR,
	dns.TypeSOA,
	dns.TypeTXT,
	dns.TypeSRV,
	dns.TypeSPF,
}

func (d *DeepmonDNS) SampleConfig() string {
	return sampleConfig
}

func (d *DeepmonDNS) Init() error {
	if _, err := idna.Lookup.ToASCII(d.Domain); err != nil || d.Domain == "" {
		return errors.New("domain is missing or invalid")
	}

	if net.ParseIP(d.ResolverIP) == nil {
		return errors.New("resolver_ip is missing or invalid")
	}

	if d.ResolverPort > 65535 || d.ResolverPort < 1 {
		return errors.New("resolver_port is missing or invalid")
	}
	if d.ResolverProtocol != "udp" && d.ResolverProtocol != "tcp" && d.ResolverProtocol != "tcp-tls" {
		d.ResolverProtocol = "udp"
	}

	if d.ResolverProtocol == "tcp-tls" {
		d.tlsConfig = &tls.Config{
			ServerName: d.ResolverIP,
		}
	}
	if d.Timeout == 0 {
		d.Timeout = config.Duration(2 * time.Second)
	}

	return nil
}

func (d *DeepmonDNS) Gather(acc telegraf.Accumulator) error {
	fields := &monitors.DNSData{}
	tags := monitors.MonitorData[*monitors.DNSData]{
		Domain: d.Domain,
		Data:   fields,
	}
	d.getQuery(fields)
	acc.AddFields(pluginName, tags.GetFields(), tags.GetTags())
	return nil
}

func (d *DeepmonDNS) getQuery(fields *monitors.DNSData) {
	dnsClient := dns.Client{
		Timeout:   time.Duration(d.Timeout),
		Net:       d.ResolverProtocol,
		TLSConfig: d.tlsConfig,
	}
	resolverAddr := net.JoinHostPort(d.ResolverIP, strconv.Itoa(d.ResolverPort))
	var suc, fail bool
	var totalRtt float64
	for _, recordType := range recordTypes {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(d.Domain), recordType)
		rec, rtt, err := dnsClient.Exchange(msg, resolverAddr)
		if err != nil {
			if netErr, ok := err.(*net.OpError); ok && netErr.Timeout() {
				fields.Result = monitors.Timeout
			} else {
				fields.Result = monitors.ConnectionFailed
			}
			fail = true
			continue
		}
		suc = true
		totalRtt += (float64(rtt.Milliseconds()))
		if record := recordParser(rec, rtt); record != nil {
			fields.Records = append(fields.Records, record...)
		}
	}
	if suc && fail {
		fields.Result = monitors.PartialFailure
	} else if suc {
		fields.Result = monitors.Success
	}
	fields.ResolverIP = d.ResolverIP
	fields.ResolverPort = strconv.Itoa(d.ResolverPort)
	fields.ResolverProtocol = d.ResolverProtocol
	fields.ResponseTime = strconv.FormatFloat(totalRtt, 'f', 0, 64)
	fields.ResolverName = getResolverName(d.ResolverIP)
	return

}

func getResolverName(resolverIP string) string {
	names, err := net.LookupAddr(resolverIP)
	if err != nil {
		return ""
	}
	return names[0]
}

func recordParser(resp *dns.Msg, rtt time.Duration) (result []monitors.DNSRecord) {
	for _, ans := range resp.Answer {
		var record = &monitors.DNSRecord{
			RCode:        dns.RcodeToString[resp.Rcode],
			RType:        dns.TypeToString[ans.Header().Rrtype],
			RTTL:         int(ans.Header().Ttl),
			ResponseTime: rtt.String(),
		}
		switch ans.Header().Rrtype {
		case dns.TypeA:
			record.RData = ans.(*dns.A).A.String()
		case dns.TypeAAAA:
			record.RData = ans.(*dns.AAAA).AAAA.String()
		case dns.TypeCNAME:
			record.RData = ans.(*dns.CNAME).Target
		case dns.TypeMX:
			record.RData = fmt.Sprintf("(%d) %s", ans.(*dns.MX).Preference, ans.(*dns.MX).Mx)
		case dns.TypeNS:
			record.RData = ans.(*dns.NS).Ns
		case dns.TypePTR:
			record.RData = ans.(*dns.PTR).Ptr
		case dns.TypeSOA:
			record.RData = strings.Replace(ans.(*dns.SOA).String(), ans.Header().String(), "", 1)
		case dns.TypeTXT:
			record.RData = strings.Replace(ans.(*dns.TXT).String(), ans.Header().String(), "", 1)
		case dns.TypeSRV:
			record.RData = strings.Replace(ans.(*dns.SRV).String(), ans.Header().String(), "", 1)
		case dns.TypeSPF:
			record.RData = strings.Replace(ans.(*dns.SPF).String(), ans.Header().String(), "", 1)
		default:
			record = nil
		}
		if record != nil {
			result = append(result, *record)
		}
	}
	return
}

func (d *DeepmonDNS) DNSSECValidation() {

}

func init() {
	inputs.Add(pluginName, func() telegraf.Input {
		return &DeepmonDNS{}
	})
}
