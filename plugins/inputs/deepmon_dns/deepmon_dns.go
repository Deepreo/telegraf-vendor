package deepmon_dns

import (
	"crypto/tls"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Deepreo/MonitoringTime-Backend/pkg/monitors"
	"github.com/ResulCelik0/go-tld"
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
	client           *dns.Client
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
	dns.TypeDS,
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
	d.client = &dns.Client{
		Timeout:   time.Duration(d.Timeout),
		Net:       d.ResolverProtocol,
		TLSConfig: d.tlsConfig,
	}
	return nil
}
func (d *DeepmonDNS) senMessage(domain string, recordType uint16) (r *dns.Msg, rtt time.Duration, err error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), recordType)
	msg.SetEdns0(2048, true)
	return d.client.Exchange(msg, net.JoinHostPort(d.ResolverIP, strconv.Itoa(d.ResolverPort)))
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
	var suc, fail bool
	var totalRtt float64
	// DNSKEYs
	dnsKeys := make([]*dns.DNSKEY, 0)
	keyRRSIG := new(dns.RRSIG)
	keyRec, _, err := d.senMessage(d.Domain, dns.TypeDNSKEY)
	if err != nil {
		fields.Result = monitors.ConnectionFailed
		return
	}
	for idx := range keyRec.Answer {
		if keyRec.Answer[idx].Header().Rrtype == dns.TypeDNSKEY {
			dnsKeys = append(dnsKeys, keyRec.Answer[idx].(*dns.DNSKEY))
		} else if keyRec.Answer[idx].Header().Rrtype == dns.TypeRRSIG {
			keyRRSIG = keyRec.Answer[idx].(*dns.RRSIG)
			keyRec.Answer = slices.Delete(keyRec.Answer, idx, idx+1)
			break
		}
	}
	// ZSK Verify
	if len(dnsKeys) > 0 {
		if keyRRSIG != nil {
			for _, key := range dnsKeys {
				if key.Flags == 257 {
					if err := keyRRSIG.Verify(key, keyRec.Answer); err == nil {
						fields.ZSKVerified = true
					}
				}
			}
		}
	}

	// RR
	for _, recordType := range recordTypes {
		rec, rtt, err := d.senMessage(d.Domain, recordType)
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
		if len(rec.Answer) > 0 {
			if ksk, record := d.recordParser(rec, rtt, dnsKeys); record != nil {
				fields.KSKVerified = ksk
				fields.Records = append(fields.Records, record...)
			}
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

func (d *DeepmonDNS) verifyRRWithRRSIG(resp *dns.Msg, dnsKey []*dns.DNSKEY) bool {
	if len(dnsKey) == 0 {
		return false
	}
	rrsig := new(dns.RRSIG)
	for idx := range resp.Answer {
		if resp.Answer[idx].Header().Rrtype == dns.TypeRRSIG {
			rrsig = resp.Answer[idx].(*dns.RRSIG)
			resp.Answer = slices.Delete(resp.Answer, idx, idx+1)
			break
		}
	}
	// fmt.Println("RESP", resp.Answer)
	if rrsig == nil {
		return false
	}
	flag := false

	if rrsig.TypeCovered == dns.TypeDS {
		tl, err := tld.Parse(d.Domain)
		if err != nil {
			return false
		}
		r, _, err := d.senMessage(tl.Domain, dns.TypeDNSKEY)
		if err != nil {
			return false
		}
		for _, ans := range r.Answer {
			switch ans.Header().Rrtype {
			case dns.TypeDNSKEY:
				if err := rrsig.Verify(ans.(*dns.DNSKEY), r.Answer); err == nil {
					flag = true
					break
				}
			}
		}
		return flag
	}

	for _, zskKey := range dnsKey {
		// if zskKey.Flags == 257 && rrsig.TypeCovered != dns.TypeDS {
		// 	continue
		// }
		// if _, ok := resp.Answer[0].(*dns.SOA); ok {
		// 	if rrsig.KeyTag != dnsKey.KeyTag() {
		// 		fmt.Println("KEYTAG", rrsig.KeyTag, dnsKey.KeyTag())
		// 	} else if rrsig.Hdr.Class != dnsKey.Hdr.Class {
		// 		fmt.Println("CLASS", rrsig.Hdr.Class, dnsKey.Hdr.Class)
		// 	} else if rrsig.Algorithm != dnsKey.Algorithm {
		// 		fmt.Println("ALGO", rrsig.Algorithm, dnsKey.Algorithm)
		// 	} else if rrsig.SignerName != dnsKey.Hdr.Name {
		// 		fmt.Println("SIGNER", rrsig.SignerName, dnsKey.Hdr.Name)
		// 	} else if dnsKey.Protocol != 3 {
		// 		fmt.Println("PROTOCOL", dnsKey.Protocol)
		// 	}
		// }
		// if rrsig.TypeCovered == dns.TypeDS {
		// 	fmt.Println(zskKey.Flags)
		// }
		err := rrsig.Verify(zskKey, resp.Answer)
		// fmt.Println("ERR", err)
		if err == nil {
			flag = true
			break
		}
	}
	return flag
}

func verifyKSKKeys(dnsKeys []*dns.DNSKEY, ds *dns.DS) (KSKVerified bool) {
	kskKeys := make([]*dns.DNSKEY, 0)
	for _, key := range dnsKeys {
		if key.Flags == 257 {
			kskKeys = append(kskKeys, key)
			break
		}
	}
	KSKVerified = true
	for _, ksk := range kskKeys {
		if ksk.ToDS(ds.DigestType).Digest != ds.Digest {
			KSKVerified = false
			break
		}
	}
	return
}

func (d *DeepmonDNS) recordParser(resp *dns.Msg, rtt time.Duration, dnsKeys []*dns.DNSKEY) (KSKVerifed bool, result []monitors.DNSRecord) {
	verify := d.verifyRRWithRRSIG(resp, dnsKeys)
	for _, ans := range resp.Answer {
		var record = &monitors.DNSRecord{
			RCode:          dns.RcodeToString[resp.Rcode],
			RType:          dns.TypeToString[ans.Header().Rrtype],
			RTTL:           int(ans.Header().Ttl),
			ResponseTime:   rtt.String(),
			DNSSECVerified: verify,
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
		case dns.TypeDS:
			record.RData = strings.Replace(ans.(*dns.DS).String(), ans.Header().String(), "", 1)
			KSKVerifed = verifyKSKKeys(dnsKeys, ans.(*dns.DS))
		default:
			record = nil
		}

		if record != nil {
			result = append(result, *record)
		}
	}
	return
}

func init() {
	inputs.Add(pluginName, func() telegraf.Input {
		return &DeepmonDNS{}
	})
}
