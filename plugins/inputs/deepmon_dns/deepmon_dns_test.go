package deepmon_dns

import (
	"testing"
	"time"

	"github.com/Deepreo/MonitoringTime-Backend/pkg/monitors"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/testutil"
	"github.com/stretchr/testify/require"
)

func TestDoT(t *testing.T) {
	// Init plugin
	var acc testutil.Accumulator
	c := DeepmonDNS{
		ResolverProtocol: "tcp-tls",
		ResolverIP:       "8.8.8.8",
		ResolverPort:     853,
		Domain:           "example.com",
		Timeout:          config.Duration(2 * time.Second),
	}

	require.NoError(t, c.Init())
	require.NoError(t, c.Gather(&acc))
	//override the response time
	data := getMockData(&acc, monitors.Success, "dns.google.", "8.8.8.8", "853", "tcp-tls")
	acc.AssertContainsTaggedFields(t, pluginName, data.GetFields(), data.GetTags())
}

func TestDoUdp(t *testing.T) {
	// Init plugin
	var acc testutil.Accumulator
	c := DeepmonDNS{
		ResolverProtocol: "udp",
		ResolverIP:       "8.8.8.8",
		ResolverPort:     53,
		Domain:           "example.com",
		Timeout:          config.Duration(2 * time.Second),
	}
	require.NoError(t, c.Init())
	require.NoError(t, c.Gather(&acc))
	//override the response time
	data := getMockData(&acc, monitors.Success, "dns.google.", "8.8.8.8", "53", "udp")
	acc.AssertContainsTaggedFields(t, pluginName, data.GetFields(), data.GetTags())
}

func TestGatherInvalidDomain(t *testing.T) {
	// Init plugin
	var acc testutil.Accumulator
	c := DeepmonDNS{
		ResolverProtocol: "udp",
		ResolverIP:       "8.8.8.8",
		ResolverPort:     53,
		Domain:           "qwerty1234.example.com",
		Timeout:          config.Duration(1 * time.Second),
	}
	require.NoError(t, c.Init())
	require.NoError(t, c.Gather(&acc))
	require.Empty(t, acc.Errors)
}

func TestGatherInvalidResolverIP(t *testing.T) {
	c := DeepmonDNS{
		ResolverProtocol: "udp",
		ResolverIP:       "qwerty1234.example.com",
		ResolverPort:     53,
		Domain:           "example.com",
		Timeout:          config.Duration(1 * time.Second),
	}
	require.EqualError(t, c.Init(), "resolver_ip is missing or invalid")
}

func TestGatherInvalidResolverPort(t *testing.T) {
	c := DeepmonDNS{
		ResolverProtocol: "udp",
		ResolverIP:       "8.8.8.8",
		ResolverPort:     65536,
		Domain:           "example.com",
		Timeout:          config.Duration(1 * time.Second),
	}
	require.EqualError(t, c.Init(), "resolver_port is missing or invalid")
}

func TestGatherInvalidResolverProtocol(t *testing.T) {
	c := DeepmonDNS{
		ResolverProtocol: "invalid",
		ResolverIP:       "8.8.8.8",
		ResolverPort:     53,
		Domain:           "example.com",
		Timeout:          config.Duration(1 * time.Second),
	}
	require.NoError(t, c.Init())
}

func getMockData(acc *testutil.Accumulator, result monitors.Result, res_name, res_ip, res_port, res_protocol string) (data monitors.MonitorData[*monitors.DNSData]) {
	data = monitors.MonitorData[*monitors.DNSData]{
		Domain: "example.com",
		Data: &monitors.DNSData{
			Result:           monitors.Success,
			ResolverName:     res_name,
			ResolverIP:       res_ip,
			ResolverPort:     res_port,
			ResolverProtocol: res_protocol,
			ResponseTime:     "1ms",
			Records: []monitors.DNSRecord{
				{
					RCode:        "NOERROR",
					RType:        "A",
					ResponseTime: "1ms",
					RTTL:         1,
					RData:        "data",
				},
				{
					RCode:        "NOERROR",
					RType:        "AAAA",
					ResponseTime: "1ms",
					RTTL:         1,
					RData:        "data",
				},
				{
					RCode:        "NOERROR",
					RType:        "MX",
					ResponseTime: "1ms",
					RTTL:         1,
					RData:        "data",
				},
				{
					RCode:        "NOERROR",
					RType:        "NS",
					ResponseTime: "1ms",
					RTTL:         1,
					RData:        "data",
				},
				{
					RCode:        "NOERROR",
					RType:        "NS",
					ResponseTime: "1ms",
					RTTL:         1,
					RData:        "data",
				},
				{
					RCode:        "NOERROR",
					RType:        "SOA",
					ResponseTime: "1ms",
					RTTL:         1,
					RData:        "data",
				},
				{
					RCode:        "NOERROR",
					RType:        "TXT",
					ResponseTime: "1ms",
					RTTL:         1,
					RData:        "data",
				},
				{
					RCode:        "NOERROR",
					RType:        "TXT",
					ResponseTime: "1ms",
					RTTL:         1,
					RData:        "data",
				},
			},
		},
	}
	for _, p := range acc.Metrics {
		p.Fields["response_time"] = "1ms"
		for idx, _ := range p.Fields["records"].([]monitors.DNSRecord) {
			p.Fields["records"].([]monitors.DNSRecord)[idx].ResponseTime = "1ms"
			p.Fields["records"].([]monitors.DNSRecord)[idx].RTTL = 1
			p.Fields["records"].([]monitors.DNSRecord)[idx].RData = "data"
		}
	}
	return
}
