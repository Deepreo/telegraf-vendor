//go:generate ../../../tools/readme_config_includer/generator
package deepmon_ping

import (
	_ "embed"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Deepreo/MonitoringTime-Backend/pkg/monitors"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
	ping "github.com/prometheus-community/pro-bing"
	"golang.org/x/net/idna"
)

//go:embed sample.conf
var sampleConfig string

// Burayı bi elden geçireceğim çünkü domain paketindeki MonitorData struct'ı ile uyumlu olacak şekilde değiştirmem gerekiyor.
type MontimePinger struct {
	// domainm is the address to ping
	Domain string `toml:"domain"`
	Count  int    `toml:"count"`
	// Timeout is the maximum amount of time a ping will wait for a response.
	Timeout int `toml:"timeout"`
	// Size is the number of bytes to send in the ICMP packet.
	Size int `toml:"packet_size"`
}

const defaultCount = 3
const defaultSize = 24

func (p *MontimePinger) Init() error {
	if _, err := idna.Lookup.ToASCII(p.Domain); err != nil || p.Domain == "" {
		return errors.New("domain is missing or invalid")
	}
	if p.Count == 0 {
		p.Count = defaultCount
	}
	if p.Size == 0 {
		p.Size = defaultSize
	}
	if p.Timeout == 0 {
		p.Timeout = 1
	}
	return nil
}

var pluginName = monitors.MonitorTypes_DEEPMON_PING.String()

func (p *MontimePinger) SampleConfig() string {
	return sampleConfig

}

func (p *MontimePinger) Gather(acc telegraf.Accumulator) error {
	p.sendData(acc)
	return nil
}

func init() {
	inputs.Add(pluginName, func() telegraf.Input {
		return &MontimePinger{}
	})
}

type pingStats struct {
	ping.Statistics
	ttl int
}

func (p *MontimePinger) goping() (*pingStats, error) {
	ps := &pingStats{}

	//set NewPing
	pinger, err := ping.NewPinger(p.Domain)
	if err != nil {
		return nil, fmt.Errorf("failed to create new pinger: %w", err)
	}
	// pinger.SetPrivileged(true)

	//struct options

	// Get Time to live (TTL) of first response, matching original implementation
	once := &sync.Once{}
	pinger.OnRecv = func(pkt *ping.Packet) {
		once.Do(func() {
			ps.ttl = pkt.TTL // Buraya bak
		})
	}
	err = pinger.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to run pinger: %w", err)
	}
	ps.Statistics = *pinger.Statistics()
	return ps, nil
}

func (p *MontimePinger) sendData(acc telegraf.Accumulator) {
	fields := &monitors.PingData{}
	tags := monitors.MonitorData[*monitors.PingData]{
		Domain: p.Domain,
		Data:   fields,
	}
	stats, err := p.goping()
	if err != nil {
		if strings.Contains(err.Error(), "unknown") {
			fields.Result = monitors.NoPacketsSent
		} else {
			fields.Result = monitors.NoPacketsReceived
		}
		acc.AddFields(pluginName, tags.GetFields(), tags.GetTags())
		return
	}

	// fields = map[string]interface{}{
	// 	"result_code":         0,
	// 	"packets_transmitted": stats.PacketsSent,
	// 	"packets_received":    stats.PacketsRecv,
	// }

	fields.Result = monitors.Success
	fields.PacketsTransmitted = stats.PacketsSent
	fields.PacketsReceived = stats.PacketsRecv
	fields.IPAddress = stats.IPAddr.String()

	if stats.PacketsSent == 0 {
		fields.Result = monitors.NoPacketsSent
		acc.AddFields(pluginName, tags.GetFields(), tags.GetTags())
		return
	}

	if stats.PacketsRecv == 0 {
		fields.Result = monitors.NoPacketsReceived
		fields.PercentPacketLoss = 100
		acc.AddFields(pluginName, tags.GetFields(), tags.GetTags())
		return
	}

	// Set TTL only on supported platform. See golang.org/x/net/ipv4/payload_cmsg.go
	switch runtime.GOOS {
	case "aix", "darwin", "dragonfly", "freebsd", "linux", "netbsd", "openbsd", "solaris":
		// fields["ttl"] = stats.ttl
		fields.TTL = stats.ttl
	}

	// fields["percent_packet_loss"] = float64(stats.PacketLoss)
	// fields["minimum_response_ms"] = float64(stats.MinRtt) / float64(time.Millisecond)
	// fields["average_response_ms"] = float64(stats.AvgRtt) / float64(time.Millisecond)
	// fields["maximum_response_ms"] = float64(stats.MaxRtt) / float64(time.Millisecond)
	// fields["standard_deviation_ms"] = float64(stats.StdDevRtt) / float64(time.Millisecond)

	fields.PercentPacketLoss = float64(stats.PacketLoss)
	fields.MinimumResponseMs = float64(stats.MinRtt) / float64(time.Millisecond)
	fields.AverageResponseMs = float64(stats.AvgRtt) / float64(time.Millisecond)
	fields.MaximumResponseMs = float64(stats.MaxRtt) / float64(time.Millisecond)
	fields.StandardDeviationMs = float64(stats.StdDevRtt) / float64(time.Millisecond)
	acc.AddFields(pluginName, tags.GetFields(), tags.GetTags())
}
