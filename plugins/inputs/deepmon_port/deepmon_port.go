//go:generate ../../../tools/readme_config_includer/generator
package deepmon_port

import (
	"bufio"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"net"
	"net/textproto"
	"regexp"
	"time"

	"github.com/Deepreo/MonitoringTime-Backend/pkg/monitors"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/internal/choice"
	"github.com/influxdata/telegraf/plugins/inputs"
)

//go:embed sample.conf
var sampleConfig string

// NetResponse struct
type NetResponse struct {
	Address     string
	Timeout     config.Duration
	ReadTimeout config.Duration
	Send        string
	Expect      string
	Protocol    string
}

func (*NetResponse) SampleConfig() string {
	return sampleConfig
}

// TCPGather will execute if there are TCP tests defined in the configuration.
// It will return a map[string]interface{} for fields and a map[string]string for tags
func (n *NetResponse) TCPGather(fields *monitors.PortData) (err error) {
	// Prepare returns
	// Start Timer
	start := time.Now()
	// Connecting
	conn, err := net.DialTimeout("tcp", n.Address, time.Duration(n.Timeout))
	// Stop timer
	responseTime := time.Since(start).Seconds()
	// Handle error
	if err != nil {
		var e net.Error
		if errors.As(err, &e) && e.Timeout() {
			fields.Result = monitors.Timeout
		} else {
			fields.Result = monitors.ConnectionFailed
		}
		return nil
	}
	defer conn.Close()
	// Send string if needed
	if n.Send != "" {
		msg := []byte(n.Send)
		if ln, gerr := conn.Write(msg); gerr != nil {
			return gerr
		} else {
			fields.SendedPacketSize = ln //ln yazılan paket sayısı gönderilen byte kadar eğer yazılmazsa zaten hata dönüyor
		}
		// Stop timer
		responseTime = time.Since(start).Seconds()
	}
	// Read string if needed
	if n.Expect != "" {
		// Set read timeout
		if gerr := conn.SetReadDeadline(time.Now().Add(time.Duration(n.ReadTimeout))); gerr != nil {
			return gerr
		}
		// Prepare reader
		reader := bufio.NewReader(conn)
		tp := textproto.NewReader(reader)
		// Read
		data, err := tp.ReadLine()
		// Stop timer
		fields.ExpectedPacketSize = len(data) // Gelen datanın uzunluğunu expected (beklenen) datanın uzunluğu olarak yazdım.
		responseTime = time.Since(start).Seconds()
		// Handle error
		if err != nil {
			log.Println(err.Error())
			fields.Result = monitors.ReadFailed
		} else {
			// Looking for string in answer
			regEx := regexp.MustCompile(`.*` + n.Expect + `.*`)
			find := regEx.FindString(data)
			if find != "" {
				fields.Result = monitors.Success
			} else {
				fields.Result = monitors.StringMismatch
			}
		}
	} else {
		fields.Result = monitors.Success
	}
	fields.RemoteAddr, _, _ = net.SplitHostPort(conn.RemoteAddr().String())
	fields.ResponseTime = responseTime
	return nil
}

// UDPGather will execute if there are UDP tests defined in the configuration.
// It will return a map[string]interface{} for fields and a map[string]string for tags
func (n *NetResponse) UDPGather(fields *monitors.PortData) (err error) {
	// Prepare returns

	// Start Timer
	start := time.Now()
	// Resolving
	udpAddr, err := net.ResolveUDPAddr("udp", n.Address)
	// Handle error
	if err != nil {
		fields.Result = monitors.ConnectionFailed
		return nil
	}
	// Connecting
	conn, err := net.DialUDP("udp", nil, udpAddr)
	// Handle error
	if err != nil {
		fields.Result = monitors.ConnectionFailed
		return nil
	}
	defer conn.Close()
	// Send string
	msg := []byte(n.Send)
	if ln, gerr := conn.Write(msg); gerr != nil {
		return gerr
	} else {
		fields.SendedPacketSize = ln
	}
	// Read string
	// Set read timeout
	if gerr := conn.SetReadDeadline(time.Now().Add(time.Duration(n.ReadTimeout))); gerr != nil {
		return gerr
	}
	// Read
	buf := make([]byte, 1024)
	ln, _, err := conn.ReadFromUDP(buf)
	// Stop timer
	// log.Println("DATA:", string(buf))
	responseTime := time.Since(start).Seconds()
	// Handle error
	if err != nil {
		fields.Result = monitors.ReadFailed
		return nil
	}
	// Looking for string in answer
	regEx := regexp.MustCompile(`.*` + n.Expect + `.*`)
	find := regEx.FindString(string(buf))
	if find != "" {
		fields.Result = monitors.Success
	} else {
		fields.Result = monitors.StringMismatch
	}
	fields.ResponseTime = responseTime
	fields.RemoteAddr, _, _ = net.SplitHostPort(conn.RemoteAddr().String())
	fields.ExpectedPacketSize = ln
	return nil
}

// Init performs one time setup of the plugin and returns an error if the
// configuration is invalid.
func (n *NetResponse) Init() error {
	// Set default values
	if n.Timeout == 0 {
		n.Timeout = config.Duration(time.Second)
	}
	if n.ReadTimeout == 0 {
		n.ReadTimeout = config.Duration(time.Second)
	}
	// Check send and expected string
	if n.Protocol == "udp" && n.Send == "" {
		return errors.New("send string cannot be empty")
	}
	if n.Protocol == "udp" && n.Expect == "" {
		return errors.New("expected string cannot be empty")
	}
	// Prepare host and port
	host, port, err := net.SplitHostPort(n.Address)
	if err != nil {
		return err
	}
	if host == "" {
		n.Address = "localhost:" + port
	}
	if port == "" {
		return errors.New("bad port in config option address")
	}

	if err := choice.Check(n.Protocol, []string{"tcp", "udp"}); err != nil {
		return fmt.Errorf("config option protocol: %w", err)
	}

	return nil
}

// Gather is called by telegraf when the plugin is executed on its interval.
// It will call either UDPGather or TCPGather based on the configuration and
// also fill an Accumulator that is supplied.
func (n *NetResponse) Gather(acc telegraf.Accumulator) error {
	// Prepare host and port
	host, port, err := net.SplitHostPort(n.Address)
	if err != nil {
		return err
	}

	fields := &monitors.PortData{}
	tags := monitors.MonitorData[*monitors.PortData]{
		Domain: host,
		Data:   fields,
	}
	// Prepare data
	// tags := map[string]string{"server": host, "port": port}
	// var fields map[string]interface{}
	// var returnTags map[string]string

	// Gather data
	fields.Port = port
	switch n.Protocol {
	case "tcp":
		err = n.TCPGather(fields)
		if err != nil {
			return err
		}
		fields.Protocol = "tcp"
	case "udp":
		err = n.UDPGather(fields)
		if err != nil {
			return err
		}
		fields.Protocol = "udp"
	}
	fields.ExpectedString = n.Expect
	fields.SendedString = n.Send
	// Merge the tags
	// for k, v := range returnTags {
	// 	tags[k] = v
	// }
	// Add metrics
	acc.AddFields("deepmon_port", tags.GetField(), tags.GetTag())
	return nil
}

func init() {
	inputs.Add("deepmon_port", func() telegraf.Input {
		return &NetResponse{}
	})
}
