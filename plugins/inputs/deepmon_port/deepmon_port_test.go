package deepmon_port

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Deepreo/MonitoringTime-Backend/pkg/monitors"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/testutil"

	"github.com/stretchr/testify/require"
)

func TestBadProtocol(t *testing.T) {
	// Init plugin
	c := NetResponse{
		Protocol: "unknownprotocol",
		Domain:   "localhost",
		Port:     "2004",
	}
	// Error
	err := c.Init()
	require.Error(t, err)
	require.Equal(t, "config option protocol: unknown choice unknownprotocol", err.Error())
}

func TestNoPort(t *testing.T) {
	c := NetResponse{
		Protocol: "tcp",
		Domain:   "localhost",
		Port:     "",
	}
	err := c.Init()
	require.Error(t, err)
	require.Equal(t, "bad port in config option address", err.Error())
}

func TestAddressOnly(t *testing.T) {
	c := NetResponse{
		Protocol: "tcp",
		Domain:   "127.0.0.1",
	}
	err := c.Init()
	require.Error(t, err)
	require.Equal(t, "bad port in config option address", err.Error())
}

func TestSendExpectStrings(t *testing.T) {
	tc := NetResponse{
		Protocol: "udp",
		Domain:   "127.0.0.1",
		Port:     "7",
		Send:     "",
		Expect:   "toast",
	}
	uc := NetResponse{
		Protocol: "udp",
		Domain:   "127.0.0.1",
		Port:     "7",
		Send:     "toast",
		Expect:   "",
	}
	err := tc.Init()
	require.Error(t, err)
	require.Equal(t, "send string cannot be empty", err.Error())
	err = uc.Init()
	require.Error(t, err)
	require.Equal(t, "expected string cannot be empty", err.Error())
}

func TestTCPError(t *testing.T) {
	var acc testutil.Accumulator
	// Init plugin
	c := NetResponse{
		Protocol: "tcp",
		Domain:   "localhost",
		Port:     "9999",
		Timeout:  config.Duration(time.Second * 30),
	}
	data := monitors.MonitorData[*monitors.PortData]{
		Domain: "localhost",
		Data: &monitors.PortData{
			Result:   monitors.ConnectionFailed,
			Port:     "9999",
			Protocol: "tcp",
		},
	}

	require.NoError(t, c.Init())
	// Gather
	require.NoError(t, c.Gather(&acc))
	acc.AssertContainsTaggedFields(t,
		pluginName,
		data.GetFields(), data.GetTags())
}

func TestTCPOK1(t *testing.T) {
	var wg sync.WaitGroup
	var acc testutil.Accumulator
	// Init plugin
	c := NetResponse{
		Domain:      "localhost",
		Port:        "2004",
		Send:        "test",
		Expect:      "test",
		ReadTimeout: config.Duration(time.Second * 3),
		Timeout:     config.Duration(time.Second * 3),
		Protocol:    "tcp",
	}
	require.NoError(t, c.Init())
	// Start TCP server
	wg.Add(1)
	go TCPServer(t, &wg)
	wg.Wait() // Wait for the server to spin up
	wg.Add(1)
	// Connect
	require.NoError(t, c.Gather(&acc))
	acc.Wait(1)

	// Override response time and expected_packet_size
	for _, p := range acc.Metrics {
		p.Fields["response_time"] = 1.0
	}
	data := monitors.MonitorData[*monitors.PortData]{
		Domain: "localhost",
		Data: &monitors.PortData{
			Result:             monitors.Success,
			Port:               "2004",
			Protocol:           "tcp",
			RemoteAddr:         "127.0.0.1",
			SendedString:       "test",
			SendedPacketSize:   4,
			ExpectedPacketSize: 4,
			ResponseTime:       1.0,
			ExpectedString:     "test",
		},
	}
	acc.AssertContainsTaggedFields(t,
		pluginName,
		data.GetFields(), data.GetTags())

	// Waiting TCPserver
	wg.Wait()
}

func TestTCPOK2(t *testing.T) {
	var wg sync.WaitGroup
	var acc testutil.Accumulator
	// Init plugin
	c := NetResponse{
		Domain:      "localhost",
		Port:        "2004",
		Send:        "test",
		Expect:      "test2",
		ReadTimeout: config.Duration(time.Second * 3),
		Timeout:     config.Duration(time.Second),
		Protocol:    "tcp",
	}
	require.NoError(t, c.Init())
	// Start TCP server
	wg.Add(1)
	go TCPServer(t, &wg)
	wg.Wait()
	wg.Add(1)

	// Connect
	require.NoError(t, c.Gather(&acc))
	acc.Wait(1)

	// Override response time
	for _, p := range acc.Metrics {
		p.Fields["response_time"] = 1.0
	}
	data := monitors.MonitorData[*monitors.PortData]{
		Domain: "localhost",
		Data: &monitors.PortData{
			Result:             monitors.StringMismatch,
			Port:               "2004",
			Protocol:           "tcp",
			RemoteAddr:         "127.0.0.1",
			SendedString:       "test",
			SendedPacketSize:   4,
			ExpectedPacketSize: 4,
			ResponseTime:       1.0,
			ExpectedString:     "test2",
		},
	}
	acc.AssertContainsTaggedFields(t,
		pluginName,
		data.GetFields(), data.GetTags())
	// Waiting TCPserver
	wg.Wait()
}

func TestUDPError(t *testing.T) {
	var acc testutil.Accumulator
	// Init plugin
	c := NetResponse{
		Domain:   "localhost",
		Port:     "9999",
		Send:     "test",
		Expect:   "test",
		Protocol: "udp",
	}
	require.NoError(t, c.Init())
	// Gather
	require.NoError(t, c.Gather(&acc))
	acc.Wait(1)

	// Override response time
	for _, p := range acc.Metrics {
		p.Fields["response_time"] = 1.0
	}
	// Error
	data := monitors.MonitorData[*monitors.PortData]{
		Domain: "localhost",
		Data: &monitors.PortData{
			Result:             monitors.ReadFailed,
			Port:               "9999",
			Protocol:           "udp",
			RemoteAddr:         "",
			SendedString:       "test",
			SendedPacketSize:   4,
			ExpectedPacketSize: 0,
			ResponseTime:       1.0,
			ExpectedString:     "test",
		},
	}
	acc.AssertContainsTaggedFields(t,
		pluginName, data.GetFields(), data.GetTags())
}

func TestUDPOK1(t *testing.T) {
	var wg sync.WaitGroup
	var acc testutil.Accumulator
	// Init plugin
	c := NetResponse{
		Domain:      "localhost",
		Port:        "2004",
		Send:        "test",
		Expect:      "test",
		ReadTimeout: config.Duration(time.Second * 3),
		Timeout:     config.Duration(time.Second),
		Protocol:    "udp",
	}
	require.NoError(t, c.Init())
	// Start UDP server
	wg.Add(1)
	go UDPServer(t, &wg)
	wg.Wait()
	wg.Add(1)

	// Connect
	require.NoError(t, c.Gather(&acc))
	acc.Wait(1)

	// Override response time
	for _, p := range acc.Metrics {
		p.Fields["response_time"] = 1.0
	}
	data := monitors.MonitorData[*monitors.PortData]{
		Domain: "localhost",
		Data: &monitors.PortData{
			Result:             monitors.Success,
			Port:               "2004",
			Protocol:           "udp",
			RemoteAddr:         "127.0.0.1",
			SendedString:       "test",
			SendedPacketSize:   4,
			ExpectedPacketSize: 4,
			ResponseTime:       1.0,
			ExpectedString:     "test",
		},
	}
	acc.AssertContainsTaggedFields(t,
		pluginName,
		data.GetFields(), data.GetTags())
	// Waiting TCPserver
	wg.Wait()
}

func UDPServer(t *testing.T, wg *sync.WaitGroup) {
	defer wg.Done()
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2004")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", udpAddr)
	require.NoError(t, err)
	wg.Done()
	buf := make([]byte, 1024)
	_, remoteaddr, err := conn.ReadFromUDP(buf)
	require.NoError(t, err)
	buf = bytes.Trim(buf, "\x00")
	_, err = conn.WriteToUDP(buf, remoteaddr)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
}

func TCPServer(t *testing.T, wg *sync.WaitGroup) {
	defer wg.Done()
	tcpAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:2004")
	require.NoError(t, err)
	tcpServer, err := net.ListenTCP("tcp", tcpAddr)
	require.NoError(t, err)
	wg.Done()
	conn, err := tcpServer.AcceptTCP()
	require.NoError(t, err)
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	require.NoError(t, err)
	buf = bytes.Trim(buf, "\x00")
	_, err = conn.Write(buf)
	require.NoError(t, err)
	require.NoError(t, conn.CloseWrite())
	require.NoError(t, tcpServer.Close())
}
