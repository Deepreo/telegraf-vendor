package deepmon_uptime

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/require"
)

// TC: 1
// geçersiz bir URL ile Uptime struct'ı oluşturulduğunda hata döndürülmeli
func TestInavlidURL(t *testing.T) {
	testCase := []map[string]string{
		{
			"invalidurl": "protocol is missing",
		},
		{
			"https://": "domain is missing",
		},
		{
			"https://.com": "invalid domain: .com",
		},
		{
			"ftp://example.com": "invalid protocol: ftp",
		},
		{
			"https://192.1658.0.1": "invalid domain: 192.1658.0.1",
		},
		{
			"https://example.com?arg1=": "",
		},
	}

	// var acc testutil.Accumulator
	uptime := Uptime{}
	for _, tc := range testCase {
		sq := maps.Keys(tc)
		sq(func(k string) bool {
			uptime.URL = k
			require.EqualError(t, uptime.Init(), tc[k])
			return true
		})

	}
}
