//go:build !custom || inputs || inputs.deepmon_ping

package all

import _ "github.com/influxdata/telegraf/plugins/inputs/deepmon_ping" // register plugin
