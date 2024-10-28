//go:build !custom || inputs || inputs.deepmon_uptime

package all

import _ "github.com/influxdata/telegraf/plugins/inputs/deepmon_uptime" // register plugin
