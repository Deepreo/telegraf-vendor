//go:build !custom || inputs || inputs.deepmon_port

package all

import _ "github.com/influxdata/telegraf/plugins/inputs/deepmon_port" // register plugin
