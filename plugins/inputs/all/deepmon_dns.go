//go:build !custom || inputs || inputs.deepmon_dns

package all

import _ "github.com/influxdata/telegraf/plugins/inputs/deepmon_dns" // register plugin
