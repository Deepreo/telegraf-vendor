//go:build !custom || inputs || inputs.deepmon_domain

package all

import _ "github.com/influxdata/telegraf/plugins/inputs/deepmon_domain" // register plugin
