//go:build !custom || inputs || inputs.deepmon_cert

package all

import _ "github.com/influxdata/telegraf/plugins/inputs/deepmon_cert" // register plugin
