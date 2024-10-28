//go:generate ../../../tools/readme_config_includer/generator
package deepmon_domain

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"github.com/Deepreo/MonitoringTime-Backend/pkg/monitors"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

type MontimeDomain struct {
	//param for func
	domain string `toml:"domain"`
	//log keeper
}

//go:embed sample.conf
var sampleConfig string

var pluginName = monitors.MonitorTypes_DEEPMON_DOMAIN.String()

func (t *MontimeDomain) SampleConfig() string {
	return sampleConfig
}

func (t *MontimeDomain) Gather(acc telegraf.Accumulator) error {
	t.sendData(acc)
	return nil
}

func init() {
	inputs.Add(pluginName, func() telegraf.Input {
		return &MontimeDomain{}
	})
}

// ConnectionInfo contains information about a single Domain connection.
type domainStats struct {
	DomainName string
	Registrar  struct {
		Name        string
		ReferralURL string
	}
	CreationDate   string
	ExpirationDate string
	UpdatedDate    string
	Status         string
	NameServers    string
	DNSSEC         bool
	AdminContact   struct {
		Name  string
		Email string
		Phone string
	}
	TechContact struct {
		Name  string
		Email string
		Phone string
	}
	Registrant struct {
		Name  string
		Email string
		Phone string
	}
}

func (t *MontimeDomain) FetchWhoisData() (*domainStats, error) {
	ts := &domainStats{}

	// Perform WHOIS lookup
	rawWhois, err := whois.Whois(t.domain)
	if err != nil {
		return ts, fmt.Errorf("error fetching WHOIS data: %v", err)
	}

	// Parse the WHOIS data
	result, err := whoisparser.Parse(rawWhois)
	if err != nil {
		return ts, fmt.Errorf("error parsing WHOIS data: %v", err)
	}

	// Populate the WhoisData struct based on available data
	if result.Domain != nil {
		ts.DomainName = result.Domain.Domain
		ts.CreationDate = result.Domain.CreatedDate
		ts.ExpirationDate = result.Domain.ExpirationDate
		ts.UpdatedDate = result.Domain.UpdatedDate
		// Convert Status and NameServers slices to strings
		ts.Status = strings.Join(result.Domain.Status, ", ")
		ts.NameServers = strings.Join(result.Domain.NameServers, ", ")
		ts.DNSSEC = result.Domain.DNSSec
	}

	if result.Registrar != nil {
		ts.Registrar.Name = result.Registrar.Name
		ts.Registrar.ReferralURL = result.Registrar.ReferralURL
	}
	// Inspect the available fields and adjust accordingly
	// Example: Check if 'Administrative' is a valid field
	if result.Administrative != nil {
		ts.AdminContact.Name = result.Administrative.Name
		ts.AdminContact.Email = result.Administrative.Email
		ts.AdminContact.Phone = result.Administrative.Phone
	}

	if result.Technical != nil {
		ts.TechContact.Name = result.Technical.Name
		ts.TechContact.Email = result.Technical.Email
		ts.TechContact.Phone = result.Technical.Phone
	}

	if result.Registrant != nil {
		ts.Registrant.Name = result.Registrant.Name
		ts.Registrant.Email = result.Registrant.Email
		ts.Registrant.Phone = result.Registrant.Phone
	}

	return ts, nil
}

// ExtractEmails extracts email addresses from raw WHOIS data
func ExtractEmails(rawWhois string) []string {
	var emails []string
	re := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	emails = re.FindAllString(rawWhois, -1)
	return emails
}

func (t *MontimeDomain) sendData(acc telegraf.Accumulator) {
	fields := &monitors.DomainData{}
	tags := monitors.MonitorData[*monitors.DomainData]{
		Domain: t.domain,
		Data:   fields,
	}
	stats, err := t.FetchWhoisData()
	if err != nil {
		fields.Result = monitors.Failed
		acc.AddFields(pluginName, tags.GetFields(), tags.GetTags())
		return
	}
	fields.Result = monitors.Success
	fields.DomainName = stats.DomainName
	fields.DNSSEC = stats.DNSSEC
	fields.RegistrarName = stats.Registrar.Name
	fields.RegistrarReferralURL = stats.Registrar.ReferralURL
	fields.CreationDate = stats.CreationDate
	fields.ExpirationDate = stats.ExpirationDate
	fields.UpdatedDate = stats.UpdatedDate
	fields.Status = stats.Status
	fields.NameServers = stats.NameServers
	fields.AdminName = stats.AdminContact.Name
	fields.AdminEmail = stats.AdminContact.Email
	fields.AdminPhone = stats.AdminContact.Phone
	fields.TechName = stats.TechContact.Name
	fields.TechEmail = stats.TechContact.Email
	fields.TechPhone = stats.TechContact.Phone
	fields.RegistrantName = stats.Registrant.Name
	fields.RegistrantEmail = stats.Registrant.Email
	fields.RegistrantPhone = stats.Registrant.Phone

	acc.AddFields(pluginName, tags.GetFields(), tags.GetTags())

}
