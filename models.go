package dnsla

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// DNSLAProviderData stores DNS.LA specific data for records
type DNSLAProviderData struct {
	ID string
}

type dnslaResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data"`
}
type dnslaDomainResponse struct {
	ID            string `json:"id"`
	CreatedAt     int    `json:"createdAt"`
	UpdatedAt     int    `json:"updatedAt"`
	UserID        string `json:"userId"`
	UserAccount   string `json:"userAccount"`
	AssetID       string `json:"assetId"`
	GroupID       string `json:"groupId"`
	GroupName     string `json:"groupName"`
	Domain        string `json:"domain"`
	DisplayDomain string `json:"displayDomain"`
	State         int    `json:"state"`
	NsState       int    `json:"nsState"`
	NsCheckedAt   int    `json:"nsCheckedAt"`
	ProductCode   string `json:"productCode"`
	ProductName   string `json:"productName"`
	ExpiredAt     int64  `json:"expiredAt"`
	QuoteDomainID string `json:"quoteDomainId"`
	QuoteDomain   string `json:"quoteDomain"`
	Suffix        string `json:"suffix"`
	DisplaySuffix string `json:"displaySuffix"`
}

type dnslaDomainRecordsResponse struct {
	Total   int                         `json:"total"`
	Results []dnslaDomainRecordResponse `json:"results"`
}

type dnslaDomainRecordResponse struct {
	ID          string `json:"id"`
	CreatedAt   int    `json:"createdAt"`
	UpdatedAt   int    `json:"updatedAt"`
	DomainID    string `json:"domainId"`
	GroupID     string `json:"groupId"`
	GroupName   string `json:"groupName"`
	Host        string `json:"host"`
	DisplayHost string `json:"displayHost"`
	Type        int    `json:"type"`
	LineID      string `json:"lineId"`
	LineCode    string `json:"lineCode"`
	LineName    string `json:"lineName"`
	Data        string `json:"data"`
	DisplayData string `json:"displayData"`
	TTL         int    `json:"ttl"`
	Weight      int    `json:"weight"`
	Preference  int    `json:"preference"`
	Domaint     bool   `json:"domaint"`
	System      bool   `json:"system"`
	Disable     bool   `json:"disable"`
}

type dnslaRecordPayload struct {
	ID         string `json:"id"`
	Type       int    `json:"type"`
	Host       string `json:"host"`
	Data       string `json:"data"`
	TTL        int    `json:"ttl"`
	GroupID    string `json:"groupId"`
	LineID     string `json:"lineId"`
	Preference int    `json:"preference"`
	Weight     int    `json:"weight"`
	Dominant   bool   `json:"dominant"`
}

type dnslaCreateRecordPayload struct {
	DomainId   string `json:"domainId"`
	Type       int    `json:"type"`
	Host       string `json:"host"`
	Data       string `json:"data"`
	TTL        int    `json:"ttl"`
	GroupID    string `json:"groupId"`
	LineID     string `json:"lineId"`
	Preference int    `json:"preference"`
	Weight     int    `json:"weight"`
	Dominant   bool   `json:"dominant"`
}

type dnslaCreateRecordResponse struct {
	ID string `json:"id"`
}

type dnslaDeleteRecordResponse struct {
}

type dnslaUpdateRecordResponse struct {
}

func (record dnslaDomainRecordResponse) toLibdnsRecord(zone string) libdns.Record {
	ttl := time.Duration(record.TTL) * time.Second
	relativeName := libdns.RelativeName(record.Host, libdnsZoneToDnslaDomain(zone))

	providerData := DNSLAProviderData{ID: record.ID}

	switch record.Type {
	case 1: // A record
		ip, err := netip.ParseAddr(record.Data)
		if err != nil {
			// Return RR for invalid IP addresses
			return libdns.RR{
				Name: relativeName,
				TTL:  ttl,
				Type: "A",
				Data: record.Data,
			}
		}
		return libdns.Address{
			Name:         relativeName,
			TTL:          ttl,
			IP:           ip,
			ProviderData: providerData,
		}
	case 28: // AAAA record
		ip, err := netip.ParseAddr(record.Data)
		if err != nil {
			// Return RR for invalid IP addresses
			return libdns.RR{
				Name: relativeName,
				TTL:  ttl,
				Type: "AAAA",
				Data: record.Data,
			}
		}
		return libdns.Address{
			Name:         relativeName,
			TTL:          ttl,
			IP:           ip,
			ProviderData: providerData,
		}
	case 16: // TXT record
		return libdns.TXT{
			Name:         relativeName,
			TTL:          ttl,
			Text:         record.Data,
			ProviderData: providerData,
		}
	case 5: // CNAME record
		return libdns.CNAME{
			Name:         relativeName,
			TTL:          ttl,
			Target:       record.Data,
			ProviderData: providerData,
		}
	case 15: // MX record
		return libdns.MX{
			Name:         relativeName,
			TTL:          ttl,
			Preference:   uint16(record.Preference),
			Target:       record.Data,
			ProviderData: providerData,
		}
	case 2: // NS record
		return libdns.NS{
			Name:         relativeName,
			TTL:          ttl,
			Target:       record.Data,
			ProviderData: providerData,
		}
	case 33: // SRV record
		// SRV record data format: "port target" or "priority weight port target"
		// Name format should be "_service._protocol.name"
		parts := strings.Fields(record.Data)
		var port uint16 = 443
		var target string = record.Data

		if len(parts) >= 2 {
			// Try to parse port from data
			if p, err := strconv.ParseUint(parts[0], 10, 16); err == nil {
				port = uint16(p)
				target = parts[1]
			} else if len(parts) >= 4 {
				// Format: priority weight port target
				if p, err := strconv.ParseUint(parts[2], 10, 16); err == nil {
					port = uint16(p)
					target = parts[3]
				}
			}
		}

		// Extract service and transport from name
		var service, transport string
		nameParts := strings.Split(relativeName, ".")
		if len(nameParts) >= 2 {
			if strings.HasPrefix(nameParts[0], "_") {
				service = strings.TrimPrefix(nameParts[0], "_")
			}
			if strings.HasPrefix(nameParts[1], "_") {
				transport = strings.TrimPrefix(nameParts[1], "_")
			}
		}

		return libdns.SRV{
			Service:      service,
			Transport:    transport,
			Name:         relativeName,
			TTL:          ttl,
			Priority:     uint16(record.Preference),
			Weight:       uint16(record.Weight),
			Port:         port,
			Target:       target,
			ProviderData: providerData,
		}
	case 257: // CAA record
		// CAA record data format: "flags tag value"
		parts := strings.Fields(record.Data)
		var flags uint8 = 0
		var tag string = ""
		var value string = record.Data

		if len(parts) >= 3 {
			// Parse flags
			if f, err := strconv.ParseUint(parts[0], 10, 8); err == nil {
				flags = uint8(f)
			}
			tag = parts[1]
			// Value might contain spaces, so join the remaining parts
			value = strings.Join(parts[2:], " ")
			// Remove quotes if present
			value = strings.Trim(value, `"`)
		}

		return libdns.CAA{
			Name:         relativeName,
			TTL:          ttl,
			Flags:        flags,
			Tag:          tag,
			Value:        value,
			ProviderData: providerData,
		}
	default:
		// Return RR for unknown record types
		return libdns.RR{
			Name: relativeName,
			TTL:  ttl,
			Type: dnslaToLibDnsRecordType(record.Type),
			Data: record.Data,
		}
	}
}

func dnslaToLibDnsRecordType(t int) string {
	var recordType string
	//A	    1
	//NS	2
	//CNAME	5
	//MX	15
	//TXT	16
	//AAAA	28
	//SRV	33
	//CAA	257
	switch t {
	case 1:
		recordType = "A"
	case 2:
		recordType = "NS"
	case 5:
		recordType = "CNAME"
	case 15:
		recordType = "MX"
	case 16:
		recordType = "TXT"
	case 28:
		recordType = "AAAA"
	case 33:
		recordType = "SRV"
	case 257:
		recordType = "CAA"
	}

	return recordType
}

func libDnsToDnslaRecordType(t string) int {
	var recordType int

	switch t {
	case "A":
		recordType = 1
	case "NS":
		recordType = 2
	case "CNAME":
		recordType = 5
	case "MX":
		recordType = 15
	case "TXT":
		recordType = 16
	case "AAAA":
		recordType = 28
	case "SRV":
		recordType = 33
	case "CAA":
		recordType = 257
	}

	return recordType
}
