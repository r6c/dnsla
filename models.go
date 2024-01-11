package dnsla

import (
	"fmt"
	"github.com/libdns/libdns"
	"time"
)

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
	ID         string `json:"Id"`
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
	ttl, _ := time.ParseDuration(fmt.Sprintf("%ds", record.TTL))
	var recordType string

	recordType = dnslaToLibDnsRecordType(record.Type)

	return libdns.Record{
		ID:       record.ID,
		Name:     libdns.RelativeName(record.Host, libdnsZoneToDnslaDomain(zone)),
		Priority: record.Weight,
		TTL:      ttl,
		Type:     recordType,
		Value:    record.Data,
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
