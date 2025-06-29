package dnsla

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with dnsla.
type Provider struct {
	APIID     string `json:"api_id,omitempty"`
	APISecret string `json:"api_secret,omitempty"`
}

// extractID extracts the DNS.LA record ID from a libdns.Record
func extractID(record libdns.Record) string {
	switch r := record.(type) {
	case libdns.Address:
		if data, ok := r.ProviderData.(DNSLAProviderData); ok {
			return data.ID
		}
	case libdns.TXT:
		if data, ok := r.ProviderData.(DNSLAProviderData); ok {
			return data.ID
		}
	case libdns.CNAME:
		if data, ok := r.ProviderData.(DNSLAProviderData); ok {
			return data.ID
		}
	case libdns.MX:
		if data, ok := r.ProviderData.(DNSLAProviderData); ok {
			return data.ID
		}
	case libdns.NS:
		if data, ok := r.ProviderData.(DNSLAProviderData); ok {
			return data.ID
		}
	case libdns.SRV:
		if data, ok := r.ProviderData.(DNSLAProviderData); ok {
			return data.ID
		}
	case libdns.CAA:
		if data, ok := r.ProviderData.(DNSLAProviderData); ok {
			return data.ID
		}
	case libdns.RR:
		// RR doesn't have ProviderData, return empty
		return ""
	}
	return ""
}

// extractRR extracts RR from a libdns.Record
func extractRR(record libdns.Record) libdns.RR {
	return record.RR()
}

// addIDToRecord creates a new record with the same data but adds the ID to ProviderData
func addIDToRecord(record libdns.Record, id string) libdns.Record {
	providerData := DNSLAProviderData{ID: id}

	switch r := record.(type) {
	case libdns.Address:
		return libdns.Address{
			Name:         r.Name,
			TTL:          r.TTL,
			IP:           r.IP,
			ProviderData: providerData,
		}
	case libdns.TXT:
		return libdns.TXT{
			Name:         r.Name,
			TTL:          r.TTL,
			Text:         r.Text,
			ProviderData: providerData,
		}
	case libdns.CNAME:
		return libdns.CNAME{
			Name:         r.Name,
			TTL:          r.TTL,
			Target:       r.Target,
			ProviderData: providerData,
		}
	case libdns.MX:
		return libdns.MX{
			Name:         r.Name,
			TTL:          r.TTL,
			Preference:   r.Preference,
			Target:       r.Target,
			ProviderData: providerData,
		}
	case libdns.NS:
		return libdns.NS{
			Name:         r.Name,
			TTL:          r.TTL,
			Target:       r.Target,
			ProviderData: providerData,
		}
	case libdns.SRV:
		return libdns.SRV{
			Service:      r.Service,
			Transport:    r.Transport,
			Name:         r.Name,
			TTL:          r.TTL,
			Priority:     r.Priority,
			Weight:       r.Weight,
			Port:         r.Port,
			Target:       r.Target,
			ProviderData: providerData,
		}
	case libdns.CAA:
		return libdns.CAA{
			Name:         r.Name,
			TTL:          r.TTL,
			Flags:        r.Flags,
			Tag:          r.Tag,
			Value:        r.Value,
			ProviderData: providerData,
		}
	case libdns.RR:
		// RR doesn't have ProviderData, return as-is
		return r
	default:
		// For unknown types, return as-is
		return record
	}
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	trimmedZone := libdnsZoneToDnslaDomain(zone)

	credentials := p.getCredentials()
	// URL encode the domain parameter
	domainParams := url.Values{}
	domainParams.Set("domain", trimmedZone)
	domainEndpoint := "/api/domain?" + domainParams.Encode()
	response, err := MakeApiRequest("GET", domainEndpoint, credentials, nil, dnslaDomainResponse{})
	if err != nil {
		return nil, err
	}

	id := response.ID

	// URL encode the record list parameters
	recordParams := url.Values{}
	recordParams.Set("pageIndex", "1")
	recordParams.Set("pageSize", "10")
	recordParams.Set("domainId", id)
	recordEndpoint := "/api/recordList?" + recordParams.Encode()

	response2, err := MakeApiRequest("GET", recordEndpoint, credentials, nil, dnslaDomainRecordsResponse{})
	if err != nil {
		return nil, err
	}

	total := response2.Total
	if total > 10 {
		// Update page size for larger result sets
		recordParams.Set("pageSize", fmt.Sprintf("%d", total))
		recordEndpoint = "/api/recordList?" + recordParams.Encode()
		response2, err = MakeApiRequest("GET", recordEndpoint, credentials, nil, dnslaDomainRecordsResponse{})
		if err != nil {
			return nil, err
		}
	}

	recs := make([]libdns.Record, 0, len(response2.Results))
	for _, rec := range response2.Results {
		recs = append(recs, rec.toLibdnsRecord(zone))
	}
	return recs, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	credentials := p.getCredentials()
	trimmedZone := libdnsZoneToDnslaDomain(zone)

	// URL encode the domain parameter
	domainParams := url.Values{}
	domainParams.Set("domain", trimmedZone)
	domainEndpoint := "/api/domain?" + domainParams.Encode()
	response, err := MakeApiRequest("GET", domainEndpoint, credentials, nil, dnslaDomainResponse{})
	if err != nil {
		return nil, err
	}

	id := response.ID

	var createdRecords []libdns.Record

	for _, record := range records {
		rr := extractRR(record)

		if rr.TTL/time.Second < 600 {
			rr.TTL = 600 * time.Second
		}
		ttlInSeconds := int(rr.TTL / time.Second)
		trimmedName := libdns.RelativeName(rr.Name, zone)
		recordType := libDnsToDnslaRecordType(rr.Type)

		// Extract preference and weight from specific record types
		var preference, weight int = 1, 1
		switch r := record.(type) {
		case libdns.MX:
			preference = int(r.Preference)
		case libdns.SRV:
			preference = int(r.Priority)
			weight = int(r.Weight)
		}

		reqBody := dnslaCreateRecordPayload{
			DomainId:   id,
			Type:       recordType,
			Host:       trimmedName,
			Data:       rr.Data,
			TTL:        ttlInSeconds,
			Preference: preference,
			Weight:     weight,
		}
		reqJson, err := json.Marshal(reqBody)
		if err != nil {
			return createdRecords, err
		}

		createResponse, err := MakeApiRequest("POST", "/api/record", credentials,
			bytes.NewReader(reqJson), dnslaCreateRecordResponse{})

		if err != nil {
			return createdRecords, err
		}

		// Use the ID from the create response to create a record with provider data
		if createResponse.ID != "" {
			// Create a new record with the same data but with ID in ProviderData
			recordWithID := addIDToRecord(record, createResponse.ID)
			createdRecords = append(createdRecords, recordWithID)
		} else {
			// Fallback to the original record without ID
			createdRecords = append(createdRecords, record)
		}
	}

	return createdRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var updates []libdns.Record
	var creates []libdns.Record
	var results []libdns.Record

	credentials := p.getCredentials()
	trimmedZone := libdnsZoneToDnslaDomain(zone)

	// URL encode the domain parameter
	domainParams := url.Values{}
	domainParams.Set("domain", trimmedZone)
	domainEndpoint := "/api/domain?" + domainParams.Encode()
	response, err := MakeApiRequest("GET", domainEndpoint, credentials, nil, dnslaDomainResponse{})
	if err != nil {
		return nil, err
	}

	id := response.ID

	for _, r := range records {
		recordID := extractID(r)
		if recordID == "" {
			// Try fetch record in case we are just missing the ID
			matches, err := p.getMatchingRecord(r, id, zone)
			if err != nil {
				return nil, err
			}

			if len(matches) == 0 {
				creates = append(creates, r)
				continue
			}

			if len(matches) > 1 {
				return nil, fmt.Errorf("unexpectedly found more than 1 record for %v", r)
			}

			// Use the found record with ID for update
			updates = append(updates, matches[0])
		} else {
			updates = append(updates, r)
		}
	}

	created, err := p.AppendRecords(ctx, zone, creates)
	if err != nil {
		return nil, err
	}
	updated, err := p.updateRecords(ctx, zone, updates)
	if err != nil {
		return nil, err
	}

	results = append(results, created...)
	results = append(results, updated...)
	return results, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	credentials := p.getCredentials()
	trimmedZone := libdnsZoneToDnslaDomain(zone)

	// URL encode the domain parameter
	domainParams := url.Values{}
	domainParams.Set("domain", trimmedZone)
	domainEndpoint := "/api/domain?" + domainParams.Encode()
	response, err := MakeApiRequest("GET", domainEndpoint, credentials, nil, dnslaDomainResponse{})
	if err != nil {
		return nil, err
	}

	id := response.ID

	var deletedRecords []libdns.Record

	for _, record := range records {
		var queuedDeletes []libdns.Record
		recordID := extractID(record)
		if recordID == "" {
			// Try fetch record in case we are just missing the ID
			matches, err := p.getMatchingRecord(record, id, zone)
			if err != nil {
				return deletedRecords, err
			}
			for _, rec := range matches {
				queuedDeletes = append(queuedDeletes, rec)
			}
		} else {
			queuedDeletes = append(queuedDeletes, record)
		}

		for _, recordToDelete := range queuedDeletes {
			deleteID := extractID(recordToDelete)
			if deleteID == "" {
				continue // Skip records without ID
			}
			// URL encode the delete request
			deleteParams := url.Values{}
			deleteParams.Set("id", deleteID)
			deleteEndpoint := "/api/record?" + deleteParams.Encode()
			_, err = MakeApiRequest("DELETE", deleteEndpoint, credentials, nil, dnslaDeleteRecordResponse{})
			if err != nil {
				return deletedRecords, err
			}
			deletedRecords = append(deletedRecords, recordToDelete)
		}
	}

	return deletedRecords, nil
}

// updateRecords updates existing records in the zone. It returns the records that were updated.
func (p *Provider) updateRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	credentials := p.getCredentials()

	var updatedRecords []libdns.Record

	for _, record := range records {
		rr := extractRR(record)
		recordID := extractID(record)

		if recordID == "" {
			return updatedRecords, fmt.Errorf("record ID is required for update: %v", record)
		}

		if rr.TTL/time.Second < 600 {
			rr.TTL = 600 * time.Second
		}
		ttlInSeconds := int(rr.TTL / time.Second)
		trimmedName := libdns.RelativeName(rr.Name, zone)
		recordType := libDnsToDnslaRecordType(rr.Type)

		// Extract preference and weight from specific record types
		var preference, weight int = 1, 1
		switch r := record.(type) {
		case libdns.MX:
			preference = int(r.Preference)
		case libdns.SRV:
			preference = int(r.Priority)
			weight = int(r.Weight)
		}

		reqBody := dnslaRecordPayload{
			ID:         recordID,
			Type:       recordType,
			Host:       trimmedName,
			Data:       rr.Data,
			TTL:        ttlInSeconds,
			Preference: preference,
			Weight:     weight,
		}
		reqJson, err := json.Marshal(reqBody)
		if err != nil {
			return updatedRecords, err
		}
		_, err = MakeApiRequest("PUT", "/api/record", credentials, bytes.NewReader(reqJson), dnslaUpdateRecordResponse{})
		if err != nil {
			return updatedRecords, err
		}

		updatedRecords = append(updatedRecords, record)
	}

	return updatedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
