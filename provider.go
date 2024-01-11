package dnsla

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/libdns/libdns"
	"time"
)

// Provider facilitates DNS record manipulation with dnsla.
type Provider struct {
	APIID     string `json:"api_id,omitempty"`
	APISecret string `json:"api_secret,omitempty"`
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	trimmedZone := libdnsZoneToDnslaDomain(zone)

	credentials := p.getCredentials()
	response, err := MakeApiRequest("GET", "/api/domain?domain="+trimmedZone,
		credentials, nil, dnslaDomainResponse{})
	if err != nil {
		return nil, err
	}

	id := response.ID

	response2, err := MakeApiRequest("GET", "/api/recordList?pageIndex=1&pageSize=10&domainId="+id,
		credentials, nil, dnslaDomainRecordsResponse{})
	if err != nil {
		return nil, err
	}

	total := response2.Total
	if total > 10 {
		response2, err = MakeApiRequest("GET", "/api/recordList?pageIndex=1&pageSize="+fmt.Sprintf("%d", total)+"&domainId="+id,
			credentials, nil, dnslaDomainRecordsResponse{})
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

	response, err := MakeApiRequest("GET", "/api/domain?domain="+trimmedZone,
		credentials, nil, dnslaDomainResponse{})
	if err != nil {
		return nil, err
	}

	id := response.ID

	var createdRecords []libdns.Record

	for _, record := range records {
		if record.TTL/time.Second < 600 {
			record.TTL = 600 * time.Second
		}
		ttlInSeconds := int(record.TTL / time.Second)
		trimmedName := libdns.RelativeName(record.Name, zone)
		recordType := libDnsToDnslaRecordType(record.Type)

		reqBody := dnslaCreateRecordPayload{
			DomainId:   id,
			Type:       recordType,
			Host:       trimmedName,
			Data:       record.Value,
			TTL:        ttlInSeconds,
			Preference: 1,
			Weight:     1,
		}
		reqJson, err := json.Marshal(reqBody)
		if err != nil {
			return createdRecords, err
		}

		_, err = MakeApiRequest("POST", "/api/record", credentials,
			bytes.NewReader(reqJson), dnslaCreateRecordResponse{})

		if err != nil {
			return createdRecords, err
		}

		created, err := p.getMatchingRecord(record, id, zone)
		if err == nil && len(created) == 1 {
			record.ID = created[0].ID
		}
		createdRecords = append(createdRecords, record)
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

	response, err := MakeApiRequest("GET", "/api/domain?domain="+trimmedZone,
		credentials, nil, dnslaDomainResponse{})
	if err != nil {
		return nil, err
	}

	id := response.ID

	for _, r := range records {
		if r.ID == "" {
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

			r.ID = matches[0].ID
			updates = append(updates, r)
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

	response, err := MakeApiRequest("GET", "/api/domain?domain="+trimmedZone,
		credentials, nil, dnslaDomainResponse{})
	if err != nil {
		return nil, err
	}

	id := response.ID

	var deletedRecords []libdns.Record

	for _, record := range records {
		var queuedDeletes []libdns.Record
		if record.ID == "" {
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
			_, err = MakeApiRequest("DELETE", "/api/record?id="+recordToDelete.ID, credentials, nil, dnslaDeleteRecordResponse{})
			if err != nil {
				return deletedRecords, err
			}
			deletedRecords = append(deletedRecords, recordToDelete)
		}
	}

	return deletedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
