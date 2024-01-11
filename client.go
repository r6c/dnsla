package dnsla

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/libdns/libdns"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const ApiBase = "https://api.dns.la"

// libdnsZoneToDnslaDomain Strips the trailing dot from a Zone
func libdnsZoneToDnslaDomain(zone string) string {
	return strings.TrimSuffix(zone, ".")
}

func (p *Provider) getCredentials() string {
	str := fmt.Sprintf("%s:%s", p.APIID, p.APISecret)
	token := base64.URLEncoding.EncodeToString([]byte(str))
	return token
}

func (p *Provider) getMatchingRecord(r libdns.Record, domainId string, zone string) ([]libdns.Record, error) {
	var recs []libdns.Record
	credentials := p.getCredentials()

	recordType := libDnsToDnslaRecordType(r.Type)
	response, err := MakeApiRequest("GET", "/api/recordList?pageIndex=1&pageSize=10&domainId="+
		domainId+"&type="+fmt.Sprintf("%d", recordType)+"&host="+r.Name,
		credentials, nil, dnslaDomainRecordsResponse{})
	if err != nil {
		return nil, err
	}

	total := response.Total
	if total > 10 {
		response, err = MakeApiRequest("GET", "/api/recordList?pageIndex=1&pageSize=10&domainId="+
			domainId+"&type="+fmt.Sprintf("%d", recordType)+"&host="+r.Name,
			credentials, nil, dnslaDomainRecordsResponse{})
		if err != nil {
			return nil, err
		}
	}

	recs = make([]libdns.Record, 0, len(response.Results))
	for _, rec := range response.Results {
		recs = append(recs, rec.toLibdnsRecord(zone))
	}
	return recs, nil
}

// UpdateRecords adds records to the zone. It returns the records that were added.
func (p *Provider) updateRecords(_ context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	credentials := p.getCredentials()

	var createdRecords []libdns.Record

	for _, record := range records {
		if record.TTL/time.Second < 600 {
			record.TTL = 600 * time.Second
		}
		ttlInSeconds := int(record.TTL / time.Second)
		trimmedName := libdns.RelativeName(record.Name, zone)
		recordType := libDnsToDnslaRecordType(record.Type)

		reqBody := dnslaRecordPayload{
			ID:         record.ID,
			Type:       recordType,
			Host:       trimmedName,
			Data:       record.Value,
			TTL:        ttlInSeconds,
			Preference: 1,
			Weight:     1,
		}
		reqJson, err := json.Marshal(reqBody)
		if err != nil {
			return nil, err
		}
		_, err = MakeApiRequest("PUT", "/api/record", credentials, bytes.NewReader(reqJson), dnslaUpdateRecordResponse{})
		if err != nil {
			return nil, err
		}

		createdRecords = append(createdRecords, record)
	}

	return createdRecords, nil
}

func MakeApiRequest[T any](method string, endpoint string, token string, body io.Reader, responseType T) (T, error) {
	client := http.Client{}

	fullUrl := ApiBase + endpoint
	u, err := url.Parse(fullUrl)
	if err != nil {
		return responseType, err
	}

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return responseType, err
	}
	req.Header.Add("Authorization", "Basic "+token)
	req.Header.Add("Content-Type", "application/json; charset=utf-8")

	resp, err := client.Do(req)
	if err != nil {
		return responseType, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal("Couldn't close body")
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		err = errors.New("Invalid http response status, " + string(bodyBytes))
		return responseType, err
	}

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return responseType, err
	}

	response := dnslaResponse{Data: &responseType}
	err = json.Unmarshal(result, &response)
	if err != nil {
		return responseType, err
	}

	if response.Code != 200 {
		return responseType, errors.New(fmt.Sprintf("Invalid response code %d", response.Code))
	}

	return responseType, nil
}
