package dnsla

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/libdns/libdns"
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

	rr := extractRR(r)
	recordType := libDnsToDnslaRecordType(rr.Type)

	// URL encode the parameters
	params := url.Values{}
	params.Set("pageIndex", "1")
	params.Set("pageSize", "10")
	params.Set("domainId", domainId)
	params.Set("type", fmt.Sprintf("%d", recordType))
	params.Set("host", rr.Name)

	endpoint := "/api/recordList?" + params.Encode()
	response, err := MakeApiRequest("GET", endpoint, credentials, nil, dnslaDomainRecordsResponse{})
	if err != nil {
		return nil, err
	}

	total := response.Total
	if total > 10 {
		// Update page size for larger result sets
		params.Set("pageSize", fmt.Sprintf("%d", total))
		endpoint = "/api/recordList?" + params.Encode()
		response, err = MakeApiRequest("GET", endpoint, credentials, nil, dnslaDomainRecordsResponse{})
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
		// Ignore close errors as they are typically not critical
		_ = Body.Close()
	}(resp.Body)

	// Accept all 2xx status codes as success
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		err = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
		return responseType, err
	}

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return responseType, err
	}

	response := dnslaResponse{Data: &responseType}
	err = json.Unmarshal(result, &response)
	if err != nil {
		return responseType, fmt.Errorf("failed to parse JSON response: %v", err)
	}

	if response.Code != 200 {
		return responseType, fmt.Errorf("API error (code %d): %s", response.Code, response.Msg)
	}

	return responseType, nil
}
