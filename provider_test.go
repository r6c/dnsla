package dnsla

import (
	"context"
	"github.com/libdns/libdns"
	"log"
	"testing"
	"time"
)

var records []libdns.Record
var testRecord libdns.Record

func getInitialRecords(t *testing.T, provider Provider, zone string) []libdns.Record {
	if len(records) == 0 {
		fetchedRecords, err := provider.GetRecords(context.TODO(), zone)
		if err != nil {
			t.Error(err)
		}
		records = fetchedRecords
	}

	return records
}

func createOrGetTestRecord(t *testing.T, provider Provider, zone string) libdns.Record {
	if testRecord.ID == "" {
		testValue := "test-value"
		ttl := 600 * time.Second
		recordType := "TXT"
		testFullName := "libdns_test_record"

		//Create record
		appendedRecords, err := provider.AppendRecords(context.TODO(), zone, []libdns.Record{
			{
				Type:  recordType,
				Name:  testFullName,
				TTL:   ttl,
				Value: testValue,
			},
		})

		if err != nil {
			t.Error(err)
		}

		if len(appendedRecords) != 1 {
			t.Errorf("Incorrect amount of records %d created", len(appendedRecords))
		}

		testRecord = appendedRecords[0]
	}

	return testRecord
}

func getProvider(t *testing.T) (Provider, string) {
	apiId := ""
	apiSecret := ""
	zone := "test-for-jump.com"

	provider := Provider{
		APIID:     apiId,
		APISecret: apiSecret,
	}
	return provider, zone
}

func TestProvider_GetRecords(t *testing.T) {
	provider, zone := getProvider(t)

	//Get records
	initialRecords := getInitialRecords(t, provider, zone)

	log.Println("Records fetched:")
	for _, record := range initialRecords {
		t.Logf("%s %s (.%s): %s, %s\n", record.ID, record.Name, zone, record.Value, record.Type)
	}
}

func TestProvider_AppendRecords(t *testing.T) {
	provider, zone := getProvider(t)

	//Get records
	initialRecords := getInitialRecords(t, provider, zone)

	createdRecord := createOrGetTestRecord(t, provider, zone)
	//Get records
	postCreatedRecords, err := provider.GetRecords(context.TODO(), zone)
	if err != nil {
		t.Error(err)
	}

	if len(postCreatedRecords) != len(initialRecords)+1 {
		t.Errorf("Additional record not created")
	}

	t.Logf("Created record: \n%v\n", createdRecord.ID)
}

func TestProvider_UpdateRecordsByLookup(t *testing.T) {
	provider, zone := getProvider(t)

	//Get records
	initialRecords := getInitialRecords(t, provider, zone)

	//_ = createOrGetTestRecord(t, provider, zone)

	ttl := 600 * time.Second
	recordType := "TXT"
	testFullName := "libdns_test_record"

	updatedTestValue := "updated-test-value-by-lookup"
	// Update record
	updatedRecords, err := provider.SetRecords(context.TODO(), zone, []libdns.Record{
		{
			Type:  recordType,
			Name:  testFullName,
			TTL:   ttl,
			Value: updatedTestValue,
		},
	})

	if err != nil {
		t.Error(err)
	}

	if len(updatedRecords) != 1 {
		t.Logf("Incorrect amount of records changed")
	}

	t.Logf("Updated record: \n%v\n", updatedRecords[0])

	//Get records
	postUpdatedRecords, err := provider.GetRecords(context.TODO(), zone)
	if err != nil {
		t.Error(err)
	}

	if len(postUpdatedRecords) != len(initialRecords)+1 {
		t.Errorf("Additional record created instead of updating existing. Started with: %d, now has: %d", len(initialRecords), len(postUpdatedRecords))
	}
}

func TestProvider_DeleteRecords(t *testing.T) {
	provider, zone := getProvider(t)

	//Create record
	//createdRecord := createOrGetTestRecord(t, provider, zone)

	ttl := 600 * time.Second
	recordType := "TXT"
	testFullName := "libdns_test_record"

	updatedTestValue := "updated-test-value-by-lookup"

	// Delete record
	deleteRecords, err := provider.DeleteRecords(context.TODO(), zone, []libdns.Record{{
		Type:  recordType,
		Name:  testFullName,
		TTL:   ttl,
		Value: updatedTestValue,
	}})

	if err != nil {
		t.Error(err)
	}

	if len(deleteRecords) != 1 {
		t.Errorf("Deleted incorrect amount of records %d", len(deleteRecords))
	}

	t.Logf("Deleted record: \n%v\n", deleteRecords[0])
}
