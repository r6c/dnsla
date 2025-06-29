package dnsla

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/libdns/libdns"
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
	if testRecord == nil {
		testValue := "test-value"
		ttl := 600 * time.Second
		testFullName := "libdns_test_record"

		//Create TXT record
		appendedRecords, err := provider.AppendRecords(context.TODO(), zone, []libdns.Record{
			libdns.TXT{
				Name: testFullName,
				TTL:  ttl,
				Text: testValue,
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
	// Get credentials from environment variables
	apiId := os.Getenv("DNSLA_API_ID")
	apiSecret := os.Getenv("DNSLA_API_SECRET")
	zone := os.Getenv("DNSLA_TEST_ZONE")

	if apiId == "" || apiSecret == "" || zone == "" {
		t.Skip("Skipping test: DNSLA_API_ID, DNSLA_API_SECRET, and DNSLA_TEST_ZONE environment variables must be set")
	}

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
		rr := extractRR(record)
		recordID := extractID(record)
		t.Logf("%s %s (.%s): %s, %s\n", recordID, rr.Name, zone, rr.Data, rr.Type)
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

	recordID := extractID(createdRecord)
	t.Logf("Created record: \n%v\n", recordID)
}

func TestProvider_UpdateRecordsByLookup(t *testing.T) {
	provider, zone := getProvider(t)

	//Get records
	initialRecords := getInitialRecords(t, provider, zone)

	//_ = createOrGetTestRecord(t, provider, zone)

	ttl := 600 * time.Second
	testFullName := "libdns_test_record"

	updatedTestValue := "updated-test-value-by-lookup"
	// Update record
	updatedRecords, err := provider.SetRecords(context.TODO(), zone, []libdns.Record{
		libdns.TXT{
			Name: testFullName,
			TTL:  ttl,
			Text: updatedTestValue,
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
	testFullName := "libdns_test_record"

	updatedTestValue := "updated-test-value-by-lookup"

	// Delete record
	deleteRecords, err := provider.DeleteRecords(context.TODO(), zone, []libdns.Record{
		libdns.TXT{
			Name: testFullName,
			TTL:  ttl,
			Text: updatedTestValue,
		},
	})

	if err != nil {
		t.Error(err)
	}

	if len(deleteRecords) != 1 {
		t.Errorf("Deleted incorrect amount of records %d", len(deleteRecords))
	}

	t.Logf("Deleted record: \n%v\n", deleteRecords[0])
}
