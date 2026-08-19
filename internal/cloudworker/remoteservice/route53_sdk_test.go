package remoteservice

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type fakeRoute53API struct {
	zones   []*route53.ListHostedZonesOutput
	changes []*route53.ChangeResourceRecordSetsInput
	records []route53types.ResourceRecordSet
}

func (client *fakeRoute53API) ListHostedZones(_ context.Context, input *route53.ListHostedZonesInput, _ ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	if input.Marker == nil {
		return client.zones[0], nil
	}
	return client.zones[1], nil
}

func (client *fakeRoute53API) ChangeResourceRecordSets(_ context.Context, input *route53.ChangeResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	client.changes = append(client.changes, input)
	return &route53.ChangeResourceRecordSetsOutput{}, nil
}

func (client *fakeRoute53API) ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: client.records}, nil
}

type fakeRoute53STS struct{ accountID string }

func (client fakeRoute53STS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String(client.accountID)}, nil
}

func TestRoute53SDKResolvesLongestPublicZoneDeterministically(t *testing.T) {
	api := &fakeRoute53API{zones: []*route53.ListHostedZonesOutput{
		{HostedZones: []route53types.HostedZone{
			{Id: aws.String("/hostedzone/Z-PARENT"), Name: aws.String("example.com.")},
			{Id: aws.String("/hostedzone/Z-PRIVATE"), Name: aws.String("api.example.com."), Config: &route53types.HostedZoneConfig{PrivateZone: true}},
		}, IsTruncated: true, NextMarker: aws.String("next")},
		{HostedZones: []route53types.HostedZone{
			{Id: aws.String("/hostedzone/Z-SECOND"), Name: aws.String("api.example.com.")},
			{Id: aws.String("/hostedzone/Z-FIRST"), Name: aws.String("api.example.com.")},
		}},
	}}
	client := newRoute53SDK(api, fakeRoute53STS{accountID: "123456789012"})
	zoneID, found, err := client.ResolveHostedZone(context.Background(), "App.API.Example.Com.")
	if err != nil || !found || zoneID != "Z-FIRST" {
		t.Fatalf("ResolveHostedZone = %q, %v, %v", zoneID, found, err)
	}
}

func TestRoute53SDKRejectsPrivateOnlyAndNonMatchingZonesWithoutWrite(t *testing.T) {
	tests := []struct {
		name  string
		zones []route53types.HostedZone
	}{
		{name: "private only", zones: []route53types.HostedZone{{
			Id: aws.String("/hostedzone/Z-PRIVATE"), Name: aws.String("example.com."), Config: &route53types.HostedZoneConfig{PrivateZone: true},
		}}},
		{name: "non matching public zone", zones: []route53types.HostedZone{{
			Id: aws.String("/hostedzone/Z-OTHER"), Name: aws.String("other.example."),
		}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := &fakeRoute53API{zones: []*route53.ListHostedZonesOutput{{HostedZones: test.zones}}}
			client := newRoute53SDK(api, fakeRoute53STS{accountID: "123456789012"})
			zoneID, found, err := client.ResolveHostedZone(context.Background(), "app.example.com")
			if err != nil || found || zoneID != "" || len(api.changes) != 0 {
				t.Fatalf("zone=%q found=%v err=%v writes=%d", zoneID, found, err, len(api.changes))
			}
		})
	}
}

func TestRoute53SDKWritesAndReadsExactARecord(t *testing.T) {
	api := &fakeRoute53API{records: []route53types.ResourceRecordSet{{
		Name: aws.String("app.example.com."), Type: route53types.RRTypeA, TTL: aws.Int64(300),
		ResourceRecords: []route53types.ResourceRecord{{Value: aws.String("203.0.113.10")}},
	}}}
	client := newRoute53SDK(api, fakeRoute53STS{accountID: "123456789012"})
	if err := client.VerifyAccount(context.Background(), "123456789012"); err != nil {
		t.Fatal(err)
	}
	for _, action := range []DNSAction{DNSUpsertA, DNSDeleteA} {
		mutation := dnsFixture(action)
		var err error
		if action == DNSUpsertA {
			err = client.UpsertA(context.Background(), mutation)
		} else {
			err = client.DeleteA(context.Background(), mutation)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(api.changes) != 2 {
		t.Fatalf("changes = %d", len(api.changes))
	}
	for index, action := range []route53types.ChangeAction{route53types.ChangeActionUpsert, route53types.ChangeActionDelete} {
		input := api.changes[index]
		change := input.ChangeBatch.Changes[0]
		record := change.ResourceRecordSet
		if aws.ToString(input.HostedZoneId) != "Z0123456789" || change.Action != action || aws.ToString(record.Name) != "app.example.com" ||
			record.Type != route53types.RRTypeA || aws.ToInt64(record.TTL) != 300 || len(record.ResourceRecords) != 1 || aws.ToString(record.ResourceRecords[0].Value) != "203.0.113.10" {
			t.Fatalf("change[%d] = %#v", index, input)
		}
	}
	record, found, err := client.ReadA(context.Background(), "/hostedzone/Z0123456789", "App.Example.Com.")
	if err != nil || !found || record != (ARecord{ZoneID: "/hostedzone/Z0123456789", Hostname: "app.example.com", IPv4: "203.0.113.10", TTL: 300}) {
		t.Fatalf("ReadA = %#v, %v, %v", record, found, err)
	}
}
