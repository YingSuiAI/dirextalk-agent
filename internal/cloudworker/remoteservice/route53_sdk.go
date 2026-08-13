package remoteservice

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Route53API interface {
	ListHostedZones(context.Context, *route53.ListHostedZonesInput, ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ChangeResourceRecordSets(context.Context, *route53.ChangeResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error)
	ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

type Route53STSAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// Route53SDK uses the App-provided AWS credentials. Route 53 records point
// directly to the Worker's ordinary public IPv4; this adapter never allocates
// or manages an Elastic IP.
type Route53SDK struct {
	route53 Route53API
	sts     Route53STSAPI
}

func NewRoute53SDK(config aws.Config) (*Route53SDK, error) {
	if config.Credentials == nil {
		return nil, ErrInvalid
	}
	return newRoute53SDK(route53.NewFromConfig(config), sts.NewFromConfig(config)), nil
}

func newRoute53SDK(route53Client Route53API, stsClient Route53STSAPI) *Route53SDK {
	return &Route53SDK{route53: route53Client, sts: stsClient}
}

func (client *Route53SDK) VerifyAccount(ctx context.Context, accountID string) error {
	if client == nil || client.sts == nil || !validAccountID(accountID) {
		return ErrInvalid
	}
	identity, err := client.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return err
	}
	if identity == nil || aws.ToString(identity.Account) != accountID {
		return ErrReadback
	}
	return nil
}

// ResolveHostedZone selects the public hosted zone with the longest suffix
// match for hostname. Duplicate matching zones are resolved by hosted-zone ID
// so the result is stable regardless of AWS page ordering.
func (client *Route53SDK) ResolveHostedZone(ctx context.Context, hostname string) (string, bool, error) {
	if client == nil || client.route53 == nil || !validHostname(hostname) {
		return "", false, ErrInvalid
	}
	hostname = canonicalHostname(hostname)
	type match struct{ name, id string }
	var matches []match
	var marker *string
	for {
		page, err := client.route53.ListHostedZones(ctx, &route53.ListHostedZonesInput{Marker: marker})
		if err != nil {
			return "", false, err
		}
		if page == nil {
			return "", false, ErrReadback
		}
		for _, zone := range page.HostedZones {
			if zone.Config != nil && zone.Config.PrivateZone {
				continue
			}
			name := canonicalHostname(aws.ToString(zone.Name))
			id := canonicalZoneID(aws.ToString(zone.Id))
			if validHostname(name) && safeToken(id, 128) && (hostname == name || strings.HasSuffix(hostname, "."+name)) {
				matches = append(matches, match{name: name, id: id})
			}
		}
		if !page.IsTruncated {
			break
		}
		if aws.ToString(page.NextMarker) == "" {
			return "", false, ErrReadback
		}
		marker = page.NextMarker
	}
	if len(matches) == 0 {
		return "", false, nil
	}
	sort.Slice(matches, func(i, j int) bool {
		if len(matches[i].name) != len(matches[j].name) {
			return len(matches[i].name) > len(matches[j].name)
		}
		return matches[i].id < matches[j].id
	})
	return matches[0].id, true, nil
}

func (client *Route53SDK) UpsertA(ctx context.Context, mutation DNSMutation) error {
	if mutation.Action != DNSUpsertA || mutation.validate() != nil {
		return ErrInvalid
	}
	return client.changeA(ctx, mutation.Record, route53types.ChangeActionUpsert)
}

func (client *Route53SDK) DeleteA(ctx context.Context, mutation DNSMutation) error {
	if mutation.Action != DNSDeleteA || mutation.validate() != nil {
		return ErrInvalid
	}
	return client.changeA(ctx, mutation.Record, route53types.ChangeActionDelete)
}

func (client *Route53SDK) changeA(ctx context.Context, record ARecord, action route53types.ChangeAction) error {
	if client == nil || client.route53 == nil {
		return ErrInvalid
	}
	_, err := client.route53.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(canonicalZoneID(record.ZoneID)),
		ChangeBatch: &route53types.ChangeBatch{Changes: []route53types.Change{{
			Action: action,
			ResourceRecordSet: &route53types.ResourceRecordSet{
				Name: aws.String(canonicalHostname(record.Hostname)), Type: route53types.RRTypeA,
				TTL: aws.Int64(int64(record.TTL)), ResourceRecords: []route53types.ResourceRecord{{Value: aws.String(record.IPv4)}},
			},
		}}},
	})
	return err
}

func (client *Route53SDK) ReadA(ctx context.Context, zoneID, hostname string) (ARecord, bool, error) {
	if client == nil || client.route53 == nil || !safeToken(zoneID, 128) || !validHostname(hostname) {
		return ARecord{}, false, ErrInvalid
	}
	hostname = canonicalHostname(hostname)
	page, err := client.route53.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(canonicalZoneID(zoneID)), StartRecordName: aws.String(hostname),
		StartRecordType: route53types.RRTypeA, MaxItems: aws.Int32(1),
	})
	if err != nil {
		return ARecord{}, false, err
	}
	if page == nil || len(page.ResourceRecordSets) == 0 {
		return ARecord{}, false, nil
	}
	record := page.ResourceRecordSets[0]
	if canonicalHostname(aws.ToString(record.Name)) != hostname || record.Type != route53types.RRTypeA {
		return ARecord{}, false, nil
	}
	if record.AliasTarget != nil || len(record.ResourceRecords) != 1 || record.TTL == nil || *record.TTL < 0 || *record.TTL > int64(^uint32(0)) {
		return ARecord{}, false, ErrReadback
	}
	address, err := netip.ParseAddr(aws.ToString(record.ResourceRecords[0].Value))
	if err != nil || !address.Is4() {
		return ARecord{}, false, errors.Join(ErrReadback, err)
	}
	return ARecord{ZoneID: zoneID, Hostname: hostname, IPv4: address.String(), TTL: uint32(*record.TTL)}, true, nil
}

func canonicalZoneID(value string) string {
	return strings.TrimPrefix(value, "/hostedzone/")
}
