//go:build linux

package main

import (
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/pisandbox"
)

func TestValidWorkerIdentityRequiresDistinctOfficialNumericIdentity(t *testing.T) {
	valid := identitySnapshot{
		RealUID: pisandbox.OfficialWorkerUID, EffectiveUID: pisandbox.OfficialWorkerUID, SavedUID: pisandbox.OfficialWorkerUID,
		RealGID: pisandbox.OfficialWorkerGID, EffectiveGID: pisandbox.OfficialWorkerGID, SavedGID: pisandbox.OfficialWorkerGID,
		Groups: []int{pisandbox.OfficialWorkerGID},
	}
	if !validWorkerIdentity(valid) {
		t.Fatal("official Worker identity was rejected")
	}
	for name, mutate := range map[string]func(*identitySnapshot){
		"Pi UID":        func(value *identitySnapshot) { value.EffectiveUID = pisandbox.OfficialPiUID },
		"wrong GID":     func(value *identitySnapshot) { value.SavedGID = 0 },
		"foreign group": func(value *identitySnapshot) { value.Groups = append(value.Groups, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Groups = append([]int(nil), valid.Groups...)
			mutate(&candidate)
			if validWorkerIdentity(candidate) {
				t.Fatalf("unsafe identity accepted: %+v", candidate)
			}
		})
	}
}
