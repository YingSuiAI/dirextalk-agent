//go:build linux

package main

import (
	"github.com/YingSuiAI/dirextalk-agent/internal/pisandbox"
	"golang.org/x/sys/unix"
)

type identitySnapshot struct {
	RealUID      int
	EffectiveUID int
	SavedUID     int
	RealGID      int
	EffectiveGID int
	SavedGID     int
	Groups       []int
}

func validateWorkerIdentity() error {
	realUID, effectiveUID, savedUID := unix.Getresuid()
	realGID, effectiveGID, savedGID := unix.Getresgid()
	groups, err := unix.Getgroups()
	if err != nil || !validWorkerIdentity(identitySnapshot{
		RealUID: realUID, EffectiveUID: effectiveUID, SavedUID: savedUID,
		RealGID: realGID, EffectiveGID: effectiveGID, SavedGID: savedGID, Groups: groups,
	}) {
		return errConfig
	}
	return nil
}

func validWorkerIdentity(identity identitySnapshot) bool {
	if identity.RealUID != pisandbox.OfficialWorkerUID || identity.EffectiveUID != pisandbox.OfficialWorkerUID ||
		identity.SavedUID != pisandbox.OfficialWorkerUID || identity.RealGID != pisandbox.OfficialWorkerGID ||
		identity.EffectiveGID != pisandbox.OfficialWorkerGID || identity.SavedGID != pisandbox.OfficialWorkerGID {
		return false
	}
	for _, group := range identity.Groups {
		if group != pisandbox.OfficialWorkerGID {
			return false
		}
	}
	return true
}
