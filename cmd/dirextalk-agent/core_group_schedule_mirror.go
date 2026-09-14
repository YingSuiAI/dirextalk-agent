package main

import (
	"context"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
)

// groupScheduleMirror publishes the group Agent's durable schedules to Product,
// which is the only place every member can read them: a member's client cannot
// reach the owner's Agent.
type groupScheduleMirror struct {
	product interface {
		RecordGroupSchedule(context.Context, capabilityclient.GroupAgentScheduleMirror) error
		RemoveGroupSchedule(context.Context, string, string) error
	}
}

func (m groupScheduleMirror) RecordGroupSchedule(ctx context.Context, record coreconversation.GroupScheduleMirrorRecord) error {
	if m.product == nil {
		return nil
	}
	return m.product.RecordGroupSchedule(ctx, capabilityclient.GroupAgentScheduleMirror{
		RoomID: record.RoomID, ScheduleID: record.ScheduleID, Name: record.Name,
		Capability: record.Capability, Cron: record.Cron, Timezone: record.Timezone,
		CreatedBy: record.CreatedBy, RunAt: mirrorScheduleTime(record.RunAt), NextRunAt: mirrorScheduleTime(record.NextRunAt),
	})
}

func (m groupScheduleMirror) RemoveGroupSchedule(ctx context.Context, roomID, scheduleID string) error {
	if m.product == nil {
		return nil
	}
	return m.product.RemoveGroupSchedule(ctx, roomID, scheduleID)
}

func mirrorScheduleTime(value *time.Time) string {
	if value == nil || value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}
