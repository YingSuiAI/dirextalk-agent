package coretask

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestScheduleOutputRejectsUnboundedOrInvalidFailureProjection(t *testing.T) {
	now := time.Now().UTC()
	valid := ScheduleOutput{
		OccurrenceID: uuid.NewString(), ScheduleID: uuid.NewString(), TaskID: uuid.NewString(),
		ScheduledFor: now, Status: StatusCanceled, CreatedAt: now, UpdatedAt: now,
	}
	tests := []struct {
		name   string
		mutate func(*ScheduleOutput)
	}{
		{name: "oversized code", mutate: func(output *ScheduleOutput) { output.FailureCode = strings.Repeat("c", 129) }},
		{name: "invalid code UTF-8", mutate: func(output *ScheduleOutput) { output.FailureCode = string([]byte{0xff}) }},
		{name: "oversized summary", mutate: func(output *ScheduleOutput) { output.FailureSummary = strings.Repeat("s", MaxSummaryBytes+1) }},
		{name: "invalid summary UTF-8", mutate: func(output *ScheduleOutput) { output.FailureSummary = string([]byte{0xff}) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := valid
			test.mutate(&output)
			if output.Validate() == nil {
				t.Fatalf("invalid output was accepted: %+v", output)
			}
		})
	}
}
