package cloudworker

import (
	"fmt"
	"strings"
)

// PublicComputeSummary returns a bounded, secret-free description suitable
// for durable transcript text and transient model context.
func PublicComputeSummary(compute ComputeSpec) string {
	parts := []string{compute.InstanceType}
	if compute.AcceleratorType != "" {
		accelerator := strings.ToUpper(compute.AcceleratorType)
		if compute.AcceleratorName != "" {
			accelerator += " " + compute.AcceleratorName
		}
		if compute.AcceleratorMemoryMiB != 0 {
			accelerator += fmt.Sprintf(" (%s accelerator memory)", formatMemoryMiB(compute.AcceleratorMemoryMiB))
		}
		parts = append(parts, accelerator)
	}
	parts = append(parts,
		fmt.Sprintf("%d vCPU", compute.VCPU),
		fmt.Sprintf("%d GiB system memory", compute.MemoryGiB),
		fmt.Sprintf("%d GiB %s storage", compute.VolumeGiB, compute.VolumeType),
	)
	return strings.Join(parts, "; ")
}

func formatMemoryMiB(value uint64) string {
	if value%1024 == 0 {
		return fmt.Sprintf("%d GiB", value/1024)
	}
	return fmt.Sprintf("%.2f GiB", float64(value)/1024)
}
