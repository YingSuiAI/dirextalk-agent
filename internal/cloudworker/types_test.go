package cloudworker

import "testing"

func TestValidateComputeAcceptsProviderCapacityAboveRequestedMinimumLimits(t *testing.T) {
	compute := ComputeSpec{
		InstanceType: "p5.48xlarge", Architecture: "x86_64",
		AcceleratorType: AcceleratorGPU, AcceleratorName: "H100", AcceleratorMemoryMiB: 640 * 1024,
		VCPU: 192, MemoryGiB: 2048, RootDeviceName: "/dev/xvda",
		VolumeGiB: 600, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiB: 125,
	}
	if err := ValidatePublicCompute(compute); err != nil {
		t.Fatalf("large GPU provider capacity rejected: %v", err)
	}
}
