package installer

import "testing"

func TestParseFixedUnitStateIsOrderIndependentAndExact(t *testing.T) {
	t.Parallel()
	for _, output := range []string{
		"LoadState=loaded\nActiveState=inactive\n",
		"ActiveState=inactive\nLoadState=loaded\n",
	} {
		state, err := parseFixedUnitState(output)
		if err != nil {
			t.Fatal(err)
		}
		if state != (UnitState{LoadState: "loaded", ActiveState: "inactive"}) {
			t.Fatalf("state = %#v", state)
		}
	}
	for _, output := range []string{
		"",
		"LoadState=loaded\n",
		"LoadState=loaded\nActiveState=inactive\nUnknown=value\n",
		"LoadState=loaded\nLoadState=loaded\nActiveState=inactive\n",
	} {
		if _, err := parseFixedUnitState(output); err == nil {
			t.Fatalf("accepted invalid output %q", output)
		}
	}
}
