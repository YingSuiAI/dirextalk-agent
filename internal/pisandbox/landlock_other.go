//go:build !linux

package pisandbox

func CurrentABI() (uint32, error) { return 0, ErrUnsupported }

func Apply(policy Policy) error {
	if policy.Validate() != nil {
		return ErrInvalid
	}
	return ErrUnsupported
}
