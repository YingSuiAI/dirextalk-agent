package installer

import (
	"fmt"
	"os/user"
	"strconv"
)

type SystemIdentityResolver struct{}

func (SystemIdentityResolver) Resolve(userName string) (Identity, error) {
	account, err := user.Lookup(userName)
	if err != nil {
		return Identity{}, fmt.Errorf("lookup fixed service identity: %w", err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return Identity{}, fmt.Errorf("parse service uid: %w", err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return Identity{}, fmt.Errorf("parse service gid: %w", err)
	}
	if uid <= 0 || gid <= 0 {
		return Identity{}, fmt.Errorf("service identity must be unprivileged")
	}
	return Identity{UID: uid, GID: gid}, nil
}
