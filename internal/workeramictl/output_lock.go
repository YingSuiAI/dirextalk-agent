package workeramictl

import "os"

const buildOutputLockSuffix = ".lock"

func acquireBuildOutputLock(outputPath string) (*os.File, error) {
	if !validLocalPath(outputPath) {
		return nil, errInvalidInput
	}
	lock, err := openBuildOutputLock(outputPath + buildOutputLockSuffix)
	if err != nil {
		return nil, errOutput
	}
	if err := tryLockBuildOutput(lock); err != nil {
		_ = lock.Close()
		return nil, errOutput
	}
	return lock, nil
}

func releaseBuildOutputLock(lock *os.File) error {
	if lock == nil {
		return errOutput
	}
	unlockErr := unlockBuildOutput(lock)
	closeErr := lock.Close()
	if unlockErr != nil || closeErr != nil {
		return errOutput
	}
	return nil
}
