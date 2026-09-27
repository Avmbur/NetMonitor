//go:build !linux

package collect

func ReadSSHFailures(cursor string) (hits []SSHFail, next string, err error) {
	return nil, cursor, nil
}
