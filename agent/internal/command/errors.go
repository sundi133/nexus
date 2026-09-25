package command

import "fmt"

type execError struct {
	cmd string
	out string
	err error
}

func (e *execError) Error() string {
	if e.out != "" {
		return fmt.Sprintf("%s: %v: %s", e.cmd, e.err, e.out)
	}
	return fmt.Sprintf("%s: %v", e.cmd, e.err)
}
