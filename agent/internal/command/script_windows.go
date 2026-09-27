package command

import "os/exec"

// setProcessGroup: on Windows the context kills the interpreter itself.
func setProcessGroup(*exec.Cmd) {}
