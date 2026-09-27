package settings

import "os"

func (OS) ReadFile(path string) ([]byte, error)     { return os.ReadFile(path) }
func (OS) WriteFile(path string, data []byte) error { return os.WriteFile(path, data, 0o644) }
func (OS) MkdirAll(path string) error               { return os.MkdirAll(path, 0o755) }
