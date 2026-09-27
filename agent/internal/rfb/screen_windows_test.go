//go:build windows

package rfb

import (
	"testing"
	"unsafe"
)

// SendInput takes an array of INPUT structs by size: a wrong layout would silently do nothing.
func TestInputLayoutMatchesWindows(t *testing.T) {
	want := map[uintptr]uintptr{8: 40, 4: 28}[unsafe.Sizeof(uintptr(0))]
	if got := unsafe.Sizeof(input{}); got != want {
		t.Fatalf("INPUT is %d bytes, Windows expects %d", got, want)
	}
	if unsafe.Sizeof(keybdInput{}) > unsafe.Sizeof(mouseInput{}) {
		t.Fatal("KEYBDINPUT must fit in the INPUT union")
	}
	if off := unsafe.Offsetof(input{}.mi); off != map[uintptr]uintptr{8: 8, 4: 4}[unsafe.Sizeof(uintptr(0))] {
		t.Fatalf("the union starts at %d", off)
	}
}
