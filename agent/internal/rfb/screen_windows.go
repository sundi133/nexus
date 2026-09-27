//go:build windows

package rfb

import (
	"errors"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32 = windows.NewLazySystemDLL("user32.dll")
	gdi32  = windows.NewLazySystemDLL("gdi32.dll")

	procGetSystemMetrics   = user32.NewProc("GetSystemMetrics")
	procGetDC              = user32.NewProc("GetDC")
	procReleaseDC          = user32.NewProc("ReleaseDC")
	procSendInput          = user32.NewProc("SendInput")
	procSetProcessDPIAware = user32.NewProc("SetProcessDPIAware")
	procCreateCompatibleDC = gdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection   = gdi32.NewProc("CreateDIBSection")
	procSelectObject       = gdi32.NewProc("SelectObject")
	procBitBlt             = gdi32.NewProc("BitBlt")
	procDeleteObject       = gdi32.NewProc("DeleteObject")
	procDeleteDC           = gdi32.NewProc("DeleteDC")
)

const (
	smXVirtualScreen  = 76
	smYVirtualScreen  = 77
	smCXVirtualScreen = 78
	smCYVirtualScreen = 79
	srcCopy           = 0x00CC0020
	captureBlt        = 0x40000000

	inputMouse    = 0
	inputKeyboard = 1

	mouseMove       = 0x0001
	mouseLeftDown   = 0x0002
	mouseLeftUp     = 0x0004
	mouseRightDown  = 0x0008
	mouseRightUp    = 0x0010
	mouseMiddleDown = 0x0020
	mouseMiddleUp   = 0x0040
	mouseWheel      = 0x0800
	mouseVirtual    = 0x4000
	mouseAbsolute   = 0x8000

	keyExtended = 0x0001
	keyUp       = 0x0002
	keyUnicode  = 0x0004
)

type bitmapInfoHeader struct {
	size          uint32
	width, height int32
	planes        uint16
	bitCount      uint16
	compression   uint32
	sizeImage     uint32
	xPPM, yPPM    int32
	clrUsed       uint32
	clrImportant  uint32
}

type mouseInput struct {
	dx, dy    int32
	mouseData uint32
	flags     uint32
	time      uint32
	extra     uintptr
}

type keybdInput struct {
	vk, scan uint16
	flags    uint32
	time     uint32
	extra    uintptr
}

// input is Windows' INPUT: a type and a union, sized by its largest member (MOUSEINPUT).
type input struct {
	typ uint32
	mi  mouseInput
}

func metric(i uintptr) int {
	v, _, _ := procGetSystemMetrics.Call(i)
	return int(int32(v))
}

// WindowsScreen is the signed-in person's desktop (every monitor), captured with GDI, with input
// through SendInput. It must run in their session, not the service's.
type WindowsScreen struct {
	mu      sync.Mutex
	x, y    int // the virtual desktop's top-left (it can be negative)
	w, h    int
	buttons uint8
}

// NewWindowsScreen measures the virtual desktop. Call it from a process in the user's session.
func NewWindowsScreen() (*WindowsScreen, error) {
	_, _, _ = procSetProcessDPIAware.Call() // real pixels, not scaled ones
	s := &WindowsScreen{x: metric(smXVirtualScreen), y: metric(smYVirtualScreen), w: metric(smCXVirtualScreen), h: metric(smCYVirtualScreen)}
	if s.w <= 0 || s.h <= 0 {
		return nil, errors.New("no desktop to capture (is anyone signed in?)")
	}
	return s, nil
}

func (s *WindowsScreen) Size() (int, int) { return s.w, s.h }

func (s *WindowsScreen) Capture(dst []byte) error {
	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return errors.New("GetDC failed")
	}
	defer procReleaseDC.Call(0, screenDC)
	memDC, _, _ := procCreateCompatibleDC.Call(screenDC)
	if memDC == 0 {
		return errors.New("CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(memDC)
	bi := struct {
		h      bitmapInfoHeader
		colors [4]byte
	}{h: bitmapInfoHeader{width: int32(s.w), height: -int32(s.h), planes: 1, bitCount: 32}} // top-down rows
	bi.h.size = uint32(unsafe.Sizeof(bi.h))
	var bits unsafe.Pointer
	bmp, _, _ := procCreateDIBSection.Call(memDC, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if bmp == 0 || bits == nil {
		return errors.New("CreateDIBSection failed")
	}
	defer procDeleteObject.Call(bmp)
	old, _, _ := procSelectObject.Call(memDC, bmp)
	defer procSelectObject.Call(memDC, old)
	// Fails on the secure desktop (lock screen, UAC prompts): the viewer keeps the last picture.
	if ok, _, _ := procBitBlt.Call(memDC, 0, 0, uintptr(s.w), uintptr(s.h), screenDC, uintptr(s.x), uintptr(s.y), srcCopy|captureBlt); ok == 0 {
		return nil
	}
	copy(dst, unsafe.Slice((*byte)(bits), s.w*s.h*4))
	return nil
}

func send(in []input) {
	if len(in) > 0 {
		_, _, _ = procSendInput.Call(uintptr(len(in)), uintptr(unsafe.Pointer(&in[0])), unsafe.Sizeof(in[0]))
	}
}

func (s *WindowsScreen) Pointer(x, y int, buttons uint8) {
	s.mu.Lock()
	prev := s.buttons
	s.buttons = buttons &^ 0x18 // the wheel "buttons" are clicks, not held
	s.mu.Unlock()
	// Absolute positions on the virtual desktop are scaled to 0–65535.
	dx := int32(x * 65535 / max(1, s.w-1))
	dy := int32(y * 65535 / max(1, s.h-1))
	ins := []input{{typ: inputMouse, mi: mouseInput{dx: dx, dy: dy, flags: mouseMove | mouseAbsolute | mouseVirtual}}}
	for _, b := range []struct {
		bit      uint8
		down, up uint32
	}{{1, mouseLeftDown, mouseLeftUp}, {2, mouseMiddleDown, mouseMiddleUp}, {4, mouseRightDown, mouseRightUp}} {
		switch {
		case buttons&b.bit != 0 && prev&b.bit == 0:
			ins = append(ins, input{typ: inputMouse, mi: mouseInput{flags: b.down}})
		case buttons&b.bit == 0 && prev&b.bit != 0:
			ins = append(ins, input{typ: inputMouse, mi: mouseInput{flags: b.up}})
		}
	}
	if buttons&8 != 0 {
		ins = append(ins, input{typ: inputMouse, mi: mouseInput{flags: mouseWheel, mouseData: 120}})
	}
	if buttons&16 != 0 {
		ins = append(ins, input{typ: inputMouse, mi: mouseInput{flags: mouseWheel, mouseData: uint32(0xFFFFFF88)}}) // -120
	}
	send(ins)
}

func keyInput(k keybdInput) input {
	var in input
	in.typ = inputKeyboard
	*(*keybdInput)(unsafe.Pointer(&in.mi)) = k
	return in
}

func (s *WindowsScreen) Key(keysym uint32, down bool) {
	k, ok := KeysymToKey(keysym)
	if !ok {
		return
	}
	var up uint32
	if !down {
		up = keyUp
	}
	if k.VK != 0 {
		flags := up
		if k.Extended {
			flags |= keyExtended
		}
		send([]input{keyInput(keybdInput{vk: k.VK, flags: flags})})
		return
	}
	// A character: typed as UTF-16 code units.
	var ins []input
	for _, u := range windows.StringToUTF16(string(k.Char)) {
		if u != 0 {
			ins = append(ins, keyInput(keybdInput{scan: u, flags: keyUnicode | up}))
		}
	}
	send(ins)
}
