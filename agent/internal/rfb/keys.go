package rfb

// Windows virtual-key codes for the X11 keysyms viewers send for keys that aren't characters.
var specialVK = map[uint32]uint16{
	0xff08: 0x08, // BackSpace
	0xff09: 0x09, // Tab
	0xff0d: 0x0d, // Return
	0xff1b: 0x1b, // Escape
	0xff13: 0x13, // Pause
	0xff14: 0x91, // Scroll_Lock
	0xff61: 0x2c, // Print
	0xffff: 0x2e, // Delete
	0xff50: 0x24, // Home
	0xff51: 0x25, // Left
	0xff52: 0x26, // Up
	0xff53: 0x27, // Right
	0xff54: 0x28, // Down
	0xff55: 0x21, // Page_Up
	0xff56: 0x22, // Page_Down
	0xff57: 0x23, // End
	0xff63: 0x2d, // Insert
	0xff67: 0x5d, // Menu
	0xff7f: 0x90, // Num_Lock
	0xffe5: 0x14, // Caps_Lock
	0xffe1: 0xa0, // Shift_L
	0xffe2: 0xa1, // Shift_R
	0xffe3: 0xa2, // Control_L
	0xffe4: 0xa3, // Control_R
	0xffe9: 0xa4, // Alt_L
	0xffea: 0xa5, // Alt_R
	0xffe7: 0x5b, // Meta_L (the Windows key, from a Mac keyboard's Command)
	0xffe8: 0x5c, // Meta_R
	0xffeb: 0x5b, // Super_L
	0xffec: 0x5c, // Super_R
	0xff8d: 0x0d, // KP_Enter
	0xffaa: 0x6a, // KP_Multiply
	0xffab: 0x6b, // KP_Add
	0xffad: 0x6d, // KP_Subtract
	0xffae: 0x6e, // KP_Decimal
	0xffaf: 0x6f, // KP_Divide
}

// Extended keys need KEYEVENTF_EXTENDEDKEY on Windows, or they act as their number-pad twins.
var extendedVK = map[uint16]bool{0x21: true, 0x22: true, 0x23: true, 0x24: true, 0x25: true, 0x26: true, 0x27: true, 0x28: true, 0x2d: true, 0x2e: true, 0xa3: true, 0xa5: true, 0x5b: true, 0x5c: true, 0x5d: true, 0x6f: true}

// Key is what to press on Windows for an X11 keysym: a virtual key, or failing that a character.
type Key struct {
	VK       uint16
	Extended bool
	Char     rune // when VK is 0: typed as a Unicode character
}

// KeysymToKey maps a keysym. Letters and digits become their virtual keys, so shortcuts like
// Ctrl+C work; other characters are typed as Unicode.
func KeysymToKey(k uint32) (Key, bool) {
	if vk, ok := specialVK[k]; ok {
		return Key{VK: vk, Extended: extendedVK[vk]}, true
	}
	switch {
	case k >= 0xffbe && k <= 0xffc9: // F1–F12
		return Key{VK: uint16(0x70 + k - 0xffbe)}, true
	case k >= 0xffb0 && k <= 0xffb9: // KP_0–KP_9
		return Key{VK: uint16(0x60 + k - 0xffb0)}, true
	case k >= 'a' && k <= 'z':
		return Key{VK: uint16(k - 'a' + 'A')}, true
	case k >= 'A' && k <= 'Z', k >= '0' && k <= '9':
		return Key{VK: uint16(k)}, true
	case k == ' ':
		return Key{VK: 0x20}, true
	case k >= 0x20 && k <= 0xff: // the rest of Latin-1 is the same in Unicode
		return Key{Char: rune(k)}, true
	case k >= 0x1000100 && k <= 0x110ffff: // keysyms that carry a Unicode code point
		return Key{Char: rune(k - 0x1000000)}, true
	}
	return Key{}, false
}
