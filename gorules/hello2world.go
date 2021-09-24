package mod

func Packet(p []byte) []byte {
	out := []byte("world")
	out = append(out, 0x0a)
	return out
}
