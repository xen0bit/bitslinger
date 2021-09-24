package mod

func Packet(p []byte) []byte {
	out := []byte("no")
	out = append(out, 0x0a)
	return out
}
