package mod

import "sort"

type sortRunes []rune

func (s sortRunes) Less(i, j int) bool {
	return s[i] < s[j]
}

func (s sortRunes) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s sortRunes) Len() int {
	return len(s)
}

func SortString(s string) string {
	r := []rune(s)
	sort.Sort(sortRunes(r))
	return string(r)
}

func Packet(p []byte) []byte {
	asString := string(p[:len(p)-1])
	sortedString := SortString(asString)
	out := []byte(sortedString)
	out = append(out, 0x0a)
	return out
}
