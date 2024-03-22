package tracetest

import (
	"strings"
	"unicode"

	// Force-load native and js packages, to trigger registration
	_ "github.com/XinFinOrg/XDPoSChain/eth/tracers/js"
	_ "github.com/XinFinOrg/XDPoSChain/eth/tracers/native"
)

// camel converts a snake cased input string into a camel cased output.
func camel(str string) string {
	pieces := strings.Split(str, "_")
	for i := 1; i < len(pieces); i++ {
		pieces[i] = string(unicode.ToUpper(rune(pieces[i][0]))) + pieces[i][1:]
	}
	return strings.Join(pieces, "")
}
