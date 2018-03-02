package main

import (
	"io"
	"sort"

	"honnef.co/go/js/dom"

	"golang.org/x/crypto/openpgp/armor"
)

func readArmored(r io.Reader, heading string) dom.Element {
	armored, err := armor.Decode(r)
	if err != nil {
		return formatError(err)
	}

	outer := formatWrapper(heading)

	outer.AppendChild(formatRow("Type", "%s", armored.Type))

	if len(armored.Header) != 0 {
		headers := formatWrapper("Headers")

		keys := make([]string, 0, len(armored.Header))
		for k := range armored.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			headers.AppendChild(formatRow(k, "%s", armored.Header[k]))
		}

		outer.AppendChild(headers)
	}

	outer.AppendChild(readBody(armored.Body, "Packets"))

	return outer
}
