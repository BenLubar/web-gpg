package main

import (
	"encoding/hex"
	"io/ioutil"
	"time"

	"golang.org/x/crypto/openpgp/packet"
	"honnef.co/go/js/dom"
)

func readLiteralData(p *packet.LiteralData) dom.Element {
	outer := formatWrapper("Literal Data")

	if p.FileName != "" {
		outer.AppendChild(formatRow("File Name", "%s", p.FileName))
	}
	if p.Time != 0 {
		outer.AppendChild(formatTime("Timestamp", time.Unix(int64(p.Time), 0).UTC()))
	}

	var data dom.Element

	body, err := ioutil.ReadAll(p.Body)
	if p.IsBinary {
		data = formatWrapper("Binary Data")

		pre := doc.CreateElement("pre")
		pre.Class().Add("hexdump")
		pre.SetTextContent(hex.Dump(body))

		data.AppendChild(pre)
	} else {
		data = formatWrapper("Raw Text")

		pre := doc.CreateElement("pre")
		pre.Class().Add("text")
		pre.SetTextContent(string(body))

		data.AppendChild(pre)
	}

	if err != nil {
		data.AppendChild(formatError(err))
	}

	outer.AppendChild(data)

	return outer
}

func readUserId(p *packet.UserId) dom.Element {
	outer := formatWrapper("User ID")

	if p.Id != packet.NewUserId(p.Name, p.Comment, p.Email).Id {
		outer.AppendChild(formatRow("ID", "%s", p.Id))
	}
	if p.Name != "" {
		outer.AppendChild(formatRow("Name", "%s", p.Name))
	}
	if p.Comment != "" {
		outer.AppendChild(formatRow("Comment", "%s", p.Comment))
	}
	if p.Email != "" {
		outer.AppendChild(formatRow("Email", "%s", p.Email))
	}

	return outer
}
