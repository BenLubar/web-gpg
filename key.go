package main

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"net/http"

	humanize "github.com/dustin/go-humanize"

	"golang.org/x/crypto/openpgp/packet"

	"honnef.co/go/js/dom"
)

type cachedKey struct {
	data []byte
	err  error
}

var keyCache = make(map[uint64]cachedKey)

func getPublicKeyRaw(keyID uint64) ([]byte, error) {
	if cached, ok := keyCache[keyID]; ok {
		return cached.data, cached.err
	}

	resp, err := http.Get(fmt.Sprintf("https://pgp.mit.edu/pks/lookup?op=get&search=0x%016X&options=mr", keyID))
	if err != nil {
		keyCache[keyID] = cachedKey{err: err}
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err == nil && resp.StatusCode >= 400 {
		err = fmt.Errorf("HTTP status code indicates failure: %s\n%s", resp.Status, body)
	}

	keyCache[keyID] = cachedKey{data: body, err: err}
	return body, err
}

func formatPublicKey(keyID uint64) dom.Element {
	btn := doc.CreateElement("button")
	btn.SetTextContent("Retrieve Public Key")
	btn.AddEventListener("click", false, func(e dom.Event) {
		e.PreventDefault()

		go func() {
			var replacement dom.Element

			data, err := getPublicKeyRaw(keyID)
			if err != nil {
				replacement = formatError(err)
			} else {
				replacement = readArmored(bytes.NewReader(data), "Retrieved Public Key")
			}

			btn.ParentElement().ReplaceChild(replacement, btn)
		}()
	})
	return btn
}

func readPublicKey(p *packet.PublicKey) dom.Element {
	outer := formatWrapper("Public Key")

	outer.AppendChild(formatTime("Creation Time", p.CreationTime))
	outer.AppendChild(formatPublicKeyAlgorithm("Public Key Algorithm", p.PubKeyAlgo))
	outer.AppendChild(formatRow("Fingerprint", "% 02X", p.Fingerprint))
	outer.AppendChild(formatRow("Key ID", "0x%016X", p.KeyId))
	outer.AppendChild(formatRow("Is Subkey", "%v", p.IsSubkey))

	switch key := p.PublicKey.(type) {
	case *rsa.PublicKey:
		inner := formatWrapper("RSA Key")

		inner.AppendChild(formatBigInt("Exponent", key.N))
		inner.AppendChild(formatRow("Modulus", "%s", humanize.Comma(int64(key.E))))

		outer.AppendChild(inner)
	//case *dsa.PublicKey:
	//case *ecdsa.PublicKey:
	default:
		outer.AppendChild(formatError(fmt.Errorf("unhandled public key type: %T", key)))
	}

	return outer
}
