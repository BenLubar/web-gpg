package main

import (
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"honnef.co/go/js/dom"
)

func readBody(r io.Reader, heading string) dom.Element {
	outer := formatWrapper(heading)

	var ops hash.Hash
	var pub *packet.PublicKey
	var uid *packet.UserId

	packets := packet.NewReader(r)
	for {
		pkt, err := packets.Next()
		if err != nil {
			if err != io.EOF {
				outer.AppendChild(formatError(err))
			}
			break
		}

		switch p := pkt.(type) {
		case *packet.Compressed:
			packets.Push(p.Body)
		case *packet.LiteralData:
			if ops != nil {
				p.Body = io.TeeReader(p.Body, ops)
			}
			outer.AppendChild(readLiteralData(p))
		case *packet.OnePassSignature:
			if pub != nil {
				outer.AppendChild(formatError(errors.New("unexpected OnePassSignature")))
			} else if ops != nil {
				outer.AppendChild(formatError(errors.New("already processing OnePassSignature")))
			} else if p.SigType == packet.SigTypeBinary {
				ops = p.Hash.New()
			} else if p.SigType == packet.SigTypeText {
				ops = openpgp.NewCanonicalTextHash(p.Hash.New())
			} else {
				outer.AppendChild(formatError(errors.New("unhandled OnePassSignature type")))
			}

			outer.AppendChild(readOnePassSignature(p))
		case *packet.PublicKey:
			if ops != nil {
				outer.AppendChild(formatError(errors.New("unexpected public key")))
			} else {
				pub = p
				uid = nil
			}
			outer.AppendChild(readPublicKey(p))
		case *packet.Signature:
			if ops != nil {
				outer.AppendChild(checkSignatureOnePass(p, ops))
				ops = nil
			} else if pub != nil {
				outer.AppendChild(checkSignaturePublicKey(p, pub, uid))
			} else {
				outer.AppendChild(formatError(errors.New("warning: signature was not verified")))
			}
			outer.AppendChild(readSignature(p))
		case *packet.UserId:
			if pub != nil {
				uid = p
			}
			outer.AppendChild(readUserId(p))
		default:
			outer.AppendChild(formatError(fmt.Errorf("unhandled packet type: %T", p)))
		}
	}

	return outer
}
