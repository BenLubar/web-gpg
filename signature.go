package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"honnef.co/go/js/dom"
)

func readOnePassSignature(p *packet.OnePassSignature) dom.Element {
	outer := formatWrapper("One-Pass Signature")

	outer.AppendChild(formatSignatureType("Signature Type", p.SigType))
	outer.AppendChild(formatHashAlgorithm("Hash Algorithm", p.Hash))
	outer.AppendChild(formatPublicKeyAlgorithm("Public Key Algorithm", p.PubKeyAlgo))
	outer.AppendChild(formatRow("Key ID", "0x%016X", p.KeyId))
	outer.AppendChild(formatRow("Is Last", "%v", p.IsLast))

	outer.AppendChild(formatPublicKey(p.KeyId))

	return outer
}

func readSignature(p *packet.Signature) dom.Element {
	outer := formatWrapper("Signature")

	outer.AppendChild(formatSignatureType("Signature Type", p.SigType))
	outer.AppendChild(formatPublicKeyAlgorithm("Public Key Algorithm", p.PubKeyAlgo))
	outer.AppendChild(formatHashAlgorithm("Hash Algorithm", p.Hash))

	if len(p.HashSuffix) != 0 {
		inner := formatRow("Extra Data to Hash", "")

		pre := doc.CreateElement("pre")
		pre.Class().Add("hexdump")
		pre.SetTextContent(hex.Dump(p.HashSuffix))

		inner.LastChild().AppendChild(pre)
		outer.AppendChild(inner)
	}

	outer.AppendChild(formatRow("First Two Bytes of Hash", "% 02X", p.HashTag))
	outer.AppendChild(formatTime("Creation Time", p.CreationTime))
	if p.IssuerKeyId != nil {
		outer.AppendChild(formatRow("Issuer Key ID", "0x%016X", *p.IssuerKeyId))
		outer.AppendChild(formatPublicKey(*p.IssuerKeyId))
	}

	if p.FlagsValid {
		flags := make([]string, 0, 4)
		if p.FlagCertify {
			flags = append(flags, "certify")
		}
		if p.FlagSign {
			flags = append(flags, "sign")
		}
		if p.FlagEncryptCommunications {
			flags = append(flags, "encrypt communications")
		}
		if p.FlagEncryptStorage {
			flags = append(flags, "encrypt storage")
		}

		outer.AppendChild(formatRow("Flags", "%s", strings.Join(flags, ", ")))
	}

	/*
		type Signature struct {
			// The following are optional so are nil when not included in the
			// signature.

			SigLifetimeSecs, KeyLifetimeSecs                        *uint32
			PreferredSymmetric, PreferredHash, PreferredCompression []uint8
			IsPrimaryId                                             *bool

			// RevocationReason is set if this signature has been revoked.
			// See RFC 4880, section 5.2.3.23 for details.
			RevocationReason     *uint8
			RevocationReasonText string

			// MDC is set if this signature has a feature packet that indicates
			// support for MDC subpackets.
			MDC bool
		}
	*/

	if p.EmbeddedSignature != nil {
		inner := readSignature(p.EmbeddedSignature)
		inner.FirstChild().SetTextContent("Embedded Signature")
		outer.AppendChild(inner)
	}

	return outer
}

func checkSignatureOnePass(p *packet.Signature, h hash.Hash) dom.Element {
	if p.IssuerKeyId == nil {
		return formatError(errors.New("signature missing Key ID"))
	}

	data, err := getPublicKeyRaw(*p.IssuerKeyId)
	if err != nil {
		return formatError(err)
	}

	armored, err := armor.Decode(bytes.NewReader(data))
	if err != nil {
		return formatError(err)
	}

	packets := packet.NewReader(armored.Body)
	for {
		pkt, err := packets.Next()
		if err == io.EOF {
			return formatError(errors.New("could not find public key"))
		}
		if err != nil {
			return formatError(err)
		}

		if key, ok := pkt.(*packet.PublicKey); ok {
			if key.KeyId != *p.IssuerKeyId {
				continue
			}

			err = key.VerifySignature(h, p)
			if err != nil {
				return formatError(err)
			}
			return formatNotice("Signature is Valid", "good")
		}
	}
}

func checkSignaturePublicKey(p *packet.Signature, pub *packet.PublicKey, uid *packet.UserId) dom.Element {
	if p.IssuerKeyId == nil {
		return formatError(errors.New("signature missing Key ID"))
	}

	notice := formatNotice("Checking signature...", "pending")

	go func() {
		replace := func(e dom.Element) {
			for i := 0; i < 5000 && notice.ParentElement() == nil; i++ {
				time.Sleep(time.Millisecond)
			}
			if notice.ParentElement() == nil {
				return
			}
			notice.ParentElement().ReplaceChild(e, notice)
		}

		data, err := getPublicKeyRaw(*p.IssuerKeyId)
		if err != nil {
			replace(formatError(err))
			return
		}

		armored, err := armor.Decode(bytes.NewReader(data))
		if err != nil {
			replace(formatError(err))
			return
		}

		packets := packet.NewReader(armored.Body)
		for {
			pkt, err := packets.Next()
			if err == io.EOF {
				replace(formatError(errors.New("could not find public key")))
				return
			}
			if err != nil {
				replace(formatError(err))
				return
			}

			if key, ok := pkt.(*packet.PublicKey); ok {
				if key.KeyId != *p.IssuerKeyId {
					continue
				}

				if uid == nil {
					err = key.VerifyKeySignature(pub, p)
				} else {
					err = key.VerifyUserIdSignature(uid.Id, pub, p)
				}
				if err != nil {
					replace(formatError(err))
				} else {
					replace(formatNotice("Signature is Valid", "good"))
				}
			}
		}
	}()

	return notice
}
