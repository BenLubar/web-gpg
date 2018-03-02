package main

import (
	"crypto"
	"fmt"
	"math/big"
	"strings"
	"time"

	humanize "github.com/dustin/go-humanize"

	"golang.org/x/crypto/openpgp/packet"

	"honnef.co/go/js/dom"
)

func formatWrapper(heading string) dom.Element {
	outer := doc.CreateElement("details")
	outer.SetAttribute("open", "")
	outer.Class().Add("wrapper")

	label := doc.CreateElement("summary")
	label.Class().Add("label")
	label.SetTextContent(heading)

	outer.AppendChild(label)

	return outer
}

func formatNotice(message, class string) dom.Element {
	outer := doc.CreateElement("div")
	outer.Class().Add("wrapper")
	outer.Class().Add("notice")
	outer.Class().Add(class)

	outer.SetTextContent(message)

	return outer
}

func formatRow(key, format string, args ...interface{}) dom.Element {
	outer := doc.CreateElement("div")
	outer.Class().Add("row")

	label := doc.CreateElement("div")
	label.Class().Add("key")
	label.SetTextContent(key)

	value := doc.CreateElement("div")
	value.Class().Add("value")
	value.SetTextContent(fmt.Sprintf(format, args...))

	outer.AppendChild(label)
	outer.AppendChild(value)

	return outer
}

func formatError(err error) dom.Element {
	outer := doc.CreateElement("details")
	outer.SetAttribute("open", "")
	outer.Class().Add("wrapper")
	outer.Class().Add("error")

	label := doc.CreateElement("summary")
	label.Class().Add("label")
	label.SetTextContent("Error")

	text := doc.CreateElement("pre")
	text.Class().Add("text")
	text.SetTextContent(err.Error())

	outer.AppendChild(label)
	outer.AppendChild(text)

	return outer
}

func formatSignatureType(key string, sigType packet.SignatureType) dom.Element {
	name := "unknown"
	switch sigType {
	case packet.SigTypeBinary:
		name = "binary"
	case packet.SigTypeText:
		name = "text"
	case packet.SigTypeGenericCert:
		name = "generic cert"
	case packet.SigTypePersonaCert:
		name = "persona cert"
	case packet.SigTypeCasualCert:
		name = "casual cert"
	case packet.SigTypePositiveCert:
		name = "positive cert"
	case packet.SigTypeSubkeyBinding:
		name = "subkey binding"
	case packet.SigTypePrimaryKeyBinding:
		name = "primary key binding"
	case packet.SigTypeDirectSignature:
		name = "direct signature"
	case packet.SigTypeKeyRevocation:
		name = "key revocation"
	case packet.SigTypeSubkeyRevocation:
		name = "subkey revocation"
	}
	return formatRow(key, "%d (%s)", sigType, name)
}

func formatHashAlgorithm(key string, hashAlgo crypto.Hash) dom.Element {
	name := "unknown"
	switch hashAlgo {
	case crypto.MD4:
		name = "MD4"
	case crypto.MD5:
		name = "MD5"
	case crypto.SHA1:
		name = "SHA1"
	case crypto.SHA224:
		name = "SHA224"
	case crypto.SHA256:
		name = "SHA256"
	case crypto.SHA384:
		name = "SHA384"
	case crypto.SHA512:
		name = "SHA512"
	case crypto.MD5SHA1:
		name = "MD5+SHA1"
	case crypto.RIPEMD160:
		name = "RIPEMD160"
	case crypto.SHA3_224:
		name = "SHA3-224"
	case crypto.SHA3_256:
		name = "SHA3-256"
	case crypto.SHA3_384:
		name = "SHA3-384"
	case crypto.SHA3_512:
		name = "SHA3-512"
	case crypto.SHA512_224:
		name = "SHA512-224"
	case crypto.SHA512_256:
		name = "SHA512-256"
	case crypto.BLAKE2s_256:
		name = "BLAKE2s-256"
	case crypto.BLAKE2b_256:
		name = "BLAKE2b-256"
	case crypto.BLAKE2b_384:
		name = "BLAKE2b-384"
	case crypto.BLAKE2b_512:
		name = "BLAKE2b-512"
	}
	return formatRow(key, "%d (%s)", hashAlgo, name)
}

func formatPublicKeyAlgorithm(key string, pubKeyAlgo packet.PublicKeyAlgorithm) dom.Element {
	name := "unknown"
	switch pubKeyAlgo {
	case packet.PubKeyAlgoRSA:
		name = "RSA"
	case packet.PubKeyAlgoRSAEncryptOnly:
		name = "RSA - encrypt only"
	case packet.PubKeyAlgoRSASignOnly:
		name = "RSA - sign only"
	case packet.PubKeyAlgoElGamal:
		name = "ElGamal"
	case packet.PubKeyAlgoDSA:
		name = "DSA"
	case packet.PubKeyAlgoECDH:
		name = "ECDH"
	case packet.PubKeyAlgoECDSA:
		name = "ECDSA"
	}
	return formatRow(key, "%d (%s)", pubKeyAlgo, name)
}

func formatBigInt(key string, n *big.Int) dom.Element {
	// format with commas, allowing line breaks after each one
	parts := strings.SplitAfter(humanize.BigComma(n), ",")

	outer := doc.CreateElement("div")
	outer.Class().Add("row")

	label := doc.CreateElement("div")
	label.Class().Add("key")
	label.SetTextContent(key)

	value := doc.CreateElement("div")
	value.Class().Add("value")
	for _, p := range parts {
		value.AppendChild(doc.CreateTextNode(p))
		value.AppendChild(doc.CreateElement("wbr"))
	}

	outer.AppendChild(label)
	outer.AppendChild(value)

	return outer
}

func formatTime(key string, t time.Time) dom.Element {
	return formatRow(key, "%v (%s)", t, humanize.Time(t))
}
