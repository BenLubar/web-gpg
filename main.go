package main

import (
	"strings"

	"honnef.co/go/js/dom"
)

var doc = dom.GetWindow().Document().(dom.HTMLDocument)

func main() {
	input := doc.GetElementByID("input").(*dom.HTMLTextAreaElement)
	output := doc.GetElementByID("output")

	input.AddEventListener("change", false, func(e dom.Event) {
		update(output, input.Value)
	})

	update(output, input.Value)
}

func update(output dom.Element, message string) {
	for c := output.FirstChild(); c != nil; c = output.FirstChild() {
		output.RemoveChild(c)
	}

	output.AppendChild(readArmored(strings.NewReader(message), "ASCII Armor"))
}
