package printers

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

type ValuePrinter interface {
	PrintValue(key, value string) error
	PrintHeader()
	PrintFooter()
}

type textPrinter struct {
}

func NewTextPrinter() ValuePrinter {
	return &textPrinter{}
}

func (t *textPrinter) PrintValue(key string, value string) error {
	lineLen := 80
	stars := "***"
	txtLen := utf8.RuneCountInString(key)
	fillLen := lineLen - txtLen - 2*len(stars)
	var fillerLeft string
	var fillerRight string

	if fillLen <= 0 {
		fillerLeft = " "
		fillerRight = " "
	} else {
		if fillLen%2 == 0 {
			fillerLeft = strings.Repeat(" ", fillLen/2)
			fillerRight = strings.Repeat(" ", fillLen/2)
		} else {
			fillerLeft = strings.Repeat(" ", fillLen/2)
			fillerRight = strings.Repeat(" ", fillLen/2+1)
		}
	}

	title := fmt.Sprintf("%s%s%s%s%s", stars, fillerLeft, key, fillerRight, stars)
	e := strings.Repeat(" ", utf8.RuneCountInString(title)-2*len(stars))
	empty := fmt.Sprintf("%s%s%s", stars, e, stars)
	bar := strings.Repeat("*", utf8.RuneCountInString(title))
	fmt.Println(bar)
	fmt.Println(empty)
	fmt.Println(title)
	fmt.Println(empty)
	fmt.Println(bar)
	fmt.Println(value)
	fmt.Println()

	return nil
}

func (t *textPrinter) PrintHeader() {

}

func (t *textPrinter) PrintFooter() {

}
