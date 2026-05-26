package fcrypt

import (
	"fmt"
	"testing"
)

const umlaut string = "äöüÄÖÜß"

func TestSuccessCases(t *testing.T) {
	gB64 := NewBase64Generator()
	fmt.Println(gB64.Generate())
	fmt.Printf("Entropy: %f\n", gB64.Entropy())

	gB64.SetPwLengthByEntropy(128)
	if gB64.Entropy() < 128 {
		t.Fatalf("Entropy too small: %f", gB64.Entropy())
	}

	fmt.Println(gB64.Generate())

	gHex := NewHexGenerator()
	fmt.Println(gHex.Generate())
	fmt.Printf("Entropy: %f\n", gHex.Entropy())

	gNum := NewNumericGenerator()
	fmt.Println(gNum.Generate())
	fmt.Printf("Entropy: %f\n", gNum.Entropy())

	gUml := NewPwGenerator(umlaut, 12)
	fmt.Println(gUml.Generate())
	fmt.Printf("Entropy: %f\n", gUml.Entropy())

}
