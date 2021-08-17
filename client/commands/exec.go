package commands

import (
	"os/exec"
	"strings"
	"unicode"
)

// Exec command by: https://stackoverflow.com/questions/39151420/executing-command-with-spaces-in-one-of-the-parts
// WHAT THE FUCK
func Exec(command string) (string, error) {
	lastQuote := rune(0)
	f := func(c rune) bool {
		switch {
		case c == lastQuote:
			lastQuote = rune(0)
			return false
		case lastQuote != rune(0):
			return false
		case unicode.In(c, unicode.Quotation_Mark):
			lastQuote = c
			return false
		default:
			return unicode.IsSpace(c)
		}
	}

	var parts []string
	preParts := strings.FieldsFunc(command, f)
	for i := range preParts {
		part := preParts[i]
		parts = append(parts, strings.Replace(part, "'", "", -1))
	}

	if len(parts) == 1 {
		data, err := exec.Command(parts[0]).Output()
		if err != nil {
			return "", err
		}

		return string(data), nil
	} else if len(parts) > 1 {
		data, err := exec.Command(parts[0], parts[1:]...).Output()
		if err != nil {
			return "", err
		}

		return string(data), nil
	}

	return "", nil
}
