// utilities
package utilities

import (
	"crypto/sha256"
	"fmt"
	//"log"
	"math/rand"
	"strings"
	"time"
)

func GetSHA256Hash(value string) (string, error) {
	h := sha256.New()
	h.Write([]byte(value))
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func GetRandomAlphaNumbericValue(n int) string {
	rand.Seed(time.Now().UnixNano())
	chars := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	str := b.String()
	return str
}
