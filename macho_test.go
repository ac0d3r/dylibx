package dylibx

import (
	"fmt"
	"testing"
)

func TestParse(t *testing.T) {
	path := "/Applications/ClashX.app/Contents/MacOS/ClashX"
	// path := "/usr/bin/python3"
	infos, err := ParseMacho(path)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%#v", infos)
}
