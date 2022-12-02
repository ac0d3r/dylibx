package dylibx

import (
	"testing"
)

func TestScanApp(t *testing.T) {
	d := new(Dylibx)
	t.Log(d.ScanApp("/Applications/DingTalk.app"))
}

func TestAutoScanApps(t *testing.T) {
	d := new(Dylibx)
	vulns, err := d.AutoScanApps()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(vulns)
}
