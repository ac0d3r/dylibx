package main

import (
	"fmt"
	"log"

	"github.com/ac0d3r/dylibx"
)

func main() {
	d := new(dylibx.Dylibx)
	vulns, err := d.AutoScanApps()
	if err != nil {
		log.Println(err)
		return
	}
	for _, vuln := range vulns {
		if vuln.Injectable {
			fmt.Printf("App: %s \nExecutablePath: %s\nCodeSignFlags: %s\nDisableLibraryValidation: %v\nAllowDyldEnvironmentVariables: %v\n\tInjectable: %v\n", vuln.AppPath, vuln.ExecutablePath, vuln.CodeSignFlags, vuln.DisableLibraryValidation, vuln.AllowDyldEnvironmentVariables, vuln.Injectable)
		}
	}
	fmt.Println("-------------------------------------------------------------")
	for _, vuln := range vulns {
		if len(vuln.Dylibs) == 0 {
			continue
		}
		fmt.Printf("App: %s \nExecutablePath: %s\nCodeSignFlags: %s\nDisableLibraryValidation: %v\n", vuln.AppPath, vuln.ExecutablePath, vuln.CodeSignFlags, vuln.DisableLibraryValidation)
		for _, d := range vuln.Dylibs {
			fmt.Printf("\tType: %s \n\tPath: %s\n", d.Type, d.Path)
		}
	}
}
