package dylibx

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"howett.net/plist"
)

const (
	REQUIRE_LV = 0x2000
	RUNTIME    = 0x10000
)

type Dylibx struct {
}

type AppVulnerable struct {
	AppPath                  string
	ExecutablePath           string
	CodeSignFlags            string
	DisableLibraryValidation bool
	Injectable               bool
	Dylibs                   []VulnItem
}

type VulnItem struct {
	Type string
	Path string
}

func (d *Dylibx) AutoScanApps() ([]*AppVulnerable, error) {
	fs, err := os.ReadDir("/Applications")
	if err != nil {
		return nil, err
	}
	vs := make([]*AppVulnerable, 0)
	for i := range fs {
		if fs[i].IsDir() && strings.HasSuffix(fs[i].Name(), ".app") {
			v, err := d.ScanApp(path.Join("/Applications", fs[i].Name()))
			if err != nil {
				return nil, err
			}
			vs = append(vs, v)
		}
	}
	return vs, nil
}

func (d *Dylibx) ScanApp(path_ string) (*AppVulnerable, error) {
	exePath, err := d.GetExecutablePath(path_)
	if err != nil {
		return nil, err
	}

	var v *AppVulnerable = &AppVulnerable{
		AppPath:        path_,
		ExecutablePath: exePath,
		Dylibs:         make([]VulnItem, 0),
	}

	machoInfo, err := ParseMacho(v.ExecutablePath)
	if err != nil {
		return nil, err
	}
	v.CodeSignFlags = fmt.Sprintf("0x%x", machoInfo[0].CodeSignFlags)
	v.DisableLibraryValidation = machoInfo[0].CodeSignEntitlements.DisableLibraryValidation

	for _, m := range machoInfo {
		d.ParseRPaths(m.LcRpaths, path.Dir(v.ExecutablePath))

		if (d.IsRuntime(m.CodeSignFlags) ||
			d.IsLibraryValidation(m.CodeSignFlags)) && !m.CodeSignEntitlements.DisableLibraryValidation {
			continue
		}
		v.Injectable = true
		// weak dylib
		weaks := make([]string, 0)
		for _, weak := range m.WeakDylibLoads {
			switch true {
			case path.IsAbs(weak.Name):
				weaks = append(weaks, weak.Name)
			case strings.HasPrefix(weak.Name, "@"):
				weaks = append(weaks, d.joinPath(weak.Name, v.ExecutablePath, m.LcRpaths)...)
			}
		}
		for _, weak := range weaks {
			if d.InSIPPath(weak) || d.Exist(weak) {
				continue
			}
			v.Dylibs = append(v.Dylibs, VulnItem{
				Type: "weak",
				Path: weak,
			})
		}
		// @rpath dylib
		for _, dylib := range m.DylibLoads {
			if strings.HasPrefix(dylib.Name, RPathPre) {
				paths := d.joinPath(dylib.Name, v.ExecutablePath, m.LcRpaths)
				if len(paths) == 0 {
					continue
				}
				index := -1
				for i := range paths {
					if d.Exist(paths[i]) {
						index = i
						break
					}
				}
				if index == -1 {
					index = len(paths)
				}
				for i := range paths[:index] {
					if d.InSIPPath(paths[i]) {
						continue
					}
					v.Dylibs = append(v.Dylibs, VulnItem{
						Type: "rpath",
						Path: paths[i],
					})
				}
			} else { // dylib proxying
				dylib.Name = d.ParseProxyPath(dylib.Name, path.Dir(v.ExecutablePath))
				if !d.InSIPPath(dylib.Name) {
					v.Dylibs = append(v.Dylibs, VulnItem{
						Type: "proxy",
						Path: dylib.Name,
					})
				}
			}
		}
	}
	return v, nil
}

func (d *Dylibx) IsRuntime(f uint32) bool {
	return f&RUNTIME != 0
}

func (d *Dylibx) IsLibraryValidation(f uint32) bool {
	return f&REQUIRE_LV != 0
}

func (d *Dylibx) GetExecutablePath(app string) (string, error) {
	s, err := os.Stat(app)
	if err != nil {
		return "", err
	}
	if !s.IsDir() {
		return "", errors.New("not application")
	}
	// get application info.plist
	data, err := os.ReadFile(path.Join(app, "Contents", "Info.plist"))
	if err != nil {
		return "", err
	}
	info, err := d.parseInfoPlist(data)
	if err != nil {
		return "", err
	}
	if info.CFBundleExecutable == "" {
		return "", errors.New("not found 'CFBundleExecutable' in info.plist")
	}
	return path.Join(app, "Contents", "MacOS", info.CFBundleExecutable), nil
}

type AppInfo struct {
	CFBundleExecutable string `plist:"CFBundleExecutable"`
}

func (d *Dylibx) parseInfoPlist(data []byte) (*AppInfo, error) {
	var info = &AppInfo{}
	decoder := plist.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(info); err != nil {
		return nil, err
	}
	return info, nil
}

func (d *Dylibx) Exist(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// SIP
var (
	sippaths = []string{
		"/System/",
		"/usr/",
	}
)

func (d *Dylibx) InSIPPath(path string) bool {
	for i := range sippaths {
		if strings.HasPrefix(path, sippaths[i]) {
			return true
		}
	}
	return false
}

// rpath
const (
	RPathPre          = "@rpath"
	ExecutablePathPre = "@executable_path"
	LoaderPathPre     = "@loader_path"
)

func (d *Dylibx) ParseProxyPath(path string, ExePath string) string {
	if strings.HasPrefix(path, ExecutablePathPre) {
		return strings.ReplaceAll(path, ExecutablePathPre, ExePath)
	} else if strings.HasPrefix(path, LoaderPathPre) {
		return strings.ReplaceAll(path, LoaderPathPre, ExePath)
	}
	return path
}

func (d *Dylibx) ParseRPaths(rpath []string, ExePath string) {
	for i := range rpath {
		switch true {
		case strings.HasPrefix(rpath[i], ExecutablePathPre):
			rpath[i] = strings.ReplaceAll(rpath[i], ExecutablePathPre, ExePath)
		case strings.HasPrefix(rpath[i], LoaderPathPre):
			rpath[i] = strings.ReplaceAll(rpath[i], LoaderPathPre, ExePath)
		}
	}
}

func (d *Dylibx) joinPath(p, exec string, rpath []string) []string {
	paths := make([]string, 0)
	switch true {
	case strings.HasPrefix(p, RPathPre):
		for i := range rpath {
			paths = append(paths, strings.ReplaceAll(p, RPathPre, rpath[i]))
		}
	case strings.HasPrefix(p, ExecutablePathPre):
		paths = append(paths, strings.ReplaceAll(p, ExecutablePathPre, exec))
	}
	return paths
}
