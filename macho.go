package dylibx

import (
	"bytes"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"howett.net/plist"
)

type Dylib struct {
	Name           string
	Time           uint32
	CurrentVersion string
	CompatVersion  string
}

type MachOInfo struct {
	Magic types.Magic
	CPU   types.CPU
	Type  types.HeaderFileType

	LoadDylinker   string
	LcRpaths       []string
	DylibLoads     []Dylib
	WeakDylibLoads []Dylib

	CodeSignFlags        uint32
	CodeSignEntitlements Entitlements
}

type FatMachOInfo []*MachOInfo

func ParseMacho(path string) (FatMachOInfo, error) {
	var res FatMachOInfo
	// first check for fat file
	f, err := macho.OpenFat(path)
	if err != nil && err != macho.ErrNotFat {
		return nil, err
	}
	if err == macho.ErrNotFat {
		res = make(FatMachOInfo, 0, 1)
		m, err := macho.Open(path)
		if err != nil {
			return nil, err
		}
		res = append(res, parseMacho(m))
		m.Close()
	} else {
		res = make(FatMachOInfo, 0, len(f.Arches))
		for i := range f.Arches {
			res = append(res, parseMacho(f.Arches[i].File))
		}
		f.Close()
	}
	return res, nil
}

func parseMacho(m *macho.File) *MachOInfo {
	res := &MachOInfo{
		Magic:          m.Magic,
		Type:           m.Type,
		CPU:            m.CPU,
		DylibLoads:     make([]Dylib, 0),
		WeakDylibLoads: make([]Dylib, 0),
		LcRpaths:       make([]string, 0, 2),
	}

	for i := range m.Loads {
		switch m.Loads[i].Command() {
		case types.LC_LOAD_DYLINKER:
			res.LoadDylinker = m.Loads[i].String()
		case types.LC_LOAD_DYLIB,
			types.LC_LOAD_WEAK_DYLIB:
			dylib, ok := m.Loads[i].(*macho.Dylib)
			if !ok {
				continue
			}
			d := Dylib{
				Name:           dylib.Name,
				Time:           dylib.Time,
				CurrentVersion: dylib.CurrentVersion,
				CompatVersion:  dylib.CompatVersion,
			}

			if dylib.Command() == types.LC_LOAD_DYLIB {
				res.DylibLoads = append(res.DylibLoads, d)
			} else {
				res.WeakDylibLoads = append(res.WeakDylibLoads, d)
			}
		case types.LC_RPATH:
			res.LcRpaths = append(res.LcRpaths, m.Loads[i].String())
		case types.LC_REEXPORT_DYLIB:
		case types.LC_CODE_SIGNATURE:
			cs, ok := m.Loads[i].(*macho.CodeSignature)
			if !ok {
				continue
			}
			if len(cs.Entitlements) > 0 {
				parseEntitlements(cs.Entitlements, &res.CodeSignEntitlements)
			}
			if len(cs.CodeDirectories) > 0 {
				res.CodeSignFlags = uint32(cs.CodeDirectories[0].Header.Flags)
			}
		}
	}
	return res
}

type Entitlements struct {
	DisableLibraryValidation bool `plist:"com.apple.security.cs.disable-library-validation"`
}

func parseEntitlements(data string, e *Entitlements) {
	decoder := plist.NewDecoder(bytes.NewReader([]byte(data)))
	if err := decoder.Decode(e); err != nil {
		return
	}
}
