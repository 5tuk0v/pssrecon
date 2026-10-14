package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb"
	smbdcerpc "github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/dcerpc/msrrp"
	"github.com/jfjallid/go-smb/spnego"
)

var sccmlocation = `SOFTWARE\Microsoft\SMS`

func main() {
	err := Enumerate()
	if err != nil {
		fmt.Println("[-] Error: " + err.Error())
		return
	}
}

func Enumerate() error {
	host := flag.String("host", "", "IP of the sccm PSS or DP server")
	u := flag.String("u", "", "Username to authenticate with")
	p := flag.String("p", "", "Password to authenticate with")
	d := flag.String("d", "", "Domain FQDN to authenticate with")
	hash := flag.String("hash", "", "NTLM Hash to authenticate with")
	flag.Parse()
	var err error
	var options smb.Options
	if *hash != "" {
		var hashBytes = []byte{}
		hashBytes, err = hex.DecodeString(*hash)
		if err != nil {
			return err
		}
		options = smb.Options{
			Host: *host,
			Port: 445,
			Initiator: &spnego.NTLMInitiator{
				User:   *u,
				Domain: *d,
				Hash:   hashBytes,
			},
		}
	} else {
		options = smb.Options{
			Host: *host,
			Port: 445,
			Initiator: &spnego.NTLMInitiator{
				User:     *u,
				Password: *p,
				Domain:   *d,
			},
		}
	}
	session, err := smb.NewConnection(options)
	if err != nil {
		return err
	}
	share := "IPC$"
	err = session.TreeConnect(share)
	if err != nil {
		return err
	}
	f, err := session.OpenFile(share, "winreg")
	if err != nil {
		//sleeping here cuz sometimes after i req it it will open then i can connect
		time.Sleep(1 * time.Second)
		f, err = session.OpenFile(share, "winreg")
		if err != nil {
			return err
		}
	}
	defer f.Close()
	bind, err := smbdcerpc.Bind(f, msrrp.MSRRPUuid, msrrp.MSRRPMajorVersion, msrrp.MSRRPMinorVersion, msrrp.NDRUuid)
	if err != nil {
		return err
	}
	reg := msrrp.NewRPCCon(bind)
	err = EnumeratePSSRoles(reg)
	if err != nil {
		return err
	}
	err = EnumerateSiteDB(reg)
	if err != nil {
		return errors.New("[-] Could Not Locate Site DB")
	}
	return nil
}

func EnumerateSiteDB(reg *msrrp.RPCCon) error {

	hKey, err := reg.OpenBaseKey(msrrp.HKEYLocalMachine)
	if err != nil {
		return err
	}
	subkey := sccmlocation + `\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers`
	listedSubKeys, err := reg.GetSubKeyNames(hKey, subkey)
	if err != nil {
		return err
	}
	if len(listedSubKeys) == 1 {
		fmt.Println("[+] Site Database Found: " + listedSubKeys[0])
	}
	if len(listedSubKeys) == 0 {
		fmt.Println("[+] Site Database is Local to the Primary Site Server")
	}
	if len(listedSubKeys) > 1 {
		for i := 0; i < len(listedSubKeys); i++ {
			fmt.Println("[+] Multisite Component Server: " + listedSubKeys[i])
		}
	}
	return nil
}

func EnumeratePSSRoles(reg *msrrp.RPCCon) error {
	hKey, err := reg.OpenBaseKey(msrrp.HKEYLocalMachine)
	if err != nil {
		return err
	}
	listedSubKeys, err := reg.GetSubKeyNames(hKey, sccmlocation)
	if err != nil {
		return err
	}
	for i := 0; i < len(listedSubKeys); i++ {
		if listedSubKeys[i] == "DP" {
			if err := EnumerateDP(reg); err != nil {
				return fmt.Errorf("enumerating distribution point: %w", err)
			}
		}
		if listedSubKeys[i] == "MP" {
			fmt.Println("[i] MP registry subkey present")
		}
	}
	return nil
}

func EnumerateDP(reg *msrrp.RPCCon) error {
	hKey, err := reg.OpenBaseKey(msrrp.HKEYLocalMachine)
	if err != nil {
		return err
	}
	subkey := sccmlocation + `\DP`
	hSubKey, err := reg.OpenSubKey(hKey, subkey)
	if err != nil {
		return err
	}
	valueNames, err := reg.GetValueNames(hSubKey)
	if err != nil {
		return fmt.Errorf("list SCCM settings values: %w", err)
	}
	fmt.Println("[i] SCCM registry settings available")
	present := make(map[string]bool, len(valueNames))
	for _, name := range valueNames {
		present[strings.ToLower(name)] = true
	}

	if present["sitecode"] {
		sc, err := queryRegistryString(reg, hSubKey, "SiteCode")
		if err != nil {
			return err
		}
		fmt.Println("[+] Site Code Found: " + sc)
	} else {
		fmt.Println("[!] SiteCode registry value is absent")
	}

	if present["siteserver"] {
		ss, err := queryRegistryString(reg, hSubKey, "SiteServer")
		if err != nil {
			return err
		}
		fmt.Println("[+] Site Server Found: " + ss)
	} else {
		fmt.Println("[!] SiteServer registry value is absent")
	}

	if present["managementpoints"] {
		mps, err := queryRegistryString(reg, hSubKey, "ManagementPoints")
		if err != nil {
			return err
		}
		split := strings.Split(mps, "*")
		for i := 0; i < len(split); i++ {
			fmt.Println("[+] Management point listed: " + split[i])
		}
	} else {
		fmt.Println("[!] ManagementPoints registry value is absent")
	}

	if present["isanonymousaccessenabled"] {
		isAnonymousAccessEnabled, err := queryRegistryDWORD(reg, hSubKey, "IsAnonymousAccessEnabled")
		if err != nil {
			return err
		}
		if isAnonymousAccessEnabled == 1 {
			fmt.Println("[+] Anonymous access enabled in DP registry")
		} else if isAnonymousAccessEnabled == 0 {
			fmt.Println("[i] Anonymous access disabled in DP registry")
		}
	} else {
		fmt.Println("[!] IsAnonymousAccessEnabled registry value is absent")
	}

	var isPXE, isActive *uint32
	if present["ispxe"] {
		value, err := queryRegistryDWORD(reg, hSubKey, "IsPXE")
		if err != nil {
			return err
		}
		isPXE = &value
	}
	if present["isactive"] {
		value, err := queryRegistryDWORD(reg, hSubKey, "IsActive")
		if err != nil {
			return err
		}
		isActive = &value
	}
	fmt.Println(pxeRegistryStatus(isPXE, isActive))
	return nil
}

func pxeRegistryStatus(isPXE, isActive *uint32) string {
	if isPXE == nil && isActive == nil {
		return "[i] No PXE registry flags present"
	}
	if isPXE == nil {
		if *isActive == 0 {
			return "[i] No PXE configuration indicated (IsPXE absent, IsActive=0)"
		}
		return fmt.Sprintf("[!] IsActive set without IsPXE (IsPXE absent, IsActive=%d)", *isActive)
	}
	if isActive == nil {
		if *isPXE == 0 {
			return "[i] PXE not enabled in registry (IsPXE=0, IsActive absent)"
		}
		return fmt.Sprintf("[!] PXE response flag absent (IsPXE=%d, IsActive absent)", *isPXE)
	}
	if *isPXE > 1 || *isActive > 1 {
		return fmt.Sprintf("[!] Unexpected PXE registry values (IsPXE=%d, IsActive=%d)", *isPXE, *isActive)
	}
	switch {
	case *isPXE == 1 && *isActive == 1:
		return "[+] PXE enabled for responses in registry (IsPXE=1, IsActive=1)"
	case *isPXE == 1:
		return "[i] PXE support flag set; response flag off (IsPXE=1, IsActive=0)"
	case *isActive == 1:
		return "[!] Conflicting PXE registry flags (IsPXE=0, IsActive=1)"
	default:
		return "[i] PXE disabled in registry (IsPXE=0, IsActive=0)"
	}
}

func queryRegistryString(reg *msrrp.RPCCon, key []byte, name string) (string, error) {
	data, err := reg.QueryValue(key, name)
	if err != nil {
		return "", fmt.Errorf("query %s: %w", name, err)
	}
	return decodeRegistryString(name, data)
}

func decodeRegistryString(name string, data []byte) (string, error) {
	if len(data) == 0 || len(data)%2 != 0 {
		return "", fmt.Errorf("%s has invalid UTF-16 data length %d", name, len(data))
	}
	if data[len(data)-2] == 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-2]
	}
	value, err := msdtyp.FromUnicodeString(data)
	if err != nil {
		return "", fmt.Errorf("decode %s: %w", name, err)
	}
	if value == "" {
		return "", fmt.Errorf("%s is empty", name)
	}
	return value, nil
}

func queryRegistryDWORD(reg *msrrp.RPCCon, key []byte, name string) (uint32, error) {
	data, err := reg.QueryValue(key, name)
	if err != nil {
		return 0, fmt.Errorf("query %s: %w", name, err)
	}
	if len(data) != 4 {
		return 0, fmt.Errorf("%s has invalid DWORD data length %d", name, len(data))
	}
	return binary.LittleEndian.Uint32(data), nil
}
