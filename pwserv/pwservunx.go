//go:build darwin || linux
// +build darwin linux

package main

import (
	"pwman/pwsrvbase"
	"pwman/pwsrvbase/domainsock"
)

func main() {
	p := pwsrvbase.NewSocketPwStore(pwsrvbase.NewGenericStorer())
	//p.Serve(pwsrvbase.NewTCPPrepareFunc(pwsrvbase.PwServPort))
	p.Serve(domainsock.NewUDSPrepareFunc())
}
