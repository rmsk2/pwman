//go:build windows
// +build windows

package main

import (
	"pwman/pwsrvbase"
	"pwman/pwsrvbase/windomainsock"
)

func main() {
	p := pwsrvbase.NewSocketPwStore(pwsrvbase.NewGenericStorer())
	//p.Serve(pwsrvbase.NewTCPPrepareFunc(pwsrvbase.PwServPort))
	p.Serve(windomainsock.NewUDSPrepareFunc())
}
