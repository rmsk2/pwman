package main

import (
	"os"
	"pwman/pwsrvbase"
	"pwman/pwsrvbase/domainsock"
)

func main() {
	p := pwsrvbase.NewSocketPwStore(pwsrvbase.NewObfuscatingStorer())
	//p.Serve(pwsrvbase.NewTCPPrepareFunc(pwsrvbase.PwServPort))
	p.Serve(domainsock.NewUDSPrepareFunc())
	os.Exit(0)
}
