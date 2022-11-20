package main

import "pwman/pwsrvbase"

func main() {
	p := pwsrvbase.NewSocketPwStore(pwsrvbase.NewGenericStorer())
	p.Serve(pwsrvbase.NewTCPPrepareFunc(pwsrvbase.PwServPort))
	//p.Serve(pwsrvbase.NewUDSPrepareFunc())
}
