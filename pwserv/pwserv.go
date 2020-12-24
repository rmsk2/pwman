package main

import "pwman/pwsrvbase"

func main() {
	p := pwsrvbase.NewSocketPwStore()
	p.Serve(pwsrvbase.PwServPort)
}
