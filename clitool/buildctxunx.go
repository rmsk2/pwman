//go:build darwin || linux
// +build darwin linux

package main

import (
	"pwman/fcrypt"
	"pwman/pwsrvbase"
	"pwman/pwsrvbase/domainsock"
)

// NewContext creates a new command context
func NewContext() *CmdContext {
	return &CmdContext{
		//client: pwsrvbase.NewGenericJSONClient(pwsrvbase.NewSocketTransactor(pwsrvbase.PwServPort)),
		client:      pwsrvbase.NewGenericJSONClient(domainsock.NewUDSTransactor()),
		jotsManager: fcrypt.GetGjotsManager(),
	}
}
