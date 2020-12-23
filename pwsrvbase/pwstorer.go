package pwsrvbase

// PwStorer is an interface for a remote password storage
type PwStorer interface {
	SetPassword(name string, password string) error
	GetPassword(name string) (string, error)
	ResetPassword(name string) error
}
