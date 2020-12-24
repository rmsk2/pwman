package pwsrvbase

// TransActFunc encapsulates the knowledge of how to establish and tear down a connection
type TransActFunc func(*PwRequest) (string, error)

// GenericJSONClient holds the context for a generic JSON client
type GenericJSONClient struct {
	transact TransActFunc
}

// NewGenericJSONClient returns an initalized GenerJSONClient struct
func NewGenericJSONClient(t TransActFunc) *GenericJSONClient {
	return &GenericJSONClient{
		transact: t,
	}
}

// SetPassword sets a password for a specified name
func (g *GenericJSONClient) SetPassword(name string, password string) error {
	request := &PwRequest{
		Command: CommandSet,
		PwName:  name,
		PwData:  password,
	}

	_, err := g.transact(request)

	return err
}

// GetPassword retrieves a password for a specified name
func (g *GenericJSONClient) GetPassword(name string) (string, error) {
	request := &PwRequest{
		Command: CommandGet,
		PwName:  name,
		PwData:  "",
	}

	return g.transact(request)
}

// ResetPassword deletes a password for a specified name
func (g *GenericJSONClient) ResetPassword(name string) error {
	request := &PwRequest{
		Command: CommandReset,
		PwName:  name,
		PwData:  "",
	}

	_, err := g.transact(request)

	return err
}
