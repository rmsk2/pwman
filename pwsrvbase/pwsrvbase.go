package pwsrvbase

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
)

// APIURL contains the base URL of the API
const APIURL = "/api/pwserv/data/" // POST to set password fpr purpose, GET to get password

// PwServPort contains the server port for the API
const PwServPort = 5678

// CutPrefix removes the given prefix from the specified value. I prefer to add these 18 lines instead of
// importing the full gorilla mux package.
func CutPrefix(prefix, value string) (string, error) {
	p := []rune(prefix)
	v := []rune(value)

	if len(p) > len(v) {
		return "", fmt.Errorf("Is no prefix")
	}

	for i := range p {
		if p[i] != v[i] {
			return "", fmt.Errorf("Is no prefix")
		}
	}

	resRune := v[len(p):]

	return string(resRune), nil
}

// PwStore holds the password data
type PwStore struct {
	passwords map[string]string
}

func (p *PwStore) handleGetPassword(w http.ResponseWriter, r *http.Request) {
	name, err := CutPrefix(APIURL, r.URL.String())
	if err != nil {
		log.Printf("Unable to parse password name: %v", err)
		http.Error(w, "Unable to parse password name", http.StatusBadRequest)
		return
	}

	password, ok := p.passwords[name]
	if !ok {
		log.Printf("Password for %s not found", name)
		http.Error(w, "Password not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")

	log.Printf("Password for %s returned", name)

	w.Write([]byte(password))
}

func (p *PwStore) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	name, err := CutPrefix(APIURL, r.URL.String())
	if err != nil {
		log.Printf("Unable to parse password name: %v", err)
		http.Error(w, "Unable to parse password name", http.StatusBadRequest)
		return
	}

	password, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Unable to read password from input data")
		http.Error(w, "Unable to read password data", http.StatusBadRequest)
		return
	}

	p.passwords[name] = string(password)

	log.Printf("Password for %s set", name)

	w.Header().Set("Cache-Control", "no-store")
}

func (p *PwStore) handleRequest(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		p.handleGetPassword(w, r)
	case "POST":
		p.handleSetPassword(w, r)
	default:
		log.Printf("Only GET or POST is allowed on this resource %s", r.RequestURI)
		http.Error(w, "Only GET or POST is allowed on this resource", http.StatusMethodNotAllowed)
		return
	}
}

// Serve makes the pwstore listen on the given port
func (p *PwStore) Serve(port uint16) {
	portStr := strconv.FormatUint(uint64(port), 10)
	portSpec := net.JoinHostPort("localhost", portStr)

	log.Printf("Starting pwserv on %s", portSpec)

	router := http.NewServeMux()

	router.HandleFunc(APIURL, p.handleRequest)

	err := http.ListenAndServe(portSpec, router)
	if err != nil {
		log.Printf("Error serving for pwserv: %v", err)
		return
	}

	log.Printf("pwserv on %s stopped", portSpec)
}

// NewPwStore returns an intialized pw store
func NewPwStore() *PwStore {
	return &PwStore{
		passwords: map[string]string{},
	}
}
