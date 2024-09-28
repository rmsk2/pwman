package fcrypt

import (
	"testing"
)

func TestGjots1(t *testing.T) {
	gj := makeGjotsRaw(PbKdfSha256)

	_, err := gj.GetEntry("test1")
	if err == nil {
		t.Fatal("Non exisiting entry was found")
	}

	entryFound, err := gj.UpsertEntry("test1", "secret password")
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

	if entryFound {
		t.Fatal("Non exisitng entry was found")
	}

	entry, err := gj.GetEntry("test1")
	if err != nil {
		t.Fatal("Exisiting entry not found")
	}

	if entry != "secret password" {
		t.Fatalf("Incorrect value retrieved for key test1: %s", entry)
	}

	entryFound, err = gj.UpsertEntry("test2", "secret password2")
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

	if entryFound {
		t.Fatal("Non exisitng entry was found")
	}

	entry, err = gj.GetEntry("test2")
	if err != nil {
		t.Fatal("Exisiting entry not found")
	}

	if entry != "secret password2" {
		t.Fatalf("Incorrect value retrieved for key test2: %s", entry)
	}

	keys, err := gj.GetKeyList()
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

	if len(keys) != 2 {
		t.Fatalf("Unexpected number of keys")
	}
}

func TestGjots2(t *testing.T) {
	gj := makeGjotsRaw(PbKdfSha256)

	entryFound, err := gj.UpsertEntry("test1", "secret password")
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

	if entryFound {
		t.Fatal("Non exisitng entry was found")
	}

	entryFound, err = gj.UpsertEntry("test2", "secret password2")
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

	if entryFound {
		t.Fatal("Non exisitng entry was found")
	}

	err = gj.RenameEntry("test1", "test11")
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

	entry, err := gj.GetEntry("test11")
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

	if entry != "secret password" {
		t.Fatalf("Incorrect value retrieved for key test11: %s", entry)
	}

	err = gj.RenameEntry("test2", "test11")
	if err == nil {
		t.Fatalf("Was able to rename an entry to an existing name")
	}

	err = gj.RenameEntry("not existing", "don't care")
	if err == nil {
		t.Fatalf("Was able to rename a non existing entry")
	}
}
