package main

import "testing"

func Test_ErrorCache(t *testing.T) {

	keyValue := "ajdar: çikita muz"
	etest := NewErrorCache(5, 100)

	err := etest.Set(keyValue)

	if err != nil {
		t.Error(err)
	}

	ok := etest.Exists(keyValue)

	if !ok {
		t.Error("value does not exists:", keyValue)
	}

	err = etest.Get(keyValue)

	if err != nil {
		t.Error("key not retrieve", err)
	}

	if full := etest.Full(); full {
		t.Error("cache is full. oha!")
	}

	if elen := etest.Length(); elen != 1 {
		t.Error("indalid lenght:", elen)
	}

	etest.Remove(keyValue)
	ok = etest.Exists(keyValue)

	if !ok {
		t.Error("value still exists:", keyValue)
	}
}
