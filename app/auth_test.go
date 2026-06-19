package main

import "testing"

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := hashPassword("secret")
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(hash, "secret") {
		t.Fatal("expected password to verify")
	}
	if verifyPassword(hash, "wrong") {
		t.Fatal("expected wrong password to fail")
	}
}
