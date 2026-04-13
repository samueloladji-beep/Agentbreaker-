package main

import (
	"fmt"
	"os"

	vaultak "github.com/samueloladji-beep/vaultak-go"
)

func main() {
	fmt.Println("=== Go SDK Test ===")

	vt := vaultak.New("vtk_waX4mySWXNBnQ1BhV6P0gZWVaINYlE18OiF5ziSMd9Y",
		vaultak.WithAgentID("go-test-agent"),
		vaultak.WithBlockedResources([]string{"*.env", "prod.*"}),
	)

	// Test 1: Normal file write
	fmt.Println("Test 1: Normal file write...")
	err := vt.WriteFile("/tmp/go_test.txt", []byte("hello from go agent"), 0644)
	if err != nil {
		fmt.Println("  ERROR:", err)
	} else {
		fmt.Println("  File write logged")
	}

	// Test 2: Blocked resource
	fmt.Println("Test 2: Blocked .env file...")
	err = vt.WriteFile("/tmp/test.env", []byte("SECRET=blocked"), 0644)
	if err != nil {
		fmt.Println("  Blocked correctly:", err)
	} else {
		fmt.Println("  ERROR: should have been blocked")
	}

	// Test 3: Rollback
	fmt.Println("Test 3: File rollback...")
	os.WriteFile("/tmp/rollback_go.txt", []byte("original content"), 0644)

	vt2 := vaultak.New("vtk_waX4mySWXNBnQ1BhV6P0gZWVaINYlE18OiF5ziSMd9Y",
		vaultak.WithAgentID("rollback-test"),
		vaultak.WithRollbackThreshold(40),
	)

	vt2.WriteFile("/tmp/rollback_go.txt", []byte("modified by agent"), 0644)
	_, err = vt2.Intercept("delete", "prod.database", nil)
	if err != nil {
		content, _ := os.ReadFile("/tmp/rollback_go.txt")
		fmt.Println("  Content after rollback:", string(content))
		if string(content) == "original content" {
			fmt.Println("  ROLLBACK SUCCESSFUL")
		} else {
			fmt.Println("  ROLLBACK FAILED")
		}
	}

	fmt.Println("=== Tests complete ===")
}
