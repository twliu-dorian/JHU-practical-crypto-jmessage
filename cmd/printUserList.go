package cmd

import (
	"fmt"
	"jmessage_2024/config"
	"time"
)

func PrintUserList(userArray []config.UserStruct) {
	if len(userArray) == 0 {
		fmt.Println("There are no users on the server.")
		return
	}

	fmt.Printf("The following users were detected on the server (* indicates recently active):\n")

	// Get current Unix time
	timestamp := time.Now().Unix()

	// Iterate through the array, printing each message
	for i := 0; i < len(userArray); i++ {
		if int64(userArray[i].CheckedTime) > int64(timestamp-1200) {
			fmt.Printf("* ")
		} else {
			fmt.Printf("  ")
		}

		fmt.Printf("%s\n", userArray[i].Username)
	}
	fmt.Printf("\n")
}
