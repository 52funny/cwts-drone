package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
)

func main() {
	program := "./uav" // Replace with the path to the program you want to start
	var wg sync.WaitGroup
	cnt, err := strconv.ParseInt(os.Args[1], 10, 64)
	if err != nil {
		fmt.Println("Failed to parse the number of instances:", err)
		return
	}
	if err := os.MkdirAll("logs", os.ModePerm); err != nil {
		fmt.Printf("Failed to create logs directory: %v\n", err)
		return
	}
	for i := 1; i <= int(cnt); i++ {
		wg.Add(1)

		go func(instance int) {
			defer wg.Done()

			// Create output file, e.g., process-1.txt, process-2.txt, etc.
			outputFile := fmt.Sprintf("logs/process-%d.txt", instance)

			file, err := os.Create(outputFile)
			if err != nil {
				fmt.Printf("Failed to create file %s: %v\n", outputFile, err)
				return
			}
			defer file.Close()

			// Start the program and redirect its output to the file
			cmd := exec.Command(program)
			cmd.Stdout = file
			cmd.Stderr = file // Capture standard error output if needed

			// Start the program and check for errors
			err = cmd.Start()
			if err != nil {
				fmt.Printf("Failed to start program instance %d: %v\n", instance, err)
				return
			}
			fmt.Printf("Started program instance %d, output redirected to %s\n", instance, outputFile)

			// Wait for the program to finish
			err = cmd.Wait()
			if err != nil {
				fmt.Printf("Program instance %d encountered an error: %v\n", instance, err)
			} else {
				fmt.Printf("Program instance %d finished successfully\n", instance)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	fmt.Println("All program instances have completed")
}
