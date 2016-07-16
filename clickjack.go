package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

var concurrency = 100

type Site struct {
	url       string
	protected bool
}

var file string

func init() {
	const (
		default_file = "urls.txt"
		usage        = "This is the file that is read and processed"
	)
	flag.StringVar(&file, "file", default_file, usage)
	flag.StringVar(&file, "f", default_file, usage)
}

func make_request(queue chan string, results *[]Site, errors *[]string, complete chan bool) {
	for url := range queue {
		res, err := http.Head(url)
		if err != nil {
			*errors = append(*errors, url)
			// we need to send a signal, or counts will be off
			complete <- true
			return
		}

		xframe := res.Header.Get("X-Frame-Options")

		item := Site{url: url}
		if xframe != "" {
			item.protected = true
		}
		*results = append(*results, item)
	}

	// Signal main() that the goroutine has finished.
	complete <- true
}

func process_results(results *[]Site) (int, int) {
	pro := 0
	vul := 0
	// Range on silces returns key:value- we don't care about the key
	for _, res := range *results {
		// We could build other reporting in this block
		if res.protected == true {
			pro++
		} else {
			vul++
		}
	}
	return pro, vul
}

func process_errors(errors *[]string) {
	// Print to STDERR so we can redirect if we want
	fmt.Fprintln(os.Stderr, "\nThe following sites had issues being retreived:")
	// Range on silces returns key:value- we don't care about the key
	for _, err := range *errors {
		fmt.Fprintln(os.Stderr, "\t", err)
	}
}

func main() {

	// Get the specified file or default
	flag.Parse()

	// Channels for work and signaling
	queue := make(chan string)
	complete := make(chan bool)

	// Results go here.
	var errors []string
	var results []Site

	// Read the lines into the work queue.
	go func() {
		file, err := os.Open(file)
		if err != nil {
			log.Fatal(err)
		}

		// This will close the file when main() returns
		defer file.Close()

		scanner := bufio.NewScanner(file)

		for scanner.Scan() {
			queue <- scanner.Text()
		}
		// This will allow for draining and not cause blocking
		close(queue)
	}()

	// Run maximum concurrent jobs
	for i := 0; i < concurrency; i++ {
		go make_request(queue, &results, &errors, complete)
	}

	// Sit on the signal channel and wait for goroutines to finish.
	for i := 0; i < concurrency; i++ {
		<-complete
	}

	// Reporting
	fmt.Println(len(results), "sites returned results,",
		len(errors), "sites had errrors.")
	pro, vuln := process_results(&results)
	fmt.Println("Sites vulnerable:", vuln, "\nSites Protected :", pro)
	percent := (float64(pro) / float64(vuln+pro)) * 100
	fmt.Println(percent, "% of sites tested implemented clickjack protection.")

	// Skip this if we don't have any errors
	if len(errors) != 0 {
		process_errors(&errors)
	}
}
