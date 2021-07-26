package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/yqmmm/ssh_exporter/connect"
)

func Check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func main() {
	port := connect.ParseArgs()

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/probe", connect.ProbeHandler)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

func indexHandler(w http.ResponseWriter, _ *http.Request) {

	// Human readable navigation help.
	response := `<h1>ssh exporter</h1>
		<p><a href='/probe'>probe</a></p>
		<p><a href='/metrics'>metrics</a></p>`

	fmt.Fprint(w, response)
}
