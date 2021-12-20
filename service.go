package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
)

var wg sync.WaitGroup

func helloTLSHandlerGenerator(caCertPool *x509.CertPool, cert tls.Certificate) func(http.ResponseWriter, *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:            caCertPool,
					Certificates:       []tls.Certificate{cert},
					InsecureSkipVerify: true,
				},
			},
		}

		// request to 8443
		req, err := client.Get("https://localhost:8443/hello")
		if err != nil {
			log.Fatal(err)
		}

		// Read the response body
		defer req.Body.Close()
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			log.Fatal(err)
		}

		// Print the response body to stdout
		fmt.Printf("%s\n", body)
		io.WriteString(w, string(body))
	}
}

func helloTLSHandler(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "Hello world 2 from TLS!\n")
}

func main() {
	wg.Add(2)
	go runService1()
	go runService2()
	wg.Wait()
}

func runService1() {
	cert, err := tls.LoadX509KeyPair("certs/service1.com.crt", "certs/service1.com.key")
	if err != nil {
		log.Fatal(err)
	}

	// Create a CA certificate pool and add cert.pem to it
	caCertPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile("certs/root.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool.AppendCertsFromPEM(caCert)

	// handler setup
	muxTLS := http.NewServeMux()
	muxTLS.HandleFunc("/hello", helloTLSHandlerGenerator(caCertPool, cert))

	// server setup
	tlsConfig := &tls.Config{
		ClientCAs:          caCertPool,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		InsecureSkipVerify: true,
	}
	tlsConfig.BuildNameToCertificate()
	server := &http.Server{
		Addr:      ":4443",
		TLSConfig: tlsConfig,
		Handler:   muxTLS,
	}

	log.Fatal(server.ListenAndServeTLS("certs/service1.com.crt", "certs/service1.com.key"))
	wg.Done()
}

func runService2() {
	muxTLS := http.NewServeMux()
	muxTLS.HandleFunc("/hello", helloTLSHandler)

	caCertPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile("certs/root.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:          caCertPool,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		InsecureSkipVerify: true,
	}
	tlsConfig.BuildNameToCertificate()

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
		Handler:   muxTLS,
	}

	log.Fatal(server.ListenAndServeTLS("certs/service2.com.crt", "certs/service2.com.key"))
	wg.Done()
}
