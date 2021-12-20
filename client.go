package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	cert, err := tls.LoadX509KeyPair("certs/client.com.crt", "certs/client.com.key")
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile("certs/service.crt")
	if err != nil {
		log.Fatal(err)
	}

	pemBlock, _ := pem.Decode(caCert)
	clientCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	clientCert.BasicConstraintsValid = true
	clientCert.IsCA = true
	clientCert.KeyUsage = x509.KeyUsageCertSign

	caCertPool.AddCert(clientCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// RootCAs:            caCertPool,
				Certificates:       []tls.Certificate{cert},
				InsecureSkipVerify: true,
			},
		},
	}

	// Request /hello via the created HTTPS client over port 8443 via GET
	r, err := client.Get("https://localhost:4443/hello")
	if err != nil {
		log.Fatal(err)
	}

	// Read the response body
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Print the response body to stdout
	fmt.Printf("%s\n", body)
}
