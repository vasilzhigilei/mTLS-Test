package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"

	"github.com/grantae/certinfo"
)

func handleError(err error) {
	if err != nil {
		log.Fatal("Fatal", err)
	}
}

// readFile reads a file and returns the bytes
func readFile(path string) ([]byte, error) {
	// get cert filepath
	absPathServerCrt, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// read the cert file
	certBytes, err := ioutil.ReadFile(absPathServerCrt)
	if err != nil {
		return nil, err
	}
	return certBytes, nil
}

// getOriginCertPair gets the origin cert pair for regular TLS
func getOriginCertPair(certPath string, keyPath string) (*tls.Certificate, error) {
	// get cert and key
	originCert, err := readFile(certPath)
	if err != nil {
		return nil, err
	}
	originKey, err := readFile(keyPath)
	if err != nil {
		return nil, err
	}

	// make tls.Certificate
	certificate, err := tls.X509KeyPair(originCert, originKey)
	if err != nil {
		return nil, err
	}

	return &certificate, nil
}

// getClientCACert gets the root certificate for the origin server side of mTLS
func getClientCACert(path string) (*x509.CertPool, error) {
	// get cert
	clientCACert, err := readFile(path)
	if err != nil {
		return nil, err
	}

	// create cert pool
	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(clientCACert)

	return clientCertPool, err
}

func serve() {
	// get the origin server cert pair for TLS
	certificate, err := getOriginCertPair("certs/origin.pem", "certs/origin.key")
	handleError(err)

	// get the CA cert for server side of mTLS
	clientCertPool, err := getClientCACert("certs/root.crt")
	handleError(err)

	config := tls.Config{
		ClientAuth:               tls.RequireAndVerifyClientCert, // maybe don't verify if issues arise
		ClientCAs:                clientCertPool,
		Certificates:             []tls.Certificate{*certificate},
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}

	// start a tcp server
	listener, err := tls.Listen("tcp", "0.0.0.0:8080", &config)
	if err != nil {
		fmt.Println("server: could not start listening, error:", err)
		return
	}

	fmt.Println("server: ready")

	for {
		// wait for a new incoming connection
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("server: could not accept incoming connection, error:", err)
			continue
		}
		// we got a connection
		fmt.Println("server: accepted connection from", conn.RemoteAddr())

		// get the underlying tls connection
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			fmt.Println("server: erm, this is not a tls conn")
			return
		}
		// perform handshake
		if err := tlsConn.Handshake(); err != nil {
			fmt.Println("client: error during handshake, error:", err)
			return
		}

		// get connection state and print some stuff
		state := tlsConn.ConnectionState()
		for _, v := range state.PeerCertificates {
			text, err := certinfo.CertificateText(v)
			handleError(err)
			fmt.Printf("Cert data: %s\n", text)
		}

		// close connection
		conn.Close()
	}
}

func main() {
	serve()
}
