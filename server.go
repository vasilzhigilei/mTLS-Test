package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"path/filepath"

	"github.com/grantae/certinfo"
)

func main() {
	// flag for whether to print full cert details or just minimal details
	verbose := flag.Bool("verbose", false, "Verbose==true prints out entire client certificates in human-readable format.")
	// set port
	port := flag.String("port", "443", "Set port to listen on.")
	flag.Parse()

	// get the origin server cert pair for TLS
	certificate, err := getOriginCertPair("certs/origin.pem", "certs/origin.key")
	handleError(err)

	// get the CA cert for server side of mTLS
	clientCertPool, err := getClientCACert("certs/root.crt")
	handleError(err)

	config := tls.Config{
		ClientAuth:         tls.RequireAndVerifyClientCert, // set to tls.RequireAndVerifyClientCert if you want the chain to be verified (if not valid, you won't get to see the client cert data sent to server- handshake will fail first)
		ClientCAs:          clientCertPool,
		Certificates:       []tls.Certificate{*certificate},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // true == accept any cert from origin server (used if you self-signed your origin certs) (this is unrelated to mutual authentication)
	}

	// start a tcp server
	listener, err := tls.Listen("tcp", "0.0.0.0:"+*port, &config)
	if err != nil {
		log.Printf("server: could not start listening, error: %s\n", err)
		log.Printf("try running the server with the -port=# flag to listen on another port\n")
		return
	}
	log.Printf("server: ready\n")

	for {
		// wait for a new incoming connection
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: could not accept incoming connection, error: %s\n", err)
			continue
		}
		// we got a connection
		log.Printf("server: accepted connection from: %s\n", conn.RemoteAddr())

		// get the underlying tls connection
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			log.Printf("server: erm, this is not a tls conn\n")
		}
		// perform handshake
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("client: error during handshake, error: %s\n", err)
		}

		tlsConn.ConnectionState()
		// get connection state and print certs sent by client
		state := tlsConn.ConnectionState()

		log.Printf("Certs from state.VerifiedChains\n")
		for _, list := range state.VerifiedChains {
			log.Printf("VERIFIED\n")
			for _, v := range list {
				log.Printf(" * Verified cert: Subject %s, Issuer: %s\n", v.Subject, v.Issuer)
			}
		}

		log.Printf("Certs from state.PeerCertificates\n")
		for _, v := range state.PeerCertificates {
			log.Printf(" * Client cert: Subject: %s, Issuer: %s\n", v.Subject, v.Issuer)

			if *verbose {
				text, err := certinfo.CertificateText(v) // this library can only give the entire human-readable cert, cannot specific select parts
				if err != nil {
					log.Printf("server: error converting cert to human-readable format, error: %s\n", err)
				}
				log.Printf("Cert data:\n%s\n", text)
			}
		}
		log.Println("Did resume? ", tlsConn.ConnectionState().DidResume)
		// close connection
		conn.Close()

		log.Println()
	}
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

func handleError(err error) {
	if err != nil {
		log.Println("Error, ", err)
	}
}
