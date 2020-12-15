package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"github.com/willf/bloom"
	"golang.org/x/crypto/ocsp"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func getSha256Fingerprint(certificate *x509.Certificate) [sha256.Size]byte {
	return sha256.Sum256(certificate.Raw)
}

func getSha1Fingerprint(certificate *x509.Certificate) [sha1.Size]byte {
	return sha1.Sum(certificate.Raw)
}

func getSha384Fingerprint(certificate *x509.Certificate) [sha512.Size384]byte {
	return sha512.Sum384(certificate.Raw)
}



type CRLInfo struct {
	Size       int64
	RemoteAddr string
	FileName string
}

type CertificateBundle struct {
	CommonNames []string
	SubjectAlternativeNames [][]string
	Certificates []x509.Certificate
	CRLFileNames []string
	Hash256 []string
}

func downloadFromUrl(url string, port int) CRLInfo {
	tokens := strings.Split(url, "/")
	host := tokens[2]
	host += ":" + strconv.Itoa(port)
	conn, err := net.Dial("tcp", host)
	if err != nil {
		panic("Unable to connect to " + host)
	}
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
	fileName := tokens[len(tokens)-1]
	fmt.Println("Downloading", url, "to", fileName)

	// TODO: check file existence first with io.IsExist
	output, err := os.Create(fileName)
	if err != nil {
		panic("Error while creating " + fileName)
	}
	defer output.Close()

	response, err := http.Get(url)
	if err != nil {
		panic("Error while downloading " + url)
	}
	defer response.Body.Close()

	n, err := io.Copy(output, response.Body)
	if err != nil {
		panic("Error while downloading " + url)
	}

	return CRLInfo{Size: n, RemoteAddr: conn.RemoteAddr().String(), FileName:fileName}
	//fmt.Println(n, "bytes downloaded.")
}

func convertBytesToCertificate(certificate []byte) *x509.Certificate {
	block, _ := pem.Decode([]byte(certificate))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	return cert
}

func VerifyCertificate(certificate x509.Certificate) bool {
	// First, create the set of root certificates.
	// This includes the four (currently valid) DOD Root CAs

	const rootCA5 = `
-----BEGIN CERTIFICATE-----
MIICJDCCAaqgAwIBAgIBDzAKBggqhkjOPQQDAzBbMQswCQYDVQQGEwJVUzEYMBYG
A1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAKBgNVBAsTA1BL
STEWMBQGA1UEAxMNRG9EIFJvb3QgQ0EgNTAeFw0xNjA2MTQxNzE3MjdaFw00MTA2
MTQxNzE3MjdaMFsxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1l
bnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRYwFAYDVQQDEw1Eb0QgUm9v
dCBDQSA1MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAENmLeC07Ax9cpRTp/HJnmKiF2
sQDdjEf/wLG0+s46TlL7p+02LRweHJCNl6orpuLTc3N8XBzQZ/QKKdOQhOtR5fFe
HMDShoTFbdEkSQ7sF4nkaMjeGlwaBtA4GTMpARqBo0IwQDAdBgNVHQ4EFgQUhsAV
Qvtxdtw+LRFbIRBENcrB3BQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMB
Af8wCgYIKoZIzj0EAwMDaAAwZQIwQQbk3t5iNJ3fuKoW2W2iOB85IlfJcIQfkw9X
fgUvpUszzRXqV9XSKx+bjXzOarbMAjEAt4HS4TuTzxFk3AsvF9Jt1dgF5FByYmXc
pDzKYaUGmsn77cQwyXuJ4KW+Y1XmnBHj
-----END CERTIFICATE-----`

	const rootCA4 = `
-----BEGIN CERTIFICATE-----
MIIB6zCCAY+gAwIBAgIBATAMBggqhkjOPQQDAgUAMFsxCzAJBgNVBAYTAlVTMRgw
FgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMD
UEtJMRYwFAYDVQQDEw1Eb0QgUm9vdCBDQSA0MB4XDTEyMDczMDE5NDgyM1oXDTMy
MDcyNTE5NDgyM1owWzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJu
bWVudDEMMAoGA1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxFjAUBgNVBAMTDURvRCBS
b290IENBIDQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR2yNhDyw8H0iwPKtA4
8YLNQlXn3B1agLcIkUtU1k+yZoU0lo0uPvTgSpF8zM2GnxHgUqFmgsbLkCPsX1/1
8DxFo0IwQDAdBgNVHQ4EFgQUvcG5a030HewwkL9ic8CEM/JxJIUwDgYDVR0PAQH/
BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wDAYIKoZIzj0EAwIFAANIADBFAiEA6GGK
99yqCaUH0kSeggNaRFNHhCOZz1zT3kpe1rs1NUYCIHYPuMR8FjV/1BLtiD2AEWtk
B0xFZd9Trl8B7fFD0vW3
-----END CERTIFICATE-----`

	const rootCA3 = `
-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgIBATANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJVUzEY
MBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAKBgNVBAsT
A1BLSTEWMBQGA1UEAxMNRG9EIFJvb3QgQ0EgMzAeFw0xMjAzMjAxODQ2NDFaFw0y
OTEyMzAxODQ2NDFaMFsxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVy
bm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRYwFAYDVQQDEw1Eb0Qg
Um9vdCBDQSAzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqewUcoro
S3Cj2hADhKb7pzYNKjpSFr8wFVKGBUcgz6qmzXXEZG7v8WAjywpmQK60yGgqAFFo
STfpWTJNlbxDJ+lAjToQzhS8Qxih+d7M54V2c14YGiNbvT8f8u2NGcwD0UCkj6cg
AkwnWnk29qM3IY4AWgYWytNVlm8xKbtyDsviSFHy1DekNdZv7hezsQarCxmG6CNt
MRsoeGXF3mJSvMF96+6gXVQE+7LLK7IjVJGCTPC/unRAOwwERYBnXMXrolfDGn8K
Lb1/udzBmbDIB+QMhjaUOiUv8n3mlzwblLSXWQbJOuQL2erp/DtzNG/955jk86HC
kF8c9T8u1xnTfwIDAQABo0IwQDAdBgNVHQ4EFgQUbIqUonexgHIdgXoWqvLczmbu
RcAwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAJ9xpMC2ltKAQ6BI6R92BPnFPK1mGFhjm8O26GiKhVpCZhK00uaLiH+H
9Jj1qMYJyR/wLB/sgrj0pUc4wTMr30x+mr4LC7HLD3xQKBDPio2i6bqshtfUsZNf
Io+WBbRODHWRfdPy55TClBR2T48MqxCHWDKFB3WGEgte6lO0CshMhJIf6+hBhjy6
9E5BStFsWEdBw4Za8u7p8pgnguouNtb4Bl6C8aBSk0QJutKpGVpYo6hdIG1PZPgw
hxuQE0iBzcqQxw3B1Jg/jvIOV2gzEo6ZCbHw5PYQ9DbySb3qozjIVkEjg5rfoRs1
fOs/QbP1b0s6Xq5vk3aY0vGZnUXEjnI=
-----END CERTIFICATE-----`

	const rootCA2 = `
-----BEGIN CERTIFICATE-----
MIIDcDCCAligAwIBAgIBBTANBgkqhkiG9w0BAQUFADBbMQswCQYDVQQGEwJVUzEY
MBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAKBgNVBAsT
A1BLSTEWMBQGA1UEAxMNRG9EIFJvb3QgQ0EgMjAeFw0wNDEyMTMxNTAwMTBaFw0y
OTEyMDUxNTAwMTBaMFsxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVy
bm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRYwFAYDVQQDEw1Eb0Qg
Um9vdCBDQSAyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwCzB9o07
rP8/PNZxvrh0IgfscEEV/KtA4weqwcPYn/7aTDq/P8jYKHtLNgHArEUlw9IOCo+F
GGQQPRoTcCpvjtfcjZOzQQ84Ic2tq8I9KgXTVxE3Dc2MUfmT48xGSSGOFLTNyxQ+
OM1yMe6rEvJl6jQuVl3/7mN1y226kTT8nvP0LRy+UMRC31mI/2qz+qhsPctWcXEF
lrufgOWARVlnQbDrw61gpIB1BhecDvRD4JkOG/t/9bPMsoGCsf0ywbi+QaRktWA6
WlEwjM7eQSwZR1xJEGS5dKmHQa99brrBuKG/ZTE6BGf5tbuOkooAY7ix5ow4X4P/
UNU7ol1rshDMYwIDAQABoz8wPTAdBgNVHQ4EFgQUSXS7DF66ev4CVO97oMaVxgmA
cJYwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEFBQAD
ggEBAJiRjT+JyLv1wGlzKTs1rLqzCHY9cAmS6YREIQF9FHYb7lFsHY0VNy17MWn0
mkS4r0bMNPojywMnGdKDIXUr5+AbmSbchECV6KjSzPZYXGbvP0qXEIIdugqi3VsG
K52nZE7rLgE1pLQ/E61V5NVzqGmbEfGY8jEeb0DU+HifjpGgb3AEkGaqBivO4XqS
tX3h4NGW56E6LcyxnR8FRO2HmdNNGnA5wQQM5X7Z8a/XIA7xInolpHOZzD+kByeW
qKKV7YK5FtOeC4fCwfKI9WLfaN/HvGlR7bFc3FRUKQ8JOZqsA8HbDE2ubwp6Fknx
v5HSOJTT9pUst2zJQraNypCNhdk=
-----END CERTIFICATE-----`

	roots := x509.NewCertPool()
	err5 := roots.AppendCertsFromPEM([]byte(rootCA5))
	err4 := roots.AppendCertsFromPEM([]byte(rootCA4))
	err3 := roots.AppendCertsFromPEM([]byte(rootCA3))
	err2 := roots.AppendCertsFromPEM([]byte(rootCA2))

	if !err5 || !err4 || !err3 || !err2 {
		panic("failed to parse root certificate")
	}

	//block, _ := pem.Decode(certificate.Raw)
	//if block == nil {
	//	panic("failed to parse certificate PEM")
	//}
	//cert, err := x509.ParseCertificate(block.Bytes)
	//if err != nil {
	//	panic("failed to parse certificate: " + err.Error())
	//}

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := certificate.Verify(opts); err != nil {
		return false
	} else {
		return true
	}
}

func GenerateOCSPResponse(caName string, certs CertificateBundle, responderCert *x509.Certificate) {

	var issuer *Certificate
	var status ocsp.ResponseStatus
	for _, cert := range certs.Certificates {
		if cert.Subject.CommonName == caName {

			break
		}
		//TODO: change status code based on errors
	}
	templateInfo := ocsp.Response{
		Status:             0,
		SerialNumber:       nil,
		ThisUpdate:         time.Time{},
		NextUpdate:         time.Time{},
		RevokedAt:          time.Time{},
		RevocationReason:   0,
	}
	ocsp.CreateResponse(, templateInfo, )
}

func loadCertificates() CertificateBundle {
	cert, err := os.Open("DoD_CAs.pem")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	pemfileinfo, _ := cert.Stat()
	size := pemfileinfo.Size()
	pembytes := make([]byte, size)

	buffer := bufio.NewReader(cert)
	_, err = buffer.Read(pembytes)
	certString := string(pembytes)
	concatcerts := strings.SplitAfter(certString, "-----END CERTIFICATE-----")
	var certs []x509.Certificate
	var bundle CertificateBundle
	for _, s := range concatcerts {
		cert := strings.Split(s, "\n")
		var tempString string
		for _, c := range cert {
			//determines if this certificate is a root certificate
			if strings.HasPrefix(c, "subject") || strings.HasPrefix(c, "issuer") || c == "" {
			} else {
				tempString += c
				tempString += "\n"
			}
		}
		certBytes := []byte(tempString)
		if(tempString != "") {
			tempCert := convertBytesToCertificate(certBytes)
			if (err != nil) {
				panic("oh no")
			}
			//getting Sha256 fingerprint of the certificate
			fingerprint := getSha256Fingerprint(tempCert)
			//converting the fingerprint to a hex string
			stringFingerprint := fmt.Sprintf("%x", fingerprint)
			bundle.Hash256 = append(bundle.Hash256, stringFingerprint)
			bundle.CommonNames = append(bundle.CommonNames, tempCert.Subject.CommonName)
			bundle.Certificates = append(bundle.Certificates, *tempCert)
			certs = append(certs, *tempCert)
		}
		tempString = ""
	}
	cert.Close()
	return bundle
}


func readCurrentDir() []string {
	var CRLFiles []string
	file, err := os.Open(".")
	if err != nil {
		log.Fatalf("failed opening directory: %s", err)
	}
	defer file.Close()

	list,_ := file.Readdirnames(0) // 0 to read all files and folders
	for _, name := range list {
		if filepath.Ext(name) == ".crl" {
			CRLFiles = append(CRLFiles, name)
		}
	}
	return CRLFiles
}

func loadCRLs(CRLList []string) []*pkix.CertificateList {
	var parsedCRLs []*pkix.CertificateList
	for _, crl := range CRLList {
		parsedCRLs = append(parsedCRLs, parseCRL(crl))
	}
	return parsedCRLs
}

func parseCRL(crlFile string) *pkix.CertificateList {
	cert, err := os.Open(crlFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer cert.Close()
	pemfileinfo, _ := cert.Stat()
	size := pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(cert)
	_, err = buffer.Read(pembytes)
	crl, err := x509.ParseDERCRL(pembytes)
	if (err != nil) {
		panic(err)
	}
	return crl
}

type CRLInfo struct {
	CAName string
	NumRevocations int
	CRL *pkix.CertificateList
}

type CRLPageData struct {
	PageTitle string
	CRLS     []*pkix.CertificateList
}

type CRLRevocations struct {
	Issuer string
	NumberOfRevocations int
}

type CRLStatsPageData struct {
	PageTitle string
	Revocations []CRLRevocations
}

func crlStatsHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("crllist.html"))
	CRLS := loadCRLs(readCurrentDir())
	var stats CRLStatsPageData
	for _, CRL := range CRLS {
		var ca CRLRevocations
		ca.Issuer = CRL.TBSCertList.Issuer.String()
		ca.NumberOfRevocations = len(CRL.TBSCertList.RevokedCertificates)
		stats.Revocations = append(stats.Revocations, ca)
	}
	tmpl.Execute(w, stats)
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	clock := time.Now()
	text := "Hello world!\n"
	text += clock.String() + "\n"
	io.WriteString(w, text)
}

func crlHandler(w http.ResponseWriter, r *http.Request) {
	// Write "Hello, world!" to the response body
	tmpl := template.Must(template.ParseFiles("layout.html"))
	start := time.Now()
	CRL := loadCRLs(readCurrentDir())
	data := CRLPageData{
		PageTitle: "CRLInfo Info",
		CRLS: CRL}
	elapsed := time.Since(start)
	log.Printf("crlHandler took %s", elapsed)
	tmpl.Execute(w, data)
}

type CRLBloomFilter struct {
	CA string
	Filter bloom.BloomFilter
}

func ConstructBloomFilters(crls[] CRLInfo) []CRLBloomFilter {
	var filters []CRLBloomFilter
	for _, crl := range crls {
		var temp CRLBloomFilter {
			CA: crl.FileName
		}
		filters = append(filters, ConstructBloomFilter(crl))
	}
	return filters
}

func ConstructBloomFilter(crl CRLInfo) *bloom.BloomFilter {
	filter := createBloom(1000000)
	parsedCRL := parseCRL(crl.FileName)
	for k := 0; k < len(parsedCRL.TBSCertList.RevokedCertificates); k++ {
		addItemToBloom(parsedCRL.TBSCertList.RevokedCertificates[k].SerialNumber.Uint64(), filter)
	}
	return filter
}


func main() {
	list := downloadCRLs()
	const CRLEndpoint = "crl.disa.mil"
	const OCSPEndpoint = "ocsp.disa.mil"
	//data := downloadCRLs()
	//fmt.Print("Downloaded from: ", data)
	filter := createBloom(1000000)
	CRL := parseCRL("DODEMAILCA_41.crl")
	//CRLS := loadCRLs(readCurrentDir())
	//const numFCRLS = 100
	////var filters []CRLBloomFilter

	//for i:=0; i < len(CRLS); i++ {
	//	filters = append(filters,CRLBloomFilter{})
	//	currentFilter := &filters[i].Filter
	//	currentFilter = createBloom(1000000)
	//	filters[i].CA = CRLS[i].TBSCertList.Issuer.String()
	//	for j:= 0; j < len(CRLInfo.TBSCertList.RevokedCertificates); j++  {
	//		addItemToBloom(CRLS[i].TBSCertList.RevokedCertificates[j].SerialNumber.Uint64(), currentFilter)
	//	}
	//}

	for k := 0; k < len(CRL.TBSCertList.RevokedCertificates); k++ {
		addItemToBloom(CRL.TBSCertList.RevokedCertificates[k].SerialNumber.Uint64(), filter)
	}

	fmt.Println(findItemBloom(1572835, filter))
	fmt.Println(findItemBloom(3145685, filter))
	fmt.Println(findItemBloom(3145686, filter))
	fmt.Println(findItemBloom(3145525, filter))
	fmt.Println(findItemBloom(3145526, filter))
	fmt.Println(findItemBloom(1572626, filter))


	//loadCertificates()
	//CRLDownloadInfo := downloadCRLs()
	//for _, CRLInfo := range CRLDownloadInfo {
	//	fmt.Println(CRLInfo.FileName, " has ",len(parseCRL(CRLInfo.FileName).TBSCertList.RevokedCertificates), " revocations")
	//}
	// Set up a /hello resource handler
	// Set up a /hello resource handler
	//http.HandleFunc("/hello", helloHandler)
	////http.HandleFunc("/crl", crlHandler)
	//http.HandleFunc("/crlstats", crlStatsHandler)
	//http.HandleFunc("/crl", crlHandler)
	//
	//// Create a CA certificate pool and add cert.pem to it
	////caCert, err := ioutil.ReadFile("cert.pem")
	//cloudflare, err := ioutil.ReadFile("origin-pull-ca.pem")

	//if err != nil {
	//	log.Fatal(err)
	//}
	//caCertPool := x509.NewCertPool()
	//caCertPool.AppendCertsFromPEM(cloudflare)
	////caCertPool.AppendCertsFromPEM(caCert)
	//
	//
	//// Create the TLS Config with the CA pool and enable Client certificate validation
	//tlsConfig := &tls.Config{
	//	//ClientCAs: caCertPool,
	//	//ClientAuth: tls.RequireAndVerifyClientCert,
	//}
	////tlsConfig.BuildNameToCertificate()
	//
	//// Create a Server instance to listen on port 8443 with the TLS config
	//server := &http.Server{
	//	Addr:      ":8080",
	//	TLSConfig: tlsConfig,
	//}
	//
	//// Listen to HTTPS connections with the server certificate and wait
	////log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
	//log.Fatal(server.ListenAndServe())
	////fmt.Println("Downloaded from", CRLEndpoint, CRLDownloadInfo[0].RemoteAddr)
}

func createBloom(n uint) *bloom.BloomFilter {
	filter := bloom.New(20*n, 5) // load of 20, 5 keys
	return filter
}

func addItemToBloom(serial uint64, filter *bloom.BloomFilter) {
	n1 := make([]byte,8)
	binary.BigEndian.PutUint64(n1,serial)
	filter.Add(n1)
}

func findItemBloom(serial uint64, filter *bloom.BloomFilter) bool {
	n1 := make([]byte,8)
	binary.BigEndian.PutUint64(n1,serial)
	return filter.Test(n1)
}

func downloadCRLs() []CRLInfo {
	bundle := loadCertificates()
	certs := bundle.Certificates
	var CRLDownloadInfo []CRLInfo
	for _, cert := range certs {
		if VerifyCertificate(cert) {
			if !strings.HasPrefix(cert.Subject.CommonName, "DoD Root") {
				var crl = ""
				if strings.HasPrefix(cert.Subject.CommonName, "DOD EMAIL") {
					crl = "http://crl.disa.mil/crl/DODEMAILCA_" + strings.SplitAfter(cert.Subject.CommonName, "-")[1] + ".crl"
				} else if strings.HasPrefix(cert.Subject.CommonName, "DOD ID SW") {
					crl = "http://crl.disa.mil/crl/DODIDSWCA_" + strings.SplitAfter(cert.Subject.CommonName, "-")[1] + ".crl"
				} else if strings.HasPrefix(cert.Subject.CommonName, "DOD ID") {
					crl = "http://crl.disa.mil/crl/DODIDCA_" + strings.SplitAfter(cert.Subject.CommonName, "-")[1] + ".crl"
				} else if strings.HasPrefix(cert.Subject.CommonName, "DOD SW") {
					crl = "http://crl.disa.mil/crl/DODSWCA_" + strings.SplitAfter(cert.Subject.CommonName, "-")[1] + ".crl"
				} else {
					continue
				}
				fingerprint := getSha256Fingerprint(&cert)
				var crlSize int64 = 0
				downloadInfo := downloadFromUrl(crl, 80)
				crlSize = downloadInfo.Size
				s := cert.Subject.CommonName + " " + cert.SignatureAlgorithm.String() + " Issuing CA: " + cert.Issuer.CommonName + " CRLInfo Size: " + strconv.Itoa(int(crlSize)) + ": "
				s += fmt.Sprintf("%x", fingerprint)
				//hashes = append(hashes, s)
				fmt.Println(s)
				CRLDownloadInfo = append(CRLDownloadInfo, downloadInfo)
			}
		}
	}
	return CRLDownloadInfo
}

func CreateSmartCardPlist(hashes []string, filename string) string {

	base := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>TrustedAuthorities</key>
	<array>`

	for _, k := range hashes {
		base += "\n" + "<string>" + k + "</string>" + "\n"

	}
	base += `</array>\n`
	base += `	<key>AttributeMapping</key>
	<dict>
		<key>fields</key>
		<array>
			<string>NT Principal Name</string>
		</array>
		<key>formatString</key>
		<string>Kerberos:$1</string>
		<key>dsAttributeString</key>
		<string>dsAttrTypeStandard:AltSecurityIdentities</string>
	</dict>
</dict>
</plist>`

	return base
}
