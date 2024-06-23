package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/pkg/errors"

	pb "github.com/mengbin92/goca/api/goca/v1"
	"github.com/mengbin92/goca/internal/conf"
)

// 生成密钥对
func GenerateKey(req *pb.GenKeyRequest) (any, error) {
	switch req.KeyType {
	case pb.KeyType_RSA:
		return rsa.GenerateKey(rand.Reader, int(req.KeySize))
	case pb.KeyType_ECDSA:
		curve := elliptic.P256()
		return ecdsa.GenerateKey(curve, rand.Reader)
	default:
		return nil, errors.Errorf("invalid key type: %d", req.KeyType)
	}
}

// privateKey转PEM格式
func PrivateToPEM(priv any) (string, error) {

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", errors.Wrap(err, "marshal private key failed")
	}

	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})
	return string(privPem), nil
}

func PrivatePemToKey(privStr string) (any, error) {
	privPem, _ := pem.Decode([]byte(privStr))
	if privPem == nil {
		return nil, errors.New("decode private key failed")
	}

	if privPem.Type != "PRIVATE KEY" {
		return nil, errors.Errorf("invalid private key type: %s", privPem.Type)
	}

	return x509.ParsePKCS8PrivateKey(privPem.Bytes)
}

// string格式的IP地址转换成net.IP
func StrToIP(ips []string) (netIPs []net.IP, err error) {
	for _, ip := range ips {
		netIP := net.ParseIP(ip)
		if netIP == nil {
			return nil, errors.Errorf("invalid ip: %s", ip)
		}
		netIPs = append(netIPs, netIP)
	}
	return
}

// 生成CSR
func GenerateCSR(private any, req *pb.CSRRequest) (string, error) {
	var csrBytes []byte
	var err error

	// string IP 转换成 net.IP
	netIPs, err := StrToIP(req.Ip)
	if err != nil {
		return "", errors.Wrap(err, "invalid ip")
	}
	// CSR模板
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         req.Common,
			Organization:       []string{req.Organization},
			OrganizationalUnit: []string{req.OrganizationUnit},
			Country:            []string{req.Country},
			Province:           []string{req.Province},
			Locality:           []string{req.Locality},
		},
		EmailAddresses: []string{req.Email},
		DNSNames:       req.Dns,
		IPAddresses:    netIPs,
	}

	csrBytes, err = x509.CreateCertificateRequest(rand.Reader, &csrTemplate, private)
	if err != nil {
		return "", errors.Wrap(err, "create rsa csr failed")
	}

	csrPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	return string(csrPem), nil
}

// load CSR
func LoadCSR(csr string) (*x509.CertificateRequest, error) {
	csrBlock, _ := pem.Decode([]byte(csr))
	if csrBlock == nil {
		return nil, errors.New("decode csr failed")
	}
	if csrBlock.Type != "CERTIFICATE REQUEST" {
		return nil, errors.Errorf("invalid csr type: %s", csrBlock.Type)
	}
	csrTemplate, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse csr failed")
	}
	return csrTemplate, nil
}

// load 证书
func LoadCert(cert string) (*x509.Certificate, error) {
	certBlock, _ := pem.Decode([]byte(cert))
	if certBlock == nil {
		return nil, errors.New("decode cert failed")
	}
	if certBlock.Type != "CERTIFICATE" {
		return nil, errors.Errorf("invalid cert type: %s", certBlock.Type)
	}
	certTemplate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse cert failed")
	}
	return certTemplate, nil
}

func toCryptoSigner(priv any) (crypto.Signer, error) {
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		return key, nil
	case *ecdsa.PrivateKey:
		return key, nil
	default:
		return nil, errors.New("unsupported private key type")
	}
}

func getPublicKey(priv any) (any, error) {
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		return key.PublicKey, nil
	case *ecdsa.PrivateKey:
		return key.PublicKey, nil
	default:
		return nil, errors.New("unsupported private key type")
	}
}

// 生成根证书和CRL
func GenerateRootCert(priv any, config *conf.RootCert) (string, string, error) {
	// 生成证书编号
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", errors.Wrap(err, "generate serial number failed")
	}

	// string IP 转换成 net.IP
	netIPs, err := StrToIP(config.Ip)
	if err != nil {
		return "", "", errors.Wrap(err, "invalid ip")
	}
	// 生成证书
	certTemp := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         config.Common,
			Organization:       []string{config.Organization},
			OrganizationalUnit: []string{config.OrganizationUnit},
			Country:            []string{config.Country},
			Province:           []string{config.Province},
			Locality:           []string{config.Locality},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		EmailAddresses:        []string{config.Email},
		DNSNames:              config.Dns,
		IPAddresses:           netIPs,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	crlTemp := &x509.RevocationList{
		SignatureAlgorithm:        certTemp.SignatureAlgorithm,
		RevokedCertificateEntries: []x509.RevocationListEntry{},
		Number:                    big.NewInt(0),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(0, 0, 1),
	}

	var publicKey any
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		publicKey = &key.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &key.PublicKey
	default:
		return "", "", errors.New("invalid private key type")
	}
	ski, err := generateSubjectKeyIdentifier(publicKey)
	if err != nil {
		return "", "", errors.Wrap(err, "generate subject key identifier failed")
	}
	certTemp.SubjectKeyId = ski
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemp, certTemp, publicKey, priv)
	if err != nil {
		return "", "", errors.Wrap(err, "create cert failed")
	}

	signer, err := toCryptoSigner(priv)
	if err != nil {
		return "", "", errors.Wrapf(err, "parse private key to crypto.Signer error")
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemp, certTemp, signer)
	if err != nil {
		return "", "", errors.Wrap(err, "create crl failed")
	}

	return string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		})), string(pem.EncodeToMemory(&pem.Block{
			Type:  "X509 CRL",
			Bytes: crlBytes})), nil
}

func SignCert(priv any, parent *x509.Certificate, csr *x509.CertificateRequest, day int) (string, *big.Int, error) {
	// 生成证书编号
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", nil, errors.Wrap(err, "generate serial number failed")
	}

	// 准备证书模版
	certTemp := x509.Certificate{
		SerialNumber:   serialNumber,
		Subject:        csr.Subject,
		EmailAddresses: csr.EmailAddresses,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(time.Duration(day) * time.Hour),
		KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	// 生成Subject Key Identifier
	var publicKey any
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		publicKey = &key.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &key.PublicKey
	default:
		return "", nil, errors.New("invalid private key type")
	}
	ski, err := generateSubjectKeyIdentifier(publicKey)
	if err != nil {
		return "", nil, errors.Wrap(err, "generate subject key identifier failed")
	}
	certTemp.SubjectKeyId = ski
	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemp, parent, publicKey, priv)
	if err != nil {
		return "", nil, errors.Wrap(err, "create cert failed")
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})), serialNumber, nil
}

// load crl from pem string
func LoadCRL(crlStr string) (*x509.RevocationList, error) {
	block, _ := pem.Decode([]byte(crlStr))
	if block == nil {
		return nil, errors.New("decode crl failed")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse crl failed")
	}
	return crl, nil
}

func Str2BigInt(str string) (*big.Int, bool) {
	return new(big.Int).SetString(str, 10)
}

// generateSubjectKeyIdentifier 生成一个Subject Key Identifier
func generateSubjectKeyIdentifier(pubKey any) ([]byte, error) {
	// 通常SKI是公钥的SHA-1散列值
	pubKeyASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	ski := sha1.Sum(pubKeyASN1)
	return ski[:], nil
}
