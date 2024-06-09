package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

// 生成RSA密钥对
func GenRSAKey(keySize int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keySize)
}

// RSA私钥转PEM格式
func RSAPrivateKeyToPEM(privateKey *rsa.PrivateKey) string {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	return string(privateKeyPEM)
}

// 生成ECDSA密钥对
func GenECDSAKey() (*ecdsa.PrivateKey, error) {
	// 选择椭圆曲线，这里选择P256
	curve := elliptic.P256()
	return ecdsa.GenerateKey(curve, rand.Reader)
}

// ECDSA私钥转PEM格式
func ECDSAPrivateKeyToPEM(privateKey *ecdsa.PrivateKey) string {
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return ""
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	return string(privateKeyPEM)
}

// string格式的IP地址转换成net.IP
func StrToIP(ips []string) (netIPs []net.IP, err error) {
	for _, ip := range ips {
		netIP := net.ParseIP(ip)
		if netIP != nil {
			return nil, errors.Errorf("invalid ip: %s", ip)
		}
		netIPs = append(netIPs, netIP)
	}
	return
}

// 生成CSR
func GenerateCSR(private string, req *pb.CSRRequest) (string, error) {
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

	privateKey, err := LoadPrivateKey(private)
	if err != nil {
		return "", errors.Wrap(err, "load private key failed")
	}

	csrBytes, err = x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
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
	certTemplate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse cert failed")
	}
	return certTemplate, nil
}

// load private from pem string
func LoadPrivateKey(str string) (any, error) {
	privateBlock, _ := pem.Decode([]byte(str))
	if privateBlock == nil {
		return nil, errors.New("decode private key failed")
	}
	if privateBlock.Type == "RSA PRIVATE KEY" {
		rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
		if err != nil {
			return "", errors.Wrap(err, "parse rsa private key failed")
		}
		return rsaPrivateKey, nil
	} else if privateBlock.Type == "EC PRIVATE KEY" {
		ecdsaPrivateKey, err := x509.ParseECPrivateKey(privateBlock.Bytes)
		if err != nil {
			return "", errors.Wrap(err, "parse ecdsa private key failed")
		}
		return ecdsaPrivateKey, nil
	} else {
		return "", errors.New("invalid private key type")
	}
}

// load RSA private from pem string
func LoadRSAPrivateKey(str string) (*rsa.PrivateKey, error) {
	privateBlock, _ := pem.Decode([]byte(str))
	if privateBlock == nil {
		return nil, errors.New("decode RSA private key failed")
	}
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse rsa private key failed")
	}
	return rsaPrivateKey, nil
}

// load ecdsa private from pem string
func LoadECDSAPrivateKey(str string) (*ecdsa.PrivateKey, error) {
	privateBlock, _ := pem.Decode([]byte(str))
	if privateBlock == nil {
		return nil, errors.New("decode ECDSA private key failed")
	}
	ecdsaPrivateKey, err := x509.ParseECPrivateKey(privateBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse ecdsa private key failed")
	}
	return ecdsaPrivateKey, nil
}

// 生成RSA根证书
func GenRSARootCert(privateKey *rsa.PrivateKey, config *conf.RootCert) (string, string, error) {
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
	certTemp := x509.Certificate{
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
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemp, &certTemp, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", errors.Wrap(err, "create cert failed")
	}

	crlTemp := x509.RevocationList{
		SignatureAlgorithm:        certTemp.SignatureAlgorithm,
		RevokedCertificateEntries: []x509.RevocationListEntry{},
		Number:                    big.NewInt(0),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(0, 0, 1),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &crlTemp, &certTemp, privateKey)
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

// 生成ECDSA根证书
func GenECDSARootCert(privateKey *ecdsa.PrivateKey, config *conf.RootCert) (string, string, error) {
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
	certTemp := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         config.Common,
			Organization:       []string{config.Organization},
			OrganizationalUnit: []string{config.OrganizationUnit},
			Country:            []string{config.Country},
			Province:           []string{config.Province},
			Locality:           []string{config.Locality},
		},
		EmailAddresses: []string{config.Email},
		DNSNames:       config.Dns,
		IPAddresses:    netIPs,
		KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemp, &certTemp, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", errors.Wrap(err, "create cert failed")
	}
	crlTemp := x509.RevocationList{
		SignatureAlgorithm:        certTemp.SignatureAlgorithm,
		RevokedCertificateEntries: []x509.RevocationListEntry{},
		Number:                    big.NewInt(0),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(0, 0, 1),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &crlTemp, &certTemp, privateKey)
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

func SignCert(private any, csr *x509.CertificateRequest, day int) (string, *big.Int, error) {
	var publicKey any
	switch private.(type) {
	case *rsa.PrivateKey:
		publicKey = &private.(*rsa.PrivateKey).PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &private.(*ecdsa.PrivateKey).PublicKey
	default:
		return "", nil, errors.New("invalid private key type")
	}
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
	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemp, &certTemp, publicKey, private)
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
