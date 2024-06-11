package service

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	pb "github.com/mengbin92/goca/api/goca/v1"
	"github.com/mengbin92/goca/internal/biz"
	"github.com/mengbin92/goca/internal/conf"
	"github.com/mengbin92/goca/internal/utils"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"software.sslmate.com/src/go-pkcs12"
)

type CertService struct {
	pb.UnimplementedCertServer
	repo *biz.CAUseCase
}

func NewCertService(cert *biz.CAUseCase, root *conf.RootCert, logger log.Logger) (*CertService, error) {
	cs := &CertService{repo: cert}

	rootCert, err := cs.repo.GetRootCert(context.Background(), root.Common)
	if err != nil && err != redis.Nil {
		return nil, errors.Wrap(err, "get root cert error")
	}
	if rootCert == "" {
		var privateKeyStr, rootCert, crl string
		var err error
		if root.KeyPair.KeyType == conf.KeyType_RSA {
			privateKey, err := utils.GenRSAKey(int(root.KeyPair.KeySize))
			if err != nil {
				return nil, errors.Wrap(err, "generate rsa key error")
			}
			privateKeyStr = utils.RSAPrivateKeyToPEM(privateKey)

			rootCert, crl, err = utils.GenRSARootCert(privateKey, root)
			if err != nil {
				return nil, errors.Wrap(err, "generate rsa root cert error")
			}
		} else if root.KeyPair.KeyType == conf.KeyType_ECDSA {
			privateKey, err := utils.GenECDSAKey()
			if err != nil {
				return nil, errors.Wrap(err, "generate ecdsa key error")
			}
			privateKeyStr = utils.ECDSAPrivateKeyToPEM(privateKey)
			rootCert, crl, err = utils.GenECDSARootCert(privateKey, root)
			if err != nil {
				return nil, errors.Wrap(err, "generate ecdsa root cert error")
			}
		} else {
			return nil, errors.Errorf("invalid key type: %d", root.KeyPair.KeyType)
		}
		if err = cs.repo.SavePrivateKey(context.Background(), root.Common, privateKeyStr); err != nil {
			return nil, errors.Wrap(err, "save private key error")
		}
		if err = cs.repo.SaveCert(context.Background(), root.Common, rootCert); err != nil {
			return nil, errors.Wrap(err, "save root cert error")
		}
		if err = cs.repo.SaveCRL(context.Background(), root.Common, crl); err != nil {
			return nil, errors.Wrap(err, "save root crl error")
		}
		if err = cs.repo.SaveRootCert(context.Background(), root.Common, rootCert); err != nil {
			return nil, errors.Wrap(err, "save root cert error")
		}
	}

	return cs, nil
}

func (s *CertService) GenKey(ctx context.Context, req *pb.GenKeyRequest) (*pb.GenKeyResponse, error) {
	var privateKeyStr string
	var err error

	if req.KeyType == pb.KeyType_RSA {
		privateKey, err := utils.GenRSAKey(int(req.KeySize))
		if err != nil {
			return nil, errors.Wrap(err, "generate rsa key error")
		}
		privateKeyStr = utils.RSAPrivateKeyToPEM(privateKey)
	} else if req.KeyType == pb.KeyType_ECDSA {
		privateKey, err := utils.GenECDSAKey()
		if err != nil {
			return nil, errors.Wrap(err, "generate ecdsa key error")
		}
		privateKeyStr = utils.ECDSAPrivateKeyToPEM(privateKey)
	} else {
		return nil, errors.Errorf("invalid key type: %d", req.KeyType)
	}
	if err = s.repo.SavePrivateKey(ctx, req.Common, privateKeyStr); err != nil {
		return nil, errors.Wrap(err, "save private key error")
	}
	return &pb.GenKeyResponse{
		KeyType:    req.KeyType,
		PrivateKey: privateKeyStr,
		Common:     req.Common,
	}, err
}
func (s *CertService) CSR(ctx context.Context, req *pb.CSRRequest) (*pb.CSRResponse, error) {
	// load private key
	privateKeyString, err := s.repo.GetPrivateKey(ctx, req.Common)
	if err != nil {
		return nil, errors.Wrap(err, "get private key error")
	}

	csr, err := utils.GenerateCSR(privateKeyString, req)
	if err != nil {
		return nil, errors.Wrap(err, "generate csr error")
	}

	return &pb.CSRResponse{
		CaCommon: req.CaCommon,
		Csr:      csr,
	}, nil
}
func (s *CertService) GetCert(ctx context.Context, req *pb.CertRequest) (*pb.CertResponse, error) {
	// load cert
	cert, err := s.repo.GetCert(ctx, req.Common)
	if err != nil && err != redis.Nil{
		return nil, errors.Wrap(err, "get cert error")
	}
	return &pb.CertResponse{Cert: cert}, nil
}
func (s *CertService) CASignCSR(ctx context.Context, req *pb.CASignCSRRequest) (*pb.CASignCSRResponse, error) {
	// load ca private key
	caPrivateKeyStr, err := s.repo.GetPrivateKey(ctx, req.CaCommon)
	if err != nil && err != redis.Nil{
		return nil, errors.Wrap(err, "get ca private key error")
	}
	caPrivateKey, err := utils.LoadPrivateKey(caPrivateKeyStr)
	if err != nil {
		return nil, errors.Wrap(err, "parse ca private key error")
	}

	// load csr from pem string
	csr, err := utils.LoadCSR(req.Csr)
	if err != nil {
		return nil, errors.Wrap(err, "load csr error")
	}

	// create cert
	cert, serial, err := utils.SignCert(caPrivateKey, csr, int(req.Days))
	if err != nil {
		return nil, errors.Wrap(err, "ca sign csr error")
	}

	// save cert to local
	s.repo.SaveCert(ctx, csr.Subject.CommonName, cert)

	return &pb.CASignCSRResponse{
		SerialNumber: serial.String(),
		Cert:         cert,
		CaCommon:     req.CaCommon,
	}, nil
}
func (s *CertService) RevokeCert(ctx context.Context, req *pb.RevokeCertRequest) (*pb.RevokeCertResponse, error) {
	var revokeds []x509.RevocationListEntry

	// load current CRL
	crlStr, err := s.repo.GetCRL(ctx, req.CaCommon)
	if err != nil && err != redis.Nil{
		return nil, errors.Wrap(err, "get crl error")
	}
	crl, err := utils.LoadCRL(crlStr)
	if err != nil {
		return nil, errors.Wrap(err, "parse crl error")
	}
	if crl != nil {
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.String() == req.SerialNumber {
				return &pb.RevokeCertResponse{}, errors.New("this cert has been revoked")
			}
			revokeds = crl.RevokedCertificateEntries
		}
	}
	serial, ok := utils.Str2BigInt(req.SerialNumber)
	if !ok {
		return &pb.RevokeCertResponse{}, errors.New("invalid serial number")
	}
	newRevoked := x509.RevocationListEntry{
		SerialNumber:   serial,
		RevocationTime: time.Now(),
	}
	revokeds = append(revokeds, newRevoked)

	// load ca private key
	caPrivateKeyStr, err := s.repo.GetPrivateKey(ctx, req.CaCommon)
	if err != nil {
		return nil, errors.Wrap(err, "get ca private key error")
	}
	caPrivateKey, err := utils.LoadPrivateKey(caPrivateKeyStr)
	if err != nil {
		return nil, errors.Wrap(err, "parse ca private key error")
	}

	// load ca cert
	caCertStr, err := s.repo.GetCert(ctx, req.CaCommon)
	if err != nil && err != redis.Nil{
		return nil, errors.Wrap(err, "get ca cert error")
	}
	caCert, err := utils.LoadCert(caCertStr)
	if err != nil {
		return nil, errors.Wrap(err, "parse ca cert error")
	}

	// create new crl
	crlTemp := x509.RevocationList{
		RevokedCertificateEntries: revokeds,
		SignatureAlgorithm:        caCert.SignatureAlgorithm,
		Number: big.NewInt(int64(len(revokeds))),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(0, 0, 1),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &crlTemp, caCert, caPrivateKey.(crypto.Signer))
	if err != nil {
		return nil, errors.Wrap(err, "create crl failed")
	}
	if err := s.repo.SaveCRL(ctx, req.CaCommon, string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes}))); err != nil {
		return nil, errors.Wrap(err, "save crl error")
	}

	return &pb.RevokeCertResponse{
		CaCommon: req.CaCommon,
		Crl:      string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})),
	}, nil
}
func (s *CertService) PKCS12(ctx context.Context, req *pb.PKCS12Request) (*pb.PKCS12Response, error) {
	// loca ca cert and private key
	caCertStr, err := s.repo.GetCert(ctx, req.CaCommon)
	if err != nil && err != redis.Nil{
		return nil, errors.Wrap(err, "get ca cert error")
	}
	caCert, err := utils.LoadCert(caCertStr)
	if err != nil {
		return nil, errors.Wrap(err, "parse ca cert error")
	}
	caPrivateKeyStr, err := s.repo.GetPrivateKey(ctx, req.CaCommon)
	if err != nil && err != redis.Nil{
		return nil, errors.Wrap(err, "get ca private key error")
	}
	caPrivateKey, err := utils.LoadPrivateKey(caPrivateKeyStr)
	if err != nil {
		return nil, errors.Wrap(err, "parse ca private key error")
	}

	// new keys with request
	var privateKeyStr string
	if req.GenKeyRequest.KeyType == pb.KeyType_RSA {
		privateKey, err := utils.GenRSAKey(int(req.GenKeyRequest.KeySize))
		if err != nil {
			return nil, errors.Wrap(err, "generate rsa key error")
		}
		privateKeyStr = utils.RSAPrivateKeyToPEM(privateKey)
	} else if req.GenKeyRequest.KeyType == pb.KeyType_ECDSA {
		privateKey, err := utils.GenECDSAKey()
		if err != nil {
			return nil, errors.Wrap(err, "generate ecdsa key error")
		}
		privateKeyStr = utils.ECDSAPrivateKeyToPEM(privateKey)
	} else {
		return nil, errors.Errorf("invalid key type: %d", req.GenKeyRequest.KeyType)
	}
	// save to local
	s.repo.SavePrivateKey(ctx, req.GenKeyRequest.Common, privateKeyStr)

	privateKey, err := utils.LoadPrivateKey(privateKeyStr)
	if err != nil {
		return nil, errors.Wrap(err, "parse private key error")
	}
	// new csr
	csrStr, err := utils.GenerateCSR(privateKeyStr, req.CsrRequest)
	if err != nil {
		return nil, errors.Wrap(err, "generate csr error")
	}
	csr, err := utils.LoadCSR(csrStr)
	if err != nil {
		return nil, errors.Wrap(err, "load csr error")
	}

	certStr, _, err := utils.SignCert(caPrivateKey, csr, int(req.Days))
	if err != nil {
		return nil, errors.Wrap(err, "ca sign csr error")
	}
	// save to local
	s.repo.SaveCert(ctx, req.GenKeyRequest.Common, certStr)

	cert, err := utils.LoadCert(certStr)
	if err != nil {
		return nil, errors.Wrap(err, "load cert error")
	}

	pkfDate, err := pkcs12.Encode(rand.Reader, privateKey, cert, []*x509.Certificate{caCert}, req.GenKeyRequest.Password)
	if err != nil {
		return nil, errors.Wrap(err, "encode pkcs12 error")
	}

	return &pb.PKCS12Response{
		Pkcs12: string(pem.EncodeToMemory(&pem.Block{Type: "PKCS12", Bytes: pkfDate})),
	}, nil
}
