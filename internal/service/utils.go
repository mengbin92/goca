package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"

	pb "github.com/mengbin92/goca/api/goca/v1"
	"github.com/mengbin92/goca/internal/utils"
	"github.com/pkg/errors"
)

// func (s *CertService) loadCert(ctx context.Context, common string) (*x509.Certificate, error) {
// 	caCertStr, err := s.repo.GetCert(ctx, common)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return utils.LoadCert(caCertStr)
// }

// func (s *CertService) loadPrivateKey(ctx context.Context, common string) (any, error) {
// 	privateKeyStr, err := s.repo.GetPrivateKey(ctx, common)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return utils.PrivatePemToKey(privateKeyStr)
// }

func (s *CertService) loadCA(ctx context.Context, common string) (*x509.Certificate, any, error) {
	caCertStr, err := s.repo.GetRootCert(ctx, common)
	if err != nil {
		return nil, nil, err
	}
	cert, err := utils.LoadCert(caCertStr)
	if err != nil {
		return nil, nil, err
	}
	privateKeyStr, err := s.repo.GetPrivateKey(ctx, common)
	if err != nil {
		return nil, nil, err
	}
	private, err := utils.PrivatePemToKey(privateKeyStr)
	if err != nil {
		return nil, nil, err
	}
	return cert, private, nil
}

func (s *CertService) generateKey(ctx context.Context, req *pb.GenKeyRequest) (string, error) {
	priv, err := utils.GenerateKey(req)
	if err != nil {
		return "", errors.Wrap(err, "generate key error")
	}
	privStr, err := utils.PrivateToPEM(priv)
	if err != nil {
		return "", errors.Wrap(err, "private key to pem error")
	}

	// if req.Password == "" {
	// 	return "", errors.New("password is empty")
	// }
	// encryptPrivStr, err := utils.TripleDESEncrypt([]byte(privStr), []byte(req.Password))
	// if err != nil {
	// 	return "", errors.Wrap(err, "encrypt private key error")
	// }

	if err := s.repo.SavePrivateKey(ctx, req.Common, string(privStr)); err != nil {
		return "", errors.Wrap(err, "save private key error")
	}
	return privStr, nil
}

func (s *CertService) csr(ctx context.Context, req *pb.CSRRequest) (string, error) {
	privateKeyString, err := s.repo.GetPrivateKey(ctx, req.Common)
	if err != nil {
		return "", errors.Wrap(err, "get private key error")
	}
	if len(privateKeyString) == 0 {
		return "", errors.Errorf("private key: %s not found", req.Common)
	}

	priv, err := utils.PrivatePemToKey(privateKeyString)
	if err != nil {
		return "", errors.Wrap(err, "parse pem private key error")
	}

	csr, err := utils.GenerateCSR(priv, req)
	if err != nil {
		return "", errors.Wrap(err, "generate csr error")
	}
	return csr, nil
}

func isKeyMatchingCertificate(priv any, cert *x509.Certificate) bool {
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		return key.PublicKey.Equal(cert.PublicKey.(*rsa.PublicKey))
	case *ecdsa.PrivateKey:
		return key.PublicKey.Equal(cert.PublicKey.(*rsa.PublicKey))
	default:
		return false
	}
}

func isKeyMatchingCertificateRequest(privKey any, csr *x509.CertificateRequest) bool {
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		return key.PublicKey.Equal(csr.PublicKey.(*rsa.PublicKey))
	case *ecdsa.PrivateKey:
		return key.PublicKey.Equal(csr.PublicKey.(*rsa.PublicKey))
	default:
		return false
	}
}
