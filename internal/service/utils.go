package service

import (
	"context"
	"crypto/x509"

	pb "github.com/mengbin92/goca/api/goca/v1"
	"github.com/mengbin92/goca/internal/utils"
	"github.com/pkg/errors"
)

func (s *CertService) loadCert(ctx context.Context, common string) (*x509.Certificate, error) {
	caCertStr, err := s.repo.GetCert(ctx, common)
	if err != nil {
		return nil, err
	}
	return utils.LoadCert(caCertStr)
}

func (s *CertService) LoadPrivateKey(ctx context.Context, common string) (any, error) {
	privateKeyStr, err := s.repo.GetPrivateKey(ctx, common)
	if err != nil {
		return nil, err
	}
	return utils.LoadPrivateKey(privateKeyStr)
}

func (s *CertService) generateKey(ctx context.Context, req *pb.GenKeyRequest) (string, error) {
	var privateKeyStr string

	if req.KeyType == pb.KeyType_RSA {
		privateKey, err := utils.GenRSAKey(int(req.KeySize))
		if err != nil {
			return "", errors.Wrap(err, "generate rsa key error")
		}
		privateKeyStr = utils.RSAPrivateKeyToPEM(privateKey)
	} else if req.KeyType == pb.KeyType_ECDSA {
		privateKey, err := utils.GenECDSAKey()
		if err != nil {
			return "", errors.Wrap(err, "generate ecdsa key error")
		}
		privateKeyStr = utils.ECDSAPrivateKeyToPEM(privateKey)
	} else {
		return "", errors.Errorf("invalid key type: %d", req.KeyType)
	}
	if err := s.repo.SavePrivateKey(ctx, req.Common, privateKeyStr); err != nil {
		return "", errors.Wrap(err, "save private key error")
	}
	return privateKeyStr, nil
}

func (s *CertService) csr(ctx context.Context, req *pb.CSRRequest) (string, error) {
	privateKeyString, err := s.repo.GetPrivateKey(ctx, req.Common)
	if err != nil {
		return "", errors.Wrap(err, "get private key error")
	}

	csr, err := utils.GenerateCSR(privateKeyString, req)
	if err != nil {
		return "", errors.Wrap(err, "generate csr error")
	}
	return csr, nil
}
