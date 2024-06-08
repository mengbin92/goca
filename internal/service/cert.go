package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	pb "github.com/mengbin92/goca/api/goca/v1"
	"github.com/mengbin92/goca/internal/biz"
	"github.com/mengbin92/goca/internal/utils"
)

type CertService struct {
	pb.UnimplementedCertServer
}

func NewCertService(cert *biz.CAUseCase, logger log.Logger) *CertService {
	return &CertService{}
}

func (s *CertService) GenKey(ctx context.Context, req *pb.GenKeyRequest) (*pb.GenKeyResponse, error) {
	var publicKey, privateKey string
	var err error

	if req.KeyType == pb.KeyType_RSA {
		privateKey, publicKey, err = utils.GenRSAKey(int(req.KeySize))
	}

	return &pb.GenKeyResponse{
		KeyType:    req.KeyType,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, err
}
func (s *CertService) CSR(ctx context.Context, req *pb.CSRRequest) (*pb.CSRResponse, error) {
	return &pb.CSRResponse{}, nil
}
func (s *CertService) GetCert(ctx context.Context, req *pb.CertRequest) (*pb.CertResponse, error) {
	return &pb.CertResponse{}, nil
}
func (s *CertService) CASignCSR(ctx context.Context, req *pb.CASignCSRRequest) (*pb.CASignCSRResponse, error) {
	return &pb.CASignCSRResponse{}, nil
}
func (s *CertService) RevokeCert(ctx context.Context, req *pb.RevokeCertRequest) (*pb.RevokeCertResponse, error) {
	return &pb.RevokeCertResponse{}, nil
}
func (s *CertService) PKCS12(ctx context.Context, req *pb.PKCS12Request) (*pb.PKCS12Response, error) {
	return &pb.PKCS12Response{}, nil
}
