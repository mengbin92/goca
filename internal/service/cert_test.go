package service

import (
	"context"
	"testing"

	pb "github.com/mengbin92/goca/api/goca/v1"
	"github.com/mengbin92/goca/internal/biz"
	"github.com/mengbin92/goca/internal/conf"
	"github.com/mengbin92/goca/internal/data"
	"github.com/mengbin92/goca/internal/utils"
	"github.com/stretchr/testify/assert"
)

var s *CertService

func newService() *CertService {
	redisConf := &conf.Data{
		Redis: &conf.Redis{
			Addr:     "127.0.0.1:6379",
			Password: "capwd",
			Db:       0,
		},
	}
	d, _, _ := data.NewData(redisConf, nil)
	repo := data.NewCARepo(d, nil)
	useCase := biz.NewCAUseCase(repo, nil)

	rootCert := &conf.RootCert{
		Common:           "ROOTCA",
		Country:          "CN",
		Province:         "GD",
		Locality:         "SZ",
		Organization:     "test",
		OrganizationUnit: "test01",
		Email:            "123@qq.com",
		Dns:              []string{"test.com"},
		Ip:               []string{"123.123.123.123", "123.123.123.124"},
		KeyPair: &conf.KeyPair{
			KeyType: conf.KeyType_RSA,
			KeySize: 2048,
		},
	}

	s, err := NewCertService(useCase, rootCert, nil)
	if err != nil {
		panic(err)
	}

	return s
}

func TestNewCertService(t *testing.T) {
	s = newService()
	assert.NotNil(t, s)
}

func TestGenKey(t *testing.T) {
	s = newService()
	assert.NotNil(t, s)

	req := &pb.GenKeyRequest{
		KeyType: pb.KeyType_RSA,
		KeySize: 2048,
		Common:  "123456",
	}

	resp, err := s.GenKey(context.Background(), req)
	assert.Nil(t, err)
	assert.NotNil(t, resp)

	assert.Equal(t, req.Common, resp.Common)
	assert.Equal(t, req.KeyType, resp.KeyType)
}

func TestCSR(t *testing.T) {
	s = newService()
	assert.NotNil(t, s)

	req := &pb.CSRRequest{
		Common:           "123456",
		Country:          "CN",
		Province:         "Beijing",
		Locality:         "haidian",
		Organization:     "test",
		OrganizationUnit: "test01",
		Email:            "123@qq.com",
		Dns:              []string{"test.com"},
		Ip:               []string{"123.123.123.123"},
	}

	resp, err := s.CSR(context.Background(), req)
	assert.Nil(t, err)
	assert.NotNil(t, resp)

	assert.Equal(t, req.CaCommon, resp.CaCommon)
}

func TestGetCert(t *testing.T) {
	s = newService()
	assert.NotNil(t, s)

	resp, err := s.GetCert(context.Background(), &pb.CertRequest{
		Common: "ROOTCA",
	})
	assert.Nil(t, err)
	assert.NotNil(t, resp)

	cert, err := utils.LoadCert(resp.Cert)
	assert.Nil(t, err)
	assert.NotNil(t, cert)

	assert.Equal(t, "ROOTCA", cert.Subject.CommonName)
}

func TestCASignCSR(t *testing.T) {
	s = newService()
	assert.NotNil(t, s)

	csrReq := &pb.CSRRequest{
		Common:           "123456",
		Country:          "CN",
		Province:         "Beijing",
		Locality:         "haidian",
		Organization:     "test",
		OrganizationUnit: "test01",
		Email:            "123@qq.com",
		Dns:              []string{"test.com"},
		Ip:               []string{"123.123.123.123"},
	}

	csrResp, err := s.CSR(context.Background(), csrReq)
	assert.Nil(t, err)
	assert.NotNil(t, csrResp)

	// parse csr
	csr, err := utils.LoadCSR(csrResp.Csr)
	assert.Nil(t, err)
	assert.NotNil(t, csr)
	assert.Equal(t, csrReq.Common, csr.Subject.CommonName)

	certReq := &pb.CASignCSRRequest{
		Csr:      csrResp.Csr,
		CaCommon: "ROOTCA",
		Days:     365,
	}

	certResp, err := s.CASignCSR(context.Background(), certReq)
	assert.Nil(t, err)
	assert.NotNil(t, certResp)

	cert, err := utils.LoadCert(certResp.Cert)
	assert.Nil(t, err)
	assert.NotNil(t, cert)

	assert.Equal(t, "ROOTCA", cert.Issuer.CommonName)
	assert.Equal(t, csrReq.Common, cert.Subject.CommonName)
}

func TestRevokeCert(t *testing.T) {
	s = newService()
	assert.NotNil(t, s)

	revokedReq := &pb.RevokeCertRequest{
		SerialNumber: "214479120649001408102415970299220634165",
		CaCommon:     "ROOTCA",
	}
	resp, err := s.RevokeCert(context.Background(), revokedReq)
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "ROOTCA", resp.CaCommon)

	crl, err := utils.LoadCRL(resp.Crl)
	assert.Nil(t, err)
	assert.NotNil(t, crl)
}
