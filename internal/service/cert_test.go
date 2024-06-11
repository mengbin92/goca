package service

import (
	"context"
	"testing"

	pb "github.com/mengbin92/goca/api/goca/v1"
	"github.com/mengbin92/goca/internal/biz"
	"github.com/mengbin92/goca/internal/conf"
	"github.com/mengbin92/goca/internal/data"
)

var s *CertService

func newService() *CertService {
	redisConf := &conf.Data{
		Redis: &conf.Redis{
			Addr:     "127.0.0.1:6379",
			Password: "",
			Db:       0,
		},
	}
	d, _, _ := data.NewData(redisConf, nil)
	repo := data.NewCARepo(d, nil)
	useCase := biz.NewCAUseCase(repo, nil)

	rootCert := &conf.RootCert{
		Common:           "test",
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
}

func TestGenKey(t *testing.T) {
	s = newService()
	req := &pb.GenKeyRequest{
		KeyType: pb.KeyType_RSA,
		KeySize: 2048,
		Common:  "123456",
	}
	resp, err := s.GenKey(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(resp)
}

func TestCSR(t *testing.T) {
	s = newService()
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
	if err != nil {
		t.Fatal(err)
	}
	t.Log(resp)
}

func TestGetCert(t *testing.T) {
	s = newService()
	resp, err := s.GetCert(context.Background(), &pb.CertRequest{
		Common: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(resp)
}

func TestCASignCSR(t *testing.T) {
	s = newService()
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
	if err != nil {
		t.Fatal(err)
	}

	certReq := &pb.CASignCSRRequest{
		Csr:      csrResp.Csr,
		CaCommon: "test",
		Days:     365,
	}

	certResp, err := s.CASignCSR(context.Background(), certReq)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(certResp.Cert, certResp.SerialNumber)
}

func TestRevokeCert(t *testing.T) {
	s = newService()

	revokedReq := &pb.RevokeCertRequest{
		SerialNumber: "214479120649001408102415970299220634165",
		CaCommon:     "test",
	}
	resp, err := s.RevokeCert(context.Background(), revokedReq)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(resp.Crl)
}

func TestPKCS12(t *testing.T) {
	s = newService()

	req := &pb.PKCS12Request{
		CaCommon: "test",
		GenKeyRequest: &pb.GenKeyRequest{
			KeyType: pb.KeyType_RSA,
			KeySize: 2048,
			Common:  "pkcs12",
		},
		CsrRequest: &pb.CSRRequest{
			Common:           "pkcs12",
			Province:         "Beijing",
			Locality:         "haidian",
			Organization:     "test",
			OrganizationUnit: "test01",
			Email:            "123@qq.com",
			Dns:              []string{"test.com"},
			Ip:               []string{"123.123.123.123"},
		},
		Days: 365,
	}
	resp, err := s.PKCS12(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(resp.Pkcs12)
}
