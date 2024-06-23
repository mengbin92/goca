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

func newSelfSign(common string, typ conf.KeyType) (*CertService, error) {

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
		Common:           common,
		Country:          "CN",
		Province:         "GD",
		Locality:         "SZ",
		Organization:     "test",
		OrganizationUnit: "test01",
		Email:            "123@qq.com",
		Dns:              []string{"test.com"},
		Ip:               []string{"123.123.123.123", "123.123.123.124"},
		KeyPair: &conf.KeyPair{
			KeyType:  typ,
			KeySize:  2048,
			Password: "passowd",
		},
	}

	return NewCertService(useCase, rootCert, nil)
}

func TestNewCertService(t *testing.T) {
	tests := []struct {
		name    string
		common  string
		keyTpye conf.KeyType
	}{
		{
			name:    "rsa cert",
			common:  "rsa_common",
			keyTpye: conf.KeyType_RSA,
		},
		{
			name:    "ecdsa cert",
			common:  "ecdsa_common",
			keyTpye: conf.KeyType_ECDSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := newSelfSign(tt.common, tt.keyTpye)
			assert.Nil(t, err)
			assert.NotNil(t, s)
		})
	}
}

func TestGenKey(t *testing.T) {
	s, err := newSelfSign("test", conf.KeyType_RSA)
	assert.Nil(t, err)
	assert.NotNil(t, s)

	tests := []struct {
		name            string
		req             *pb.GenKeyRequest
		emptyError      bool
		unknowTypeError bool
	}{
		{
			name:            "generate RSA key pair",
			unknowTypeError: false,
			emptyError:      false,
			req: &pb.GenKeyRequest{
				KeyType:  pb.KeyType_RSA,
				KeySize:  2048,
				Common:   "123456",
				Password: "rsapwd",
			},
		},
		{
			name:            "generate ECDSA key pair",
			unknowTypeError: false,
			emptyError:      false,
			req: &pb.GenKeyRequest{
				KeyType:  pb.KeyType_ECDSA,
				Common:   "123456",
				Password: "ecdsapwd",
			},
		},
		{
			name:            "generate RSA key pair without password",
			unknowTypeError: false,
			emptyError:      true,
			req: &pb.GenKeyRequest{
				KeyType: pb.KeyType_RSA,
				KeySize: 2048,
				Common:  "123456",
			},
		},
		{
			name:            "generate unknow key pair",
			unknowTypeError: true,
			emptyError:      false,
			req: &pb.GenKeyRequest{
				KeyType:  3,
				KeySize:  2048,
				Common:   "123456",
				Password: "ecdsapwd",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.emptyError && !tt.unknowTypeError {
				resp, err := s.GenKey(context.Background(), tt.req)
				assert.Nil(t, err)
				assert.NotNil(t, resp)

				assert.Equal(t, tt.req.Common, resp.Common)
				assert.Equal(t, tt.req.KeyType, resp.KeyType)
			} else if tt.emptyError {
				resp, err := s.GenKey(context.Background(), tt.req)
				assert.Contains(t, err.Error(), "password is empty")
				assert.Nil(t, resp)
			} else if tt.unknowTypeError {
				resp, err := s.GenKey(context.Background(), tt.req)
				assert.Contains(t, err.Error(), "invalid key type")
				assert.Nil(t, resp)
			}
		})
	}
}

func TestCSR(t *testing.T) {
	s, err := newSelfSign("test", conf.KeyType_RSA)
	assert.Nil(t, err)
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
	s, err := newSelfSign("test", conf.KeyType_RSA)
	assert.Nil(t, err)
	assert.NotNil(t, s)

	tests := []struct {
		name        string
		common      string
		returnError bool
	}{
		{
			name:        "common exist",
			common:      "test",
			returnError: false,
		},
		{
			name:        "common not exist",
			common:      "nocommon",
			returnError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.returnError {
				resp, err := s.GetCert(context.Background(), &pb.CertRequest{
					Common: tt.common,
				})
				assert.Contains(t, err.Error(), " is not found in service")
				assert.Nil(t, resp)
			} else {
				resp, err := s.GetCert(context.Background(), &pb.CertRequest{
					Common: tt.common,
				})
				assert.Nil(t, err)
				assert.NotNil(t, resp)
				cert, err := utils.LoadCert(resp.Cert)
				assert.Nil(t, err)
				assert.NotNil(t, cert)
				t.Log(cert.Subject.CommonName)
				assert.Equal(t, tt.common, cert.Subject.CommonName)
			}
		})
	}

}

func TestCASignCSR(t *testing.T) {
	s, err := newSelfSign("test", conf.KeyType_RSA)
	assert.Nil(t, err)
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
		CaCommon: "test",
		Days:     365,
	}

	certResp, err := s.CASignCSR(context.Background(), certReq)
	assert.Nil(t, err)
	assert.NotNil(t, certResp)

	cert, err := utils.LoadCert(certResp.Cert)
	assert.Nil(t, err)
	assert.NotNil(t, cert)

	assert.Equal(t, "test", cert.Issuer.CommonName)
	assert.Equal(t, csrReq.Common, cert.Subject.CommonName)
}

func TestRevokeCert(t *testing.T) {
	s, err := newSelfSign("test", conf.KeyType_RSA)
	assert.Nil(t, err)
	assert.NotNil(t, s)

	revokedReq := &pb.RevokeCertRequest{
		SerialNumber: "214479120649001408102415970299220634165",
		CaCommon:     "test",
	}
	resp, err := s.RevokeCert(context.Background(), revokedReq)
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test", resp.CaCommon)

	crl, err := utils.LoadCRL(resp.Crl)
	assert.Nil(t, err)
	assert.NotNil(t, crl)
}

// func TestPKCS12(t *testing.T) {
// 	s, err := newSelfSign("test", conf.KeyType_RSA)
// 	assert.Nil(t, err)
// 	assert.NotNil(t, s)

// 	req := &pb.PKCS12Request{
// 		CaCommon: "test",
// 		GenKeyRequest: &pb.GenKeyRequest{
// 			KeyType: pb.KeyType_RSA,
// 			KeySize: 2048,
// 			Common:  "pkcs12",
// 		},
// 		CsrRequest: &pb.CSRRequest{
// 			Common:           "pkcs12",
// 			Province:         "Beijing",
// 			Locality:         "haidian",
// 			Organization:     "test",
// 			OrganizationUnit: "test01",
// 			Email:            "123@qq.com",
// 			Dns:              []string{"test.com"},
// 			Ip:               []string{"123.123.123.123"},
// 		},
// 		Days: 365,
// 	}

// 	resp, err := s.PKCS12(context.Background(), req)
// 	assert.Nil(t, err)
// 	assert.NotNil(t, resp)

// 	pkfBlock, _ := pem.Decode([]byte(resp.Pkcs12))
// 	if pkfBlock == nil {
// 		t.Fatal("decode csr failed")
// 	}
// 	priv, cert, caCerts, err := pkcs12.DecodeChain(pkfBlock.Bytes, req.GenKeyRequest.Password)
// 	assert.Nil(t, err)
// 	assert.NotNil(t, priv)
// 	assert.NotNil(t, cert)
// 	assert.NotNil(t, caCerts)

// 	// privStr,_ := utils.PrivateToPEM(priv)
// 	// certByte := pem.EncodeToMemory(&pem.Block{
// 	// 	Type:  "CERTIFICATE",
// 	// 	Bytes: cert.Raw,
// 	// })

// 	// fmt.Printf("%s\n", string(certByte))
// 	// fmt.Printf("%s\n", string(privStr))
// }
