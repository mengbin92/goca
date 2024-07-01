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
	log  *log.Helper
}

func NewCertService(cert *biz.CAUseCase, root *conf.RootCert, logger log.Logger) (*CertService, error) {
	cs := &CertService{repo: cert,
		log: log.NewHelper(logger),
	}

	rootCert, err := cs.repo.GetRootCert(context.Background(), root.Common)
	if err != nil && err != redis.Nil {
		cs.log.Error("get root cert error: ", err)
		return nil, errors.Wrap(err, "get root cert error")
	}
	if rootCert == "" {

		privSrt, err := cs.generateKey(context.Background(), &pb.GenKeyRequest{
			KeyType:  pb.KeyType(root.KeyPair.KeyType),
			KeySize:  root.KeyPair.KeySize,
			Common:   root.Common,
			Password: root.KeyPair.Password,
		})
		if err != nil {
			cs.log.Errorf("generate root key error: %s", err.Error())
			return nil, errors.Wrap(err, "generate root key error")
		}
		priv, err := utils.PrivatePemToKey(privSrt)
		if err != nil {
			cs.log.Errorf("parse pem private key error: %s", err.Error())
			return nil, errors.Wrap(err, "parse pem private key error")
		}

		rootCert, crl, err := utils.GenerateRootCert(priv, root)
		if err != nil {
			cs.log.Errorf("generate root cert error: %s", err.Error())
			return nil, errors.Wrap(err, "generate root cert error")
		}

		if err = cs.repo.SavePrivateKey(context.Background(), root.Common, privSrt); err != nil {
			cs.log.Errorf("save private key error: %s", err.Error())
			return nil, errors.Wrap(err, "save private key error")
		}
		if err = cs.repo.SaveCert(context.Background(), root.Common, rootCert); err != nil {
			cs.log.Errorf("save root cert error: %s", err.Error())
			return nil, errors.Wrap(err, "save root cert error")
		}
		if err = cs.repo.SaveCRL(context.Background(), root.Common, crl); err != nil {
			cs.log.Errorf("save root crl error: %s", err.Error())
			return nil, errors.Wrap(err, "save root crl error")
		}
		if err = cs.repo.SaveRootCert(context.Background(), root.Common, rootCert); err != nil {
			cs.log.Errorf("save root cert error: %s", err.Error())
			return nil, errors.Wrap(err, "save root cert error")
		}
	}

	return cs, nil
}

func (s *CertService) GenKey(ctx context.Context, req *pb.GenKeyRequest) (*pb.GenKeyResponse, error) {
	if req.Password == "" {
		s.log.Error("password is empty")
		return nil, errors.New("password is empty")
	}

	privateKeyStr, err := s.generateKey(ctx, req)
	if err != nil {
		s.log.Errorf("GenKey error: %s", err.Error())
		return nil, errors.Wrap(err, "GenKey error")
	}
	s.log.Debugf("GenKey success: %s", privateKeyStr)
	return &pb.GenKeyResponse{
		KeyType:    req.KeyType,
		PrivateKey: privateKeyStr,
		Common:     req.Common,
	}, nil
}
func (s *CertService) CSR(ctx context.Context, req *pb.CSRRequest) (*pb.CSRResponse, error) {
	csr, err := s.csr(ctx, req)
	if err != nil {
		s.log.Errorf("CSR error: %s", err.Error())
		return nil, errors.Wrap(err, "CSR error")
	}
	s.log.Debugf("CSR success: %s", csr)
	return &pb.CSRResponse{
		CaCommon: req.CaCommon,
		Csr:      csr,
	}, nil
}
func (s *CertService) GetCert(ctx context.Context, req *pb.CertRequest) (*pb.CertResponse, error) {
	// load cert
	cert, err := s.repo.GetCert(ctx, req.Common)
	if err != nil {
		if err == redis.Nil {
			s.log.Errorf("cert: %s is not found in service", req.Common)
			return nil, errors.Errorf("cert: %s is not found in service", req.Common)
		}
		s.log.Errorf("get cert error: %s", err.Error())
		return nil, errors.Wrap(err, "get cert error")
	}
	if len(cert) == 0 {
		s.log.Warnf("not found cert: %s", req.Common)
		return nil, errors.Errorf("not found cert: %s", req.Common)
	}
	s.log.Debugf("GetCert success: %s", cert)
	return &pb.CertResponse{Cert: cert}, nil
}
func (s *CertService) CASignCSR(ctx context.Context, req *pb.CASignCSRRequest) (*pb.CASignCSRResponse, error) {
	// load parent ca private key and certificate
	caCert, caPrivateKey, err := s.loadCertAndPrivate(ctx, req.CaCommon)
	if err != nil {
		s.log.Errorf("load parent ca error: %s", err.Error())
		return nil, errors.Wrap(err, "load parent ca error")
	}

	// load csr from pem string
	csr, err := utils.LoadCSR(req.Csr)
	if err != nil {
		s.log.Errorf("load csr error: %s", err.Error())
		return nil, errors.Wrap(err, "load csr error")
	}

	// create cert
	cert, serial, err := utils.SignCert(caPrivateKey, caCert, csr, int(req.Days))
	if err != nil {
		s.log.Errorf("ca sign csr error: %s", err.Error())
		return nil, errors.Wrap(err, "ca sign csr error")
	}

	// save cert to local
	if err := s.repo.SaveCert(ctx, csr.Subject.CommonName, cert); err != nil {
		s.log.Errorf("save cert error: %s", err.Error())
		return nil, errors.Wrapf(err, "save cert: %s error", csr.Subject.CommonName)
	}

	s.log.Debugf("CASignCSR success serial number: %s", serial)
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
	if err != nil && err != redis.Nil {
		return nil, errors.Wrap(err, "get crl error")
	}
	crl, err := utils.LoadCRL(crlStr)
	if err != nil {
		return nil, errors.Wrap(err, "parse crl error")
	}

	if crl != nil {
		s.log.Debugf("get RevokedCertificateEntries: %d", len(crl.RevokedCertificateEntries))
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.String() == req.SerialNumber {
				return &pb.RevokeCertResponse{}, errors.New("this cert has been revoked")
			}
			revokeds = crl.RevokedCertificateEntries
		}
	}
	serial, ok := utils.Str2BigInt(req.SerialNumber)
	if !ok {
		s.log.Errorf("invalid serial number: %s", req.SerialNumber)
		return &pb.RevokeCertResponse{}, errors.New("invalid serial number")
	}
	newRevoked := x509.RevocationListEntry{
		SerialNumber:   serial,
		RevocationTime: time.Now(),
	}
	revokeds = append(revokeds, newRevoked)

	// load parent ca private key and certificate
	caCert, caPrivateKey, err := s.loadCertAndPrivate(ctx, req.CaCommon)
	if err != nil {
		s.log.Errorf("load parent ca error: %s", err.Error())
		return nil, errors.Wrap(err, "load parent ca error")
	}

	// create new crl
	crlTemp := x509.RevocationList{
		RevokedCertificateEntries: revokeds,
		SignatureAlgorithm:        caCert.SignatureAlgorithm,
		Number:                    big.NewInt(int64(len(revokeds))),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(0, 0, 1),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &crlTemp, caCert, caPrivateKey.(crypto.Signer))
	if err != nil {
		s.log.Errorf("create crl error: %s", err.Error())
		return nil, errors.Wrap(err, "create crl failed")
	}
	if err := s.repo.SaveCRL(ctx, req.CaCommon, string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes}))); err != nil {
		s.log.Errorf("save crl error: %s", err.Error())
		return nil, errors.Wrap(err, "save crl error")
	}

	return &pb.RevokeCertResponse{
		CaCommon: req.CaCommon,
		Crl:      string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})),
	}, nil
}
func (s *CertService) PKCS12(ctx context.Context, req *pb.PKCS12Request) (*pb.PKCS12Response, error) {
	var newPrivateKey any
	var err error
	var cert *x509.Certificate

	// load parent ca private key and certificate
	caCert, caPrivateKey, err := s.loadCertAndPrivate(ctx, req.CaCommon)
	if err != nil {
		s.log.Errorf("load parent ca error: %s", err.Error())
		return nil, errors.Wrap(err, "load parent ca error")
	}

	if req.Operate == pb.PKCS12Request_GET {
		if req.GenKeyRequest.Password == "" {
			s.log.Errorf("password is empty while get PKCS#12")
			return nil, errors.New("password is empty while get PKCS#12")
		}
		cert, newPrivateKey, err = s.loadCertAndPrivate(ctx, req.GenKeyRequest.Common)
		if err != nil {
			s.log.Errorf("load Certificate: %s error: %s", req.GenKeyRequest.Common, err.Error())
			return nil, errors.Wrap(err, "load Certificate error")
		}
	} else if req.Operate == pb.PKCS12Request_CREATE {
		// new keys with request
		newPrivateStr, err := s.generateKey(ctx, req.GenKeyRequest)
		if err != nil {
			s.log.Errorf("generateKey error while generate PKCS12 error: %s", err.Error())
			return nil, errors.Wrap(err, "generateKey error while generate PKCS12")
		}
		newPrivateKey, err = utils.PrivatePemToKey(newPrivateStr)
		if err != nil {
			s.log.Errorf("parse pem private key error while generate PKCS12 error: %s", err.Error())
			return nil, errors.Wrap(err, "parse pem private key error while generate PKCS12")
		}

		// new csr
		csrStr, err := s.csr(ctx, req.CsrRequest)
		if err != nil {
			s.log.Errorf("csr error while generate PKCS12 error: %s", err.Error())
			return nil, errors.Wrap(err, "generate csr error")
		}
		csr, err := utils.LoadCSR(csrStr)
		if err != nil {
			s.log.Errorf("load csr error while generate PKCS12 error: %s", err.Error())
			return nil, errors.Wrap(err, "load csr error")
		}

		certStr, _, err := utils.SignCert(caPrivateKey, caCert, csr, int(req.Days))
		if err != nil {
			s.log.Errorf("ca sign csr error while generate PKCS12 error: %s", err.Error())
			return nil, errors.Wrap(err, "ca sign csr error")
		}
		// save to local
		if err := s.repo.SaveCert(ctx, req.GenKeyRequest.Common, certStr); err != nil {
			s.log.Errorf("save cert error while generate PKCS12 error: %s", err.Error())
			return nil, errors.Wrap(err, "save cert error")
		}
		cert, err = utils.LoadCert(certStr)
		if err != nil {
			s.log.Errorf("load cert error while generate PKCS12 error: %s", err.Error())
			return nil, errors.Wrap(err, "load cert error")
		}
	} else {
		s.log.Errorf("invalid PKCS#12 operate: %v", req.Operate)
		return nil, errors.New("invalid operate")
	}

	pkfDate, err := pkcs12.Legacy.Encode(newPrivateKey, cert, []*x509.Certificate{caCert}, req.GenKeyRequest.Password)
	if err != nil {
		s.log.Errorf("encode pkcs12 error while generate PKCS12 error: %s", err.Error())
		return nil, errors.Wrap(err, "encode pkcs12 error")
	}

	return &pb.PKCS12Response{
		Pkcs12: string(pem.EncodeToMemory(&pem.Block{Type: "PKCS12", Bytes: pkfDate})),
	}, nil
}
