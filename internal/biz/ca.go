package biz

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
)

type CARepo interface {
	GetCert(context.Context, string) (string, error)
	GetCertBySerial(context.Context, string) (string, error)
	GetParentCert(context.Context, string) (string, error)
	GetPrivateKey(context.Context, string) (string, error)
	SavePrivateKey(context.Context, string, string) error
	SaveCert(context.Context, string, string) error
	SaveParentKey(context.Context, string, string) error

	// for CRL
	GetCRL(context.Context, string) (string, error)
	SaveCRL(context.Context, string, string) error

	// root ca
	GetRootCert(context.Context, string) (string, error)
	SaveRootCert(context.Context, string, string) error
}

type CAUseCase struct {
	repo CARepo
}

func NewCAUseCase(repo CARepo, logger log.Logger) *CAUseCase {
	return &CAUseCase{repo: repo}
}

func (ca *CAUseCase) GetCert(ctx context.Context, common string) (string, error) {
	return ca.repo.GetCert(ctx, common)
}
func (ca *CAUseCase) GetCertBySerial(ctx context.Context, serial string) (string, error) {
	return ca.repo.GetCertBySerial(ctx, serial)
}
func (ca *CAUseCase) GetParentCert(ctx context.Context, common string) (string, error) {
	return ca.repo.GetParentCert(ctx, common)
}
func (ca *CAUseCase) GetPrivateKey(ctx context.Context, common string) (string, error) {
	return ca.repo.GetPrivateKey(ctx, common)
}
func (ca *CAUseCase) SavePrivateKey(ctx context.Context, common, privateKey string) error {
	return ca.repo.SavePrivateKey(ctx, common, privateKey)
}

func (ca *CAUseCase) SaveCert(ctx context.Context, serial, cert string) error {
	return ca.repo.SaveCert(ctx, serial, cert)
}

func (ca *CAUseCase) SaveParentKey(ctx context.Context, common, privateKey string) error {
	return ca.repo.SaveParentKey(ctx, common, privateKey)
}

func (ca *CAUseCase) GetCRL(ctx context.Context, common string) (string, error) {
	return ca.repo.GetCRL(ctx, common)
}

func (ca *CAUseCase) SaveCRL(ctx context.Context, common, crl string) error {
	return ca.repo.SaveCRL(ctx, common, crl)
}

func (ca *CAUseCase) GetRootCert(ctx context.Context, common string) (string, error) {
	return ca.repo.GetRootCert(ctx, common)
}

func (ca *CAUseCase) SaveRootCert(ctx context.Context, common, cert string) error {
	return ca.repo.SaveRootCert(ctx, common, cert)
}