package data

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/mengbin92/goca/internal/biz"
)

func NewCARepo(data *Data, logger log.Logger) biz.CARepo {
	return &caRepo{data: data}
}

type caRepo struct {
	data *Data
}

func (r *caRepo) GetCert(ctx context.Context, common string) (string, error) {
	return r.data.rdb.Get(ctx, fmt.Sprintf("cert-%s", common)).Result()
}

func (r *caRepo) GetCertBySerial(ctx context.Context, serial string) (string, error) {
	return r.data.rdb.Get(ctx, fmt.Sprintf("cert-%s", serial)).Result()
}

func (r *caRepo) GetParentCert(ctx context.Context, common string) (string, error) {
	return "", nil
}

func (r *caRepo) GetPrivateKey(ctx context.Context, common string) (string, error) {
	return r.data.rdb.Get(ctx, fmt.Sprintf("private-%s", common)).Result()
}

func (r *caRepo) SavePrivateKey(ctx context.Context, common, privateKey string) error {
	return r.data.rdb.Set(ctx, fmt.Sprintf("private-%s", common), privateKey, 0).Err()
}

func (r *caRepo) SaveCert(ctx context.Context, common, cert string) error {
	return r.data.rdb.Set(ctx, fmt.Sprintf("cert-%s", common), cert, 0).Err()
}

func (r *caRepo) SaveParentKey(ctx context.Context, common, privateKey string) error {
	return r.data.rdb.Set(ctx, fmt.Sprintf("parent-%s", common), privateKey, 0).Err()
}

func (r *caRepo) GetCRL(ctx context.Context, common string) (string, error) {
	return r.data.rdb.Get(ctx, fmt.Sprintf("crl-%s", common)).Result()
}

func (r *caRepo) SaveCRL(ctx context.Context, common, crl string) error {
	return r.data.rdb.Set(ctx, fmt.Sprintf("crl-%s", common), crl, 0).Err()
}