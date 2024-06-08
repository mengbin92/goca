package data

import (
	"github.com/go-kratos/kratos/v2/log"
	"github.com/mengbin92/goca/internal/biz"
)

func NewCARepo(data *Data, logger log.Logger) biz.CARepo {
	return &caRepo{}
}

type caRepo struct {
}
