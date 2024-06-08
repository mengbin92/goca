package biz

import "github.com/go-kratos/kratos/v2/log"

type CARepo interface {
}

type CAUseCase struct {
	repo CARepo
}

func NewCAUseCase(repo CARepo, logger log.Logger) *CAUseCase {
	return &CAUseCase{repo: repo}
}
