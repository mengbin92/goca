package data

import (
	"context"

	"github.com/google/wire"
	"github.com/mengbin92/goca/internal/conf"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"

	"github.com/go-kratos/kratos/v2/log"
)

// ProviderSet is data providers.
var ProviderSet = wire.NewSet(NewData, NewCARepo)

// Data .
type Data struct {
	// TODO wrapped database client
	rdb *redis.Client
}

// NewData .
func NewData(c *conf.Data, logger log.Logger) (*Data, func(), error) {
	log := log.NewHelper(logger)

	rdb := redis.NewClient(&redis.Options{
		Addr:         c.Redis.Addr,
		Password:     c.Redis.Password,
		DB:           int(c.Redis.Db),
		DialTimeout:  c.Redis.DialTimeout.AsDuration(),
		WriteTimeout: c.Redis.WriteTimeout.AsDuration(),
		ReadTimeout:  c.Redis.ReadTimeout.AsDuration(),
	})

	if _, err := rdb.Ping(context.Background()).Result(); err != nil {
		log.Errorf("init redis error: %v", err)
		return nil, nil, errors.Wrap(err, "init redis error")
	}
	d := &Data{
		rdb: rdb,
	}

	cleanup := func() {
		log.Info("closing the data resources")
		if err := d.rdb.Close(); err != nil {
			log.Error(err)
		}
	}
	return d, cleanup, nil
}
