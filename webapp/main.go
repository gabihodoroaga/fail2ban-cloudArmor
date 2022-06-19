package main

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
)

var (
	rdb *redis.Client = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_HOST"),
		Password: "",
		DB:       0,
	})
	newAccountsLimit    int64         = 3
	newAccountsInterval time.Duration = time.Hour
	banTime             time.Duration = 24 * time.Hour
)

func main() {

	initLogger()
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.POST("/info", func(c *gin.Context) {

		// check if the IP is in the ban list
		banned, err := checkIP(c, c.ClientIP())
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if banned {
			c.Status(http.StatusForbidden)
			return
		}

		var info Info
		if err := c.ShouldBindJSON(&info); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// updateIP
		err = updateIP(c, c.ClientIP(), info.AccountID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// application specific logic
		c.JSON(http.StatusOK, info)
	})

	r.Run() // listen and serve on 0.0.0.0:8080
}

func checkIP(ctx context.Context, ip string) (bool, error) {

	zap.L().Sugar().Debugf("checking if ip %q is in the banned list", ip)
	_, err := rdb.Get(ctx, "deny:"+ip).Result()
	if err == redis.Nil {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}

func updateIP(ctx context.Context, ip, accountID string) error {

	added, err := rdb.SAdd(ctx, "accounts", accountID).Result()
	if err != nil {
		return err
	}

	if added == 0 {
		zap.L().Sugar().Debugf("updateIP: account %q exists", accountID)
		return nil
	}

	ipkey := "ip:" + ip
	if _, err := rdb.SAdd(ctx, ipkey, accountID).Result(); err != nil {
		return err
	}

	zap.L().Sugar().Debugf("updateIP: account %q added to the account list", accountID)

	ipLength, err := rdb.SCard(ctx, ipkey).Result()
	if err != nil {
		return err
	}

	if ipLength > newAccountsLimit {
		// add the ip to the deny list
		if _, err := rdb.SetNX(ctx, "deny:"+ip, 1, banTime).Result(); err != nil {
			return err
		}
		zap.L().Sugar().Debugf("updateIP: ip %q added to the deny list", ip)

		// remove all the keys from this ip from accounts list
		rkeys, err := rdb.SMembers(ctx, ipkey).Result()
		if err != nil {
			return err
		}
		for _, rk := range rkeys {
			if _, err := rdb.SRem(ctx, "accounts", rk).Result(); err != nil {
				return err
			}
		}
		zap.L().Sugar().Debugf("updateIP: removed ip set %q with members %v", ipkey, rkeys)

		// delete the ip set
		if err := rdb.Del(ctx, ipkey).Err(); err != nil {
			return err
		}

		zap.L().Sugar().Debugf("updateIP: %q set removed", ipkey)
		return nil
	}

	// HACK options: NX, XX, GT and LT for EXPIRE are available in version >=7.0.0 (GCP version is 6.x)
	exp, err := rdb.TTL(ctx, ipkey).Result()
	if err != nil {
		return err
	}
	if exp < 0 {
		zap.L().Sugar().Debugf("security: added expire time for %q to %q", ipkey, newAccountsInterval)
		if err := rdb.Expire(ctx, ipkey, newAccountsInterval).Err(); err != nil {
			return err
		}
	}

	return nil
}

func initLogger() error {
	loggerConfig := zap.NewProductionConfig()
	loggerConfig.Level.SetLevel(zap.DebugLevel)
	loggerConfig.EncoderConfig.LevelKey = "severity"
	loggerConfig.EncoderConfig.MessageKey = "message"
	logger, err := loggerConfig.Build()
	if err != nil {
		return err
	}

	zap.ReplaceGlobals(logger)
	return nil
}

type Info struct {
	AccountID string `json:"account_id"`
	Name      string `json:"name"`
}
