package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/api/compute/v1"
)

var (
	rdb *redis.Client = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_HOST"),
		Password: "",
		DB:       0,
	})
	secPolicyProject string = os.Getenv("PROJECT_ID")
	secPolicyName    string = os.Getenv("SECURITY_POLICY_NAME")
)

func main() {

	initLogger()
	r := gin.Default()
	r.GET("/update_armor", func(c *gin.Context) {

		if err := updateSecurityRules(c.Request.Context()); err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		c.Status(http.StatusOK)
	})

	r.Run() // listen and serve on 0.0.0.0:8080
}

func updateSecurityRules(ctx context.Context) error {

	ipList, err := readIPAddresses(ctx)
	if err != nil {
		return err
	}

	zap.L().Debug(fmt.Sprintf("process ip list with %d elements", len(ipList)), zap.Any("ip_list", ipList))

	ruleList, lastPriority, err := readRuleList(ctx)
	if err != nil {
		return err
	}

	zap.L().Debug(fmt.Sprintf("process rule list with %d elements", len(ruleList)), zap.Any("ip_list", ruleList))

	var openRuleList []*ruleItem
	var updateRuleList []*ruleItem

	// search and remove all missing ip
	for _, rule := range ruleList {
		zap.L().Sugar().Debugf("checking rule %s", rule.Description)
		newSrcIPRanges := []string{}
		updated := false
		for _, ruleRange := range rule.Match.Config.SrcIpRanges {
			ip := strings.TrimSuffix(ruleRange, "/32")
			if ipList[ip] {
				delete(ipList, ip)
				newSrcIPRanges = append(newSrcIPRanges, toRange(ruleRange))
			} else {
				updated = true
			}
		}
		if updated {
			zap.L().Sugar().Debugf("rule %s updated\n", rule.Description)
			rule.Match.Config.SrcIpRanges = newSrcIPRanges
			openRuleList = append(openRuleList, &ruleItem{rule, true, false})
		} else if len(rule.Match.Config.SrcIpRanges) < 10 {
			zap.L().Sugar().Debugf("rule %s has empty slots", rule.Description)
			openRuleList = append(openRuleList, &ruleItem{rule, false, false})
		}
	}

	for ip := range ipList {
		// TODO: test if ip is v6
		zap.L().Sugar().Debugf("adding new ip %s", ip)

		if isIPv6(ip) {
			zap.L().Sugar().Info("skiping ipv6 address %s", ip)
			continue
		}

		if len(openRuleList) == 0 {
			openRuleList = append(openRuleList, &ruleItem{createNewRule(lastPriority + 1), false, true})
			lastPriority++
		}
		currentRule := openRuleList[0]
		currentRule.rule.Match.Config.SrcIpRanges = append(currentRule.rule.Match.Config.SrcIpRanges, ip+"/32")
		currentRule.update = true
		if len(currentRule.rule.Match.Config.SrcIpRanges) == 10 {
			// full rule move to updated list
			updateRuleList = append(updateRuleList, currentRule)
			openRuleList = openRuleList[1:]
		}
	}

	// copy the remaining open list to updated
	for _, rule := range openRuleList {
		if rule.update {
			updateRuleList = append(updateRuleList, rule)
		}
	}

	return updateSecurityPolicy(ctx, updateRuleList, len(ruleList))
}

func updateSecurityPolicy(ctx context.Context, rules []*ruleItem, maxRules int) error {

	if len(rules) == 0 {
		zap.L().Info("no update required")
		return nil
	}

	svc, err := compute.NewService(ctx)
	if err != nil {
		return err
	}

	for _, currentRule := range rules {
		if currentRule.append {
			if maxRules >= 98 {
				zap.L().Sugar().Warnf("cannot add rule %s, max number of rules reached", currentRule.rule.Description)
				continue
			} else {
				zap.L().Sugar().Infof("adding rule %s", currentRule.rule.Description)
				if _, err := svc.SecurityPolicies.AddRule(secPolicyProject, secPolicyName, currentRule.rule).
					Do(); err != nil {
					return err
				}
				// we need to wait after a new rule is added
				time.Sleep(10 * time.Second)
				maxRules++
			}
		} else {
			if len(currentRule.rule.Match.Config.SrcIpRanges) == 0 {
				zap.L().Sugar().Infof("deleting rule %s", currentRule.rule.Description)
				if _, err := svc.SecurityPolicies.RemoveRule(secPolicyProject, secPolicyName).
					Priority(currentRule.rule.Priority).
					Do(); err != nil {
					return err
				}
				maxRules--
			} else {
				zap.L().Sugar().Infof("updating rule %s", currentRule.rule.Description)
				if _, err := svc.SecurityPolicies.PatchRule(secPolicyProject, secPolicyName, currentRule.rule).
					Priority(currentRule.rule.Priority).
					Do(); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func createNewRule(priority int64) *compute.SecurityPolicyRule {
	return &compute.SecurityPolicyRule{
		Action:      "deny(502)",
		Description: "ip-deny-list-" + strconv.Itoa(int(priority)),
		Match: &compute.SecurityPolicyRuleMatcher{
			Config: &compute.SecurityPolicyRuleMatcherConfig{
				SrcIpRanges: []string{},
			},
			VersionedExpr: "SRC_IPS_V1",
		},
		Priority: priority,
	}
}

func readIPAddresses(ctx context.Context) (map[string]bool, error) {

	zap.L().Sugar().Infof("reading ip list from %s", rdb.Options().Addr)
	keyPrefix := "deny:"
	var cursor uint64
	var n int
	result := make(map[string]bool)

	for {
		var keys []string
		var err error
		zap.L().Sugar().Debugf("readIPAddresses: begin scan redis keys")
		keys, cursor, err = rdb.Scan(ctx, cursor, keyPrefix+"*", 1000).Result()
		if err != nil {
			return nil, errors.Wrapf(err, "error scan redis")
		}
		n += len(keys)
		for _, k := range keys {
			result[strings.TrimLeft(k, keyPrefix)] = true
		}
		zap.L().Sugar().Debugf("readIPAddresses: found %d keys", len(keys))
		if cursor == 0 {
			break
		}
	}

	return result, nil
}

func readRuleList(ctx context.Context) ([]*compute.SecurityPolicyRule, int64, error) {
	var lastPriority int64 = 1000
	svc, err := compute.NewService(ctx)
	if err != nil {
		return nil, 0, err
	}

	policy, err := svc.SecurityPolicies.Get(secPolicyProject, secPolicyName).Do()
	if err != nil {
		return nil, 0, err
	}

	ruleList := []*compute.SecurityPolicyRule{}
	for _, rule := range policy.Rules {
		// skip the default rule
		if rule.Priority != 2147483647 {
			ruleList = append(ruleList, rule)
			if rule.Priority > lastPriority {
				lastPriority = rule.Priority
			}
		}
	}

	return ruleList, lastPriority, nil
}

type ruleItem struct {
	rule   *compute.SecurityPolicyRule
	update bool
	append bool
}

func toRange(ip string) string {
	if strings.HasSuffix(ip, "/32") {
		return ip
	}
	return ip + "/32"
}

func isIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
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
