package main

import (
	"strings"
)

// Fingerprint 代表一条指纹规则
type Fingerprint struct {
	Name     string   // 指纹名称（例如 "RuoYi"）
	Headers  []string // 匹配响应头特征（例如 "Set-Cookie: rememberMe"）
	BodyKeys []string // 匹配网页正文特征（例如 "若依", "ruoyi"）

}

// 预定义规则库（今天先写几条国内常见的）
var FingerprintRules = []Fingerprint{
	// ======== OA 与 国内管理系统 ========
	{
		Name:     "RuoYi",
		Headers:  []string{},
		BodyKeys: []string{"<title>若依", "/prod-api/", "ruoyi"}, // 加上 <title> 降低误报
	},
	{
		Name:     "JeecgBoot",
		Headers:  []string{"X-Powered-By: Jeecg-Boot"},
		BodyKeys: []string{"jeecg-boot", "JeecgBoot", "积木报表"},
	},
	{
		Name:     "ZhiyuanOA",
		Headers:  []string{},
		BodyKeys: []string{"致远OA", "seeyon", "/seeyon/"},
	},
	{
		Name:     "WeaverOA",
		Headers:  []string{},
		BodyKeys: []string{"泛微", "weaver", "/wui/"},
	},

	// ======== Java 生态与框架 ========
	{
		Name:     "Shiro",
		Headers:  []string{"Set-Cookie: rememberMe=deleteMe"}, // 强特征
		BodyKeys: []string{},
	},
	{
		Name:     "Spring Boot",
		Headers:  []string{"X-Application-Context"},
		BodyKeys: []string{"Whitelabel Error Page", "Spring Boot"},
	},
	{
		Name:     "Swagger UI",
		Headers:  []string{},
		BodyKeys: []string{"<title>Swagger UI</title>", "swagger-ui"},
	},
	{
		Name:     "Druid",
		Headers:  []string{},
		BodyKeys: []string{"<title>Druid Stat Index</title>", "druid.index"},
	},

	// ======== 中间件与基础设施 ========
	{
		Name:     "Nacos",
		Headers:  []string{},
		BodyKeys: []string{"<title>Nacos</title>", "console-ui/public/img/favicon.ico"}, // 收窄特征
	},
	{
		Name:     "Tomcat",
		Headers:  []string{"Server: Apache-Coyote"},
		BodyKeys: []string{"Apache Tomcat"},
	},
	{
		Name:     "Jenkins",
		Headers:  []string{"X-Jenkins"},
		BodyKeys: []string{"<title>Dashboard [Jenkins]</title>"},
	},
	{
		Name:     "GitLab",
		Headers:  []string{},
		BodyKeys: []string{"<title>GitLab</title>", "GitLab Community Edition"},
	},
	{
		Name:     "Grafana",
		Headers:  []string{},
		BodyKeys: []string{"<title>Grafana</title>"},
	},
	{
		Name:     "Elasticsearch",
		Headers:  []string{"X-Elastic-Product: Elasticsearch"},
		BodyKeys: []string{"You Know, for Search", "\"cluster_name\""},
	},
	{
		Name:     "Kibana",
		Headers:  []string{},
		BodyKeys: []string{"<title>Kibana</title>"},
	},
	{
		Name:     "Zabbix",
		Headers:  []string{},
		BodyKeys: []string{"<title>Zabbix</title>"},
	},
	{
		Name:     "宝塔面板",
		Headers:  []string{},
		BodyKeys: []string{"<title>宝塔面板</title>", "bt.cn", "btwaf"},
	},

	// ======== 常见 Web 应用与语言 ========
	{
		Name:     "WordPress",
		Headers:  []string{},
		BodyKeys: []string{"wp-content", "wp-includes", "wordpress"},
	},
	{
		Name:     "ThinkPHP",
		Headers:  []string{"X-Powered-By: ThinkPHP"},
		BodyKeys: []string{"ThinkPHP"},
	},
	{
		Name:     "Laravel",
		Headers:  []string{"Set-Cookie: laravel_session"},
		BodyKeys: []string{},
	},
	{
		Name:     "PhpMyAdmin",
		Headers:  []string{},
		BodyKeys: []string{"<title>phpMyAdmin</title>", "pma_username"},
	},
	{
		Name:     "Discuz",
		Headers:  []string{},
		BodyKeys: []string{"Discuz!", "discuz"},
	},
}

// identifyFingerprint 接收响应数据，返回匹配到的指纹名称列表
func identifyFingerprint(headers map[string][]string, body string) []string {
	var matches []string
	for _, rule := range FingerprintRules {
		isMatched := false

		//1. 匹配 Header
		for _, headerRule := range rule.Headers {
			parts := strings.SplitN(headerRule, ":", 2)
			if len(parts) == 2 {
				headerKey := strings.TrimSpace(parts[0])
				headerVal := strings.TrimSpace(parts[1])
				// 遍历响应的 headers 看是否包含规则里的值
				for respKey, respVals := range headers {
					if strings.EqualFold(respKey, headerKey) {
						for _, val := range respVals {
							if strings.Contains(strings.ToLower(val), strings.ToLower(headerVal)) {
								isMatched = true
								break
							}
						}
					}
				}

				// 2. 匹配 Body（如果 Header 没匹配到）
				if !isMatched {
					for _, keyword := range rule.BodyKeys {
						if strings.Contains(strings.ToLower(body), strings.ToLower(keyword)) {
							isMatched = true
							break
						}
					}
				}
				if isMatched {
					matches = append(matches, rule.Name)
				}
			}
		}
	}
	return matches
}
