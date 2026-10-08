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
	{
		Name:     "RouYi",
		Headers:  []string{"Set-Cookie: rememberMe"},
		BodyKeys: []string{"若依", "ruoyi", "/prod-api/"},
	},
	{
		Name:     "Spring Boot",
		Headers:  []string{"X-Application-Context"},
		BodyKeys: []string{"Whitelabel Error Page", "Spring Boot"},
	},
	{
		Name:     "Shiro",
		Headers:  []string{"Set-Cookie: rememberMe=deleteMe"},
		BodyKeys: []string{},
	},
	{
		Name:     "Nginx",
		Headers:  []string{"Server: nginx"},
		BodyKeys: []string{},
	},
	{
		Name:     "Tengine",
		Headers:  []string{"Server: Tengine"},
		BodyKeys: []string{},
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
