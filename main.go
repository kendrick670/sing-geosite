package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sagernet/sing-box/common/geosite"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func gfwlistDownload() ([]byte, error) {
	const gfwlistURL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
	log.Info("download ", gfwlistURL)
	client := http.DefaultClient
	if proxyURL := os.Getenv("HTTP_PROXY"); proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	}
	response, err := client.Get(gfwlistURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	// gfwlist.txt is Base64 encoded
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(decoded, data)
	if err != nil {
		return nil, err
	}
	return decoded[:n], nil
}

var (
	abpPattern       = regexp.MustCompile(`^\|\|(.+)`)
	plainDomainPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$`)
)

func gfwlistParse(data []byte) ([]geosite.Item, error) {
	var items []geosite.Item
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		if strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "|") && !strings.HasPrefix(line, "||") {
			continue
		}

		domain := ""
		if matches := abpPattern.FindStringSubmatch(line); len(matches) > 1 {
			domain = matches[1]
		} else if plainDomainPattern.MatchString(line) {
			domain = line
		}

		if domain == "" || seen[domain] {
			continue
		}
		seen[domain] = true

		items = append(items, geosite.Item{
			Type:  geosite.RuleTypeDomainSuffix,
			Value: domain,
		})
	}

	return items, scanner.Err()
}

func main() {
	data, err := gfwlistDownload()
	if err != nil {
		log.Fatal(err)
	}
	log.Info("downloaded ", len(data), " bytes")

	items, err := gfwlistParse(data)
	if err != nil {
		log.Fatal(err)
	}
	log.Info("parsed ", len(items), " items")

	const code = "gfw"
	const ruleSetOutput = "rule-set"
	os.RemoveAll(ruleSetOutput)
	err = os.MkdirAll(ruleSetOutput, 0o755)
	if err != nil {
		log.Fatal(err)
	}

	defaultRule := geosite.Compile(items)
	var plainRuleSet option.PlainRuleSet
	plainRuleSet.Rules = []option.HeadlessRule{
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultHeadlessRule{
				Domain:        defaultRule.Domain,
				DomainSuffix:  defaultRule.DomainSuffix,
				DomainKeyword:  defaultRule.DomainKeyword,
				DomainRegex:   defaultRule.DomainRegex,
			},
		},
	}

	srsPath, _ := filepath.Abs(filepath.Join(ruleSetOutput, "geosite-"+code+".srs"))
	outputRuleSet, err := os.Create(srsPath)
	if err != nil {
		log.Fatal(err)
	}
	defer outputRuleSet.Close()

	err = srs.Write(outputRuleSet, plainRuleSet, 0)
	if err != nil {
		log.Fatal(err)
	}
	log.Info("write ", srsPath)
}
