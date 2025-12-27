package ghasset

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/go-github/v73/github"
)

type ReleaseAssetQuery struct {
	Owner            string  `yaml:"owner"`
	Repo             string  `yaml:"repo"`
	Pattern          string  `yaml:"pattern"`
	ChecksumsPattern *string `yaml:"checksums_pattern,omitempty"`
}

type Checksum struct {
	Value string
}

type ReleaseAssetResult struct {
	Owner string
	Repo  string
	Tag   string
	Url   string
	Hash  *Checksum
}

func getAssetByPattern(assets []*github.ReleaseAsset, pattern string) *github.ReleaseAsset {
	assetIdx := slices.IndexFunc(
		assets,
		func(v *github.ReleaseAsset) bool {
			matched, err := regexp.MatchString(pattern, *v.Name)
			if err != nil {
				return false
			}
			if matched {
				return true
			} else {
				return false
			}
		})
	if assetIdx == -1 {
		return nil
	} else {
		return assets[assetIdx]
	}
}

func getChecksum(assetName string, assets []*github.ReleaseAsset, checksumsPattern *string) (*Checksum, error) {
	if checksumsPattern == nil {
		return nil, nil
	}
	checksumsAsset := getAssetByPattern(assets, *checksumsPattern)
	if checksumsAsset == nil {
		return nil, fmt.Errorf("no asset matched pattern '%s'", *checksumsPattern)
	}
	httpClient := &http.Client{}
	req, err := http.NewRequest("GET", *checksumsAsset.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/octet-stream")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	re := regexp.MustCompile(`\s+`)
	var res Checksum
	for scanner.Scan() {
		parts := re.Split(scanner.Text(), -1)
		if strings.Contains(parts[1], assetName) {
			res = Checksum{Value: parts[0]}
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return &res, nil
}

func GetAsset(token string, raq ReleaseAssetQuery) (*ReleaseAssetResult, error) {
	repos := github.NewClient(nil).WithAuthToken(token).Repositories
	d, err := time.ParseDuration("30s")
	if err != nil {
		return nil, err
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), d)
	defer cancelFunc()
	release, _, err := repos.GetLatestRelease(ctx, raq.Owner, raq.Repo)
	if err != nil {
		return nil, err
	}
	asset := getAssetByPattern(release.Assets, raq.Pattern)
	if asset == nil {
		return nil, fmt.Errorf("no asset matched pattern '%s'", raq.Pattern)
	}
	checksum, err := getChecksum(*asset.Name, release.Assets, raq.ChecksumsPattern)
	if err != nil {
		return nil, err
	}
	return &ReleaseAssetResult{
		Tag:   *release.TagName,
		Url:   *asset.URL,
		Hash:  checksum,
		Owner: raq.Owner,
		Repo:  raq.Repo,
	}, nil
}
