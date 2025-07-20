package deps

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"time"

	"github.com/google/go-github/v73/github"
	"github.com/niule-eu/hlcli/pkg/framework"
)

type ReleaseAssetQuery struct {
	Owner string
	Repo string
	Pattern string
	ChecksumsPattern *string
}

type Checksum struct {
	Value string
}

func getAssetByPattern(assets []*github.ReleaseAsset, pattern string) *github.ReleaseAsset {
	assetIdx := slices.IndexFunc(
		assets, 
		func(v *github.ReleaseAsset) bool {
			matched, err := regexp.MatchString(pattern, *v.Name )
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
		line := re.Split(scanner.Text(), -1)
		if line[1] == assetName {
			res = Checksum{Value: line[0]}
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return &res, nil
}

func GetRelease(token string, raq ReleaseAssetQuery) (framework.Effect, error) {
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
	return framework.NewStdOutIO(fmt.Sprintf("\nTAG=%s\nURL=%s\nHASH=%s", *release.TagName, *asset.URL, checksum.Value)), nil
}
