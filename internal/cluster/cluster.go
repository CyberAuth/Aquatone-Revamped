package cluster

import (
	"fmt"
	"math/bits"
	"sort"
	"strconv"

	"github.com/CyberAuth/Aquatone-Revamped/v2/internal/model"
)

func Build(results []*model.Result, similarity float64) []model.Cluster {
	if similarity < 0 {
		similarity = 0
	}
	if similarity > 1 {
		similarity = 1
	}
	threshold := int((1 - similarity) * 64)
	type item struct {
		url  string
		hash uint64
		hex  string
	}
	var items []item
	for _, result := range results {
		if result.ScreenshotHash == "" || result.ScreenshotState != "ok" {
			continue
		}
		value, err := strconv.ParseUint(result.ScreenshotHash, 16, 64)
		if err == nil {
			items = append(items, item{url: result.URL, hash: value, hex: result.ScreenshotHash})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].url < items[j].url })
	parent := make([]int, len(items))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(value int) int {
		if parent[value] != value {
			parent[value] = find(parent[value])
		}
		return parent[value]
	}
	for i := range items {
		for j := i + 1; j < len(items); j++ {
			if bits.OnesCount64(items[i].hash^items[j].hash) <= threshold {
				a, b := find(i), find(j)
				if a != b {
					parent[b] = a
				}
			}
		}
	}
	groups := map[int][]item{}
	for i, entry := range items {
		root := find(i)
		groups[root] = append(groups[root], entry)
	}
	clusters := make([]model.Cluster, 0, len(groups))
	for _, group := range groups {
		members := make([]string, 0, len(group))
		for _, entry := range group {
			members = append(members, entry.url)
		}
		clusters = append(clusters, model.Cluster{
			ID: fmt.Sprintf("cluster-%03d", len(clusters)+1), Hash: group[0].hex, Members: members,
		})
	}
	sort.Slice(clusters, func(i, j int) bool {
		if len(clusters[i].Members) == len(clusters[j].Members) {
			return clusters[i].Members[0] < clusters[j].Members[0]
		}
		return len(clusters[i].Members) > len(clusters[j].Members)
	})
	for i := range clusters {
		clusters[i].ID = fmt.Sprintf("cluster-%03d", i+1)
	}
	return clusters
}
