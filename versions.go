package prometheusNetworkscan

import "github.com/hashicorp/go-version"

type byVersion []string

func (s byVersion) Len() int {
	return len(s)
}

func (s byVersion) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s byVersion) Less(i, j int) bool {
	v1, err := version.NewVersion(s[i])
	if err != nil {
		panic(err)
	}
	v2, err := version.NewVersion(s[j])
	if err != nil {
		panic(err)
	}
	return v1.LessThan(v2)
}
