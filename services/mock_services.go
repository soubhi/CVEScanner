package services

type RepoFetcher interface {
	GetRepoFiles(owner, repo string) ([]map[string]interface{}, error)
}

type DefaultRepoFetcher struct{}

func (d DefaultRepoFetcher) GetRepoFiles(owner, repo string) ([]map[string]interface{}, error) {
	return GetRepoFiles(owner, repo)
}
