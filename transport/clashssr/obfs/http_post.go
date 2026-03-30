package obfs

func init() {
	register("http_post", newHTTPPost, 0)
}

func newHTTPPost(b *Base) Obfs {
	hostCandidates, bodyHeader := parseHTTPObfsParam(b)
	return &httpObfs{Base: b, post: true, hostCandidates: hostCandidates, bodyHeader: bodyHeader}
}
