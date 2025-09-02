package levin

type ResponsePing struct {
	Status string
	Id     uint64
}

func NewPingFromPortableStorage(store *PortableStorage) *ResponsePing {
	ResponsePing := ResponsePing{}
	for _, entry := range store.Entries {
		switch entry.Name {
		case "peer_id":
			ResponsePing.Id = entry.Uint64()
		case "status":
			ResponsePing.Status = entry.String()
		}
	}

	return &ResponsePing
}
