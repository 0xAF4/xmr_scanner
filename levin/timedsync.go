package levin

import (
	"net"
)

type CoreSyncData struct {
	CurrentHeight             uint64
	CumulativeDifficulty      uint64
	CumulativeDifficultyTop64 uint64
	TopId                     string
	TopVersion                uint8
	PruningSeed               uint32
}

type PeerListEntryBase struct {
	Adr               Peer
	Id                uint64
	LastSeen          int64
	PruningSeed       uint32
	RPCPort           uint16
	RPCCreditsPerHash uint32
}

type RequestTimedSync struct {
	PayloadData CoreSyncData
}

type ResponseTimedSync struct {
	PayloadData       CoreSyncData
	LocalPeerlistNew  []PeerListEntryBase
	LocalPeerlistNewE Entry
}

func NewRequestTimedSync(Height uint64, Hash string) *RequestTimedSync {
	return &RequestTimedSync{
		PayloadData: CoreSyncData{
			CurrentHeight: Height,
			TopId:         Hash,
		},
	}
}

func (r *RequestTimedSync) Bytes() []byte {
	return (&PortableStorage{
		Entries: []Entry{
			{
				Name: "payload_data",
				Serializable: &Section{
					Entries: []Entry{
						{
							Name:         "cumulative_difficulty",
							Serializable: BoostUint64(CumulativeDifficulty),
						},
						{
							Name:         "cumulative_difficulty_top64",
							Serializable: BoostUint64(CumulativeDifficultyTop64),
						},
						{
							Name:         "current_height",
							Serializable: BoostUint64(r.PayloadData.CurrentHeight),
						},
						{
							Name:         "top_id",
							Serializable: BoostHash(r.PayloadData.TopId),
						},
						{
							Name:         "top_version",
							Serializable: BoostUint8(TopVersion),
						},
					},
				},
			},
		},
	}).Bytes()
}

func NewResponseTimedSync(storage *PortableStorage) *ResponseTimedSync {
	PayloadData := CoreSyncData{}
	PeerlistNew := []PeerListEntryBase{}
	PeerlistNewE := Entry{}

	payload_data := func(entries Entries) CoreSyncData {
		localPayloadData := CoreSyncData{}
		for _, entry := range entries {
			switch entry.Name {
			case "cumulative_difficulty":
				localPayloadData.CumulativeDifficulty = entry.Uint64()
			case "cumulative_difficulty_top64":
				localPayloadData.CumulativeDifficultyTop64 = entry.Uint64()
			case "current_height":
				localPayloadData.CurrentHeight = entry.Uint64()
			case "top_id":
				localPayloadData.TopId = entry.String()
			case "top_version":
				localPayloadData.TopVersion = entry.Uint8()
			}
		}
		return localPayloadData
	}

	local_peerlist_new := func(entries Entries) []PeerListEntryBase {
		localPeerlistNew := []PeerListEntryBase{}
		for _, entry := range entries {
			local2PeerlistNew := PeerListEntryBase{}
			for _, entry2 := range entry.Entries() {
				switch entry2.Name {
				case "adr":
					for _, addrField := range entry2.Entries() {
						if addrField.Name != "addr" {
							continue
						}
						peer := Peer{}

						for _, field := range addrField.Entries() {
							switch field.Name {
							case "m_ip":
								peer.Ip = ipzify(field.Uint32())
							case "m_port":
								peer.Port = field.Uint16()
							case "addr":
								peer.Ip = net.IP([]byte(field.String())).String()
							}
						}

						if peer.Ip != "" && peer.Port != 0 {
							local2PeerlistNew.Adr = peer
						}
					}
				case "id":
					local2PeerlistNew.Id = entry2.Uint64()
				case "pruning_seed":
					local2PeerlistNew.PruningSeed = entry2.Uint32()
				}

			}
			localPeerlistNew = append(localPeerlistNew, local2PeerlistNew)
		}
		return localPeerlistNew
	}

	for _, entry := range storage.Entries {
		switch entry.Name {
		case "payload_data":
			PayloadData = payload_data(entry.Entries())
		case "local_peerlist_new":
			PeerlistNewE = entry
			PeerlistNew = local_peerlist_new(entry.Entries())
		}
	}

	return &ResponseTimedSync{
		PayloadData:       PayloadData,
		LocalPeerlistNew:  PeerlistNew,
		LocalPeerlistNewE: PeerlistNewE,
	}
}
