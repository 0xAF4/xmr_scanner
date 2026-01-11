package levin

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"sort"
	"strings"
)

const (
	BlocksPerDay = 720.0
	RecentDays   = 1.8
	RecentRatio  = 0.5
	GammaShape   = 19.28
	GammaScale   = 1.0 / 1.61
	MaxGammaDays = 365.0 * 10
)

func sampleGamma(r *rand.Rand, k, theta float64) float64 {
	// Marsaglia and Tsang
	if k < 1 {
		return sampleGamma(r, k+1, theta) * math.Pow(r.Float64(), 1.0/k)
	}

	d := k - 1.0/3.0
	c := 1.0 / math.Sqrt(9*d)

	for {
		x := r.NormFloat64()
		v := 1 + c*x
		if v <= 0 {
			continue
		}
		v = v * v * v
		u := r.Float64()

		if u < 1-0.0331*(x*x)*(x*x) {
			return d * v * theta
		}
		if math.Log(u) < 0.5*x*x+d*(1-v+math.Log(v)) {
			return d * v * theta
		}
	}
}

func sampleOutputAgeDays(r *rand.Rand) float64 {
	if r.Float64() < RecentRatio {
		return r.Float64() * RecentDays
	}

	age := sampleGamma(r, GammaShape, GammaScale)
	if age > MaxGammaDays {
		return MaxGammaDays
	}
	return age
}

func getOutputIndex(txId string, vout int) (uint64, error) {
	if vout < 0 {
		return 0, fmt.Errorf("vout must be non-negative")
	}

	body := fmt.Sprintf(`{"txs_hashes":["%s"],"decode_as_json":false}`, txId)

	resp, err := http.Post(daemonURL, "application/json", strings.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("daemon returned status %s", resp.Status)
	}

	// Структура ответа
	type txResponse struct {
		Txs []struct {
			OutputIndices []json.Number `json:"output_indices"`
		} `json:"txs"`
	}

	var result txResponse

	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()

	if err := decoder.Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(result.Txs) == 0 {
		return 0, fmt.Errorf("no transactions found in response")
	}

	outputs := result.Txs[0].OutputIndices

	if vout >= len(outputs) {
		return 0, fmt.Errorf("vout index out of range")
	}

	indexUint64, err := outputs[vout].Int64()
	if err != nil {
		return 0, fmt.Errorf("invalid output index value: %w", err)
	}

	return uint64(indexUint64), nil
}

func BuildKeyOffsets(indices []uint64) ([]uint64, error) {
	if len(indices) == 0 {
		return nil, errors.New("empty indices")
	}

	// 1. Копируем и сортируем
	sorted := make([]uint64, len(indices))
	copy(sorted, indices)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	// 2. Проверка на дубликаты (важно)
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return nil, errors.New("duplicate global index")
		}
	}

	// 3. Строим offsets
	offsets := make([]uint64, len(sorted))
	offsets[0] = sorted[0]

	for i := 1; i < len(sorted); i++ {
		offsets[i] = sorted[i] - sorted[i-1]
	}

	return offsets, nil
}

func getMaxGlobalIndex() (uint64, error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "0",
		"method":  "get_output_distribution",
		"params": map[string]interface{}{
			"amounts":     []uint64{0},
			"from_height": currentBlockHeight - 10,
			"cumulative":  true,
			"binary":      false,
			"compress":    false,
		},
	}

	var resp struct {
		Result struct {
			Distributions []struct {
				Distribution []uint64 `json:"distribution"`
			} `json:"distributions"`
		} `json:"result"`
	}

	if err := call(req, &resp); err != nil {
		return 0, err
	}

	dist := resp.Result.Distributions[0].Distribution
	return dist[len(dist)-1] - 1, nil
}

func call(reqBody any, respBody any) error {
	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", "https://xmr3.doggett.tech:18089/json_rpc", bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf(
			"daemon rpc http %d: %s",
			resp.StatusCode,
			string(body),
		)
	}

	return json.NewDecoder(resp.Body).Decode(respBody)
}

type getOut struct {
	Amount uint64 `json:"amount"`
	Index  uint64 `json:"index"`
}

// структура запроса
type getOutsReq struct {
	Outputs []getOut `json:"outputs"`
}

type GetOutsResp struct {
	Credits   uint64 `json:"credits"`
	Outs      []Out  `json:"outs"`
	Status    string `json:"status"`
	TopHash   string `json:"top_hash"`
	Untrusted bool   `json:"untrusted"`
}

type Out struct {
	Height   uint64 `json:"height"`
	Key      string `json:"key"`
	Mask     string `json:"mask"`
	Txid     string `json:"txid"`
	Unlocked bool   `json:"unlocked"`
}

func GetMixins(keyOffsets []uint64, inputIndx uint64) (*[]Mixin, *int, error) {
	indxs := append([]uint64(nil), keyOffsets...)
	for i := 1; i < len(indxs); i++ {
		indxs[i] = indxs[i] + indxs[i-1]
	}

	reqd := getOutsReq{
		Outputs: make([]getOut, 0, len(indxs)),
	}

	// заполняем outputs
	var OrderIndx int
	for i, idx := range indxs {
		if idx == inputIndx {
			OrderIndx = i
		}
		reqd.Outputs = append(reqd.Outputs, getOut{
			Amount: 0, // RingCT → всегда 0
			Index:  uint64(idx),
		})
	}

	data, err := json.Marshal(reqd)
	if err != nil {
		return nil, nil, err
	}

	// req, err := http.NewRequest("POST", "https://xmr.unshakled.net:443/get_outs", bytes.NewReader(data))
	req, err := http.NewRequest("POST", "https://xmr3.doggett.tech:18089/get_outs", bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, nil, fmt.Errorf(
			"daemon rpc http %d: %s",
			resp.StatusCode,
			string(body),
		)
	}

	var respS GetOutsResp
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &respS); err != nil {
		log.Fatal(err)
	}

	mixins := new([]Mixin)
	for _, out := range respS.Outs {
		dest, _ := hex.DecodeString(out.Key)
		mask, _ := hex.DecodeString(out.Mask)

		*mixins = append(*mixins, Mixin{
			Dest: Hash(dest),
			Mask: Hash(mask),
		})
	}

	return mixins, &OrderIndx, nil
}
