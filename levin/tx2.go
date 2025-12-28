package levin

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"time"

	"filippo.io/edwards25519"
)

type InputPrm map[string]interface{}

const daemonURL = "https://xmr3.doggett.tech:18089/get_transactions"
const currentBlockHeight = 3570154

var mockOffset = []uint64{
	143369868,
	506667,
	605704,
	69702,
	405731,
	275890,
	249503,
	38215,
	86866,
	1588,
	17,
	266,
	1281,
	231,
	223,
	1401,
}

func NewEmptyTransaction() *Transaction {
	return &Transaction{
		Version:    2,
		UnlockTime: 0,
		VinCount:   0,
		RctSignature: &RctSignature{
			Type: 6,
		},
		RctSigPrunable: &RctSigPrunable{},
	}
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

func (t *Transaction) WriteInput(prm InputPrm) error {
	vout := prm["vout"].(int)
	indx, err := getOutputIndex(prm["txId"].(string), vout)
	if err != nil {
		return fmt.Errorf("failed to get output index: %w", err)
	}

	maxIndx, err := getMaxGlobalIndex()
	if err != nil {
		return fmt.Errorf("failed to get max global index: %w", err)
	}

	ring, err := SelectDecoys(rand.New(rand.NewSource(time.Now().UnixNano())), indx, maxIndx)
	if err != nil {
		panic(err)
	}

	keyOffset, err := BuildKeyOffsets(ring)
	if err != nil {
		return fmt.Errorf("failed to build key offsets: %w", err)
	}
	_ = keyOffset

	privViewKeyBytes, err := hexTo32(prm["privateViewKey"].(string)) // correct ✅
	if err != nil {
		return fmt.Errorf("failed to decode private view key: %w", err)
	}

	pubSpendKey, _ /*pubViewKey*/, err := DecodeAddress(prm["address"].(string)) // correct ✅
	if err != nil {
		return fmt.Errorf("failed to decode address: %w", err)
	}

	extra, err := hex.DecodeString(prm["extra"].(string)) // correct ✅
	if err != nil {
		return fmt.Errorf("failed to decode extra: %w", err)
	}

	txPubKey, _, _, _, err := parseTxExtra(extra)
	if err != nil {
		return fmt.Errorf("failed to extract tx public key: %w", err)
	}

	outputPubKey, err := DerivePublicKey(txPubKey, privViewKeyBytes, pubSpendKey[:], uint64(vout))
	if err != nil {
		return fmt.Errorf("failed to get output public key: %w", err)
	}

	keyImage, err := t.generateKeyImage(prm["privateSpendKey"].(string), outputPubKey)
	if err != nil {
		return fmt.Errorf("failed to generate key image: %w", err)
	}

	fmt.Printf("Key Image: %x\n", keyImage)

	t.VinCount += 1
	t.Inputs = append(t.Inputs, TxInput{
		Amount:     0,
		Type:       0x02,
		KeyOffsets: mockOffset, //keyOffset,
		KeyImage:   keyImage,
	})
	return nil
}

func hashToPoint(publicKey []byte) *edwards25519.Point {
	hash := hashToScalar(publicKey)
	point := new(edwards25519.Point).ScalarBaseMult(hash)
	return point
}

func (t *Transaction) generateKeyImage(privateKey string, outputPubKey []byte) (Hash, error) {
	// 1. Декодируем приватный spend ключ
	privKeyBytes, err := hexTo32(privateKey)
	if err != nil {
		return Hash{}, fmt.Errorf("failed to decode private spend key: %w", err)
	}

	// 2. Создаем скаляр
	privScalar := new(edwards25519.Scalar)
	if _, err := privScalar.SetCanonicalBytes(privKeyBytes); err != nil {
		return Hash{}, fmt.Errorf("invalid private spend key: %w", err)
	}

	hashPoint := hashToPoint(outputPubKey)
	keyImage := new(edwards25519.Point).ScalarMult(privScalar, hashPoint)

	keyImageBytes := keyImage.Bytes()
	var result Hash
	copy(result[:], keyImageBytes)

	return result, nil
}

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

func hashToScalar(data []byte) *edwards25519.Scalar {
	hash := Hash(data)
	scalar := new(edwards25519.Scalar)
	scalar.SetBytesWithClamping(hash[:])
	return scalar
}

func SelectDecoys(rng *rand.Rand, realGlobalIndex uint64, maxGlobalIndex uint64) ([]uint64, error) {

	ringSize := 16

	selected := make(map[uint64]struct{})
	selected[realGlobalIndex] = struct{}{}

	for len(selected) < ringSize {
		// 1. возраст
		ageDays := sampleOutputAgeDays(rng)
		ageBlocks := uint64(ageDays * BlocksPerDay)

		if ageBlocks >= maxGlobalIndex {
			continue
		}

		// 2. перевод возраста → индекс
		target := maxGlobalIndex - ageBlocks

		// 3. uniform смещение (ВАЖНО)
		offset := uint64(rng.Int63n(int64(target + 1)))
		gi := offset

		// 4. проверки
		if gi == realGlobalIndex {
			continue
		}
		if _, exists := selected[gi]; exists {
			continue
		}

		selected[gi] = struct{}{}
	}

	// 5. финальный массив
	ring := make([]uint64, 0, ringSize)
	for gi := range selected {
		ring = append(ring, gi)
	}

	// 6. перемешать кольцо
	rng.Shuffle(len(ring), func(i, j int) {
		ring[i], ring[j] = ring[j], ring[i]
	})

	return ring, nil
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

	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("https://xmr3.doggett.tech:18089/json_rpc"),
		bytes.NewReader(data),
	)
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
