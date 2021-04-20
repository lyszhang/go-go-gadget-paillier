/**
 * @Author: lyszhang
 * @Email: ericlyszhang@gmail.com
 * @Date: 2021/4/20 4:15 PM
 */

package compare

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
)

var limit  = big.NewInt(114823432545353)

type PrivateKey struct {
	PublicKey
	X *big.Int
	Y *big.Int
}

type PublicKey = string

// 生成私钥
func GenerateKey() *PrivateKey{
	x, _ := rand.Int(rand.Reader, limit)
	y, _ := rand.Int(rand.Reader, limit)

	buffer := append(x.Bytes(), y.Bytes()...)
	digest := sha256.Sum256(buffer)
	return &PrivateKey{
		PublicKey: hex.EncodeToString(digest[:]),
		X: x,
		Y: y,
	}
}

func NewKeyFromString(str string) *PrivateKey{
	buf, _ := base64.StdEncoding.DecodeString(str)

	p := PrivateKey{}
	json.Unmarshal(buf, &p)
	return &p
}

func(p *PrivateKey)String() string {
	buf, _ := json.Marshal(p)
	return base64.StdEncoding.EncodeToString(buf)
}


