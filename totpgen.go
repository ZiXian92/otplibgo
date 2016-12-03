/**
 * Main reference: https://github.com/pquerna/otp
 *
 * Main aim of this library is to generalize for more use cases and settings.
 * @author zixian92
 */

package otplibgo

import (
  "crypto/hmac"
  "crypto/sha1"
  "crypto/sha256"
  "crypto/sha512"
  "encoding/binary"
  "hash"
  "math"
  "strconv"
  "time"
)

// Defining algorithm types that can be specified to functions
type CryptAlgo int

const (
  SHA1 CryptAlgo = iota
  SHA256
  SHA512
)

// Generate hash using given key on the message and specified hashing algorithm
// Defaults to SHA1 if no algorithm is specified
func generateHMAC(key, message []byte, algo ...CryptAlgo) ([]byte){
  var algoConstructor func() (hash.Hash)
  if len(algo)==0 {
    algoConstructor = sha1.New
  } else {
    switch algo[0] {
    case SHA1: algoConstructor = sha1.New
    case SHA256: algoConstructor = sha256.New
    case SHA512: algoConstructor = sha512.New
    default: algoConstructor = sha1.New
    }
  }
  hashGen:=hmac.New(algoConstructor, key)
  hashGen.Write(message)
  hash:=hashGen.Sum(nil)
  return hash
}

// Truncates hash into 4-byte hash
func truncateHash(hash []byte)([]byte){
  numBytes:=len(hash)
  offset:=hash[numBytes-1]&0xf  // Least significant 4 bits as offset
  return hash[offset:offset+4]
}

// Genarate HOTP using HMAC-SHA-256 algorithm
// Defaults to 6-digit password if numDigit is too low or too high
// Sensible number of digits is between 6 to 10
// Defaults to SHA1 if no algorithm is specified
func GenerateHOTP(key, message []byte, numDigits uint, algo ...CryptAlgo) (string){
  if numDigits<6 || numDigits>10 {
    numDigits = 6
  }
  hash:=generateHMAC([]byte(key), []byte(string(message)), algo...)
  hash = truncateHash(hash)
  value:=int32(binary.BigEndian.Uint32(hash)&0x7fffffff)
  value%=int32(math.Pow10(int(numDigits)))
  password:=strconv.Itoa(int(value))
  for numZeroes:=int(numDigits)-len(password); numZeroes>0; numZeroes-- {
    password = "0"+password
  }
  return password
}

// Generates time-based OTP with given number of digits using specified hashing algorithm
// Defaults to 6-digit password if numDigit is too low or too high
// Sensible number of digits is between 6 to 10
// Defaults to SHA1 if no algorithm is specified
// timeStep defaults to 30 if value given is 0
// Refer to RFC6238 for explanation on t0 and timeStep
func GenerateTOTP(key []byte, t0, timeStep, numDigits uint, algo ...CryptAlgo) (string) {
  if timeStep==0 {
    timeStep = 30
  }
  if numDigits<6 || numDigits>10 {
    numDigits = 6
  }
  elapsed:=time.Now().UTC().Unix()-int64(t0)
  counter:=uint64(math.Floor(float64(elapsed)/float64(timeStep)))
  buf:=make([]byte, 8)
  binary.BigEndian.PutUint64(buf, counter)
  return GenerateHOTP(key, buf, numDigits, algo...)
}
