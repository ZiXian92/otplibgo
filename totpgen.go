/**
 * Main reference: https://github.com/pquerna/otp
 */

package otplibgo

import (
  "crypto/hmac"
  "crypto/sha512"
  "encoding/binary"
  "math"
  "strconv"
  "time"
)

// Generate SHA256 hash using given key on the message
func generateHMAC(key, message []byte) ([]byte){
  hashGen:=hmac.New(sha512.New, key)
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
// TODO: Refactoring
func GenerateHOTP(key, message []byte, numDigits uint) (string){
  if numDigits==0 {
    numDigits = 6
  }
  hash:=generateHMAC([]byte(key), []byte(string(message)))
  hash = truncateHash(hash)
  value:=int32(binary.BigEndian.Uint32(hash)&0x7fffffff)
  value%=int32(math.Pow10(int(numDigits)))
  password:=strconv.Itoa(int(value))
  for numZeroes:=int(numDigits)-len(password); numZeroes>0; numZeroes-- {
    password = "0"+password
  }
  return password
}

// Generates
func GenerateTOTP(key string, t0, timeStep, numDigits uint) (string) {
  if timeStep==0 {
    timeStep = 30
  }
  if numDigits==0 {
    numDigits = 6
  }
  elapsed:=time.Now().UTC().Unix()-int64(t0)
  counter:=uint64(math.Floor(float64(elapsed)/float64(timeStep)))
  buf:=make([]byte, 8)
  binary.BigEndian.PutUint64(buf, counter)
  return GenerateHOTP([]byte(key), buf, numDigits)
}
