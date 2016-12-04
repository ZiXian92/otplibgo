# otplibgo
Go library to generate HMAC-based One-time Password(HOTP) and Time-based One-time Password(TOTP) using RFC4226 and RFC6238 respectively.

## Example Usage
```
package main

import (
  "github.com/zixian92/otplibgo"
  "fmt"
)

func main(){
  key:="Do not mess with the keys"
  fmt.Println(otplibgo.GenerateHOTP([]byte(key), []byte("Hello"), 6))
  fmt.Println(otplibgo.GenerateHOTP([]byte(key), []byte("Hello"), 6, otplibgo.SHA256))
  fmt.Println(otplibgo.GenerateTOTP([]byte(key), 0, 30, 10))
  fmt.Println(otplibgo.GenerateTOTP([]byte(key), 0, 30, 10, otplibgo.SHA512))
}
```
Running `go install <directory containing the above code>` should trigger a fetch on this library(to be tested).

## API
### const SHA1 otplibgo.CryptAlgo
### const SHA256 otplibgo.CryptAlgo
### const SHA512 otplibgo.CryptAlgo
### func GenerateHOTP(key, message []byte, numDigits uint, algo ...otplibgo.CryptAlgo) (string)
**Parameters**  
* key: Key byte string used for encryption/hashing.
* message: The content to be encrypted/hashed.
* numDigits: Number of digits in password output. Use values between 6 and 10.
* algo: The encryption/hashing algorithm to use. Defaults to otplibgo.SHA1.

### func GenerateTOTP(key []byte, t0 int64, timeStep, numDigits uint, algo ...otplibgo.CryptAlgo) (string)
**Parameters**  
* key: Key byte string used for encryption/hashing.
* t0: The base Unix timestamp to compute time offset from.
* timeStep: Number of seconds before the password expires. Recommended to use a small value that is long enough for user to receive and enter the password.
* numDigits: Number of digits in password output. Use values between 6 and 10.
* algo: The encryption/hashing algorithm to use. Defaults to otplibgo.SHA1.
