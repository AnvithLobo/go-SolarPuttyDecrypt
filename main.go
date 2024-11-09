package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/pbkdf2"
)

func main() {
	var CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	sessionFile := flag.String("session", "", "SolarPutty session file path [required]")
	wordlistFile := flag.String("wordlist", "", "Wordlist file path")
	password := flag.String("password", "", "Password to decrypt the session file")
	threads := flag.Int("threads", runtime.NumCPU(), "Number of threads to use")

	flag.Parse()

	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintf(CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		return
	}

	if *sessionFile == "" {
		fmt.Println("--session is required")
		return
	}

	if *wordlistFile == "" && *password == "" {
		fmt.Println("--wordlist or --password is required")
		return
	}

	if *password != "" && *wordlistFile != "" {
		fmt.Println("--wordlist and --password cannot be used together")
		return
	}

	if exists, err := fileExists(*sessionFile); !exists {
		fmt.Println(err)
		return
	}

	if exists, err := fileExists(*wordlistFile); !exists && *wordlistFile != "" {
		fmt.Println(err)
		return
	}

	fmt.Println("-----------------------------------------------------")
	fmt.Println("SolarPutty's Sessions Bruteforce Decrypter in go")
	fmt.Println("-----------------------------------------------------")

	err := runDecrypt(*sessionFile, *wordlistFile, *password, *threads)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("\r-----------------------------------------------------")
}

type cipherStruct struct {
	cipherText    string
	base64Array   []byte
	salt          []byte
	iv            []byte
	encryptedData []byte
}

func newCipherStruct(cipherText string) (cipherStruct, error) {
	// Decode base64 input
	array, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return cipherStruct{}, err
	}

	// Extract salt, IV and encrypted data
	// Note: TripleDES uses 8-byte block size, so IV must be 8 bytes
	salt := array[:24]
	iv := array[24:32]
	encryptedData := array[48:]

	return cipherStruct{
		cipherText:    cipherText,
		base64Array:   array,
		salt:          salt,
		iv:            iv,
		encryptedData: encryptedData,
	}, nil
}

func runDecrypt(sessionFile, wordlist, passwordArg string, threads int) error {
	fileContent, err := os.ReadFile(sessionFile)
	if err != nil {
		return err
	}

	text := string(fileContent)

	cipherData, err := newCipherStruct(text)

	if err != nil {
		return err
	}

	// Handle single password case
	if passwordArg != "" {
		decryptedText, err := Decrypt(passwordArg, cipherData)
		if err != nil {
			return err
		}

		if output, isValidDecrypt := isValid(decryptedText, passwordArg); isValidDecrypt {
			fmt.Println(output)
			return nil
		}

		return errors.New("invalid password unable to decrypt file")
	}

	// Bruteforce case
	passwordsFile, err := os.Open(wordlist)
	if err != nil {
		return err
	}
	defer passwordsFile.Close()

	totalLines := getLineCount(wordlist)
	numWorkers := threads // Use number of CPU threads
	passwords := make(chan string, numWorkers)
	foundCh := make(chan string)

	var attemptCount atomic.Int64
	currentPassCh := make(chan string, 1)

	startTime := time.Now()

	// Start progress printer goroutine
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		var currentPass string
		for range ticker.C {
			select {
			case pass := <-currentPassCh:
				currentPass = pass
			default:
			}

			count := attemptCount.Load()
			if count > 0 {
				percentComplete := (float64(count) / float64(totalLines)) * 100.0
				speed := float64(count) / time.Since(startTime).Seconds()
				fmt.Print("\r\033[K")
				fmt.Printf("\r[%.2f%% done] [%d/%d] [%.0f p/s] Trying: %s",
					percentComplete, count, totalLines, speed, currentPass)
			}
		}
	}()

	// Start workers
	for i := 0; i < numWorkers; i++ {
		go func() {
			for pass := range passwords {
				select {
				case currentPassCh <- pass:
				default:
				}

				decryptedText, err := Decrypt(pass, cipherData)
				if err != nil {
					continue
				}

				if output, isValidDecrypt := isValid(decryptedText, pass); isValidDecrypt {
					foundCh <- output
					return
				}

				attemptCount.Add(1)
			}
		}()
	}

	// Feed passwords to workers
	go func() {
		scanner := bufio.NewScanner(passwordsFile)
		for scanner.Scan() {
			select {
			case passwords <- scanner.Text():
			case <-foundCh: // Exit if password found
				return
			}
		}
		close(passwords)
	}()

	// Wait for success
	output := <-foundCh
	fmt.Print("\r\033[K\r\n")
	fmt.Println(output)

	return nil
}

func Decrypt(passPhrase string, cipherData cipherStruct) (string, error) {

	// Derive key using PBKDF2
	key := pbkdf2.Key([]byte(passPhrase), cipherData.salt, 1000, 24, sha1.New)

	// Create triple DES cipher
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}

	// Create CBC decrypter
	mode := cipher.NewCBCDecrypter(block, cipherData.iv)

	// Create output buffer
	decrypted := make([]byte, len(cipherData.encryptedData))
	mode.CryptBlocks(decrypted, cipherData.encryptedData)

	// Remove PKCS7 padding
	paddingLen := int(decrypted[len(decrypted)-1])
	if paddingLen > 0 && paddingLen <= len(decrypted) {
		decrypted = decrypted[:len(decrypted)-paddingLen]
	}

	return string(decrypted), nil
}

func isValid(decryptedText, password string) (string, bool) {

	if decryptedText[:1] != "{" {
		return "", false
	}

	// Check if the result is valid UTF-8 (meaning the decryption was likely successful)
	if !utf8.ValidString(decryptedText) {
		return "", false
	}

	var data map[string]interface{}
	err := json.Unmarshal([]byte(decryptedText), &data)
	if err != nil {
		return "", false
	}

	prettyData, _ := json.MarshalIndent(data, "", "    ")
	output := fmt.Sprintf("password: %s \n  -> \n%s\n", password, prettyData)
	return output, true
}

func getLineCount(file_path string) int {
	file, err := os.Open(file_path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	defaultSize := bufio.MaxScanTokenSize
	defaultEndLine := "\n"
	sepByte := []byte(defaultEndLine)[0]

	buf := make([]byte, defaultSize)
	var count int

	for {
		bufferSize, err := file.Read(buf)
		if err != nil && err != io.EOF {
			return 0
		}

		var buffPosition int
		for {
			i := bytes.IndexByte(buf[buffPosition:], sepByte)
			if i == -1 || bufferSize == buffPosition {
				break
			}
			buffPosition += i + 1
			count++
		}
		if err == io.EOF {
			break
		}
	}

	return count
}

func fileExists(file string) (bool, error) {
	fileStat, err := os.Stat(file)
	if errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("file %s does not exist", file)
	}

	if err != nil {
		return false, err
	}

	if fileStat.IsDir() {
		return false, fmt.Errorf("%s is a directory", file)
	}
	return true, nil
}
