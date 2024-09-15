package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/antchfx/xmlquery"
)

type DecryptResult struct {
	text string
	node *xmlquery.Node
	err  error
}

var HMAC_KEY = []byte("{22C58AC3-F1C7-4D96-8B88-5E4BBF505817}")

func change_extension(path string, ext string) string {
	index := strings.LastIndex(path, ".")
	if index == -1 {
		return path + ext
	}
	return path[:index] + ext
}

func aes_cbc_decrypt(key []byte, iv []byte, data []byte) ([]byte, int, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, err
	}
	dataLength := len(data)
	buffer := make([]byte, dataLength)
	stream := cipher.NewCBCDecrypter(block, iv)
	stream.CryptBlocks(buffer, data)
	paddingLength := buffer[dataLength-1]
	raw_length := dataLength - int(paddingLength)
	return buffer[:raw_length], raw_length, nil
}

func base64_decode(text string) ([]byte, error) {
	bytes, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func hmac256_digest(data []byte, key []byte) ([]byte, error) {
	hmac := hmac.New(sha256.New, key)
	_, err := hmac.Write(data)
	if err != nil {
		return nil, err
	}
	return hmac.Sum(nil), nil
}

func generate_key(nonce []byte) ([]byte, error) {
	key := make([]byte, 16)
	var err error
	for i := 0; i < 50000; i++ {
		nonce, err = hmac256_digest(nonce, HMAC_KEY)
		if err != nil {
			return nil, err
		}
		for j := 0; j < 16; j++ {
			key[j] ^= nonce[j]
		}
	}
	return key, nil
}

func slice_equal(s1 []byte, s2 []byte) bool {
	length := len(s1)
	if length != len(s2) {
		return false
	}
	for i := 0; i < length; i++ {
		if s1[i] != s2[i] {
			return false
		}
	}
	return true
}

func decrypt_note(content string) (string, error) {
	decoded_content, err := base64_decode(content)
	decoded_content_length := len(decoded_content)
	if err != nil {
		return "", err
	}
	reader := bytes.NewReader(decoded_content)
	signature := make([]byte, 4)
	reader.Read(signature)
	if string(signature) != "ENC0" {
		return "", errors.New("signature verification failed")
	}
	nonce1 := make([]byte, 16)
	reader.Read(nonce1)
	nonce1 = append(nonce1, 0, 0, 0, 1)
	key1, err := generate_key(nonce1)
	if err != nil {
		return "", err
	}
	nonce2 := make([]byte, 16)
	reader.Read(nonce2)
	nonce2 = append(nonce2, 0, 0, 0, 1)
	key2, err := generate_key(nonce2)
	if err != nil {
		return "", err
	}
	iv := make([]byte, 16)
	reader.Read(iv)
	encrypted_data := make([]byte, decoded_content_length-4-16*5)
	reader.Read(encrypted_data)
	hash := make([]byte, 32)
	reader.Read(hash)
	computed_hash, err := hmac256_digest(decoded_content[:decoded_content_length-32], key2)
	if err != nil {
		return "", err
	}
	if !slice_equal(computed_hash, hash) {
		return "", errors.New("hash verification failed")
	}
	raw_data, raw_data_length, err := aes_cbc_decrypt(key1, iv, encrypted_data)
	if err != nil {
		return "", err
	}
	return string(raw_data[:raw_data_length-1]), nil
}

func decrypt_file(filepath string, savepath string) error {
	fmt.Printf("Decrypting file: %s\n", filepath)
	infile, err := os.OpenFile(filepath, os.O_RDONLY, 0666)
	if err != nil {
		return err
	}
	defer infile.Close()
	doc, err := xmlquery.Parse(infile)
	if err != nil {
		return err
	}
	ch := make(chan DecryptResult, 1)
	var wg sync.WaitGroup
	for _, noteNode := range xmlquery.Find(doc, "//en-export/note") {
		title := noteNode.SelectElement("title").InnerText()
		contentNode := noteNode.SelectElement("content")
		if contentNode.SelectAttr("encoding") == "base64:aes" {
			wg.Add(1)
			go func() {
				fmt.Printf("Decrypting note: %s\n", title)
				raw_text, err := decrypt_note(contentNode.InnerText())
				if err != nil {
					ch <- DecryptResult{err: err, text: "", node: noteNode}
				} else {
					ch <- DecryptResult{err: nil, text: raw_text, node: noteNode}
				}
				wg.Done()
			}()
		}
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
	for result := range ch {
		noteNode := result.node
		if result.err != nil {
			fmt.Printf("Note decryption failed, error: %s\n", result.err.Error())
		} else {
			contentNode := noteNode.SelectElement("content")
			contentNode.FirstChild.Data = result.text
			contentNode.RemoveAttr("encoding")
		}
	}

	outfile, err := os.OpenFile(savepath, os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	_, err = outfile.WriteString(doc.OutputXML(true))
	if err != nil {
		return err
	}
	outfile.Close()
	fmt.Printf("File has been saved to %s\n", savepath)
	return nil
}
func print_help_text() {
	fmt.Println("go run yinxiangbijidecrypt.go <filepath|directory>")
}

func main() {
	if len(os.Args) <= 1 {
		print_help_text()
		return
	}
	path := os.Args[1]
	states, err := os.Stat(path)

	if err != nil {
		abs_path, _ := filepath.Abs(path)
		fmt.Printf("Path %s not exists\n", abs_path)
		return
	}
	if states.IsDir() {
		filepath.Walk(path, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".notes") {
				err = decrypt_file(path, change_extension(path, ".enex"))
				if err != nil {
					fmt.Println(err.Error())
				}
			}
			return nil
		})
	} else {
		err = decrypt_file(path, change_extension(path, ".enex"))
		if err != nil {
			fmt.Println(err.Error())
		}
	}
}
