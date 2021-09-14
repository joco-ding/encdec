package controllers

import (
	"bufio"
	"encdec/lib/stores"
	"encdec/lib/utils"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func RunApp() {
	var fname string
	args := os.Args[1:]
	jumargs := len(args)
	if jumargs == 3 && args[0] == "decrypt" {
		stores.Config.KeyString = args[1]
		content, err := ioutil.ReadFile(args[2])
		if err != nil {
			log.Fatal(err)
		}
		_hasildekripsi := utils.Decrypt(string(content))
		fmt.Print(_hasildekripsi)
		return
	} else if jumargs == 1 {
		fname = args[0]
	} else {
		return
	}

	_reader := bufio.NewReader(os.Stdin)
	fmt.Print("Password: ")
	_readpwd, _err := term.ReadPassword(int(syscall.Stdin))
	if _err != nil {
		panic(_err)
	}
	fmt.Println()
	_textread := string(_readpwd)
	utils.GenKeyString(_textread)
	fmt.Print("Teks yang akan dienkripsi: ")
	_textread, _err = _reader.ReadString('\n')
	if _err != nil {
		panic(_err)
	}
	_textread = strings.Trim(_textread, " \n")
	_hasilenkripsi := utils.Encrypt(_textread)
	d1 := []byte(_hasilenkripsi)
	_err = os.WriteFile(fname, d1, 0644)
	if _err != nil {
		panic(_err)
	}
	_hasildekripsi := utils.Decrypt(_hasilenkripsi)
	fmt.Println(_hasildekripsi)
}
