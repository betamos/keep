package main

import (
	"flag"
	"fmt"
	"github.com/betamos/clui"
	"github.com/fatih/color"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var delete bool

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  keep [-d] FILE\n")
	fmt.Fprintf(os.Stderr, "  keep [-d] FILE.keep\n\n")
	flag.PrintDefaults()
}

func init() {
	// TODO: Add -o for outfile
	// TODO: Clever flags for enforcing mode when file names are not conventional?
	// Or simply use the magic header to decide mode?
	// flag.BoolVar(&encrypt, "encrypt", false, "Encrypt a file")
	// flag.BoolVar(&decrypt, "decrypt", false, "Decrypt a file")
	flag.BoolVar(&delete, "d", false, "Delete the original file")
	flag.Usage = usage
}

func main() {
	// TODO: Inject encrypted magic number in order to reject bad passwords
	// TOOD: Inject file header identifier to automatically detect if already encrypted
	flag.Parse()
	if encrypt == decrypt || flag.NArg() != 1 {
		usage()
		os.Exit(2)
	}
	infile := flag.Arg(0)
	if _, err := os.Stat(infile); os.IsNotExist(err) {
		log.Fatalf("%v does not exist\n", infile)
	}
	outfile := infile + ".keep"
	status := "encrypting"
	d := encrypt
	if filepath.Ext(infile) == ".keep" {
		//mode = decrypt
		outfile = strings.TrimSuffix(infile, ".keep")
		status = "decrypting"
		d = decrypt
	}
	passphrase := promptPassphrase()

	overwrite := true
	if _, err := os.Stat(outfile); os.IsNotExist(err) {
		overwrite = false
	}
	task := clui.NewTask(status)
	if err := encryptOrDecrypt(d, passphrase, infile, outfile); err != nil {
		task.Fail(err.Error())
		log.Fatalln()
	}
	task.Success(status)
	if overwrite {
		color.Yellow("~ " + outfile)
	} else {
		color.Green("+ " + outfile)
	}
	if delete {
		if err := os.Remove(infile); err != nil {
			log.Fatalln(err)
		}
		color.Red("- " + infile)
	}

}

func promptPassphrase() string {
	fmt.Print("passphrase: ")
	pass, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		color.Red("✘")
		log.Fatalln(err)
	}
	color.Green("✔")
	return string(pass)
}
