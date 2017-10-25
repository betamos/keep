package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/betamos/clui"
	"github.com/fatih/color"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"os"
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
	// flag.BoolVar(&encrypt, "encrypt", false, "Encrypt a file")
	// flag.BoolVar(&decrypt, "decrypt", false, "Decrypt a file")
	flag.BoolVar(&delete, "d", false, "Delete the original file")
	flag.Usage = usage
}

func main() {
	// TODO: Inject encrypted magic number in order to reject bad passwords
	flag.Parse()
	if flag.NArg() != 1 {
		usage()
		os.Exit(2)
	}
	var (
		infilePath      = flag.Arg(0)
		outfilePath     string
		infile, outfile *os.File
		in              *bufio.Reader
		out             *bufio.Writer
		d               op // encrypt or decrypt, change op to the var name
		status          string
		err             error
		fileSize        int64
	)
	if infile, err = os.Open(infilePath); err != nil {
		log.Fatalf("could not open %v: %v\n", infilePath, err)
	}
	stat, err := infile.Stat()
	fileSize = stat.Size()
	in = bufio.NewReader(infile)
	if readSignature(in) { // encrypted file
		d = decrypt
		outfilePath = strings.TrimSuffix(infilePath, ".keep")
		if outfilePath == infilePath {
			outfilePath += ".unkeep" // TODO: Tmp file with prefix?
		}
		status = "decrypting"
	} else {
		d = encrypt
		outfilePath = infilePath + ".keep"
		status = "encrypting"
	}
	passphrase := promptPassphrase()

	overwrite := true
	if _, err := os.Stat(outfilePath); os.IsNotExist(err) {
		overwrite = false
	}

	outfile, err = os.Create(outfilePath)
	if err != nil {
		log.Fatalln(err)
	}
	// Out buffer
	out = bufio.NewWriter(outfile)
	task := clui.NewTask(status)
	if d == encrypt {
		writeSignature(out)
	}
	if err = encryptOrDecrypt(d, passphrase, in, out, fileSize); err != nil {
		task.Fail(err.Error())
		os.Exit(1)
	}
	task.Success(status)
	if overwrite {
		color.Yellow("~ " + outfilePath)
	} else {
		color.Green("+ " + outfilePath)
	}
	if delete {
		if err = os.Remove(infilePath); err != nil {
			log.Fatalln(err)
		}
		color.Red("- " + infilePath)
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
