// genrotor project main.go
package main

import (
	cRand "crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	mRand "math/rand"
	"os"
	"strings"

	"github.com/bgallie/jc1"
	"github.com/bgallie/tnt2/cryptors"
	"github.com/bgallie/tnt2/cryptors/bitops"
	"github.com/bgallie/tnt2/cryptors/permutator"
	"github.com/bgallie/tnt2/cryptors/rotor"
	"github.com/bgallie/utilities"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	rotorSizes             []int
	rotorSizesIndex        int
	cycleSizes             []int
	key                    *jc1.UberJc1
	rRead                  func([]byte) (n int, err error)
	rInt                   func(int64) int64
	outputFileName         string
	r1, r2, r3, r4, r5, r6 *rotor.Rotor
	p1, p2                 *permutator.Permutator
	rotor1                 = new(rotor.Rotor)
	rotor2                 = new(rotor.Rotor)
	rotor3                 = new(rotor.Rotor)
	rotor4                 = new(rotor.Rotor)
	rotor5                 = new(rotor.Rotor)
	rotor6                 = new(rotor.Rotor)
	permutator1            = new(permutator.Permutator)
	permutator2            = new(permutator.Permutator)
	proFormaMachine        = []cryptors.Crypter{rotor1, rotor2, permutator1, rotor3, rotor4, permutator2, rotor5, rotor6}
	un                     = utilities.Un
	trace                  = utilities.Trace
	deferClose             = utilities.DeferClose
	checkFatal             = utilities.CheckFatal
	turnOffLogging         = utilities.TurnOffLogging
	turnOnLogging          = utilities.TurnOnLogging
	truelyRandom           = false
	rCnt                   = 0
	pCnt                   = 0
	outputFile             = os.Stdout
)

func init() {
	var secret string
	var exists bool

	flag.StringVar(&outputFileName, "outputFile", "", "output file name")
	flag.StringVar(&outputFileName, "of", "", "output file name (shorthand)")
	flag.Parse()

	if flag.NArg() == 0 {
		secret, exists = os.LookupEnv("tnt2Secret")
		if !exists {
			// fmt.Fprintf(os.Stderr, "IsTerminal: %s\n", terminal.IsTerminal(int(os.Stdin.Fd())))
			if terminal.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprintf(os.Stderr, "Enter the passphrase: ")
				byteSecret, err := terminal.ReadPassword(int(os.Stdin.Fd()))
				checkFatal(err)
				fmt.Fprintln(os.Stderr, "")
				secret = string(byteSecret)
				// fmt.Fprintf(os.Stderr, "The entered password is \"%s\"\n", secret)
			} else {
				fmt.Fprintln(os.Stderr, "Generating truly random rotors and permutators.")
				truelyRandom = true
			}
		}
	} else {
		secret = strings.Join(flag.Args(), " ")
	}

	// Define rRead and rInt based on weither we are generating a cryptographically
	// strong set of rotors and permatators
	if truelyRandom {
		bKey := make([]byte, 32, 32)
		_, err := cRand.Read(bKey)
		checkFatal(err)
		// Seed the uberJc1 function with a cyptographically strong sequence of bytes
		key = jc1.NewUberJc1(bKey)
		// Define rRead and rInt to use the crypto/rand based functions.
		rRead = cRand.Read
		rInt = cInt
	} else {
		// Seed the uberJc1 function with the given secret.
		key = jc1.NewUberJc1([]byte(secret))
		// Seed the math.Rand function iwht an integer generated from uberJc1
		// and define rRead and rInt to use the math/rand based fucntions.
		mRand.Seed(key.Int64())
		rRead = mRand.Read
		rInt = mRand.Int63n
	}

	// rotoSizes is an array of possible rotor sizes.  It consists of prime
	// numbers less than 2048 to allow for 256 bit splce at the end of the rotor.
	// The rotor sizes selected from this list will maximizes the number of
	// unique states the rotors can take.
	rotorSizes = []int{
		1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733,
		1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789}

	// Define a random order of rotor sizes based on the key.
	rotorSizesPerm := perm(len(rotorSizes))

	for i, val := range rotorSizesPerm {
		rotorSizesPerm[i] = rotorSizes[val]
	}

	rotorSizes = rotorSizesPerm

	// Define a random order of cycle sizes based on the key.
	cycleSizes = perm(len(cryptors.CycleSizes))
}

func cInt(n int64) int64 {
	max := big.NewInt(n)
	j, err := cRand.Int(cRand.Reader, max)
	checkFatal(err)
	return j.Int64()
}

func perm(n int) []int {
	res := make([]int, n, n)

	for i := range res {
		res[i] = i
	}

	for i := (n - 1); i > 0; i-- {
		j := rInt(int64(i))
		res[i], res[j] = res[j], res[i]
	}

	return res
}

func randP() []byte {
	res := make([]byte, 256, 256)

	for i := range res {
		res[i] = byte(i)
	}

	for i := (256 - 1); i > 0; i-- {
		j := int(rInt(int64(i)))
		res[i], res[j] = res[j], res[i]
	}

	return res
}

func updateRotor(r *rotor.Rotor) {
	r.Size = rotorSizes[rCnt]
	r.Start = int(rInt(int64(r.Size)))
	r.Current = r.Start
	r.Step = int(rInt(int64(r.Size)))
	size := (r.Size/8 + 1)
	r.Rotor = make([]byte, size+32, size+32)
	size, err := rRead(r.Rotor)
	checkFatal(err)

	//Slice the first 256 bits of the rotor to the end of the rotor
	var j = r.Size
	for i := 0; i < 256; i++ {
		if bitops.GetBit(r.Rotor, uint(i)) {
			bitops.SetBit(r.Rotor, uint(j))
		} else {
			bitops.ClrBit(r.Rotor, uint(j))
		}
		j++
	}

	rCnt++
}

func updatePermutator(p *permutator.Permutator) {
	p.Randp = randP()
	p.Cycles = make([]permutator.Cycle, cryptors.NumberPermutationCycles)

	for i := range p.Cycles {
		p.Cycles[i].Length = cryptors.CycleSizes[cycleSizes[pCnt]][i]
		p.Cycles[i].Current = 0
		// Adjust the start to reflect the lenght of the previous cycles
		if i == 0 { // no previous cycle so start at 0
			p.Cycles[i].Start = 0
		} else {
			p.Cycles[i].Start = p.Cycles[i-1].Start + p.Cycles[i-1].Length
		}
	}

	p.CurrentState = 0
	p.MaximalStates = p.Cycles[0].Length

	for i := 1; i < len(p.Cycles); i++ {
		p.MaximalStates *= p.Cycles[i].Length
	}

	pCnt++
}

func main() {
	var err error
	// Update the rotors and permutators in a very non-linear fashion.
	for _, machine := range proFormaMachine {
		switch v := machine.(type) {
		default:
			fmt.Fprintf(os.Stderr, "Unknown machine: %v\n", v)
		case *rotor.Rotor:
			updateRotor(machine.(*rotor.Rotor))
		case *permutator.Permutator:
			updatePermutator(machine.(*permutator.Permutator))
		case *cryptors.Counter:
			machine.(*cryptors.Counter).SetIndex(big.NewInt(0))
		}
	}

	if len(outputFileName) != 0 {
		outputFile, err = os.Create(outputFileName)
		checkFatal(err)
	}

	defer deferClose("", outputFile.Close)
	jEncoder := json.NewEncoder(outputFile)
	jEncoder.SetEscapeHTML(false)

	for _, machine := range proFormaMachine {
		switch v := machine.(type) {
		default:
			fmt.Fprintf(os.Stderr, "Unknown machine: %v\n", v)
		case *rotor.Rotor:
			err = jEncoder.Encode(machine.(*rotor.Rotor))
			checkFatal(err)
		case *permutator.Permutator:
			err = jEncoder.Encode(machine.(*permutator.Permutator))
			checkFatal(err)
		}
	}

	// var r1, r2, r3, r4, r5, r6 *rotor.Rotor
	// var p1, p2 *permutator.Permutator
	// in, err := os.Open("machine.out")
	// checkFatal(err)
	// jDecoder := json.NewDecoder(in)
	// readMachine := []cryptors.Crypter{r1, r2, p1, r3, r4, p2, r5, r6}

	// for cnt, machine := range proFormaMachine {
	// 	switch v := machine.(type) {
	// 	default:
	// 		fmt.Fprintf(os.Stderr, "Unknown machine: %v\n", v)
	// 	case *rotor.Rotor:
	// 		r := new(rotor.Rotor)
	// 		err = jDecoder.Decode(&r)
	// 		checkFatal(err)
	// 		readMachine[cnt] = r
	// 	case *permutator.Permutator:
	// 		p := new(permutator.Permutator)
	// 		err = jDecoder.Decode(&p)
	// 		checkFatal(err)
	// 		readMachine[cnt] = p
	// 	}
	// }
}
