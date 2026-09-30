// The hello program is a test input for shotizam.
package main

import (
	"fmt"
	"os"
)

// Greeter is a named type that shotizam should find a type descriptor for.
type Greeter struct {
	Name  string `json:"name"`
	Count int
}

//go:noinline
func (g *Greeter) Greet() string {
	return fmt.Sprintf("hello, %s (%d)", g.Name, g.Count)
}

type stringer struct{ g *Greeter }

//go:noinline
func (s stringer) String() string { return s.g.Greet() }

var stringers = map[string]func(*Greeter) fmt.Stringer{
	"a": func(g *Greeter) fmt.Stringer { return stringer{g} },
}

func main() {
	g := &Greeter{Name: os.Args[0], Count: len(os.Args)}
	s := stringers[os.Getenv("SHOTIZAM_KEY")]
	if s != nil {
		fmt.Println(s(g), "shotizam-test-string-literal")
	}
	fmt.Println(g)
}
