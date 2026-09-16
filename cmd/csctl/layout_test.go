// Enforces the declaration order CONTRIBUTING.md numbers under File Layout, on every .go file in the module.
//
//	decl, parsed, index
//	isFunc, exported, recvName
//	parseAll, buildIndex
//	check*
//	TestLayout
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type decl struct {
	name  string
	kind  string
	recv  string
	order int
}

type parsed struct {
	path      string
	doc       string
	decls     []decl
	uses      map[string][]string
	firstFunc int
}

type index struct {
	parsed
	at     map[string]int
	count  map[string]int
	listed map[string]int
	stale  []string
}

func (d decl) isFunc() bool { return d.kind == "func" || d.kind == "method" }

func (d decl) exported() bool {
	if d.kind == "method" {
		return ast.IsExported(d.recv)
	}
	return ast.IsExported(d.name)
}

func recvName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.StarExpr:
		return recvName(e.X)
	case *ast.Ident:
		return e.Name
	case *ast.IndexExpr:
		return recvName(e.X)
	}
	return ""
}

func parseAll(t *testing.T) []parsed {
	t.Helper()
	var out []parsed
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		p := parsed{path: path, uses: map[string][]string{}, firstFunc: -1}
		if f.Doc == nil {
			t.Errorf("%s: rule 1: no doc comment is attached to the package clause", path)
		} else {
			p.doc = f.Doc.Text()
		}
		for i, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				k, recv := "func", ""
				if d.Recv != nil && len(d.Recv.List) > 0 {
					k, recv = "method", recvName(d.Recv.List[0].Type)
				}
				p.decls = append(p.decls, decl{name: d.Name.Name, kind: k, recv: recv, order: i})
				if p.firstFunc < 0 {
					p.firstFunc = i
				}
				var collect func(ast.Node) bool
				collect = func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.SelectorExpr:
						ast.Inspect(n.X, collect)
						return false
					case *ast.Ident:
						p.uses[d.Name.Name] = append(p.uses[d.Name.Name], n.Name)
					}
					return true
				}
				ast.Inspect(d.Body, collect)
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						p.decls = append(p.decls, decl{name: s.Name.Name, kind: "type", order: i})
					case *ast.ValueSpec:
						for _, n := range s.Names {
							p.decls = append(p.decls, decl{name: n.Name, kind: d.Tok.String(), order: i})
						}
					}
				}
			}
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func buildIndex(p parsed) index {
	x := index{parsed: p, at: map[string]int{}, count: map[string]int{}}
	var names []string
	for _, d := range p.decls {
		x.count[d.name]++
		if _, dup := x.at[d.name]; !dup || d.kind != "method" {
			x.at[d.name] = d.order
		}
		names = append(names, d.name)
		if d.recv != "" {
			names = append(names, d.recv)
		}
	}
	var stale []string
	covers := func(tok string) []string {
		if prefix, star := strings.CutSuffix(tok, "*"); star {
			var out []string
			for _, n := range names {
				if strings.HasPrefix(n, prefix) {
					out = append(out, n)
				}
			}
			return out
		}
		if slices.Contains(names, tok) {
			return []string{tok}
		}
		return nil
	}
	listed, pos := map[string]int{}, 0
	for _, line := range strings.Split(p.doc, "\n") {
		if !strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\t ") {
			continue
		}
		names, _, _ := strings.Cut(strings.TrimSpace(line), "  ")
		for _, tok := range strings.FieldsFunc(names, func(r rune) bool { return r == ' ' || r == ',' }) {
			hit := covers(tok)
			if hit == nil {
				stale = append(stale, tok)
				continue
			}
			for _, n := range hit {
				if _, dup := listed[n]; !dup {
					listed[n] = pos
				}
			}
			pos++
		}
	}
	x.listed, x.stale = listed, stale
	return x
}

func (x index) checkNames(t *testing.T) {
	for _, name := range x.stale {
		t.Errorf("%s: rule 7: the outline has an entry for %q, which the file does not declare", x.path, name)
	}
	for _, d := range x.decls {
		if d.name == "_" || d.kind == "const" || d.kind == "var" {
			continue
		}
		named := d.name
		if d.kind == "method" {
			named = d.recv
		}
		if _, ok := x.listed[named]; !ok {
			t.Errorf("%s: rule 1: %s %q is not named in the file's outline", x.path, d.kind, named)
		}
	}
}

func (x index) checkMethods(t *testing.T) {
	for _, d := range x.decls {
		if d.name == "_" || d.kind != "method" {
			continue
		}
		if o, ok := x.at[d.recv]; ok && d.order < o {
			t.Errorf("%s: rule 3: method %q is declared above its type %q", x.path, d.name, d.recv)
		}
	}
}

func (x index) checkHoisting(t *testing.T) {
	for _, d := range x.decls {
		if d.name == "_" || d.isFunc() {
			continue
		}
		users := 0
		for _, ids := range x.uses {
			if slices.Contains(ids, d.name) {
				users++
			}
		}
		if users >= 2 && d.order > x.firstFunc {
			t.Errorf("%s: rule 2: %s %q has %d users, so it belongs above the first function",
				x.path, d.kind, d.name, users)
		}
	}
}

func (x index) checkOutlineOrder(t *testing.T) {
	seen := map[string]bool{}
	last, lastName := -1, ""
	for _, d := range x.decls {
		if d.kind == "const" || d.kind == "var" {
			continue
		}
		name := d.name
		if _, ok := x.listed[name]; !ok && d.kind == "method" {
			name = d.recv
		}
		pos, ok := x.listed[name]
		if !ok || seen[name] {
			continue
		}
		seen[name] = true
		if pos < last {
			t.Errorf("%s: rule 6: the outline lists %q before %q, but the file declares it after",
				x.path, name, lastName)
		}
		last, lastName = pos, name
	}
}

func (x index) checkDeclOrder(t *testing.T) {
	firstExported := -1
	for _, d := range x.decls {
		if !d.isFunc() {
			continue
		}
		switch {
		case d.exported() && firstExported < 0:
			firstExported = d.order
		case !d.exported() && firstExported >= 0:
			t.Errorf("%s: rule 4: unexported %q is declared below an exported function", x.path, d.name)
		}
		for _, used := range x.uses[d.name] {
			if o, ok := x.at[used]; ok && x.count[used] == 1 && used != d.name && o > d.order {
				t.Errorf("%s: rule 5: %q calls %q, which is declared below it", x.path, d.name, used)
			}
		}
	}
}

func TestLayout(t *testing.T) {
	for _, p := range parseAll(t) {
		x := buildIndex(p)
		x.checkNames(t)
		x.checkMethods(t)
		x.checkHoisting(t)
		x.checkOutlineOrder(t)
		x.checkDeclOrder(t)
	}
}
