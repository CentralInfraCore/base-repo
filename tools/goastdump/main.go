// goastdump parses Go source files with go/parser and prints their top-level
// declarations as JSON. It is the syntactic front end of tools/go.meta.gen.py:
// the Python side decides what counts as an external reference and writes the
// companion YAML, this tool only reports what the Go syntax tree says.
//
// Usage: goastdump <file.go> [<file.go> ...]
//
// Only the standard library is used and no type checking happens, so it runs
// offline and without the dependencies of the code it reads. A call receiver is
// resolved to a type only where the syntax states it (parameter, receiver,
// "var x T", "x := T{}" / "x := &T{}"); everything else stays untyped.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Ref is a selector on an imported package alias: Pkg.Name.
type Ref struct {
	Pkg  string `json:"pkg"`
	Name string `json:"name"`
}

// Call is an exported function or method call. Pkg is set for a call through an
// import alias or a receiver typed by one; Type is set when the receiver type is
// known (local or imported); both empty means the receiver could not be typed.
type Call struct {
	Pkg  string `json:"pkg,omitempty"`
	Type string `json:"type,omitempty"`
	Name string `json:"name"`
}

// Object is one top-level declaration.
type Object struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"` // struct interface type func method var const
	Receiver string   `json:"receiver,omitempty"`
	Doc      string   `json:"doc"`
	Refs     []Ref    `json:"refs"`
	Calls    []Call   `json:"calls"`
	Methods  []string `json:"methods,omitempty"` // interface only: exported method names
}

// FileDump is the result for one input file.
type FileDump struct {
	File       string            `json:"file"`
	Package    string            `json:"package"`
	PackageDoc string            `json:"package_doc"`
	Imports    map[string]string `json:"imports"` // alias -> import path
	Objects    []Object          `json:"objects"`
	Error      string            `json:"error,omitempty"`
}

var (
	reMajor   = regexp.MustCompile(`^v[0-9]+$`)
	reDotVer  = regexp.MustCompile(`\.v[0-9]+$`)
	spaceRuns = regexp.MustCompile(`\s+`)
)

// guessPkgName derives the default package name from an import path. Without
// type information the declared name is unknown, so the usual conventions are
// applied: "…/yaml.v3" -> yaml, "…/foo/v2" -> foo, otherwise the last element.
func guessPkgName(p string) string {
	elems := strings.Split(p, "/")
	last := elems[len(elems)-1]
	if reMajor.MatchString(last) && len(elems) > 1 {
		last = elems[len(elems)-2]
	}
	return reDotVer.ReplaceAllString(last, "")
}

func docText(g *ast.CommentGroup) string {
	if g == nil {
		return ""
	}
	return strings.TrimSpace(spaceRuns.ReplaceAllString(g.Text(), " "))
}

type fileCtx struct {
	imports map[string]string
}

// isImport reports whether id names an imported package: its alias is imported
// and the parser did not resolve it to a local declaration (a local variable
// called like an import shadows it).
func (c *fileCtx) isImport(id *ast.Ident) bool {
	if id.Obj != nil { //nolint:staticcheck // Obj is the parser's own scope resolution
		return false
	}
	_, ok := c.imports[id.Name]
	return ok
}

// typeName names the type an expression denotes, if it is a plain named type.
func (c *fileCtx) typeName(t ast.Expr) (pkg, name string, ok bool) {
	switch x := t.(type) {
	case *ast.StarExpr:
		return c.typeName(x.X)
	case *ast.ParenExpr:
		return c.typeName(x.X)
	case *ast.IndexExpr:
		return c.typeName(x.X)
	case *ast.IndexListExpr:
		return c.typeName(x.X)
	case *ast.SelectorExpr:
		if id, isID := x.X.(*ast.Ident); isID && c.isImport(id) {
			return id.Name, x.Sel.Name, true
		}
	case *ast.Ident:
		if types.Universe.Lookup(x.Name) != nil {
			return "", "", false
		}
		return "", x.Name, true
	}
	return "", "", false
}

// exprType resolves the type of the few initializer shapes that state it.
func (c *fileCtx) exprType(e ast.Expr) (pkg, name string, ok bool) {
	switch x := e.(type) {
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return c.exprType(x.X)
		}
	case *ast.ParenExpr:
		return c.exprType(x.X)
	case *ast.CompositeLit:
		if x.Type != nil {
			return c.typeName(x.Type)
		}
	case *ast.CallExpr:
		if f, isID := x.Fun.(*ast.Ident); isID && f.Name == "new" && len(x.Args) == 1 {
			return c.typeName(x.Args[0])
		}
	}
	return "", "", false
}

// identType resolves a local identifier to its declared type through the
// parser's scope resolution.
func (c *fileCtx) identType(id *ast.Ident) (pkg, name string, ok bool) {
	if id.Obj == nil { //nolint:staticcheck
		return "", "", false
	}
	switch d := id.Obj.Decl.(type) { //nolint:staticcheck
	case *ast.Field:
		return c.typeName(d.Type)
	case *ast.ValueSpec:
		if d.Type != nil {
			return c.typeName(d.Type)
		}
		for i, n := range d.Names {
			if n.Name == id.Name && len(d.Names) == len(d.Values) {
				return c.exprType(d.Values[i])
			}
		}
	case *ast.AssignStmt:
		if len(d.Lhs) != len(d.Rhs) {
			return "", "", false
		}
		for i, l := range d.Lhs {
			if li, isID := l.(*ast.Ident); isID && li.Name == id.Name {
				return c.exprType(d.Rhs[i])
			}
		}
	}
	return "", "", false
}

func exported(name string) bool { return ast.IsExported(name) }

// collector gathers refs and calls from a subtree, first occurrence order,
// without duplicates.
type collector struct {
	ctx      *fileCtx
	refs     []Ref
	calls    []Call
	seenRef  map[Ref]bool
	seenCall map[Call]bool
}

func newCollector(c *fileCtx) *collector {
	return &collector{ctx: c, refs: []Ref{}, calls: []Call{}, seenRef: map[Ref]bool{}, seenCall: map[Call]bool{}}
}

func (k *collector) addCall(c Call) {
	if !k.seenCall[c] {
		k.seenCall[c] = true
		k.calls = append(k.calls, c)
	}
}

func (k *collector) visit(n ast.Node) {
	if n == nil {
		return
	}
	ast.Inspect(n, func(nd ast.Node) bool {
		switch x := nd.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && k.ctx.isImport(id) {
				r := Ref{Pkg: id.Name, Name: x.Sel.Name}
				if !k.seenRef[r] {
					k.seenRef[r] = true
					k.refs = append(k.refs, r)
				}
			}
		case *ast.CallExpr:
			k.call(x)
		}
		return true
	})
}

func (k *collector) call(x *ast.CallExpr) {
	fun := x.Fun
	for { // F[T](…) -> F
		switch g := fun.(type) {
		case *ast.IndexExpr:
			fun = g.X
			continue
		case *ast.IndexListExpr:
			fun = g.X
			continue
		case *ast.ParenExpr:
			fun = g.X
			continue
		}
		break
	}
	switch f := fun.(type) {
	case *ast.Ident:
		if exported(f.Name) {
			k.addCall(Call{Name: f.Name})
		}
	case *ast.SelectorExpr:
		if !exported(f.Sel.Name) {
			return
		}
		id, ok := f.X.(*ast.Ident)
		if !ok {
			k.addCall(Call{Name: f.Sel.Name})
			return
		}
		if k.ctx.isImport(id) {
			k.addCall(Call{Pkg: id.Name, Name: f.Sel.Name})
			return
		}
		if pkg, typ, typed := k.ctx.identType(id); typed {
			k.addCall(Call{Pkg: pkg, Type: typ, Name: f.Sel.Name})
			return
		}
		k.addCall(Call{Name: f.Sel.Name})
	}
}

func recvTypeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(x.X)
	case *ast.ParenExpr:
		return recvTypeName(x.X)
	case *ast.IndexExpr:
		return recvTypeName(x.X)
	case *ast.IndexListExpr:
		return recvTypeName(x.X)
	case *ast.Ident:
		return x.Name
	}
	return ""
}

func (c *fileCtx) typeObject(name string, doc string, t ast.Expr) Object {
	k := newCollector(c)
	k.visit(t)
	o := Object{Name: name, Doc: doc, Refs: k.refs, Calls: []Call{}}
	switch it := t.(type) {
	case *ast.StructType:
		o.Kind = "struct"
	case *ast.InterfaceType:
		o.Kind = "interface"
		names := map[string]bool{}
		for _, m := range it.Methods.List {
			if _, isFn := m.Type.(*ast.FuncType); isFn {
				for _, n := range m.Names {
					if exported(n.Name) {
						names[n.Name] = true
					}
				}
			}
		}
		o.Methods = make([]string, 0, len(names))
		for n := range names {
			o.Methods = append(o.Methods, n)
		}
		sort.Strings(o.Methods)
	default:
		o.Kind = "type"
	}
	return o
}

func dump(path string) FileDump {
	d := FileDump{File: path, Imports: map[string]string{}, Objects: []Object{}}
	fset := token.NewFileSet()
	af, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		d.Error = err.Error()
		return d
	}
	d.Package = af.Name.Name
	d.PackageDoc = docText(af.Doc)

	ctx := &fileCtx{imports: map[string]string{}}
	for _, is := range af.Imports {
		p, err := strconv.Unquote(is.Path.Value)
		if err != nil {
			continue
		}
		alias := guessPkgName(p)
		if is.Name != nil {
			if is.Name.Name == "_" || is.Name.Name == "." {
				continue
			}
			alias = is.Name.Name
		}
		ctx.imports[alias] = p
		d.Imports[alias] = p
	}

	for _, decl := range af.Decls {
		switch x := decl.(type) {
		case *ast.FuncDecl:
			k := newCollector(ctx)
			k.visit(x.Type)
			if x.Recv != nil {
				k.visit(x.Recv)
			}
			if x.Body != nil {
				k.visit(x.Body)
			}
			o := Object{Name: x.Name.Name, Kind: "func", Doc: docText(x.Doc), Refs: k.refs, Calls: k.calls}
			if x.Recv != nil && len(x.Recv.List) == 1 {
				if r := recvTypeName(x.Recv.List[0].Type); r != "" {
					o.Kind = "method"
					o.Receiver = r
				}
			}
			d.Objects = append(d.Objects, o)
		case *ast.GenDecl:
			for _, spec := range x.Specs {
				doc := ""
				switch y := spec.(type) {
				case *ast.TypeSpec:
					doc = docText(y.Doc)
					if doc == "" && !x.Lparen.IsValid() {
						doc = docText(x.Doc)
					}
					d.Objects = append(d.Objects, ctx.typeObject(y.Name.Name, doc, y.Type))
				case *ast.ValueSpec:
					doc = docText(y.Doc)
					if doc == "" && !x.Lparen.IsValid() {
						doc = docText(x.Doc)
					}
					kind := "var"
					if x.Tok == token.CONST {
						kind = "const"
					}
					for _, n := range y.Names {
						if n.Name == "_" {
							continue
						}
						d.Objects = append(d.Objects, Object{Name: n.Name, Kind: kind, Doc: doc, Refs: []Ref{}, Calls: []Call{}})
					}
				}
			}
		}
	}
	return d
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: goastdump <file.go> [<file.go> ...]")
		os.Exit(2)
	}
	out := struct {
		Files []FileDump `json:"files"`
	}{Files: []FileDump{}}
	for _, p := range os.Args[1:] {
		out.Files = append(out.Files, dump(p))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
