package main

import (
	"reflect"
	"sort"
	"testing"
)

func byName(d FileDump) map[string]Object {
	m := map[string]Object{}
	for _, o := range d.Objects {
		m[o.Kind+":"+o.Receiver+":"+o.Name] = o
	}
	return m
}

func TestDumpDeclarations(t *testing.T) {
	d := dump("testdata/sample.go")
	if d.Error != "" {
		t.Fatal(d.Error)
	}
	var got []string
	for k := range byName(d) {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{
		"const::Alpha", "const::Beta", "const::Solo", "var::Gamma",
		"interface::Store", "struct::Box", "type::Alias", "type::Number",
		"struct::NoopSink", "method:NoopSink:RecordTrace", "method:Box:Put",
		"func::Handle", "func::Shadow", "func::Generic", "func::Identity",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("objects\n got %v\nwant %v", got, want)
	}
}

func TestDumpImportsAndDocs(t *testing.T) {
	d := dump("testdata/sample.go")
	wantImports := map[string]string{
		"cab": "example.com/x/cabinet", "fmt": "fmt", "http": "net/http",
		"lib": "example.com/x/lib/v2", "yaml": "gopkg.in/yaml.v3",
	}
	if !reflect.DeepEqual(d.Imports, wantImports) {
		t.Errorf("imports %v", d.Imports)
	}
	if d.PackageDoc == "" || d.Package != "sample" {
		t.Errorf("package %q doc %q", d.Package, d.PackageDoc)
	}
	if got := byName(d)["const::Alpha"].Doc; got != "Alpha is the first." {
		t.Errorf("grouped const doc %q", got)
	}
}

func TestInterfaceMethodsExportedOnly(t *testing.T) {
	st := byName(dump("testdata/sample.go"))["interface::Store"]
	if !reflect.DeepEqual(st.Methods, []string{"Get", "Put"}) {
		t.Errorf("methods %v", st.Methods)
	}
}

func TestCallResolution(t *testing.T) {
	h := byName(dump("testdata/sample.go"))["func::Handle"]
	want := []Call{
		{Pkg: "cab", Type: "Cabinet", Name: "Set"}, // typed through the parameter
		{Pkg: "http", Type: "Client", Name: "Do"},  // typed through "var cl http.Client"
		{Type: "Box", Name: "Put"},                 // typed through "s := &Box[int]{}"
		{Pkg: "yaml", Name: "Unmarshal"},
		{Pkg: "lib", Name: "Run"},
		{Pkg: "fmt", Name: "Println"},
	}
	if !reflect.DeepEqual(h.Calls, want) {
		t.Errorf("calls\n got %v\nwant %v", h.Calls, want)
	}
}

func TestShadowedImportIsNotAReference(t *testing.T) {
	s := byName(dump("testdata/sample.go"))["func::Shadow"]
	if len(s.Refs) != 0 {
		t.Errorf("a local variable named like an import produced refs %v", s.Refs)
	}
}

func TestGenericCallUnwrapped(t *testing.T) {
	g := byName(dump("testdata/sample.go"))["func::Generic"]
	if !reflect.DeepEqual(g.Calls, []Call{{Name: "Identity"}}) {
		t.Errorf("calls %v", g.Calls)
	}
}

func TestSyntaxErrorIsReportedNotFatal(t *testing.T) {
	d := dump("testdata/broken.go.txt")
	if d.Error == "" {
		t.Error("expected a parse error for a file that is not Go")
	}
}
