// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"strings"
)

var verifiedDeclarations = []string{
	"addrLevelEntryCounts", "addrLevelValues", "level0MaxEntries", "txEntrySize",
}

type sourcePaths []string

func (paths *sourcePaths) String() string { return strings.Join(*paths, ",") }

func (paths *sourcePaths) Set(path string) error {
	*paths = append(*paths, path)
	return nil
}

func parse(path string) *ast.File {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil,
		parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		fail("%v", err)
	}
	return file
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func syntax(node any) string {
	var output bytes.Buffer
	if err := format.Node(&output, token.NewFileSet(), node); err != nil {
		fail("%v", err)
	}
	file := token.NewFileSet().AddFile("declaration.go", -1, output.Len())
	var tokens scanner.Scanner
	tokens.Init(file, output.Bytes(), nil, 0)
	var result strings.Builder
	for {
		_, kind, literal := tokens.Scan()
		if kind == token.EOF {
			break
		}
		if kind == token.SEMICOLON {
			literal = ""
		}
		fmt.Fprintf(&result, "%d:%q\n", kind, literal)
	}
	return result.String()
}

func declarations(files ...*ast.File) map[string]any {
	result := make(map[string]any)
	for _, file := range files {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Recv == nil {
					result[decl.Name.Name] = decl
				}
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					switch spec := spec.(type) {
					case *ast.ValueSpec:
						if decl.Tok == token.CONST && len(spec.Names) == 1 && len(spec.Values) == 1 {
							result[spec.Names[0].Name] = spec
						}
					case *ast.TypeSpec:
						result[spec.Name.Name] = spec
					}
				}
			}
		}
	}
	return result
}

func compareDeclaration(original, verified any) error {
	if original == nil || verified == nil {
		return fmt.Errorf("missing declaration")
	}
	for _, decl := range []any{original, verified} {
		if function, ok := decl.(*ast.FuncDecl); ok {
			var parameters []*ast.Field
			for _, parameter := range function.Type.Params.List {
				if len(parameter.Names) == 0 {
					parameters = append(parameters, parameter)
				}
				for _, name := range parameter.Names {
					parameters = append(parameters, &ast.Field{
						Names: []*ast.Ident{name}, Type: parameter.Type,
					})
				}
			}
			function.Type.Params.List = parameters
		}
	}
	if function, ok := verified.(*ast.FuncDecl); ok && function.Type.Results != nil {
		var results []*ast.Field
		for _, result := range function.Type.Results.List {
			for _, name := range result.Names {
				used := false
				ast.Inspect(function.Body, func(node ast.Node) bool {
					if id, ok := node.(*ast.Ident); ok && id.Name == name.Name {
						used = true
					}
					return true
				})
				if used {
					return fmt.Errorf("result name %s occurs in the function body", name.Name)
				}
			}
			for i := 0; i < max(1, len(result.Names)); i++ {
				results = append(results, &ast.Field{Type: result.Type})
			}
		}
		function.Type.Results.List = results
	}
	if syntax(original) != syntax(verified) {
		return fmt.Errorf("erased proof differs from Go source")
	}
	return nil
}

func main() {
	var paths sourcePaths
	flag.Var(&paths, "source", "compiled Go source file, repeat for multiple files")
	flag.Parse()
	if len(paths) == 0 || flag.NArg() == 0 {
		fail("usage: sourcecheck -source source.go [-source source.go ...] erased.go ...")
	}
	if err := checkBindings(verifiedDeclarations, paths...); err != nil {
		fail("%v", err)
	}
	var files []*ast.File
	for _, path := range paths {
		files = append(files, parse(path))
	}
	source := declarations(files...)
	seen := make(map[string]bool)
	for _, name := range verifiedDeclarations {
		seen[name] = false
	}
	for _, path := range flag.Args() {
		proof := parse(path)
		if err := checkProofDeclarations(proof); err != nil {
			fail("%s: %v", path, err)
		}
		for name, verified := range declarations(proof) {
			if _, ok := seen[name]; !ok {
				fail("unexpected declaration %s in %s", name, path)
			}
			if err := compareDeclaration(source[name], verified); err != nil {
				fail("%s for %s in %s", err, name, path)
			}
			seen[name] = true
		}
		if strings.HasSuffix(path, ".go") {
			if err := checkErasure(proof, parse(path+".ghostLess")); err != nil {
				fail("%s: %v", path, err)
			}
		}
	}
	for _, name := range verifiedDeclarations {
		if !seen[name] {
			fail("missing declaration %s in erased proofs", name)
		}
	}
	fmt.Println("Gobra functions, types, and constants match the Go source.")
}
