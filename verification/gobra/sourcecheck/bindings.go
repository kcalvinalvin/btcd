// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

type packageInfo struct {
	Dir             string
	ImportPath      string
	ImportMap       map[string]string
	CompiledGoFiles []string
	Export          string
	DepOnly         bool
}

func checkBindings(names []string, sourcePaths ...string) error {
	paths := make([]string, len(sourcePaths))
	for i, path := range sourcePaths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		paths[i] = absolute
	}

	command := exec.Command("go", "list", "-compiled", "-deps", "-export", "-json", ".")
	command.Dir = filepath.Dir(paths[0])
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("load source package: %w\n%s", err, &stderr)
	}

	exports := make(map[string]string)
	var source packageInfo
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var pkg packageInfo
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		exports[pkg.ImportPath] = pkg.Export
		if !pkg.DepOnly {
			source = pkg
		}
	}

	fileSet := token.NewFileSet()
	var files []*ast.File
	byPath := make(map[string]*ast.File)
	for _, path := range source.CompiledGoFiles {
		if !filepath.IsAbs(path) {
			path = filepath.Join(source.Dir, path)
		}
		file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files = append(files, file)
		byPath[path] = file
	}
	var selected []*ast.File
	for _, path := range paths {
		file, ok := byPath[path]
		if !ok {
			return fmt.Errorf("%s is not compiled into the source package", path)
		}
		selected = append(selected, file)
	}

	config := types.Config{
		Importer: importer.ForCompiler(fileSet, "gc", func(path string) (io.ReadCloser, error) {
			if mapped, ok := source.ImportMap[path]; ok {
				path = mapped
			}
			return os.Open(exports[path])
		}),
	}
	info := types.Info{Uses: make(map[*ast.Ident]types.Object)}
	if _, err := config.Check(source.ImportPath, fileSet, files, &info); err != nil {
		return fmt.Errorf("type-check source package: %w", err)
	}

	decls := declarations(selected...)
	for _, name := range names {
		decl, ok := decls[name]
		if !ok {
			return fmt.Errorf("missing declaration %s", name)
		}
		var bindingErr error
		ast.Inspect(decl.(ast.Node), func(node ast.Node) bool {
			id, ok := node.(*ast.Ident)
			if !ok || info.Uses[id] == nil {
				return true
			}
			expected := types.Universe.Lookup(id.Name)
			if expected != nil && info.Uses[id] != expected {
				bindingErr = fmt.Errorf("%s does not refer to Go's predeclared %s", id.Name, id.Name)
			}
			return true
		})
		if bindingErr != nil {
			return bindingErr
		}
	}
	return nil
}
