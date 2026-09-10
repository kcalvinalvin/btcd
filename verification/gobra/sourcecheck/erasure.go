// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"go/ast"
	"go/token"
)

func checkProofDeclarations(file *ast.File) error {
	for _, declaration := range file.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			if declaration.Recv != nil {
				return fmt.Errorf("methods are not supported in proof inputs")
			}
		case *ast.GenDecl:
			if declaration.Tok != token.CONST && declaration.Tok != token.TYPE {
				return fmt.Errorf("only functions, types, and constants are supported in proof inputs")
			}
			for _, spec := range declaration.Specs {
				if value, ok := spec.(*ast.ValueSpec); ok &&
					(len(value.Names) != 1 || len(value.Values) != 1) {
					return fmt.Errorf("proof constants need one name and one explicit value")
				}
			}
		default:
			return fmt.Errorf("unsupported declaration in proof input")
		}
	}
	return nil
}

func pointerArrayConversion(expr ast.Expr) *ast.StarExpr {
	parentheses, ok := expr.(*ast.ParenExpr)
	if !ok {
		return nil
	}
	pointer, ok := parentheses.X.(*ast.StarExpr)
	if !ok {
		return nil
	}
	if _, ok := pointer.X.(*ast.ArrayType); !ok {
		return nil
	}
	return pointer
}

func isConversion(expr ast.Expr) bool {
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name == "int32" || id.Name == "int64" || id.Name == "uint32"
	}
	return pointerArrayConversion(expr) != nil
}

func containsConversion(node ast.Node) bool {
	if node == nil {
		return false
	}
	found := false
	ast.Inspect(node, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && isConversion(call.Fun) {
			found = true
		}
		return !found
	})
	return found
}

func checkConversionComments(file *ast.File) error {
	var commentErr error
	ast.Inspect(file, func(node ast.Node) bool {
		statement, ok := node.(ast.Stmt)
		if !ok {
			return true
		}
		start, end := statement.Pos(), statement.End()
		var converted bool
		switch statement := statement.(type) {
		case *ast.BlockStmt, *ast.LabeledStmt:
			return true
		case *ast.ForStmt:
			converted = containsConversion(statement.Init) || containsConversion(statement.Cond) || containsConversion(statement.Post)
			end = statement.Body.Lbrace
		case *ast.RangeStmt:
			converted = containsConversion(statement.X)
			end = statement.Body.Lbrace
		case *ast.IfStmt:
			converted = containsConversion(statement.Init) || containsConversion(statement.Cond)
			end = statement.Body.Lbrace
		default:
			converted = containsConversion(statement)
		}
		if converted {
			for _, group := range file.Comments {
				for _, comment := range group.List {
					if start < comment.End() && comment.Pos() < end {
						commentErr = fmt.Errorf("comments inside conversions or their statements are not supported")
					}
				}
			}
		}
		return true
	})
	return commentErr
}

// Gobra's eraser drops conversion operands. The annotated Go is compared to
// production with operands intact. Conversion statements and conditions must
// be free of annotations before this erasure comparison.
func eraseConversions(file *ast.File, annotated bool) error {
	if annotated {
		if err := checkConversionComments(file); err != nil {
			return err
		}
	}
	var conversionErr error
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !isConversion(call.Fun) {
			return true
		}
		if annotated {
			if len(call.Args) != 1 {
				conversionErr = fmt.Errorf("conversion must have one operand")
			}
		}
		return true
	})
	if conversionErr != nil {
		return conversionErr
	}
	ast.Inspect(file, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && isConversion(call.Fun) {
			call.Args = nil
		}
		return true
	})
	// The eraser also prints pointer conversions as an unparenthesized star.
	ast.Inspect(file, func(node ast.Node) bool {
		if assignment, ok := node.(*ast.AssignStmt); ok {
			for i, rhs := range assignment.Rhs {
				call, ok := rhs.(*ast.CallExpr)
				if !ok {
					continue
				}
				if pointer := pointerArrayConversion(call.Fun); pointer != nil {
					assignment.Rhs[i] = &ast.StarExpr{X: &ast.CallExpr{Fun: pointer.X}}
				}
			}
		}
		return true
	})
	return nil
}

func checkErasure(annotated, erased *ast.File) error {
	if err := checkProofDeclarations(erased); err != nil {
		return err
	}
	if err := eraseConversions(annotated, true); err != nil {
		return err
	}
	if err := eraseConversions(erased, false); err != nil {
		return err
	}
	originals := declarations(annotated)
	verified := declarations(erased)
	if len(originals) != len(verified) {
		return fmt.Errorf("declarations differ after ghost erasure")
	}
	for name, original := range originals {
		if err := compareDeclaration(original, verified[name]); err != nil {
			return fmt.Errorf("%s after ghost erasure of %s", err, name)
		}
	}
	return nil
}
