// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package tracetest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

// TestBlockContextsCarrySlotNum guards the EIP-7843 wiring in this package.
// These harnesses build vm.BlockContext by hand instead of going through
// core.NewEVMBlockContext, and the decision in
// docs/adr/0006-define-slot-number-as-block-number.md derives the slot number
// from the block number. A literal that forgets SlotNum runs with slot number
// zero, so an Amsterdam test case that executes SLOTNUM would silently encode
// the wrong expectation. The package's testdata does not execute 0x4b yet,
// hence this structural guard instead of a runtime assertion.
//
// An elided element type hides the literal from type inspection: the inner
// literal of []vm.BlockContext{{...}} has no type of its own, so the
// container's element type is checked instead.
func TestBlockContextsCarrySlotNum(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return strings.HasSuffix(fi.Name(), ".go")
	}, 0)
	if err != nil {
		t.Fatalf("failed to parse the package: %v", err)
	}
	var found int
	check := func(name string, lit *ast.CompositeLit) {
		found++
		var hasSlotNum bool
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				t.Errorf("%s: block context literal at %s uses positional fields; name SlotNum explicitly", name, fset.Position(lit.Pos()))
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "SlotNum" {
				hasSlotNum = true
			}
		}
		if !hasSlotNum {
			t.Errorf("%s: block context literal at %s does not set SlotNum", name, fset.Position(lit.Pos()))
		}
	}
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				if isBlockContextType(lit.Type) {
					check(name, lit)
					return true
				}
				elem, ok := containerElem(lit.Type)
				if !ok || !reachesBlockContext(elem) {
					return true
				}
				// Element literals elide their type, so the container is the only
				// place that names it; check them here instead of waiting for an
				// element visit that can never match. Nested containers elide it
				// too, so the element type travels down the literal tree.
				checkElems(name, lit, elem, check)
				return true
			})
		}
	}
	if found == 0 {
		t.Fatal("found no block context literals; the SlotNum guard would be vacuous")
	}
}

// isBlockContextType reports whether expr names a BlockContext type: the
// vm.BlockContext selector, the same type behind an aliased import, or a
// dot-imported BlockContext.
func isBlockContextType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name == "BlockContext"
	case *ast.SelectorExpr:
		return t.Sel.Name == "BlockContext"
	}
	return false
}

// reachesBlockContext reports whether expr is a BlockContext or a container
// that reaches one through any number of nested containers or pointers.
func reachesBlockContext(expr ast.Expr) bool {
	expr = unwrapPtr(expr)
	if isBlockContextType(expr) {
		return true
	}
	elem, ok := containerElem(expr)
	return ok && reachesBlockContext(elem)
}

// containerElem returns the element type of a slice, array or map type.
func containerElem(expr ast.Expr) (ast.Expr, bool) {
	switch t := expr.(type) {
	case *ast.ArrayType:
		return t.Elt, true
	case *ast.MapType:
		return t.Value, true
	}
	return nil, false
}

// checkElems checks the elided element literals of a container literal whose
// element type is elem. A nested container elides its type as well, so its own
// elements are checked against the inner element type here; explicitly typed
// literals are left to the AST walk that visits them directly. A literal whose
// type is behind a name (a defined type or an alias) is invisible to this walk;
// such code needs type information.
func checkElems(name string, lit *ast.CompositeLit, elem ast.Expr, check func(string, *ast.CompositeLit)) {
	for _, elt := range lit.Elts {
		sub := elementLiteral(elt)
		if sub == nil || sub.Type != nil {
			continue
		}
		if isBlockContextType(unwrapPtr(elem)) {
			check(name, sub)
			continue
		}
		if inner, ok := containerElem(unwrapPtr(elem)); ok {
			checkElems(name, sub, inner, check)
		}
	}
}

// elementLiteral returns the composite literal an array element or map value
// contributes, or nil for any other element.
func elementLiteral(elt ast.Expr) *ast.CompositeLit {
	switch e := elt.(type) {
	case *ast.CompositeLit:
		return e
	case *ast.KeyValueExpr:
		if lit, ok := e.Value.(*ast.CompositeLit); ok {
			return lit
		}
	}
	return nil
}

// unwrapPtr strips a pointer from a type expression.
func unwrapPtr(expr ast.Expr) ast.Expr {
	if star, ok := expr.(*ast.StarExpr); ok {
		return star.X
	}
	return expr
}
