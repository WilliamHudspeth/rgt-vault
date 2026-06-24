// tree.go implements the RGT-160 namespace path tree view.
package tui

import (
	"sort"
	"strings"
)

// TreeRow represents a flattened node in the secret namespace path tree.
type TreeRow struct {
	Indent int         // depth, 0 for top-level
	Label  string      // the path segment to display at this level
	IsLeaf bool        // true => a real secret; false => a grouping node
	Secret *SecretInfo // non-nil only when IsLeaf is true
}

type node struct {
	label    string
	isLeaf   bool
	secret   *SecretInfo
	children map[string]*node
}

// BuildTree builds a namespace/path tree from the given secrets and returns a flattened pre-order slice of TreeRows.
func BuildTree(secrets []SecretInfo) []TreeRow {
	if len(secrets) == 0 {
		return nil
	}

	root := &node{children: make(map[string]*node)}
	for i := range secrets {
		sec := &secrets[i]
		parts := strings.Split(sec.Name, "/")
		curr := root
		for j, part := range parts {
			isLast := j == len(parts)-1
			child, exists := curr.children[part]
			if !exists {
				child = &node{
					label:    part,
					children: make(map[string]*node),
				}
				curr.children[part] = child
			}
			if isLast {
				child.isLeaf = true
				child.secret = sec
			}
			curr = child
		}
	}

	var result []TreeRow
	var kids []*node
	for _, child := range root.children {
		kids = append(kids, child)
	}
	sort.Slice(kids, func(i, j int) bool {
		return kids[i].label < kids[j].label
	})
	for _, kid := range kids {
		walk(kid, 0, &result)
	}
	return result
}

func walk(n *node, depth int, result *[]TreeRow) {
	if len(n.children) == 0 {
		*result = append(*result, TreeRow{
			Indent: depth,
			Label:  n.label,
			IsLeaf: true,
			Secret: n.secret,
		})
		return
	}

	*result = append(*result, TreeRow{
		Indent: depth,
		Label:  n.label,
		IsLeaf: false,
		Secret: nil,
	})

	var kids []*node
	for _, child := range n.children {
		kids = append(kids, child)
	}
	if n.isLeaf {
		kids = append(kids, &node{
			label:  n.label,
			isLeaf: true,
			secret: n.secret,
		})
	}
	sort.Slice(kids, func(i, j int) bool {
		return kids[i].label < kids[j].label
	})
	for _, kid := range kids {
		walk(kid, depth+1, result)
	}
}
