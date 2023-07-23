// Copyright (c) 2019 Eduard Urbach
package api

import (
	"strings"
)

// controlFlow tells the main loop what it should do next.
type controlFlow int

// controlFlow values.
const (
	controlStop  controlFlow = 0
	controlBegin controlFlow = 1
	controlNext  controlFlow = 2
)

// node types
const (
	separator = '/'
	parameter = ':'
	wildcard  = '*'
)

// dataType specifies which type of data we are going to save for each node.
type dataType = Handler

// Tree represents a radix tree.
type Tree struct {
	root        treeNode
	static      map[string]dataType
	canBeStatic [2048]bool
}

// Add adds a new element to the tree.
func (tree *Tree) Add(path string, data dataType) {
	if !strings.Contains(path, ":") && !strings.Contains(path, "*") {
		if tree.static == nil {
			tree.static = map[string]dataType{}
		}

		tree.static[path] = data
		tree.canBeStatic[len(path)] = true
		return
	}

	// Search tree for equal parts until we can no longer proceed
	i := 0
	offset := 0
	node := &tree.root

	for {
	begin:
		switch node.kind {
		case parameter:
			// This only occurs when the same parameter based route is added twice.
			// node: /post/:id|
			// path: /post/:id|
			if i == len(path) {
				node.data = data
				return
			}

			// When we hit a separator, we'll search for a fitting child.
			if path[i] == separator {
				var control controlFlow
				node, offset, control = node.end(path, data, i, offset)

				switch control {
				case controlStop:
					return
				case controlBegin:
					goto begin
				case controlNext:
					goto next
				}
			}

		default:
			if i == len(path) {
				// The path already exists.
				// node: /blog|
				// path: /blog|
				if i-offset == len(node.prefix) {
					node.data = data
					return
				}

				// The path ended but the node prefix is longer.
				// node: /blog|feed
				// path: /blog|
				node.split(i-offset, "", data)
				return
			}

			// The node we just checked is entirely included in our path.
			// node: /|
			// path: /|blog
			if i-offset == len(node.prefix) {
				var control controlFlow
				node, offset, control = node.end(path, data, i, offset)

				switch control {
				case controlStop:
					return
				case controlBegin:
					goto begin
				case controlNext:
					goto next
				}
			}

			// We got a conflict.
			// node: /b|ag
			// path: /b|riefcase
			if path[i] != node.prefix[i-offset] {
				node.split(i-offset, path[i:], data)
				return
			}
		}

	next:
		i++
	}
}

// Lookup finds the data for the request path and assigns it to ctx.Handler, if available.
func (tree *Tree) Lookup(ctx *Context) {
	path := ctx.Request.URL.Path

	if tree.canBeStatic[len(path)] {
		handler, found := tree.static[path]

		if found {
			ctx.Handler = handler
			return
		}
	}

	var (
		i                  uint
		offset             uint
		lastWildcardOffset uint
		lastWildcard       *treeNode
		node               = &tree.root
	)

begin:
	// Search tree for equal parts until we can no longer proceed
	for {
		// We reached the end.
		if i == uint(len(path)) {
			// node: /blog|
			// path: /blog|
			if i-offset == uint(len(node.prefix)) {
				ctx.Handler = node.data
				return
			}

			// node: /blog|feed
			// path: /blog|
			ctx.Handler = nil
			return
		}

		// The node we just checked is entirely included in our path.
		// node: /|
		// path: /|blog
		if i-offset == uint(len(node.prefix)) {
			if node.wildcard != nil {
				lastWildcard = node.wildcard
				lastWildcardOffset = i
			}

			char := path[i]

			if char >= node.startIndex && char < node.endIndex {
				index := node.indices[char-node.startIndex]

				if index != 0 {
					node = node.children[index]
					offset = i
					i++
					continue
				}
			}

			// node: /|:id
			// path: /|blog
			if node.parameter != nil {
				node = node.parameter
				offset = i
				i++

				for {
					// We reached the end.
					if i == uint(len(path)) {
						ctx.addParameter(node.prefix, path[offset:i])
						ctx.Handler = node.data
						return
					}

					// node: /:id|/posts
					// path: /123|/posts
					if path[i] == separator {
						ctx.addParameter(node.prefix, path[offset:i])
						index := node.indices[separator-node.startIndex]
						node = node.children[index]
						offset = i
						i++
						goto begin
					}

					i++
				}
			}

			// node: /|*any
			// path: /|image.png
			if node.wildcard != nil {
				ctx.addParameter(node.wildcard.prefix, path[i:])
				ctx.Handler = node.wildcard.data
				return
			}

			ctx.Handler = nil
			return
		}

		// We got a conflict.
		// node: /b|ag
		// path: /b|riefcase
		if path[i] != node.prefix[i-offset] {
			if lastWildcard != nil {
				ctx.addParameter(lastWildcard.prefix, path[lastWildcardOffset:])
				ctx.Handler = lastWildcard.data
				return
			}

			ctx.Handler = nil
			return
		}

		i++
	}
}

// treeNode represents a radix tree node.
type treeNode struct {
	startIndex uint8
	endIndex   uint8
	kind       byte
	prefix     string
	indices    []uint8
	children   []*treeNode
	data       dataType
	parameter  *treeNode
	wildcard   *treeNode
}

// split splits the node at the given index and inserts
// a new child node with the given path and data.
// If path is empty, it will not create another child node
// and instead assign the data directly to the node.
func (node *treeNode) split(index int, path string, data dataType) {
	// Create split node with the remaining string
	splitNode := node.clone(node.prefix[index:])

	// The existing data must be removed
	node.reset(node.prefix[:index])

	// If the path is empty, it means we don't create a 2nd child node.
	// Just assign the data for the existing node and store a single child node.
	if path == "" {
		node.data = data
		node.addChild(splitNode)
		return
	}

	node.addChild(splitNode)

	// Create new nodes with the remaining path
	node.append(path, data)
}

// clone clones the node with a new prefix.
func (node *treeNode) clone(prefix string) *treeNode {
	return &treeNode{
		prefix:     prefix,
		data:       node.data,
		indices:    node.indices,
		startIndex: node.startIndex,
		endIndex:   node.endIndex,
		children:   node.children,
		parameter:  node.parameter,
		wildcard:   node.wildcard,
		kind:       node.kind,
	}
}

// reset resets the existing node data.
func (node *treeNode) reset(prefix string) {
	node.prefix = prefix
	node.data = nil
	node.parameter = nil
	node.wildcard = nil
	node.kind = 0
	node.startIndex = 0
	node.endIndex = 0
	node.indices = nil
	node.children = nil
}

// addChild adds a child tree.
func (node *treeNode) addChild(child *treeNode) {
	if len(node.children) == 0 {
		node.children = append(node.children, nil)
	}

	firstChar := child.prefix[0]

	switch {
	case node.startIndex == 0:
		node.startIndex = firstChar
		node.indices = []uint8{0}
		node.endIndex = node.startIndex + uint8(len(node.indices))

	case firstChar < node.startIndex:
		diff := node.startIndex - firstChar
		newIndices := make([]uint8, diff+uint8(len(node.indices)))
		copy(newIndices[diff:], node.indices)
		node.startIndex = firstChar
		node.indices = newIndices
		node.endIndex = node.startIndex + uint8(len(node.indices))

	case firstChar >= node.endIndex:
		diff := firstChar - node.endIndex + 1
		newIndices := make([]uint8, diff+uint8(len(node.indices)))
		copy(newIndices, node.indices)
		node.indices = newIndices
		node.endIndex = node.startIndex + uint8(len(node.indices))
	}

	index := node.indices[firstChar-node.startIndex]

	if index == 0 {
		node.indices[firstChar-node.startIndex] = uint8(len(node.children))
		node.children = append(node.children, child)
		return
	}

	node.children[index] = child
}

// addTrailingSlash adds a trailing slash with the same data.
func (node *treeNode) addTrailingSlash(data dataType) {
	if strings.HasSuffix(node.prefix, "/") || node.kind == wildcard || (separator >= node.startIndex && separator < node.endIndex && node.indices[separator-node.startIndex] != 0) {
		return
	}

	node.addChild(&treeNode{
		prefix: "/",
		data:   data,
	})
}

// append appends the given path to the tree.
func (node *treeNode) append(path string, data dataType) {
	// At this point, all we know is that somewhere
	// in the remaining string we have parameters.
	// node: /user|
	// path: /user|/:userid
	for {
		if path == "" {
			node.data = data
			return
		}

		paramStart := strings.IndexByte(path, parameter)

		if paramStart == -1 {
			paramStart = strings.IndexByte(path, wildcard)
		}

		// If it's a static route we are adding,
		// just add the remainder as a normal node.
		if paramStart == -1 {
			// If the node itself doesn't have a prefix (root node),
			// don't add a child and use the node itself.
			if node.prefix == "" {
				node.prefix = path
				node.data = data
				return
			}

			child := &treeNode{
				prefix: path,
				data:   data,
			}

			node.addChild(child)
			child.addTrailingSlash(data)
			return
		}

		// If we're directly in front of a parameter,
		// add a parameter node.
		if paramStart == 0 {
			paramEnd := strings.IndexByte(path, separator)

			if paramEnd == -1 {
				paramEnd = len(path)
			}

			child := &treeNode{
				prefix: path[1:paramEnd],
				kind:   path[paramStart],
			}

			switch child.kind {
			case parameter:
				child.addTrailingSlash(data)
				node.parameter = child
				node = child
				path = path[paramEnd:]
				continue

			case wildcard:
				child.data = data
				node.wildcard = child
				return
			}
		}

		// We know there's a parameter, but not directly at the start.

		// If the node itself doesn't have a prefix (root node),
		// don't add a child and use the node itself.
		if node.prefix == "" {
			node.prefix = path[:paramStart]
			path = path[paramStart:]
			continue
		}

		// Add a normal node with the path before the parameter start.
		child := &treeNode{
			prefix: path[:paramStart],
		}

		// Allow trailing slashes to return
		// the same content as their parent node.
		if child.prefix == "/" {
			child.data = node.data
		}

		node.addChild(child)
		node = child
		path = path[paramStart:]
	}
}

// end is called when the node was fully parsed
// and needs to decide the next control flow.
func (node *treeNode) end(path string, data dataType, i int, offset int) (*treeNode, int, controlFlow) {
	char := path[i]

	if char >= node.startIndex && char < node.endIndex {
		index := node.indices[char-node.startIndex]

		if index != 0 {
			node = node.children[index]
			offset = i
			return node, offset, controlNext
		}
	}

	// No fitting children found, does this node even contain a prefix yet?
	// If no prefix is set, this is the starting node.
	if node.prefix == "" {
		node.append(path[i:], data)
		return node, offset, controlStop
	}

	// node: /user/|:id
	// path: /user/|:id/profile
	if node.parameter != nil {
		node = node.parameter
		offset = i
		return node, offset, controlBegin
	}

	node.append(path[i:], data)
	return node, offset, controlStop
}
