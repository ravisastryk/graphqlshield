package graphqlshield

import "strings"

// queryDepth counts the maximum brace-nesting depth of a GraphQL query string.
// It ignores braces inside string literals so payload like {"$ne":null} in
// a variables object cannot inflate the reported depth.
func queryDepth(query string) int {
	max, cur, inStr := 0, 0, false
	for i := 0; i < len(query); i++ {
		c := query[i]
		if c == '"' && (i == 0 || query[i-1] != '\\') {
			inStr = !inStr
		}
		if inStr {
			continue
		}
		switch c {
		case '{':
			cur++
			if cur > max {
				max = cur
			}
		case '}':
			if cur > 0 {
				cur--
			}
		}
	}
	return max
}

// isIntrospection returns true when the query appears to target __schema or __type.
func isIntrospection(query string) bool {
	return strings.Contains(query, "__schema") ||
		strings.Contains(query, "__type") ||
		strings.Contains(query, "IntrospectionQuery")
}

// containsField returns true when the query references a named field
// as a whole identifier (not as part of a longer name).
func containsField(query, field string) bool {
	src := query
	for {
		i := strings.Index(src, field)
		if i < 0 {
			return false
		}
		end := i + len(field)
		// check the character after — must not be a valid identifier char
		if end < len(src) {
			next := src[end]
			if (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') ||
				(next >= '0' && next <= '9') || next == '_' {
				src = src[end:]
				continue
			}
		}
		return true
	}
}
