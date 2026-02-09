package techdetect

import (
	"regexp"
	"strings"
)

// QueryEvaluator evaluates MongoDB-style queries against a context
type QueryEvaluator struct{}

// NewQueryEvaluator creates a new query evaluator
func NewQueryEvaluator() *QueryEvaluator {
	return &QueryEvaluator{}
}

// Evaluate evaluates a query against the detection context
func (qe *QueryEvaluator) Evaluate(query map[string]interface{}, ctx *DetectionContext) (bool, string) {
	return qe.evaluateQuery(query, ctx)
}

// evaluateQuery recursively evaluates query conditions
func (qe *QueryEvaluator) evaluateQuery(query map[string]interface{}, ctx *DetectionContext) (bool, string) {
	for key, value := range query {
		switch key {
		case "$or":
			return qe.evaluateOr(value, ctx)
		case "$and":
			return qe.evaluateAnd(value, ctx)
		case "$not":
			return qe.evaluateNot(value, ctx)
		case "$nor":
			return qe.evaluateNor(value, ctx)
		default:
			// Field-level query
			return qe.evaluateField(key, value, ctx)
		}
	}
	return false, ""
}

// evaluateOr evaluates $or operator (match ANY)
func (qe *QueryEvaluator) evaluateOr(value interface{}, ctx *DetectionContext) (bool, string) {
	conditions, ok := value.([]interface{})
	if !ok {
		return false, ""
	}

	for _, cond := range conditions {
		condMap, ok := cond.(map[string]interface{})
		if !ok {
			continue
		}
		if match, version := qe.evaluateQuery(condMap, ctx); match {
			return true, version
		}
	}
	return false, ""
}

// evaluateAnd evaluates $and operator (match ALL)
func (qe *QueryEvaluator) evaluateAnd(value interface{}, ctx *DetectionContext) (bool, string) {
	conditions, ok := value.([]interface{})
	if !ok {
		return false, ""
	}

	version := ""
	for _, cond := range conditions {
		condMap, ok := cond.(map[string]interface{})
		if !ok {
			return false, ""
		}
		match, v := qe.evaluateQuery(condMap, ctx)
		if !match {
			return false, ""
		}
		if v != "" {
			version = v
		}
	}
	return true, version
}

// evaluateNot evaluates $not operator (negate)
func (qe *QueryEvaluator) evaluateNot(value interface{}, ctx *DetectionContext) (bool, string) {
	condMap, ok := value.(map[string]interface{})
	if !ok {
		return false, ""
	}
	match, _ := qe.evaluateQuery(condMap, ctx)
	return !match, ""
}

// evaluateNor evaluates $nor operator (match NONE)
func (qe *QueryEvaluator) evaluateNor(value interface{}, ctx *DetectionContext) (bool, string) {
	conditions, ok := value.([]interface{})
	if !ok {
		return false, ""
	}

	for _, cond := range conditions {
		condMap, ok := cond.(map[string]interface{})
		if !ok {
			continue
		}
		if match, _ := qe.evaluateQuery(condMap, ctx); match {
			return false, ""
		}
	}
	return true, ""
}

// evaluateField evaluates a field-level condition
func (qe *QueryEvaluator) evaluateField(fieldPath string, condition interface{}, ctx *DetectionContext) (bool, string) {
	// Get field value from context
	fieldValue := qe.getFieldValue(fieldPath, ctx)
	if fieldValue == "" {
		return false, ""
	}

	// Evaluate condition
	condMap, ok := condition.(map[string]interface{})
	if !ok {
		return false, ""
	}

	for operator, operand := range condMap {
		switch operator {
		case "$regex":
			return qe.evaluateRegex(fieldValue, operand)
		case "$eq":
			return qe.evaluateEquals(fieldValue, operand)
		case "$ne":
			return qe.evaluateNotEquals(fieldValue, operand)
		case "$exists":
			return qe.evaluateExists(fieldValue, operand)
		case "$in":
			return qe.evaluateIn(fieldValue, operand)
		case "$nin":
			return qe.evaluateNotIn(fieldValue, operand)
		}
	}

	return false, ""
}

// getFieldValue retrieves field value from context using dot notation
func (qe *QueryEvaluator) getFieldValue(fieldPath string, ctx *DetectionContext) string {
	parts := strings.Split(fieldPath, ".")

	if parts[0] == "body" {
		return ctx.Body
	}

	if parts[0] == "headers" && len(parts) > 1 {
		headerName := strings.Join(parts[1:], ".")
		// Case-insensitive header lookup
		for k, v := range ctx.Headers {
			if strings.EqualFold(k, headerName) {
				return v
			}
		}
		return ""
	}

	return ""
}

// evaluateRegex evaluates $regex operator
func (qe *QueryEvaluator) evaluateRegex(fieldValue string, pattern interface{}) (bool, string) {
	patternStr, ok := pattern.(string)
	if !ok {
		return false, ""
	}

	// Check for version extraction syntax: pattern\;version:\1
	parts := strings.Split(patternStr, "\\;version:")
	actualPattern := parts[0]

	re, err := regexp.Compile(actualPattern)
	if err != nil {
		return false, ""
	}

	matches := re.FindStringSubmatch(fieldValue)
	if len(matches) == 0 {
		return false, ""
	}

	// Extract version if specified
	version := ""
	if len(parts) > 1 && len(matches) > 1 {
		//parts[1] contains the group number (e.g., "\\1")
		// For simplicity, we take the first captured group
		version = matches[1]
	}

	return true, version
}

// evaluateEquals evaluates $eq operator
func (qe *QueryEvaluator) evaluateEquals(fieldValue string, operand interface{}) (bool, string) {
	expectedValue, ok := operand.(string)
	if !ok {
		return false, ""
	}
	return fieldValue == expectedValue, ""
}

// evaluateNotEquals evaluates $ne operator
func (qe *QueryEvaluator) evaluateNotEquals(fieldValue string, operand interface{}) (bool, string) {
	expectedValue, ok := operand.(string)
	if !ok {
		return false, ""
	}
	return fieldValue != expectedValue, ""
}

// evaluateExists evaluates $exists operator
func (qe *QueryEvaluator) evaluateExists(fieldValue string, operand interface{}) (bool, string) {
	shouldExist, ok := operand.(bool)
	if !ok {
		return false, ""
	}
	exists := fieldValue != ""
	return exists == shouldExist, ""
}

// evaluateIn evaluates $in operator
func (qe *QueryEvaluator) evaluateIn(fieldValue string, operand interface{}) (bool, string) {
	values, ok := operand.([]interface{})
	if !ok {
		return false, ""
	}

	for _, v := range values {
		strValue, ok := v.(string)
		if ok && fieldValue == strValue {
			return true, ""
		}
	}
	return false, ""
}

// evaluateNotIn evaluates $nin operator
func (qe *QueryEvaluator) evaluateNotIn(fieldValue string, operand interface{}) (bool, string) {
	values, ok := operand.([]interface{})
	if !ok {
		return false, ""
	}

	for _, v := range values {
		strValue, ok := v.(string)
		if ok && fieldValue == strValue {
			return false, ""
		}
	}
	return true, ""
}

// ExtractVersion attempts to extract version from context using extraction rules
func (qe *QueryEvaluator) ExtractVersion(rules []map[string]string, ctx *DetectionContext) string {
	for _, rule := range rules {
		for field, pattern := range rule {
			fieldValue := qe.getFieldValue(field, ctx)
			if fieldValue == "" {
				continue
			}

			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}

			matches := re.FindStringSubmatch(fieldValue)
			if len(matches) > 1 {
				return matches[1] // Return first captured group
			}
		}
	}
	return ""
}
