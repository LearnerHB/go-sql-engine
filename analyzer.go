package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/xwb1989/sqlparser"
)

//go:embed rules.json
var rulesJSON []byte

// ── Data types ───────────────────────────────────────────────────────────────

type RuleDefinition struct {
	ID       string `json:"id"`
	NameZh   string `json:"name_zh"`
	NameEn   string `json:"name_en"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	DescZh   string `json:"description_zh"`
	DescEn   string `json:"description_en"`
}

type RiskResult struct {
	RuleID      string `json:"ruleId"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type ParsedInfo struct {
	StatementType string   `json:"statementType"`
	Tables        []string `json:"tables"`
	HasWhere      bool     `json:"hasWhere"`
	HasLimit      bool     `json:"hasLimit"`
	LimitValue    *int     `json:"limitValue,omitempty"`
	IsSelectStar  bool     `json:"isSelectStar"`
	HasUnion      bool     `json:"hasUnion"`
}

type CheckResult struct {
	Success    bool         `json:"success"`
	ParsedInfo *ParsedInfo  `json:"parsedInfo,omitempty"`
	Risks      []RiskResult `json:"risks"`
	Error      string       `json:"error,omitempty"`
}

type CheckRequest struct {
	SQL    string `json:"sql"`
	Locale string `json:"locale"`
}

// ── Rule loading ─────────────────────────────────────────────────────────────

var rules []RuleDefinition

func init() {
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		log.Fatalf("Failed to load rules.json: %v", err)
	}
	log.Printf("Loaded %d detection rules", len(rules))
}

func getRuleByID(id string) *RuleDefinition {
	for i := range rules {
		if rules[i].ID == id {
			return &rules[i]
		}
	}
	return nil
}

func buildRisk(id, locale string) *RiskResult {
	rule := getRuleByID(id)
	if rule == nil {
		return nil
	}
	name := rule.NameEn
	desc := rule.DescEn
	if locale == "zh" {
		name = rule.NameZh
		desc = rule.DescZh
	}
	return &RiskResult{
		RuleID:      rule.ID,
		Name:        name,
		Severity:    rule.Severity,
		Description: desc,
	}
}

// ── AST helpers ───────────────────────────────────────────────────────────────

func extractTables(stmt sqlparser.Statement) []string {
	var tables []string
	addFromExprs := func(exprs sqlparser.TableExprs) {
		for _, expr := range exprs {
			if aliased, ok := expr.(*sqlparser.AliasedTableExpr); ok {
				if tbl, ok := aliased.Expr.(sqlparser.TableName); ok {
					name := tbl.Name.String()
					if name != "" {
						tables = append(tables, name)
					}
				}
			}
		}
	}
	var addSelect func(sel *sqlparser.Select)
	addSelect = func(sel *sqlparser.Select) {
		addFromExprs(sel.From)
	}

	switch v := stmt.(type) {
	case *sqlparser.Select:
		addSelect(v)
	case *sqlparser.Union:
		// Recursively extract tables from both sides of the UNION
		if sel, ok := v.Left.(*sqlparser.Select); ok {
			addSelect(sel)
		}
		if sel, ok := v.Right.(*sqlparser.Select); ok {
			addSelect(sel)
		}
	case *sqlparser.Delete:
		addFromExprs(v.TableExprs)
	case *sqlparser.Update:
		addFromExprs(v.TableExprs)
	case *sqlparser.DDL:
		name := v.Table.Name.String()
		if name != "" {
			tables = append(tables, name)
		}
	}
	return tables
}

var (
	reDashComment  = regexp.MustCompile(`--`)
	reBlockComment = regexp.MustCompile(`/\*`)
)

// ── Core detection ────────────────────────────────────────────────────────────

func checkSQL(sql, locale string) CheckResult {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" {
		msg := "Please enter a SQL statement"
		if locale == "zh" {
			msg = "请输入 SQL 语句"
		}
		return CheckResult{Success: false, Risks: []RiskResult{}, Error: msg}
	}

	// R006 check must happen on the raw string before the parser strips comments
	hasComment := reDashComment.MatchString(trimmed) || reBlockComment.MatchString(trimmed)

	stmt, err := sqlparser.Parse(trimmed)
	if err != nil {
		msg := "SQL parse failed — please check your syntax"
		if locale == "zh" {
			msg = "SQL 解析失败，请检查语法是否正确"
		}
		return CheckResult{Success: false, Risks: []RiskResult{}, Error: msg}
	}

	var (
		stmtType     string
		hasWhere     bool
		isSelectStar bool
		hasUnion     bool
		limitValue   *int
	)

	tables := extractTables(stmt)
	if tables == nil {
		tables = []string{}
	}

	switch v := stmt.(type) {
	case *sqlparser.Select:
		stmtType = "SELECT"
		hasWhere = v.Where != nil
		for _, expr := range v.SelectExprs {
			if _, ok := expr.(*sqlparser.StarExpr); ok {
				isSelectStar = true
				break
			}
		}
		if v.Limit != nil {
			if sqlVal, ok := v.Limit.Rowcount.(*sqlparser.SQLVal); ok && sqlVal.Type == sqlparser.IntVal {
				if val, err := strconv.Atoi(string(sqlVal.Val)); err == nil {
					limitValue = &val
				}
			}
		}
	case *sqlparser.Delete:
		stmtType = "DELETE"
		hasWhere = v.Where != nil
	case *sqlparser.Update:
		stmtType = "UPDATE"
		hasWhere = v.Where != nil
	case *sqlparser.DDL:
		stmtType = strings.ToUpper(v.Action)
	case *sqlparser.Union:
		stmtType = "SELECT"
		hasUnion = true
	default:
		stmtType = fmt.Sprintf("%T", stmt)
		stmtType = strings.TrimPrefix(stmtType, "*sqlparser.")
		stmtType = strings.ToUpper(stmtType)
	}

	parsedInfo := &ParsedInfo{
		StatementType: stmtType,
		Tables:        tables,
		HasWhere:      hasWhere,
		HasLimit:      limitValue != nil,
		LimitValue:    limitValue,
		IsSelectStar:  isSelectStar,
		HasUnion:      hasUnion,
	}

	var risks []RiskResult
	addRisk := func(id string) {
		if r := buildRisk(id, locale); r != nil {
			risks = append(risks, *r)
		}
	}

	// R001 — DELETE / UPDATE without WHERE
	if (stmtType == "DELETE" || stmtType == "UPDATE") && !hasWhere {
		addRisk("R001")
	}
	// R002 — DROP / TRUNCATE
	if stmtType == "DROP" || stmtType == "TRUNCATE" {
		addRisk("R002")
	}
	// R003 — SELECT *
	if stmtType == "SELECT" && isSelectStar {
		addRisk("R003")
	}
	// R004 — Large LIMIT
	if limitValue != nil && *limitValue > 10000 {
		addRisk("R004")
	}
	// R005 — UNION injection
	if hasUnion {
		addRisk("R005")
	}
	// R006 — Comment injection
	if hasComment {
		addRisk("R006")
	}

	if risks == nil {
		risks = []RiskResult{}
	}

	return CheckResult{Success: true, ParsedInfo: parsedInfo, Risks: risks}
}
