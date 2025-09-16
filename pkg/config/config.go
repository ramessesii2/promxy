package proxyconfig

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/prometheus/exporter-toolkit/web"
	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/model/labels"
	yaml "gopkg.in/yaml.v2"

	"github.com/jacksontj/promxy/pkg/servergroup"
)

// DefaultPromxyConfig is the default promxy config that the config file
// is loaded into
var DefaultPromxyConfig = PromxyConfig{
	Alerting: AlertingConfig{
		GeneratorURLTemplate: "{{.ExternalURL}}/graph?g0.expr={{.Expr | urlquery}}&g0.tab=1",
	},
}

// ConfigFromFile loads a config file at path
func ConfigFromFile(path string) (*Config, error) {
	// load the config file
	cfg := &Config{
		PromConfig:   config.DefaultConfig,
		PromxyConfig: DefaultPromxyConfig,
	}
	configBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %v", err)
	}
	err = yaml.Unmarshal([]byte(configBytes), &cfg)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %v", err)
	}

	// Initialize the generator URL template
	if err := cfg.PromxyConfig.Alerting.SetTemplate(); err != nil {
		return nil, fmt.Errorf("error setting generator URL template: %v", err)
	}

	return cfg, nil
}

// Config is the entire config file. This includes both the Prometheus Config
// as well as the Promxy config. This is done by "inline-ing" the promxy
// config into the prometheus config under the "promxy" key
type Config struct {
	// Prometheus configs -- this includes configurations for
	// recording rules, alerting rules, etc.
	PromConfig config.Config `yaml:",inline"`

	// Promxy specific configuration -- under its own namespace
	PromxyConfig `yaml:"promxy"`

	WebConfig web.TLSStruct `yaml:"tls_server_config"`
}

func (c *Config) String() string {
	b, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Sprintf("<error creating config string: %s>", err)
	}
	return string(b)
}

// PromxyConfig is the configuration for Promxy itself
type PromxyConfig struct {
	// Config for each of the server groups promxy is configured to aggregate
	ServerGroups []*servergroup.Config `yaml:"server_groups"`

	// Alerting configuration for custom generator URLs
	Alerting AlertingConfig `yaml:"alerting"`
}

// AlertingConfig contains configuration for alert generation
type AlertingConfig struct {
	// Legacy single template (for backward compatibility)
	// If set, this takes precedence over all other template configurations
	GeneratorURLTemplate string `yaml:"generator_url_template"`

	// Template directory for external template files
	TemplateDirectory string `yaml:"template_directory"`

	// Default template name (fallback when no rules match)
	DefaultTemplate string `yaml:"default_template"`

	// Template selection rules (evaluated in order)
	TemplateRules []TemplateRule `yaml:"template_rules"`

	// Inline templates (key: template_name, value: template_content)
	Templates map[string]string `yaml:"templates"`

	// Parsed templates (not serialized)
	parsedTemplate  *template.Template            `yaml:"-"` // Legacy single template
	parsedTemplates map[string]*template.Template `yaml:"-"` // Multiple templates
}

// TemplateRule defines conditions for selecting a specific template
type TemplateRule struct {
	// Match alerts with these exact label values
	MatchLabels map[string]string `yaml:"match_labels"`

	// Match alerts with these annotation patterns
	// Use "*" to match any value for a given annotation key
	MatchAnnotations map[string]string `yaml:"match_annotations"`

	// Template name to use when this rule matches
	Template string `yaml:"template"`
}

// SetTemplate parses and sets templates from various sources
func (ac *AlertingConfig) SetTemplate() error {
	// Initialize parsed templates map
	ac.parsedTemplates = make(map[string]*template.Template)

	// Template function map (shared across all templates)
	funcMap := template.FuncMap{
		"urlquery": template.URLQueryEscaper,
		"urlpath": func(s string) string {
			return url.PathEscape(s)
		},
	}

	// Legacy single template mode (takes precedence for backward compatibility)
	if ac.GeneratorURLTemplate != "" {
		// Already has a value, use it as-is

		tmpl, err := template.New("generator_url").Funcs(funcMap).Parse(ac.GeneratorURLTemplate)
		if err != nil {
			return fmt.Errorf("failed to parse legacy generator URL template: %v", err)
		}
		ac.parsedTemplate = tmpl
		return nil
	}

	// Load external template files
	if ac.TemplateDirectory != "" {
		if err := ac.loadExternalTemplates(funcMap); err != nil {
			return fmt.Errorf("failed to load external templates: %v", err)
		}
	}

	// Parse inline templates
	for name, content := range ac.Templates {
		tmpl, err := template.New(name).Funcs(funcMap).Parse(content)
		if err != nil {
			return fmt.Errorf("failed to parse inline template '%s': %v", name, err)
		}
		ac.parsedTemplates[name] = tmpl
	}

	// Validate that default template exists if specified
	if ac.DefaultTemplate != "" {
		if _, exists := ac.parsedTemplates[ac.DefaultTemplate]; !exists {
			return fmt.Errorf("default template '%s' not found in available templates", ac.DefaultTemplate)
		}
	} else if len(ac.parsedTemplates) > 0 {
		// Set a default template if none specified but templates exist
		for name := range ac.parsedTemplates {
			ac.DefaultTemplate = name
			break
		}
	}

	// Validate that all template rules reference existing templates
	for i, rule := range ac.TemplateRules {
		if _, exists := ac.parsedTemplates[rule.Template]; !exists {
			return fmt.Errorf("template rule %d references non-existent template '%s'", i, rule.Template)
		}
	}

	return nil
}

// loadExternalTemplates loads templates from the template directory
func (ac *AlertingConfig) loadExternalTemplates(funcMap template.FuncMap) error {
	entries, err := ioutil.ReadDir(ac.TemplateDirectory)
	if err != nil {
		return fmt.Errorf("failed to read template directory '%s': %v", ac.TemplateDirectory, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Only process .tmpl and .template files
		filename := entry.Name()
		if !strings.HasSuffix(filename, ".tmpl") && !strings.HasSuffix(filename, ".template") {
			continue
		}

		// Template name is filename without extension
		templateName := strings.TrimSuffix(strings.TrimSuffix(filename, ".tmpl"), ".template")

		filePath := filepath.Join(ac.TemplateDirectory, filename)
		content, err := ioutil.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read template file '%s': %v", filePath, err)
		}

		tmpl, err := template.New(templateName).Funcs(funcMap).Parse(string(content))
		if err != nil {
			return fmt.Errorf("failed to parse template file '%s': %v", filePath, err)
		}

		ac.parsedTemplates[templateName] = tmpl
	}

	return nil
}

// GetTemplate returns the parsed legacy template (for backward compatibility)
func (ac *AlertingConfig) GetTemplate() *template.Template {
	return ac.parsedTemplate
}

// GetTemplateCount returns the number of available templates
func (ac *AlertingConfig) GetTemplateCount() int {
	if ac.parsedTemplate != nil {
		return 1 // Legacy mode
	}
	return len(ac.parsedTemplates)
}

// SelectTemplate selects the appropriate template based on alert labels and annotations
func (ac *AlertingConfig) SelectTemplate(labels, annotations labels.Labels) string {
	// Legacy mode: use single template
	if ac.parsedTemplate != nil {
		return ""
	}

	labelsMap := labels.Map()
	annotationsMap := annotations.Map()

	// Check each rule in order (first match wins)
	for _, rule := range ac.TemplateRules {
		if ac.matchesRule(rule, labelsMap, annotationsMap) {
			return rule.Template
		}
	}

	// Fallback to default template
	return ac.DefaultTemplate
}

// matchesRule checks if a template rule matches the given labels and annotations
func (ac *AlertingConfig) matchesRule(rule TemplateRule, labels, annotations map[string]string) bool {
	// Check label matches (all must match)
	for key, expectedValue := range rule.MatchLabels {
		if actualValue, exists := labels[key]; !exists || actualValue != expectedValue {
			return false
		}
	}

	// Check annotation matches (all must match)
	for key, expectedValue := range rule.MatchAnnotations {
		if expectedValue == "*" {
			// Wildcard: just check that the annotation exists
			if _, exists := annotations[key]; !exists {
				return false
			}
		} else {
			// Exact match required
			if actualValue, exists := annotations[key]; !exists || actualValue != expectedValue {
				return false
			}
		}
	}

	return true
}

// GenerateURL generates a URL using the legacy single template (for backward compatibility)
func (ac *AlertingConfig) GenerateURL(data map[string]interface{}) (string, error) {
	if ac.parsedTemplate == nil {
		return "", fmt.Errorf("template not initialized")
	}

	var buf bytes.Buffer
	if err := ac.parsedTemplate.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute generator URL template: %v", err)
	}

	return buf.String(), nil
}

// GenerateURLWithTemplate generates a URL using a specific named template
func (ac *AlertingConfig) GenerateURLWithTemplate(templateName string, data interface{}) (string, error) {
	// Legacy mode: use the single template
	if ac.parsedTemplate != nil {
		return ac.GenerateURL(data.(map[string]interface{}))
	}

	// Get the specified template
	tmpl, exists := ac.parsedTemplates[templateName]
	if !exists {
		return "", fmt.Errorf("template '%s' not found", templateName)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template '%s': %v", templateName, err)
	}

	return buf.String(), nil
}

// TemplateData represents the data available to the generator URL template
type TemplateData struct {
	ExternalURL string
	Expr        string
	Labels      map[string]string
	Annotations map[string]string
	AlertName   string
}

// CreateTemplateData creates template data from alert information
func CreateTemplateData(externalURL, expr string, labels, annotations labels.Labels) TemplateData {
	labelsMap := make(map[string]string)
	annotationsMap := make(map[string]string)
	alertName := ""

	for _, label := range labels {
		labelsMap[label.Name] = label.Value
		if label.Name == "alertname" {
			alertName = label.Value
		}
	}

	for _, annotation := range annotations {
		annotationsMap[annotation.Name] = annotation.Value
	}

	return TemplateData{
		ExternalURL: externalURL,
		Expr:        expr,
		Labels:      labelsMap,
		Annotations: annotationsMap,
		AlertName:   alertName,
	}
}
