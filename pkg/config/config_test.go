package proxyconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/prometheus/model/labels"
)

func TestConfigFromFile(t *testing.T) {
	file, err := os.CreateTemp(os.TempDir(), "")
	if err != nil {
		t.Errorf("Could not create temp file:")
	}

	fileContents := `
tls_server_config:
  cert_file: "server.crt"
  key_file : "server.key"
  client_auth_type : "VerifyClientCertIfGiven"
  client_ca_file : "tls-ca-chain.pem"
`
	file.Write([]byte(fileContents))
	configFilePath := file.Name()

	cfg, err := ConfigFromFile(configFilePath)
	if err != nil {
		t.Errorf("Error was not nil: %+v", err)
	}

	if cfg.WebConfig.TLSCertPath != "server.crt" {
		t.Errorf("Invalid TLSKeypath. Expected 'server.crt', Got '%s'", cfg.WebConfig.TLSCertPath)
	}
	if cfg.WebConfig.TLSKeyPath != "server.key" {
		t.Errorf("Invalid TLSCertPath. Expected 'server.key', Got '%s'", cfg.WebConfig.TLSKeyPath)
	}
	if cfg.WebConfig.ClientAuth != "VerifyClientCertIfGiven" {
		t.Errorf("Invalid ClientAuth. Expected 'VerifyClientCertIfGiven', Got '%s'", cfg.WebConfig.ClientAuth)
	}
	if cfg.WebConfig.ClientCAs != "tls-ca-chain.pem" {
		t.Errorf("Invalid ClientCAs. Expected 'tls-ca-chain.pem', Got '%s'", cfg.WebConfig.ClientCAs)
	}
}

func TestAlertingConfigTemplate(t *testing.T) {
	tests := []struct {
		name        string
		template    string
		expectedURL string
		shouldFail  bool
	}{
		{
			name:        "Default Prometheus template",
			template:    "{{.ExternalURL}}/graph?g0.expr={{.Expr | urlquery}}&g0.tab=1",
			expectedURL: "http://promxy.example.com/graph?g0.expr=up+%3D%3D+0&g0.tab=1",
			shouldFail:  false,
		},
		{
			name:        "Grafana alerting template",
			template:    "https://grafana.example.com/alerting/groups?queryString=alertname%3D%22{{.AlertName | urlquery}}%22",
			expectedURL: "https://grafana.example.com/alerting/groups?queryString=alertname%3D%22TargetDown%22",
			shouldFail:  false,
		},
		{
			name:        "Custom dashboard with cluster",
			template:    "https://dashboard.example.com/alerts?alert={{.AlertName | urlquery}}&cluster={{.Labels.cluster | urlquery}}",
			expectedURL: "https://dashboard.example.com/alerts?alert=TargetDown&cluster=production",
			shouldFail:  false,
		},
		{
			name:        "URL path escaping",
			template:    "https://wiki.example.com/runbooks/{{.Labels.team | urlpath}}/{{.AlertName | urlpath}}",
			expectedURL: "https://wiki.example.com/runbooks/production/TargetDown",
			shouldFail:  false,
		},
		{
			name:       "Invalid template",
			template:   "{{.AlertName | invalidfunction}}",
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := AlertingConfig{
				GeneratorURLTemplate: tt.template,
			}

			err := config.SetTemplate()
			if tt.shouldFail && err != nil {
				// Expected parsing failure
				return
			}

			if err != nil {
				t.Errorf("Template parsing failed: %v", err)
				return
			}

			// Create test data
			testLabels := labels.Labels{
				labels.Label{Name: "alertname", Value: "TargetDown"},
				labels.Label{Name: "cluster", Value: "production"},
				labels.Label{Name: "instance", Value: "localhost:9090"},
				labels.Label{Name: "team", Value: "production"},
			}
			testAnnotations := labels.Labels{
				labels.Label{Name: "summary", Value: "Target is down"},
				labels.Label{Name: "description", Value: "Target localhost:9090 is down"},
			}

			templateData := CreateTemplateData("http://promxy.example.com", "up == 0", testLabels, testAnnotations)
			templateDataMap := map[string]interface{}{
				"ExternalURL": templateData.ExternalURL,
				"Expr":        templateData.Expr,
				"Labels":      templateData.Labels,
				"Annotations": templateData.Annotations,
				"AlertName":   templateData.AlertName,
			}

			url, err := config.GenerateURL(templateDataMap)
			if tt.shouldFail {
				if err == nil {
					t.Errorf("Expected URL generation to fail, but it succeeded")
				}
				return
			}

			if err != nil {
				t.Errorf("URL generation failed: %v", err)
				return
			}

			if url != tt.expectedURL {
				t.Errorf("Expected URL %s, got %s", tt.expectedURL, url)
			}
		})
	}
}

func TestEnhancedTemplateSelection(t *testing.T) {
	tests := []struct {
		name             string
		config           AlertingConfig
		alertLabels      map[string]string
		alertAnns        map[string]string
		expectedTemplate string
	}{
		{
			name: "Label-based template selection",
			config: AlertingConfig{
				DefaultTemplate: "default",
				TemplateRules: []TemplateRule{
					{
						MatchLabels: map[string]string{"severity": "critical"},
						Template:    "pagerduty",
					},
				},
				Templates: map[string]string{
					"default":   "https://grafana.example.com/alert?name={{.AlertName}}",
					"pagerduty": "https://pagerduty.example.com/incident?alert={{.AlertName}}",
				},
			},
			alertLabels:      map[string]string{"severity": "critical", "alertname": "HighCPU"},
			alertAnns:        map[string]string{},
			expectedTemplate: "pagerduty",
		},
		{
			name: "Annotation-based template selection",
			config: AlertingConfig{
				DefaultTemplate: "default",
				TemplateRules: []TemplateRule{
					{
						MatchAnnotations: map[string]string{"runbook_url": "*"},
						Template:         "runbook",
					},
				},
				Templates: map[string]string{
					"default": "https://grafana.example.com/alert?name={{.AlertName}}",
					"runbook": "{{.Annotations.runbook_url}}?alert={{.AlertName}}",
				},
			},
			alertLabels:      map[string]string{"alertname": "DatabaseDown"},
			alertAnns:        map[string]string{"runbook_url": "https://wiki.example.com/db-runbook"},
			expectedTemplate: "runbook",
		},
		{
			name: "Multiple rules - first match wins",
			config: AlertingConfig{
				DefaultTemplate: "default",
				TemplateRules: []TemplateRule{
					{
						MatchLabels: map[string]string{"team": "database"},
						Template:    "db_dashboard",
					},
					{
						MatchLabels: map[string]string{"severity": "critical"},
						Template:    "pagerduty",
					},
				},
				Templates: map[string]string{
					"default":      "https://grafana.example.com/alert?name={{.AlertName}}",
					"db_dashboard": "https://grafana.example.com/d/database?alert={{.AlertName}}",
					"pagerduty":    "https://pagerduty.example.com/incident?alert={{.AlertName}}",
				},
			},
			alertLabels:      map[string]string{"team": "database", "severity": "critical", "alertname": "DBDown"},
			alertAnns:        map[string]string{},
			expectedTemplate: "db_dashboard", // First rule matches
		},
		{
			name: "No matching rules - use default",
			config: AlertingConfig{
				DefaultTemplate: "default",
				TemplateRules: []TemplateRule{
					{
						MatchLabels: map[string]string{"severity": "critical"},
						Template:    "pagerduty",
					},
				},
				Templates: map[string]string{
					"default":   "https://grafana.example.com/alert?name={{.AlertName}}",
					"pagerduty": "https://pagerduty.example.com/incident?alert={{.AlertName}}",
				},
			},
			alertLabels:      map[string]string{"severity": "warning", "alertname": "HighCPU"},
			alertAnns:        map[string]string{},
			expectedTemplate: "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup config
			err := tt.config.SetTemplate()
			if err != nil {
				t.Fatalf("Failed to setup config: %v", err)
			}

			// Convert maps to labels.Labels
			var alertLabels labels.Labels
			for k, v := range tt.alertLabels {
				alertLabels = append(alertLabels, labels.Label{Name: k, Value: v})
			}

			var alertAnns labels.Labels
			for k, v := range tt.alertAnns {
				alertAnns = append(alertAnns, labels.Label{Name: k, Value: v})
			}

			// Test template selection
			selected := tt.config.SelectTemplate(alertLabels, alertAnns)
			if selected != tt.expectedTemplate {
				t.Errorf("Expected template '%s', got '%s'", tt.expectedTemplate, selected)
			}

			// Test URL generation
			templateData := CreateTemplateData("https://promxy.example.com", "up == 0", alertLabels, alertAnns)
			url, err := tt.config.GenerateURLWithTemplate(selected, templateData)
			if err != nil {
				t.Errorf("Failed to generate URL: %v", err)
			}

			// Basic validation that URL was generated
			if url == "" {
				t.Error("Generated URL is empty")
			}
		})
	}
}

func TestExternalTemplateFiles(t *testing.T) {
	// Create temporary directory for templates
	tempDir, err := os.MkdirTemp("", "promxy_templates_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test template files
	templates := map[string]string{
		"grafana.tmpl":       "https://grafana.example.com/alert?name={{.AlertName | urlquery}}",
		"pagerduty.template": "https://pagerduty.example.com/incident?alert={{.AlertName | urlquery}}&severity={{.Labels.severity}}",
		"ignored.txt":        "This should be ignored",
	}

	for filename, content := range templates {
		filepath := filepath.Join(tempDir, filename)
		err := os.WriteFile(filepath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to write template file %s: %v", filename, err)
		}
	}

	// Test config with external templates
	config := AlertingConfig{
		TemplateDirectory: tempDir,
		DefaultTemplate:   "grafana",
		TemplateRules: []TemplateRule{
			{
				MatchLabels: map[string]string{"severity": "critical"},
				Template:    "pagerduty",
			},
		},
	}

	err = config.SetTemplate()
	if err != nil {
		t.Fatalf("Failed to setup config with external templates: %v", err)
	}

	// Verify templates were loaded
	if config.GetTemplateCount() != 2 { // grafana.tmpl and pagerduty.template
		t.Errorf("Expected 2 templates, got %d", config.GetTemplateCount())
	}

	// Test template selection and URL generation
	alertLabels := labels.Labels{
		labels.Label{Name: "severity", Value: "critical"},
		labels.Label{Name: "alertname", Value: "TestAlert"},
	}
	alertAnns := labels.Labels{}

	selectedTemplate := config.SelectTemplate(alertLabels, alertAnns)
	if selectedTemplate != "pagerduty" {
		t.Errorf("Expected 'pagerduty' template, got '%s'", selectedTemplate)
	}

	templateData := CreateTemplateData("https://promxy.example.com", "up == 0", alertLabels, alertAnns)
	url, err := config.GenerateURLWithTemplate(selectedTemplate, templateData)
	if err != nil {
		t.Errorf("Failed to generate URL: %v", err)
	}

	expectedURL := "https://pagerduty.example.com/incident?alert=TestAlert&severity=critical"
	if url != expectedURL {
		t.Errorf("Expected URL '%s', got '%s'", expectedURL, url)
	}
}

func TestBackwardCompatibility(t *testing.T) {
	// Test that legacy single template mode still works
	config := AlertingConfig{
		GeneratorURLTemplate: "https://grafana.example.com/alert?name={{.AlertName | urlquery}}",
	}

	err := config.SetTemplate()
	if err != nil {
		t.Fatalf("Failed to setup legacy config: %v", err)
	}

	// Should use legacy mode
	if config.GetTemplate() == nil {
		t.Error("Expected legacy template to be set")
	}

	if config.GetTemplateCount() != 1 {
		t.Errorf("Expected 1 template in legacy mode, got %d", config.GetTemplateCount())
	}

	// Test URL generation in legacy mode
	templateData := map[string]interface{}{
		"ExternalURL": "https://promxy.example.com",
		"Expr":        "up == 0",
		"Labels":      map[string]string{"alertname": "TestAlert"},
		"Annotations": map[string]string{},
		"AlertName":   "TestAlert",
	}

	url, err := config.GenerateURL(templateData)
	if err != nil {
		t.Errorf("Failed to generate URL in legacy mode: %v", err)
	}

	expectedURL := "https://grafana.example.com/alert?name=TestAlert"
	if url != expectedURL {
		t.Errorf("Expected URL '%s', got '%s'", expectedURL, url)
	}
}

func TestConfigFromFileWithAlerting(t *testing.T) {
	file, err := os.CreateTemp(os.TempDir(), "")
	if err != nil {
		t.Errorf("Could not create temp file: %v", err)
	}
	defer os.Remove(file.Name())

	fileContents := `
promxy:
  alerting:
    generator_url_template: "https://grafana.example.com/alerting/groups?queryString=alertname%3D%22{{.AlertName | urlquery}}%22"
`
	file.Write([]byte(fileContents))
	configFilePath := file.Name()

	cfg, err := ConfigFromFile(configFilePath)
	if err != nil {
		t.Errorf("Error was not nil: %+v", err)
	}

	expectedTemplate := "https://grafana.example.com/alerting/groups?queryString=alertname%3D%22{{.AlertName | urlquery}}%22"
	if cfg.PromxyConfig.Alerting.GeneratorURLTemplate != expectedTemplate {
		t.Errorf("Expected generator URL template %s, got %s", expectedTemplate, cfg.PromxyConfig.Alerting.GeneratorURLTemplate)
	}

	// Verify template was parsed
	if cfg.PromxyConfig.Alerting.GetTemplate() == nil {
		t.Errorf("Expected template to be parsed, but it was nil")
	}
}
