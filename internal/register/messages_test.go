package register

import (
	"html/template"
	"strings"
	"testing"
	texttemplate "text/template"
)

func testUser() *User {
	return &User{
		Name:     "Test User",
		Email:    "test@example.com",
		Dojo:     "Tokyo Dojo",
		Rank:     "5th Kyu",
		WhatsApp: "+6281234567890",
	}
}

// TestWelcomeMessage_ContentAndEscaping verifies the engine split: literal
// rendering in subject/text (O'Brien stays O'Brien) and safe escaping in HTML.
func TestWelcomeMessage_ContentAndEscaping(t *testing.T) {
	tmpl := newTemplates()
	u := testUser()
	u.Name = "O'Brien"

	msg, err := tmpl.welcomeMessage(u)
	if err != nil {
		t.Fatalf("welcomeMessage: %v", err)
	}
	if msg.To != "test@example.com" {
		t.Errorf("To: got %q", msg.To)
	}
	if msg.Subject != "Welcome to Tenkei Aikidojo, O'Brien" {
		t.Errorf("subject must render literally, got %q", msg.Subject)
	}
	if !strings.Contains(msg.Text, "Hi O'Brien,") {
		t.Errorf("text part must render literally, got %q", msg.Text)
	}
	if strings.Contains(msg.Subject, "&#39;") || strings.Contains(msg.Text, "&#39;") {
		t.Error("subject/text must not be HTML-escaped")
	}
	if !strings.Contains(msg.HTML, "O&#39;Brien") {
		t.Errorf("HTML part must escape the name, got %q", msg.HTML)
	}
	if !strings.Contains(msg.Text, "verified by an administrator") {
		t.Errorf("welcome email must explain the verification step")
	}
}

// TestWelcomeMessage_ScriptInNameEscaped ensures injected HTML in a name is
// neutralized in the HTML part.
func TestWelcomeMessage_ScriptInNameEscaped(t *testing.T) {
	tmpl := newTemplates()
	u := testUser()
	u.Name = "<script>alert('xss')</script>"

	msg, err := tmpl.welcomeMessage(u)
	if err != nil {
		t.Fatalf("welcomeMessage: %v", err)
	}
	if strings.Contains(msg.HTML, "<script>") {
		t.Errorf("HTML part must escape script tags, got %q", msg.HTML)
	}
	if !strings.Contains(msg.HTML, "&lt;script&gt;") {
		t.Errorf("HTML part should contain escaped tag, got %q", msg.HTML)
	}
}

// TestAdminMessage_FieldsAndPIIBound verifies the admin notice carries
// name/email/rank/dojo and none of the sensitive fields.
func TestAdminMessage_FieldsAndPIIBound(t *testing.T) {
	tmpl := newTemplates()
	u := testUser()
	// Populate every sensitive field: none may leak into the notice.
	u.DateOfBirth = testUser().DateOfBirth
	u.MedicalConditions = "asthma"
	u.EmergencyContactName = "Jane Doe"
	u.EmergencyContactNumber = "+6289876543210"

	msg, err := tmpl.adminMessage(u, "info@tenkeiaikidojo.org")
	if err != nil {
		t.Fatalf("adminMessage: %v", err)
	}
	if msg.To != "info@tenkeiaikidojo.org" {
		t.Errorf("To: got %q", msg.To)
	}
	for _, want := range []string{"Test User", "test@example.com", "5th Kyu", "Tokyo Dojo"} {
		if !strings.Contains(msg.Subject+msg.Text+msg.HTML, want) {
			t.Errorf("admin notice missing %q", want)
		}
	}
	for _, banned := range []string{
		"+6281234567890", // WhatsApp
		"asthma",         // medical conditions
		"Jane Doe",       // emergency contact name
		"+6289876543210", // emergency contact number
	} {
		if strings.Contains(msg.Subject+msg.Text+msg.HTML, banned) {
			t.Errorf("admin notice leaks banned field %q", banned)
		}
	}
}

// TestAdminMessage_SensitiveNameEscapedInHTML keeps the PII bound honest even
// for hostile values in allowed fields.
func TestAdminMessage_SensitiveNameEscapedInHTML(t *testing.T) {
	tmpl := newTemplates()
	u := testUser()
	u.Name = "<img src=x onerror=alert(1)>"

	msg, err := tmpl.adminMessage(u, "info@tenkeiaikidojo.org")
	if err != nil {
		t.Fatalf("adminMessage: %v", err)
	}
	if strings.Contains(msg.HTML, "<img") {
		t.Errorf("admin HTML must escape injected markup, got %q", msg.HTML)
	}
}

// TestRenderExecuteErrors_Propagate covers the render error guards with a
// template that fails at execute time (index into a string field).
func TestRenderExecuteErrors_Propagate(t *testing.T) {
	brokenText := texttemplate.Must(texttemplate.New("broken").Parse(`{{index .Name 500}}`))
	if _, err := renderText(brokenText, welcomeData{Name: "x"}); err == nil {
		t.Error("renderText must propagate execute errors")
	}
	brokenHTML := template.Must(template.New("broken").Parse(`{{index .Name 500}}`))
	if _, err := renderHTML(brokenHTML, welcomeData{Name: "x"}); err == nil {
		t.Error("renderHTML must propagate execute errors")
	}
}

// TestMessageBuilder_ErrorBranches injects one broken template at a time to
// cover each guard in welcomeMessage/adminMessage without shipping broken
// constants.
func TestMessageBuilder_ErrorBranches(t *testing.T) {
	broken := func() *texttemplate.Template {
		return texttemplate.Must(texttemplate.New("broken").Parse(`{{index .Name 500}}`))
	}
	brokenH := func() *template.Template {
		return template.Must(template.New("brokenH").Parse(`{{index .Name 500}}`))
	}

	t.Run("welcome subject fails", func(t *testing.T) {
		tmpl := newTemplates()
		tmpl.welcomeSubject = broken()
		if _, err := tmpl.welcomeMessage(testUser()); err == nil {
			t.Error("want error")
		}
	})
	t.Run("welcome text fails", func(t *testing.T) {
		tmpl := newTemplates()
		tmpl.welcomeText = broken()
		if _, err := tmpl.welcomeMessage(testUser()); err == nil {
			t.Error("want error")
		}
	})
	t.Run("welcome html fails", func(t *testing.T) {
		tmpl := newTemplates()
		tmpl.welcomeHTML = brokenH()
		if _, err := tmpl.welcomeMessage(testUser()); err == nil {
			t.Error("want error")
		}
	})
	t.Run("admin subject fails", func(t *testing.T) {
		tmpl := newTemplates()
		tmpl.adminSubject = broken()
		if _, err := tmpl.adminMessage(testUser(), "info@x"); err == nil {
			t.Error("want error")
		}
	})
	t.Run("admin text fails", func(t *testing.T) {
		tmpl := newTemplates()
		tmpl.adminText = broken()
		if _, err := tmpl.adminMessage(testUser(), "info@x"); err == nil {
			t.Error("want error")
		}
	})
	t.Run("admin html fails", func(t *testing.T) {
		tmpl := newTemplates()
		tmpl.adminHTML = brokenH()
		if _, err := tmpl.adminMessage(testUser(), "info@x"); err == nil {
			t.Error("want error")
		}
	})
}

// TestNewTemplates_PanicsOnBrokenTemplate documents the intended fail-fast:
// template.Must at construction, never a mid-request error. (No assertion can
// trigger it with the shipped constants — this test pins the constructor.)
func TestNewTemplates_ParsesAllSix(t *testing.T) {
	tmpl := newTemplates()
	for _, name := range []string{"welcomeSubject", "welcomeText", "welcomeHTML", "adminSubject", "adminText", "adminHTML"} {
		switch name {
		case "welcomeSubject":
			if tmpl.welcomeSubject == nil {
				t.Error("welcomeSubject not parsed")
			}
		case "welcomeText":
			if tmpl.welcomeText == nil {
				t.Error("welcomeText not parsed")
			}
		case "welcomeHTML":
			if tmpl.welcomeHTML == nil {
				t.Error("welcomeHTML not parsed")
			}
		case "adminSubject":
			if tmpl.adminSubject == nil {
				t.Error("adminSubject not parsed")
			}
		case "adminText":
			if tmpl.adminText == nil {
				t.Error("adminText not parsed")
			}
		case "adminHTML":
			if tmpl.adminHTML == nil {
				t.Error("adminHTML not parsed")
			}
		}
	}
}
