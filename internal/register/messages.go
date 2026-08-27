package register

import (
	"fmt"
	"html/template"
	"strings"
	texttemplate "text/template"

	"github.com/sapiderman/tenkei-register/internal/mailer"
)

// templates holds the pre-parsed email templates. Parsed exactly once at
// startup via newTemplates (template.Must panics on syntax error at boot —
// intended fail-fast; the container never starts with a broken template).
//
// Engine split is deliberate: html/template auto-escapes and is used ONLY for
// the HTML part; the subject and plain-text parts use text/template — html
// escaping there would corrupt them (an "O'Brien" name would literally render
// as "O&#39;Brien" in the inbox subject line).
type templates struct {
	welcomeSubject *texttemplate.Template
	welcomeText    *texttemplate.Template
	welcomeHTML    *template.Template
	adminSubject   *texttemplate.Template
	adminText      *texttemplate.Template
	adminHTML      *template.Template
}

// welcomeData carries the (minimal) fields the welcome email renders.
type welcomeData struct {
	Name string
}

// adminData carries exactly what the admin notice may show — name, email,
// rank, dojo. Never DOB, WhatsApp, medical conditions, or emergency contacts
// (PII bound, enforced by tests).
type adminData struct {
	Name  string
	Email string
	Rank  string
	Dojo  string
}

const welcomeSubjectTmpl = `Welcome to Tenkei Aikidojo, {{.Name}}`

const welcomeTextTmpl = `Hi {{.Name}},

Thank you for registering with Tenkei Aikidojo — we have received your registration.

Your account will be reviewed and verified by an administrator. Once verified, you can sign in with your email and password.

If you did not register, you can safely ignore this email.

— Tenkei Aikidojo`

const welcomeHTMLTmpl = `<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; color: #222; max-width: 560px; margin: 0 auto;">
  <h2 style="color: #333;">Welcome to Tenkei Aikidojo, {{.Name}}!</h2>
  <p>Thank you for registering with Tenkei Aikidojo &mdash; we have received your registration.</p>
  <p>Your account will be reviewed and verified by an administrator. Once verified, you can sign in with your email and password.</p>
  <p style="color: #777; font-size: 13px;">If you did not register, you can safely ignore this email.</p>
  <p>&mdash; Tenkei Aikidojo</p>
</body>
</html>`

const adminSubjectTmpl = `New registration: {{.Name}} ({{.Rank}})`

const adminTextTmpl = `A new member has registered and is awaiting verification.

Name:  {{.Name}}
Email: {{.Email}}
Rank:  {{.Rank}}
Dojo:  {{.Dojo}}

Verify this member in the admin panel.`

const adminHTMLTmpl = `<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; color: #222; max-width: 560px; margin: 0 auto;">
  <h2 style="color: #333;">New registration awaiting verification</h2>
  <table style="text-align: left;">
    <tr><th style="padding-right: 12px;">Name:</th><td>{{.Name}}</td></tr>
    <tr><th style="padding-right: 12px;">Email:</th><td>{{.Email}}</td></tr>
    <tr><th style="padding-right: 12px;">Rank:</th><td>{{.Rank}}</td></tr>
    <tr><th style="padding-right: 12px;">Dojo:</th><td>{{.Dojo}}</td></tr>
  </table>
  <p style="color: #777; font-size: 13px;">Verify this member in the admin panel.</p>
</body>
</html>`

// newTemplates parses all email templates. A syntax error here panics at
// startup — the intended fail-fast behavior.
func newTemplates() *templates {
	return &templates{
		welcomeSubject: texttemplate.Must(texttemplate.New("welcomeSubject").Parse(welcomeSubjectTmpl)),
		welcomeText:    texttemplate.Must(texttemplate.New("welcomeText").Parse(welcomeTextTmpl)),
		welcomeHTML:    template.Must(template.New("welcomeHTML").Parse(welcomeHTMLTmpl)),
		adminSubject:   texttemplate.Must(texttemplate.New("adminSubject").Parse(adminSubjectTmpl)),
		adminText:      texttemplate.Must(texttemplate.New("adminText").Parse(adminTextTmpl)),
		adminHTML:      template.Must(template.New("adminHTML").Parse(adminHTMLTmpl)),
	}
}

// renderText executes a text template into a string.
func renderText(tmpl *texttemplate.Template, data any) (string, error) {
	var b strings.Builder
	if err := tmpl.Execute(&b, data); err != nil {
		return "", fmt.Errorf("render %s: %w", tmpl.Name(), err)
	}
	return b.String(), nil
}

// renderHTML executes an HTML template into a string.
func renderHTML(tmpl *template.Template, data any) (string, error) {
	var b strings.Builder
	if err := tmpl.Execute(&b, data); err != nil {
		return "", fmt.Errorf("render %s: %w", tmpl.Name(), err)
	}
	return b.String(), nil
}

// welcomeMessage builds the new-member welcome email.
func (t *templates) welcomeMessage(u *User) (mailer.Message, error) {
	data := welcomeData{Name: u.Name}
	subject, err := renderText(t.welcomeSubject, data)
	if err != nil {
		return mailer.Message{}, err
	}
	text, err := renderText(t.welcomeText, data)
	if err != nil {
		return mailer.Message{}, err
	}
	html, err := renderHTML(t.welcomeHTML, data)
	if err != nil {
		return mailer.Message{}, err
	}
	return mailer.Message{To: u.Email, Subject: subject, HTML: html, Text: text}, nil
}

// adminMessage builds the new-registration notice for the Tenkei team.
func (t *templates) adminMessage(u *User, notifyEmail string) (mailer.Message, error) {
	data := adminData{Name: u.Name, Email: u.Email, Rank: u.Rank, Dojo: u.Dojo}
	subject, err := renderText(t.adminSubject, data)
	if err != nil {
		return mailer.Message{}, err
	}
	text, err := renderText(t.adminText, data)
	if err != nil {
		return mailer.Message{}, err
	}
	html, err := renderHTML(t.adminHTML, data)
	if err != nil {
		return mailer.Message{}, err
	}
	return mailer.Message{To: notifyEmail, Subject: subject, HTML: html, Text: text}, nil
}
