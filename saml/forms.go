package saml

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
)

func (g *GSuite) initSSOString() string {
	return fmt.Sprintf("https://accounts.google.com/o/saml2/initsso?idpid=%s&spid=%s&forceauthn=false", g.idpid, g.spid)
}

// getLoginForm gets the login form.
func (g *GSuite) getLoginForm() (err error) {
	r, err := g.Get(g.initSSOString())
	if err != nil {
		return
	}

	if r.StatusCode != http.StatusOK {
		return errors.Errorf("failed to get login form, status code %d", r.StatusCode)
	}

	doc, err := goquery.NewDocumentFromResponse(r)
	if err != nil {
		return
	}

	if g.currentFormAction, err = scrapeFormAction(doc); err != nil {
		return
	}

	if g.cont, err = scrapeContinue(doc); err != nil {
		return
	}

	g.currentFormValues = scrapeFormValues(doc)

	return err
}

// enterEmail sets the email in the form.
func (g *GSuite) enterEmail(email string) (err error) {
	g.currentFormValues["Email"] = []string{email}

	r, err := g.PostForm(g.currentFormAction, g.currentFormValues)
	if err != nil {
		return
	}

	if r.StatusCode != http.StatusOK {
		return errors.Errorf("email failed, status code %d", r.StatusCode)
	}

	doc, err := goquery.NewDocumentFromResponse(r)
	if err != nil {
		return
	}

	if g.currentFormAction, err = scrapeFormAction(doc); err != nil {
		return
	}

	if g.cont, err = scrapeContinue(doc); err != nil {
		return
	}

	g.currentFormValues = scrapeFormValues(doc)

	return err
}

// enterPassword sets the password in the form.
func (g *GSuite) enterPassword(e, p string) (err error) {
	g.currentFormValues["Email"] = []string{e}
	g.currentFormValues["Passwd"] = []string{p}

	r, err := g.PostForm(g.currentFormAction, g.currentFormValues)
	if err != nil {
		return
	}

	if r.StatusCode != http.StatusOK {
		return errors.Errorf("password failed, status code %d", r.StatusCode)
	}

	doc, err := goquery.NewDocumentFromResponse(r)
	if err != nil {
		return
	}

	if g.currentFormAction, err = scrapeFormActionF(doc); err != nil {
		return
	}

	if g.cont, err = scrapeContinue(doc); err != nil {
		return
	}

	if g.tl, err = scrapeTL(doc); err != nil {
		return
	}

	if g.gxf, err = scrapeGXF(doc); err != nil {
		return
	}

	g.currentFormValues = scrapeFormValues(doc)

	return err
}

// enterMFA sets the MFA token in the form.
func (g *GSuite) enterMFA(m string) (err error) {
	parts := strings.Split(g.currentFormAction, "totp/")

	g.currentFormValues["continue"] = []string{g.cont}
	g.currentFormValues["scc"] = []string{"1"}
	g.currentFormValues["sarp"] = []string{"1"}
	g.currentFormValues["TrustDevice"] = []string{"on"}
	g.currentFormValues["challengeId"] = []string{parts[1]}
	g.currentFormValues["challengeType"] = []string{"6"}
	g.currentFormValues["Pin"] = []string{m}
	g.currentFormValues["TL"] = []string{g.tl}
	g.currentFormValues["gxf"] = []string{g.gxf}
	g.currentFormValues["pstMsg"] = []string{"0"}
	g.currentFormValues["checkedDomains"] = []string{"youtube"}

	r, err := g.PostForm("https://accounts.google.com"+g.currentFormAction, g.currentFormValues)
	if err != nil {
		return
	}

	if r.StatusCode != http.StatusOK {
		return errors.Errorf("MFA pin failed, status code %d", r.StatusCode)
	}

	doc, err := goquery.NewDocumentFromResponse(r)
	if err != nil {
		return
	}

	if g.currentFormAction, err = scrapeFormActionF(doc); err != nil {
		return
	}

	g.currentFormValues = scrapeFormValues(doc)

	if g.samlResponse, err = scrapeSAMLResponse(doc); err != nil {
		return
	}

	return err
}

// postAWSSaml performs an HTTP POST ...
func (g *GSuite) postAWSSaml() (accounts []Account, err error) {
	res, err := g.PostForm(g.currentFormAction, url.Values{"SAMLResponse": {g.samlResponse}})
	if err != nil {
		return
	}

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return
	}

	return scrapeAWSInfo(doc)
}
