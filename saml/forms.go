package saml

import (
	"fmt"
	"net/url"

	"github.com/PuerkitoBio/goquery"
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

	doc, err := goquery.NewDocumentFromResponse(r)
	if err != nil {
		return
	}

	g.currentFormAction = scrapeFormAction(doc)
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

	doc, err := goquery.NewDocumentFromResponse(r)
	if err != nil {
		return
	}

	g.currentFormAction = scrapeFormAction(doc)
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

	doc, err := goquery.NewDocumentFromResponse(r)
	if err != nil {
		return
	}

	g.currentFormAction = scrapeFormActionF(doc)
	g.currentFormValues = scrapeFormValues(doc)
	g.samlResponse = scrapeSAMLResponse(doc)

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
