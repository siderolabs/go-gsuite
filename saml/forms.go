package saml

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
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

	defer r.Body.Close()

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

	g.currentFormValues = scrapeFormValues(doc)

	return err
}

// enterEmail sets the email in the form.
func (g *GSuite) enterEmail(email string) (err error) {
	g.email = email
	g.currentFormValues["Email"] = []string{g.email}

	r, err := g.PostForm(g.currentFormAction, g.currentFormValues)
	if err != nil {
		return
	}

	defer r.Body.Close()

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

	g.currentFormValues = scrapeFormValues(doc)

	return err
}

// enterPassword sets the password in the form.
func (g *GSuite) enterPassword(passwd string) (err error) {
	g.passwd = passwd

	g.currentFormValues["Email"] = []string{g.email}
	g.currentFormValues["Passwd"] = []string{g.passwd}

	r, err := g.PostForm(g.currentFormAction, g.currentFormValues)
	if err != nil {
		return
	}

	defer r.Body.Close()

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

	g.currentFormValues = scrapeFormValues(doc)

	url, token, required := captchaRequired(doc)
	if required {
		g.enterCAPTCHA(url, token)
	} else {
		// TODO(andrewrynhard): How can we scrape these automatically?
		tl, _ := doc.Find("input[name=TL]").Attr("value")
		g.currentFormValues["TL"] = []string{tl}

		cont, _ := doc.Find("input[name=continue]").Attr("value")
		g.currentFormValues["continue"] = []string{cont}

		scc, _ := doc.Find("input[name=scc]").Attr("value")
		g.currentFormValues["scc"] = []string{scc}

		sarp, _ := doc.Find("input[name=sarp]").Attr("value")
		g.currentFormValues["sarp"] = []string{sarp}

		gxf, _ := doc.Find("input[name=gxf]").Attr("value")
		g.currentFormValues["gxf"] = []string{gxf}
	}

	return err
}

// enterCAPTCHA sets the captcha in the form.
func (g *GSuite) enterCAPTCHA(url, token string) (err error) {
	println("CAPTCHA URL: " + url)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter CAPTCHA: ")
	captcha, _ := reader.ReadString('\n')
	captcha = strings.Trim(captcha, "\n")

	g.currentFormValues["Email"] = []string{g.email}
	g.currentFormValues["Passwd"] = []string{g.passwd}
	g.currentFormValues["logincaptcha"] = []string{captcha}
	g.currentFormValues["logintoken"] = []string{token}
	g.currentFormValues["url"] = []string{url}

	r, err := g.PostForm(g.currentFormAction, g.currentFormValues)
	if err != nil {
		return
	}

	defer r.Body.Close()
	doc, err := goquery.NewDocumentFromResponse(r)
	if err != nil {
		return
	}

	if g.currentFormAction, err = scrapeFormActionF(doc); err != nil {
		return
	}

	g.currentFormValues = scrapeFormValues(doc)

	// TODO(andrewrynhard): How can we scrape these automatically?
	tl, _ := doc.Find("input[name=TL]").Attr("value")
	g.currentFormValues["TL"] = []string{tl}

	cont, _ := doc.Find("input[name=continue]").Attr("value")
	g.currentFormValues["continue"] = []string{cont}

	scc, _ := doc.Find("input[name=scc]").Attr("value")
	g.currentFormValues["scc"] = []string{scc}

	sarp, _ := doc.Find("input[name=sarp]").Attr("value")
	g.currentFormValues["sarp"] = []string{sarp}

	gxf, _ := doc.Find("input[name=gxf]").Attr("value")
	g.currentFormValues["gxf"] = []string{gxf}

	return err
}

// enterMFA sets the MFA token in the form.
func (g *GSuite) enterMFA(m string) (err error) {
	parts := strings.Split(g.currentFormAction, "totp/")

	if len(parts) != 2 {
		return errors.Errorf("could not find challengeId from URL %q", g.currentFormAction)
	}
	g.currentFormValues["TrustDevice"] = []string{"on"}
	g.currentFormValues["challengeId"] = []string{parts[1]}
	g.currentFormValues["challengeType"] = []string{"6"}
	g.currentFormValues["Email"] = []string{g.email}
	g.currentFormValues["Passwd"] = []string{g.passwd}
	g.currentFormValues["Pin"] = []string{m}
	g.currentFormValues["checkedDomains"] = []string{"youtube"}

	r, err := g.PostForm("https://accounts.google.com"+g.currentFormAction, g.currentFormValues)
	if err != nil {
		return
	}

	defer r.Body.Close()

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
