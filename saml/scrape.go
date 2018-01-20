package saml

import (
	"net/url"

	"github.com/PuerkitoBio/goquery"
)

func scrapeFormValues(doc *goquery.Document) (v url.Values) {
	v = url.Values{}
	doc.Find("#gaia_loginform > input").Each(func(i int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		if name == "" {
			return
		}
		value, _ := s.Attr("value")
		v[name] = []string{value}
	})

	return v
}

func scrapeFormAction(doc *goquery.Document) (formAction string) {
	formAction, found := doc.Find("#gaia_loginform").Attr("action")
	if !found {
		return
	}

	return formAction
}

func scrapeFormActionF(doc *goquery.Document) (formAction string) {
	formAction, found := doc.Find("#f").Attr("action")
	if !found {
		return
	}

	return formAction
}

func scrapeSAMLResponse(doc *goquery.Document) (SAMLResponse string) {
	SAMLResponse, found := doc.Find("[name='SAMLResponse']").Attr("value")
	if !found {
		return
	}

	return SAMLResponse
}

func scrapeAWSInfo(doc *goquery.Document) (accounts []Account) {
	accounts = []Account{}
	doc.Find("fieldset > div.saml-account").Each(func(i int, s *goquery.Selection) {
		name := s.Find("div.saml-account-name").Text()
		account := Account{Name: name}
		s.Find("label").Each(func(i int, s *goquery.Selection) {
			arn, _ := s.Attr("for")
			role := Role{
				Name: s.Text(),
				ARN:  arn,
			}
			account.Roles = append(account.Roles, role)
		})
		accounts = append(accounts, account)
	})

	return accounts
}
