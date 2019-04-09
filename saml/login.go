package saml

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/go-ini/ini"
	"golang.org/x/net/publicsuffix"
)

// GSuite is ...
type GSuite struct {
	*http.Client
	idpid             string
	spid              string
	currentFormAction string
	currentFormValues url.Values
	samlResponse      string
	email             string
	passwd            string
}

// Account represents an AWS account.
type Account struct {
	Name  string
	Roles []Role
}

// Role represents and AWS role.
type Role struct {
	Name string
	ARN  *arn.ARN
}

// NewGSuiteSAMLLogin instantiates and returns an *GSuite configured with a
// cookie jar.
func NewGSuiteSAMLLogin(idpid, spid string) (g *GSuite, err error) {
	options := &cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}

	// This enables cookies, which is a requirement for the Google authn flow.
	jar, err := cookiejar.New(options)
	if err != nil {
		return
	}

	g = &GSuite{
		&http.Client{
			Jar: jar,
		},
		idpid,
		spid,
		"",
		url.Values{},
		"",
		"",
		"",
	}

	return g, err
}

// Login executes the steps required to login using the Google authn flow.
func (g *GSuite) Login(e, p string) (accounts []Account, err error) {
	err = g.getLoginForm()
	if err != nil {
		return
	}
	err = g.enterEmail(e)
	if err != nil {
		return
	}
	err = g.enterPassword(p)
	if err != nil {
		return
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter PIN: ")
	pin, _ := reader.ReadString('\n')
	pin = strings.Trim(pin, "\n")
	err = g.enterMFA(pin)
	if err != nil {
		return
	}
	return g.postAWSSaml()
}

// RetrieveAWSCredentials gets the STS credentials.
func (g *GSuite) RetrieveAWSCredentials(principal, arn string) (o *sts.AssumeRoleWithSAMLOutput, err error) {
	svc := sts.New(session.New())

	input := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:  &principal,
		RoleArn:       &arn,
		SAMLAssertion: &g.samlResponse,
	}

	o, err = svc.AssumeRoleWithSAML(input)
	if err != nil {
		return
	}

	return o, err
}

// SaveAWSCredentials saves the STS credentials to ~/.aws/credentials.
func (g *GSuite) SaveAWSCredentials(o *sts.AssumeRoleWithSAMLOutput, p string) error {
	usr, err := user.Current()
	if err != nil {
		return err
	}
	dir := usr.HomeDir
	sharedCredentialsFile := filepath.Join(dir, ".aws", "credentials")
	if err := os.MkdirAll(filepath.Dir(sharedCredentialsFile), 0700); err != nil {
		return err
	}
	if _, err := os.Stat(sharedCredentialsFile); os.IsNotExist(err) {
		emptyFile, err := os.Create(sharedCredentialsFile)
		defer emptyFile.Close()
		if err != nil {
			return err
		}
	}
	config, err := ini.Load(sharedCredentialsFile)
	if err != nil {
		return err
	}

	iniProfile, err := config.NewSection(p)
	if err != nil {
		return err
	}
	_, err = iniProfile.NewKey("aws_access_key_id", *o.Credentials.AccessKeyId)
	if err != nil {
		return err
	}
	_, err = iniProfile.NewKey("aws_secret_access_key", *o.Credentials.SecretAccessKey)
	if err != nil {
		return err
	}
	_, err = iniProfile.NewKey("aws_session_token", *o.Credentials.SessionToken)
	if err != nil {
		return err
	}

	err = config.SaveTo(sharedCredentialsFile)
	if err != nil {
		return err
	}

	return nil
}
