package main

import (
	"fmt"
	"log"

	"github.com/talos-systems/go-gsuite/saml"
)

func prompt(accounts []saml.Account) (arn string) {
	arns := []string{}
	for _, account := range accounts {
		fmt.Printf("%s\n", account.Name)
		for _, role := range account.Roles {
			arns = append(arns, role.ARN)
			fmt.Printf("[%d]: \t%s\n", len(arns), role.ARN)
		}
	}

	fmt.Printf("Select and ARN: ")
	var i int
	_, err := fmt.Scanf("%d", &i)
	if err != nil {
		log.Fatal(err)
	}

	if len(arns) < i {
		return
	}

	// Decrement by 1 to take into consideration that we prompt starting at
	// 1.
	i--

	fmt.Printf("Retrieving credentials for ARN: %s\n", arns[i])

	return arns[i]
}

func main() {
	g, err := saml.NewGSuiteSAMLLogin("", "")
	if err != nil {
		log.Fatal(err.Error())
	}

	accounts, err := g.Login("", "")
	if err != nil {
		log.Fatal(err.Error())
	}

	arn := prompt(accounts)

	o, err := g.RetrieveAWSCredentials(
		"",
		arn,
	)
	if err != nil {
		log.Fatal(err.Error())
	}

	g.SaveAWSCredentials(o, "")
}
