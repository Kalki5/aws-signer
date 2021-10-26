package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path"
	"regexp"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/atotto/clipboard"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

const (
	baseUrl     = "https://signin.aws.amazon.com/federation"
	redirectUrl = "https://console.aws.amazon.com/console/home?region=ap-south-1"
	issuerUrl   = "https://aws-signer.skaas.guru"
	stsRegion   = "ap-south-1"
)

func getUsername() string {
	reg, _ := regexp.Compile("[^a-zA-Z0-9]+")
	u, _ := user.Current()
	username := strings.Split(u.Username, "\\")[1]
	return reg.ReplaceAllString(username, "")
}

func getProfiles() ([]string, error) {
	homeDir, _ := os.UserHomeDir()
	bytes, err := ioutil.ReadFile(path.Join(homeDir, ".aws", "credentials"))
	if err != nil {
		return nil, err
	}
	credentialText := string(bytes)
	regexMatches := regexp.MustCompile(`\[(.*)\]`).FindAllStringSubmatch(credentialText, -1)

	var profiles []string
	for _, v := range regexMatches {
		profiles = append(profiles, v[1])
	}
	return profiles, nil
}

func chooseProfile(profiles []string) string {
	answers := struct {
		Account string `survey:"account"`
	}{}

	questions := []*survey.Question{
		{
			Name: "account",
			Prompt: &survey.Select{
				Message: "Choose an AWS Profile:",
				Options: profiles,
			},
		},
	}
	survey.Ask(questions, &answers)
	return answers.Account
}

func getUrlEncodedToken(creds types.Credentials) string {
	urlCredentials := struct {
		SessionId    string `json:"sessionId"`
		SessionKey   string `json:"sessionKey"`
		SessionToken string `json:"sessionToken"`
	}{
		SessionId:    *creds.AccessKeyId,
		SessionKey:   *creds.SecretAccessKey,
		SessionToken: *creds.SessionToken,
	}
	urlCredentialsBytes, _ := json.Marshal(urlCredentials)
	return url.QueryEscape(string(urlCredentialsBytes))
}

func main() {
	username := getUsername()
	policy := "arn:aws:iam::aws:policy/AdministratorAccess"

	profiles, err := getProfiles()
	if err != nil {
		fmt.Println("Error Reading Profiles: ", err.Error())
		return
	}
	profile := chooseProfile(profiles)

	cfg, _ := config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile(profile), config.WithRegion(stsRegion))
	client := sts.NewFromConfig(cfg)

	token, err := client.GetFederationToken(context.TODO(), &sts.GetFederationTokenInput{
		Name:       &username,
		PolicyArns: []types.PolicyDescriptorType{{Arn: &policy}},
	})
	if err != nil {
		fmt.Println("GetFederationToken Failed: ", err.Error())
		return
	}

	response, _ := http.Get(baseUrl + "?Action=getSigninToken&Session=" + getUrlEncodedToken(*token.Credentials))
	var body struct{ SigninToken string }
	json.NewDecoder(response.Body).Decode(&body)

	signInUrl := baseUrl + "?Action=login&Issuer=" + url.QueryEscape(issuerUrl) + "&Destination=" + url.QueryEscape(redirectUrl) + "&SigninToken=" + body.SigninToken

	clipboard.WriteAll(signInUrl)
	fmt.Println("\nSignIn URL copied to ClipBoard")
}
