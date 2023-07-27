package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/garyburd/go-oauth/oauth"
)

type PlurkCredentials struct {
	ConsumerToken  string
	ConsumerSecret string
	AccessToken    string
	AccessSecret   string
}

const baseURL = "https://www.plurk.com"

var oauthClient = oauth.Client{
	TemporaryCredentialRequestURI: "https://www.plurk.com/OAuth/request_token",
	ResourceOwnerAuthorizationURI: "https://www.plurk.com/OAuth/authorize",
	TokenRequestURI:               "https://www.plurk.com/OAuth/access_token",
}

var plurkOAuth PlurkCredentials
var signinOAuthClient oauth.Client

var credPath = flag.String("config", "config.json", "Path to configuration file containing the application's credentials.")

func ReadCredentials(credPath string) (*PlurkCredentials, error) {
	b, err := ioutil.ReadFile(credPath)
	if err != nil {
		return nil, err
	}
	var cred PlurkCredentials
	err = json.Unmarshal(b, &cred)
	if err != nil {
		return nil, err
	}
	return &cred, nil
}

func doAuth(requestToken *oauth.Credentials) (*oauth.Credentials, error) {
	_url := oauthClient.AuthorizationURL(requestToken, nil)
	fmt.Println("Open the following URL and authorize it:", _url)

	var pinCode string
	fmt.Print("Input the PIN code: ")
	fmt.Scan(&pinCode)
	accessToken, _, err := oauthClient.RequestToken(http.DefaultClient, requestToken, pinCode)
	if err != nil {
		log.Fatal("failed to request token:", err)
	}
	return accessToken, nil
}

func getAccessToken(impl_ func(*PlurkCredentials) (*oauth.Credentials, bool, error),
	cred *PlurkCredentials) (*oauth.Credentials, bool, error) {
	return impl_(cred)
}

func GetAccessToken(cred *PlurkCredentials) (*oauth.Credentials, bool, error) {
	oauthClient.Credentials.Token = cred.ConsumerToken
	oauthClient.Credentials.Secret = cred.ConsumerSecret

	authorized := false
	var token *oauth.Credentials
	if cred.AccessToken != "" && cred.AccessSecret != "" {
		token = &oauth.Credentials{cred.AccessToken, cred.AccessSecret}
	} else {
		requestToken, err := oauthClient.RequestTemporaryCredentials(http.DefaultClient, "", nil)
		if err != nil {
			log.Printf("failed to request temporary credentials: %v", err)
			return nil, false, err
		}
		token, err = doAuth(requestToken)
		if err != nil {
			log.Printf("failed to request temporary credentials: %v", err)
			return nil, false, err
		}

		cred.AccessToken = token.Token
		cred.AccessSecret = token.Secret
		authorized = true
	}
	return token, authorized, nil
}

func callAPI(impl_ func(*oauth.Credentials, string, map[string]string) ([]byte, error),
	token *oauth.Credentials, _url string, opt map[string]string) ([]byte, error) {
	return impl_(token, _url, opt)
}

func CallAPI(token *oauth.Credentials, _url string, opt map[string]string) ([]byte, error) {
	return callAPI(callAPI_, token, _url, opt)
}

func callAPI_(token *oauth.Credentials, _url string, opt map[string]string) ([]byte, error) {
	var apiURL = baseURL + _url
	param := make(url.Values)
	for k, v := range opt {
		param.Set(k, v)
	}
	oauthClient.SignParam(token, "POST", apiURL, param)
	res, err := http.PostForm(apiURL, url.Values(param))
	if err != nil {
		log.Println("failed to call API:", err, apiURL, param)
		return nil, err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println("failed to get response:", err)
		return nil, err
	}
	if res.StatusCode != 200 {
		log.Println("failed to call API err=200:", err, apiURL, param)
		return nil, fmt.Errorf("%s", string(body))
	}
	return body, nil
}

func main() {
	flag.Parse()
	plurkOAuth, err := ReadCredentials(*credPath)
	if err != nil {
		log.Fatalf("Error reading credential, %v", err)
	}
	accessToken, authorized, err := GetAccessToken(plurkOAuth)

	if authorized {
		bytes, err := json.MarshalIndent(plurkOAuth, "", "  ")
		if err != nil {
			log.Fatalf("failed to store credential: %v", err)
		}
		err = ioutil.WriteFile(*credPath, bytes, 0700)
		if err != nil {
			log.Fatal("failed to write credential: %v", err)
		}
	}
	result, err := CallAPI(accessToken, "/APP/Profile/getOwnProfile", map[string]string{})
	if err != nil {
		log.Fatalf("failed: %v", err)
	}
	fmt.Println(string(result))
}
