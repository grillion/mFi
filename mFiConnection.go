package mFi

import (
	"net/url"
	"net/http"
	"fmt"
	"log"
	"io"
	"strings"
	"net/http/cookiejar"
)

type UrlParam struct {
	key string
	value string
}

/**
 *	mFi Base, HTTP requests, get a websocket connection, handles session
 */
type MFiConnection struct {
	Hostname string
	HTTPPort int
	WebSocketPort int
	Username string
	Password string
	SessionId string
}

func NewConnection(hostname string, username string, password string) *MFiConnection {
	return &MFiConnection{
		Hostname: hostname,
		HTTPPort: 80,
		WebSocketPort: 7681,
		Username: username,
		Password: password}
}

func (m *MFiConnection) IsLoggedIn() bool {
	return m.SessionId != ""
}

/**
 * Connect to device
 * This will attempt to login and create a session with the device
 */
func (m *MFiConnection) Login() (string, error){

	// Must be 32 chars
	m.SessionId = "01234567890123456789012345678901";

	form := url.Values{}
	form.Add("username", m.Username)
	form.Add("password", m.Password)

	_, err := m.HttpPost("login.cgi", nil, form)

	if(err != nil) {
		return "", err
	}

	//bodyContents, err := ioutil.ReadAll(resp.Body)
	//fmt.Printf("Login successful. Response (%d): %s\n", resp.StatusCode, bodyContents)

	return m.SessionId, nil
}

func (m *MFiConnection) Logout(){

}

func (m *MFiConnection) GetWebsocket() *mFiWebSocket{
	return &mFiWebSocket{}
}

func (m *MFiConnection) HttpReq(method string, requestUrl string, urlParams[] UrlParam, postForm url.Values) (*http.Response, error) {

	fullUrl := fmt.Sprintf("http://%s:%d/%s", m.Hostname, m.HTTPPort, requestUrl)

	sessionCookie := &http.Cookie{
		Name: "AIROS_SESSIONID",
		Value: m.SessionId,
		Path: "/"}

	var cookies []*http.Cookie
	cookies = append(cookies, sessionCookie)
	cookieJar, _ := cookiejar.New(nil)
	cookieUrl, _ := url.Parse(fullUrl)
	cookieJar.SetCookies(cookieUrl, cookies)

	httpClient := &http.Client{Jar: cookieJar}

	var postReader io.Reader
	if(postForm != nil && method != "GET") {
		postReader = strings.NewReader(postForm.Encode())
	}

	req, err := http.NewRequest(method, fullUrl, postReader)

	if(err != nil) {
		return nil, err
	}

	if(postReader != nil) {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		//req.Header.Add("Content-Size", strconv.Itoa(len(postForm.Encode())))
	}

	// Debugging
		logStatement := fmt.Sprintf("mFi Request: %s - %s\n", req.Method, req.URL.String())
		logStatement += fmt.Sprintf("	Headers:\n")
		for k, v := range req.Header {
			logStatement += fmt.Sprintf("		%s: %s\n", k, v)
		}

		if( req.ContentLength > 0 ){
			logStatement += fmt.Sprintf("	Body:\n")
			logStatement += fmt.Sprintf("		%s\n", postForm.Encode())
		}

		log.Print(logStatement)
	//End debugging

	httpResp, httpRequestErr := httpClient.Do(req)

	//Decode response to string
	//bodyString, readErr := ioutil.ReadAll(httpResp.Body)
	//if( readErr != nil ){
	//	return nil, readErr
	//}

	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		log.Println("Checking redir")
		return nil
	}


	responseLogStatement := fmt.Sprintf("mFi Response: %d\n", httpResp.StatusCode)
	responseLogStatement += fmt.Sprintf("	Headers:\n")
	for k, v := range httpResp.Header {
		responseLogStatement += fmt.Sprintf("		%s: %s\n", k, v)
	}
	log.Print(responseLogStatement)
	//
	//if( httpResp.ContentLength > 0 ){
	//	responseLogStatement += fmt.Sprintf("	Body:\n")
	//	responseLogStatement += fmt.Sprintf("		%s\n", httpResp.Encode())
	//}

	if( httpRequestErr != nil ){
		return nil, httpRequestErr
	}



	return httpResp, nil
}

func (m *MFiConnection) HttpPost(url string, urlParams[] UrlParam, postForm url.Values) (*http.Response, error) {
	return m.HttpReq("POST", url, urlParams, postForm)
}

func (m *MFiConnection) HttpGet(url string, urlParams[] UrlParam) (*http.Response, error) {
	return m.HttpReq("GET", url, urlParams, nil)
}

func (m *MFiConnection) HttpPut(url string, urlParams[] UrlParam, postForm url.Values) (*http.Response, error) {
	return m.HttpReq("PUT", url, urlParams, postForm)
}

func (m *MFiConnection) HttpDelete(url string, urlParams[] UrlParam, postForm url.Values) (*http.Response, error) {
	return m.HttpReq("DELETE", url, urlParams, postForm)
}

