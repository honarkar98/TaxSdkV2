package taxApi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

// JwsService handles JWS (JSON Web Signature) creation
type JwsService struct{}

// NewJwsService creates a new JwsService instance
func NewJwsService() *JwsService {
	return &JwsService{}
}

// Create generates a JWS token
func (js *JwsService) Create(privateKey *rsa.PrivateKey, header map[string]interface{}, payload map[string]interface{}) (string, error) {
	// Validate algorithm
	if alg, ok := header["alg"].(string); !ok || alg != "RS256" {
		return "", errors.New("cannot create JWS, the supported 'alg' is (RS256)")
	}

	// Encode header
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %v", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Encode payload
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %v", err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Create signing input
	signingInput := encodedHeader + "." + encodedPayload

	// Create signature
	hasher := sha256.New()
	hasher.Write([]byte(signingInput))
	hashed := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %v", err)
	}
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	// Combine to create JWS
	jws := signingInput + "." + encodedSignature

	return jws, nil
}

// MoadianClient represents the Moadian API client
type MoadianClient struct {
	apiBaseURL        string
	privateKey        *rsa.PrivateKey
	certificateBase64 string
	clientID          string
	token             string
	httpClient        *http.Client
}

// NewMoadianClient creates a new Moadian API client
func NewMoadianClient(apiBaseURL, rawPrivateKey, certificateBase64, clientID string) (*MoadianClient, error) {
	// Decode the base64 private key if it's encoded
	keyBytes := []byte(rawPrivateKey)
	if isBase64Encoded(rawPrivateKey) {
		decoded, err := base64.StdEncoding.DecodeString(rawPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 private key: %v", err)
		}
		keyBytes = decoded
	}

	// Try parsing as PKCS1 first
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err == nil {
		return &MoadianClient{
			apiBaseURL:        apiBaseURL,
			privateKey:        privateKey,
			certificateBase64: certificateBase64,
			clientID:          clientID,
			httpClient:        &http.Client{},
		}, nil
	}

	// If PKCS1 fails, try PKCS8
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key (tried both PKCS1 and PKCS8): %v", err)
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an RSA key")
	}

	return &MoadianClient{
		apiBaseURL:        apiBaseURL,
		privateKey:        rsaKey,
		certificateBase64: certificateBase64,
		clientID:          clientID,
		httpClient:        &http.Client{},
	}, nil
}

// isBase64Encoded checks if a string appears to be base64 encoded
func isBase64Encoded(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// Base request/response handling
func (mc *MoadianClient) DoRequest(ctx context.Context, method, path string, params url.Values, result interface{}) ([]byte, *http.Response, error) {

	// Build URL
	u, err := url.ParseRequestURI(mc.apiBaseURL + path)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid URL: %w", err)
	}
	u.RawQuery = params.Encode()

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	// Create request
	//req, err := http.NewRequestWithContext(ctx, method, mc.apiBaseURL+path, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("request creation failed: %w", err)
	}

	// Get or refresh token
	if _, err := mc.RequestToken(); err != nil {
		return nil, nil, err
	}
	//if err := c.ensureValidToken(ctx); err != nil {
	//	return fmt.Errorf("authentication failed: %w", err)
	//}

	req.Header.Set("Authorization", "Bearer "+mc.token)
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := mc.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	return body, resp, nil
}

// requestNonce requests a nonce from the server
func (mc *MoadianClient) requestNonce() (*NonceResponse, error) {
	url := mc.apiBaseURL + "/nonce?timeToLive=20"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("accept", "*/*")

	resp, err := mc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var nonceResponse NonceResponse
	if err := json.NewDecoder(resp.Body).Decode(&nonceResponse); err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	return &nonceResponse, nil
}

// RequestToken requests a new token from the server
func (mc *MoadianClient) RequestToken() (string, error) {
	nonceResult, err := mc.requestNonce()
	if err != nil {
		return "", fmt.Errorf("failed to get nonce: %v", err)
	}

	header := map[string]interface{}{
		"alg":  "RS256",
		"typ":  "jose",
		"x5c":  []string{mc.certificateBase64},
		"sigT": time.Now().UTC().Format(time.RFC3339),
		"crit": []string{"sigT"},
		"cty":  "text/plain",
	}

	payload := map[string]interface{}{
		"nonce":    nonceResult.Nonce,
		"clientId": mc.clientID,
	}

	jwsService := NewJwsService()
	token, err := jwsService.Create(mc.privateKey, header, payload)
	if err != nil {
		return "", fmt.Errorf("failed to create JWS: %v", err)
	}

	mc.token = token
	return token, nil
}

// GetFiscalInformation retrieves fiscal information
func (mc *MoadianClient) GetFiscalInformation(memoryID string) (interface{}, error) {
	params := url.Values{"memoryId": {memoryID}}

	body, resp, err := mc.DoRequest(context.Background(), "GET", "/fiscal-information", params, nil)

	if err != nil {
		panic(err)
	}

	if resp.StatusCode == http.StatusOK {
		var taxpayer FiscalResponse
		err := json.Unmarshal(body, &taxpayer)
		if err != nil {
			panic(err)
		}
		taxpayer.StatusCode = resp.StatusCode
		return &taxpayer, nil
	} else if resp.StatusCode >= 400 && resp.StatusCode <= 500 {
		var taxError TaxRequestErrorResponse
		err := json.Unmarshal(body, &taxError)
		if err != nil {
			panic(err)
		}
		taxError.StatusCode = resp.StatusCode
		return &taxError, errors.New("fiscal-information request failed")
	} else {
		return nil, fmt.Errorf("unexpected status code: %d , data:   %s", resp.StatusCode, string(body))
	}
}

// GetTaxPayer retrieves taxpayer information
func (mc *MoadianClient) GetTaxPayer(economicCode string) (interface{}, error) {
	params := url.Values{"economicCode": {economicCode}}

	body, resp, err := mc.DoRequest(context.Background(), "GET", "/taxpayer", params, nil)

	if err != nil {
		panic(err)
	}

	if resp.StatusCode == http.StatusOK {
		var taxpayer TaxpayerResponse
		err := json.Unmarshal(body, &taxpayer)
		if err != nil {
			panic(err)
		}
		taxpayer.StatusCode = resp.StatusCode
		return &taxpayer, nil
	} else if resp.StatusCode >= 400 && resp.StatusCode <= 500 {
		var taxError TaxRequestErrorResponse
		err := json.Unmarshal(body, &taxError)
		if err != nil {
			panic(err)
		}
		taxError.StatusCode = resp.StatusCode
		return &taxError, errors.New("fiscal-information request failed")
	} else {
		return nil, fmt.Errorf("unexpected status code: %d , data:   %s", resp.StatusCode, string(body))
	}
}

// InquiryByReferenceId retrieves information by reference IDs
func (mc *MoadianClient) InquiryByReferenceId(referenceIDs []string, startDateTime, endDateTime string) (interface{}, error) {
	if _, err := mc.RequestToken(); err != nil {
		return nil, err
	}

	params := url.Values{}
	for _, id := range referenceIDs {
		params.Add("referenceIds", id)
	}

	if startDateTime != "" {
		params.Add("start", startDateTime)
	}
	if endDateTime != "" {
		params.Add("end", endDateTime)
	}

	url := mc.apiBaseURL + "/inquiry-by-reference-id?" + params.Encode()
	return mc.sendRequest(url, "GET")
}

// sendRequest sends an HTTP request
func (mc *MoadianClient) sendRequest(url, method string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+mc.token)
	req.Header.Set("accept", "application/json")

	resp, err := mc.httpClient.Do(req)
	defer resp.Body.Close()

	return resp, err
	/*fmt.Println(resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(body))

	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	return result, nil*/
}

func (mc *MoadianClient) GetInvoiceStatusWithTaxId(ctx context.Context, taxIDs []string) (interface{}, error) {
	params := url.Values{}
	for _, taxID := range taxIDs {
		params.Add("taxIds", taxID)
	}

	//var result InvoiceStatusResponse
	body, resp, err := mc.DoRequest(
		context.Background(),
		"GET",
		"/inquiry-invoice-status",
		params,
		nil,
	)
	fmt.Printf(string(body), resp, err)

	if err != nil {
		panic(err)
	}

	if resp.StatusCode == http.StatusOK {
		var taxpayer []InquiryByTaxId
		err := json.Unmarshal(body, &taxpayer)
		if err != nil {
			panic(err)
		}
		return &taxpayer, nil
	} else if resp.StatusCode >= 400 && resp.StatusCode <= 500 {
		var taxError TaxRequestErrorResponse
		err := json.Unmarshal(body, &taxError)
		if err != nil {
			panic(err)
		}
		taxError.StatusCode = resp.StatusCode
		return &taxError, errors.New("fiscal-information request failed")
	} else {
		return nil, fmt.Errorf("unexpected status code: %d , data:   %s", resp.StatusCode, string(body))
	}
}

// NonceResponse represents the nonce response structure
type NonceResponse struct {
	Nonce   string    `json:"nonce"`
	ExpDate time.Time `json:"expDate"`
}

type TaxpayerResponse struct {
	NameTrade      string `json:"nameTrade"`
	TaxpayerStatus string `json:"taxpayerStatus"`
	NationalId     string `json:"nationalId"`
	StatusCode     int    `json:"status_code"`
}

type FiscalResponse struct {
	NameTrade    string `json:"nameTrade"`
	FiscalStatus string `json:"fiscalStatus"`
	EconomicCode string `json:"economicCode"`
	NationalId   string `json:"nationalId"`
	StatusCode   int    `json:"status_code"`
}

type TaxRequestErrorResponse struct {
	Timestamp      int64  `json:"timestamp"`
	RequestTraceId string `json:"requestTraceId"`
	Errors         []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	StatusCode int `json:"status_code"`
}

type InquiryByTaxId struct {
	TaxId          string  `json:"taxId"`
	InvoiceStatus  *string `json:"invoiceStatus"`
	Article6Status *string `json:"article6Status"`
	Error          *string `json:"error"`
}
