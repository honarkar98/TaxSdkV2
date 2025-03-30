package taxApi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
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
func (js *JwsService) Create(privateKey *rsa.PrivateKey, header map[string]interface{}, payload interface{}) (string, error) {
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
	TaxPublicKey      string
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

// SendInvoice sends invoice packets to the Moadian API
func (mc *MoadianClient) SendInvoice(ctx context.Context, invoicePackets []map[string]interface{}) (interface{}, error) {

	mc.RequestToken()

	// Prepare request body
	requestBody, err := json.Marshal(invoicePackets)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal invoice packets: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		mc.apiBaseURL+"/invoice",
		bytes.NewBuffer(requestBody),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", "Bearer "+mc.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := mc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	/*if resp.StatusCode >= 400 {
		var apiErr APIError
		if json.Unmarshal(body, &apiErr) == nil {
			apiErr.StatusCode = resp.StatusCode
			return nil, apiErr
		}
		return nil, fmt.Errorf("API error: %s (status %d)", string(body), resp.StatusCode)
	}*/

	if resp.StatusCode == http.StatusOK {
		var taxpayer SendInvoiceResponse
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

	var result interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
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

func (mc *MoadianClient) GetInvoiceStatusByReferenceId(ctx context.Context, referenceIds []string, startTime time.Time, endTime time.Time) (interface{}, error) {
	params := url.Values{}
	for _, refID := range referenceIds {
		params.Add("referenceIds", refID)
	}

	// Add time parameters with proper formatting
	if !startTime.IsZero() {
		params.Set("start", startTime.Format(time.RFC3339Nano))
	}
	if !endTime.IsZero() {
		params.Set("end", endTime.Format(time.RFC3339Nano))
	}

	//var result InvoiceStatusResponse
	body, resp, err := mc.DoRequest(
		context.Background(),
		"GET",
		"/inquiry-by-reference-id",
		params,
		nil,
	)
	fmt.Printf(string(body), resp, err)

	if err != nil {
		panic(err)
	}

	if resp.StatusCode == http.StatusOK {
		var taxpayer []InquiryByReferenceIdResponse
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

func (mc *MoadianClient) GetInvoiceStatusByUid(ctx context.Context, uids []string, fiscalId string, startTime time.Time, endTime time.Time) (interface{}, error) {
	params := url.Values{}
	for _, uid := range uids {
		params.Add("uidList", uid)
	}

	// Add time parameters with proper formatting
	if !startTime.IsZero() {
		params.Set("start", startTime.Format(time.RFC3339Nano))
	}
	if !endTime.IsZero() {
		params.Set("end", endTime.Format(time.RFC3339Nano))
	}

	params.Set("fiscalId", fiscalId)
	//var result InvoiceStatusResponse
	body, resp, err := mc.DoRequest(
		context.Background(),
		"GET",
		"/inquiry-by-uid",
		params,
		nil,
	)
	fmt.Printf(string(body), resp, err)

	if err != nil {
		panic(err)
	}

	if resp.StatusCode == http.StatusOK {
		var taxpayer []InquiryByReferenceIdResponse
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

func (mc *MoadianClient) GetServerInformation() (interface{}, error) {

	body, resp, err := mc.DoRequest(context.Background(), "GET", "/server-information", url.Values{}, nil)

	if err != nil {
		panic(err)
	}

	if resp.StatusCode == http.StatusOK {
		var taxpayer ServerInformationResponse
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

type InquiryByReferenceIdResponse struct {
	ReferenceNumber string  `json:"referenceNumber"`
	Uid             *string `json:"uid"`
	Status          string  `json:"status"`
	Data            *struct {
		Error []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		Warning []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"warning"`
		Success bool `json:"success"`
	} `json:"data"`
	PacketType *string     `json:"packetType"`
	FiscalId   *string     `json:"fiscalId"`
	Sign       interface{} `json:"sign"`
}

type ServerInformationResponse struct {
	ServerTime int64 `json:"serverTime"`
	PublicKeys []struct {
		Key       string `json:"key"`
		Id        string `json:"id"`
		Algorithm string `json:"algorithm"`
		Purpose   int    `json:"purpose"`
	} `json:"publicKeys"`
	StatusCode int `json:"statusCode"`
}

func (mc *MoadianClient) CreateInvoicePacket(jwsPayload InvoiceDto) (map[string]interface{}, error) {
	// Generate UUID
	//uid, err := uuid.NewRandom()
	//if err != nil {
	//	return nil, fmt.Errorf("failed to generate UUID: %w", err)
	//}

	// Get server public keys if not available
	if len(mc.TaxPublicKey) == 0 {
		if serverInformation, err := mc.GetServerInformation(); err != nil {
			mc.TaxPublicKey = serverInformation.(ServerInformationResponse).PublicKeys[0].Key
			return nil, fmt.Errorf("failed to get server info: %w", err)
		}
	}

	serverInformation, _ := mc.GetServerInformation()
	// Find RSA public key
	var serverPubKey *rsa.PublicKey
	var serverKeyID string
	for _, v := range serverInformation.(*ServerInformationResponse).PublicKeys {
		if v.Algorithm == "RSA" {
			cc, _ := parsePublicKey(v.Key)
			serverPubKey = cc
			serverKeyID = v.Id
			break
		}
	}
	if serverPubKey == nil {
		return nil, errors.New("server public key algorithm not supported. supported algorithm is (RSA)")
	}

	// Create JWS
	jwsHeader := map[string]interface{}{
		"alg":  "RS256",
		"typ":  "jose",
		"x5c":  []string{mc.certificateBase64},
		"sigT": time.Now().UTC().Format(time.RFC3339),
		"crit": []string{"sigT"},
		"cty":  "text/plain",
	}

	invoiceJWS, err := NewJwsService().Create(mc.privateKey, jwsHeader, jwsPayload)

	if err != nil {
		return nil, fmt.Errorf("failed to create JWS: %w", err)
	}

	// Create JWE
	/*jweHeader := map[string]interface{}{
		"alg": "RSA-OAEP-256",
		"enc": "A256GCM",
		"kid": serverKeyID,
	}*/
	jweHeaders := jwe.NewHeaders()

	if err := jweHeaders.Set("alg", jwa.RSA_OAEP_256); err != nil {
		return nil, fmt.Errorf("failed to set JWE algorithm: %w", err)
	}
	if err := jweHeaders.Set("enc", jwa.A256GCM); err != nil {
		return nil, fmt.Errorf("failed to set JWE encryption: %w", err)
	}
	if err := jweHeaders.Set("kid", serverKeyID); err != nil {
		return nil, fmt.Errorf("failed to set JWE key ID: %w", err)
	}
	//encrypted, err := jwe.Encrypt([]byte(jwsStr), jwe.WithKey(jwa.RSA_OAEP_256, key, jwe.WithProtectedHeaders(jweHeaders)),

	encryptedPayload, err := jwe.Encrypt(
		[]byte(invoiceJWS),
		jwe.WithKey(jwa.RSA_OAEP_256, serverPubKey),
		jwe.WithContentEncryption(jwa.A256GCM),
		//jwe.WithKeySet()
		jwe.WithProtectedHeaders(jweHeaders),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWE: %w", err)
	}

	// Build final packet
	data := map[string]interface{}{
		"payload": encryptedPayload,
		"header": map[string]interface{}{
			"requestTraceId": "cf019c26-f235-11ed-a05b-0242ac120003",
			"fiscalId":       mc.clientID,
		},
	}

	return data, nil
}

func parsePublicKey(keyStr string) (*rsa.PublicKey, error) {
	// Try decoding as base64 first
	keyBytes := []byte(keyStr)
	if isBase64Encoded(keyStr) {
		decoded, err := base64.StdEncoding.DecodeString(keyStr)
		if err != nil {
			return nil, fmt.Errorf("base64 decode failed: %w", err)
		}
		keyBytes = decoded
	}

	// Try parsing as PEM first
	block, _ := pem.Decode(keyBytes)
	if block != nil {
		keyBytes = block.Bytes
	}

	// Try parsing as DER encoded PKIX public key
	pub, err := x509.ParsePKIXPublicKey(keyBytes)
	if err == nil {
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("key is not an RSA public key")
		}
		return rsaPub, nil
	}

	// Try parsing as DER encoded PKCS1 public key
	return x509.ParsePKCS1PublicKey(keyBytes)
}

type SendInvoiceResponse struct {
	Timestamp int64 `json:"timestamp"`
	Result    []struct {
		Uid             string      `json:"uid"`
		PacketType      interface{} `json:"packetType"`
		ReferenceNumber string      `json:"referenceNumber"`
		Data            interface{} `json:"data"`
	} `json:"result"`
	StatusCode int `json:"statusCode"`
}
