package webanalysis

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"unicode/utf8"
)

const MaxReplayBody = 1 << 20

func SetRequestBody(e *RequestExample, body []byte) {
	e.Body = string(body)
	e.BodyEncoding = ""
	if !utf8.Valid(body) {
		e.Body = base64.StdEncoding.EncodeToString(body)
		e.BodyEncoding = "base64"
	}
}

func RequestBody(e RequestExample) ([]byte, error) {
	if e.BodyOmitted || len(e.Body) > base64.StdEncoding.EncodedLen(MaxReplayBody) {
		return nil, errors.New("request body unavailable or exceeds limit")
	}
	body := []byte(e.Body)
	switch e.BodyEncoding {
	case "":
		if !utf8.Valid(body) {
			return nil, errors.New("invalid request body text encoding")
		}
	case "base64":
		var err error
		body, err = base64.StdEncoding.Strict().DecodeString(e.Body)
		if err != nil {
			return nil, errors.New("invalid request body encoding")
		}
	default:
		return nil, errors.New("unsupported request body encoding")
	}
	if len(body) > MaxReplayBody {
		return nil, errors.New("request body limit")
	}
	return body, nil
}

func ReplayBody(e RequestExample) (string, []byte, error) {
	body, err := RequestBody(e)
	if err != nil {
		return "", nil, err
	}
	contentType := e.Headers.Get("Content-Type")
	media, params, err := mime.ParseMediaType(contentType)
	if err != nil && contentType != "" {
		return "", nil, errors.New("invalid request content type")
	}
	switch {
	case len(body) == 0:
		return "empty", body, nil
	case media == "application/json" || strings.HasSuffix(media, "+json"):
		if !json.Valid(body) {
			return "", nil, errors.New("invalid JSON request body")
		}
		return "json", body, nil
	case media == "application/x-www-form-urlencoded":
		return "form", body, nil
	case strings.HasPrefix(media, "text/") || media == "":
		return "text", body, nil
	case media == "multipart/form-data":
		if params["boundary"] == "" {
			return "", nil, errors.New("multipart boundary missing")
		}
		reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		for count := 0; ; count++ {
			part, err := reader.NextRawPart()
			if err == io.EOF {
				break
			}
			if err != nil || count >= 100 {
				return "", nil, errors.New("invalid multipart body or part limit")
			}
			_, err = io.Copy(io.Discard, part)
			if err != nil {
				return "", nil, errors.New("incomplete multipart body")
			}
		}
		return "multipart", body, nil
	case media == "application/octet-stream":
		return "binary", body, nil
	default:
		return "opaque", body, nil
	}
}
