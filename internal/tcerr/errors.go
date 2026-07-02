package tcerr

import (
	"errors"
	"fmt"
	"net/http"
)

type APIError struct {
	Status    int
	Code      string
	Message   string
	Retryable bool
	Details   map[string]any
	cause     error
}

func (e *APIError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", e.Code, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *APIError) Unwrap() error {
	return e.cause
}

func WrapRequestValidationError(err error) error {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return &APIError{
			Status:  http.StatusRequestEntityTooLarge,
			Code:    "request_body_too_large",
			Message: "request body too large",
			cause:   err,
		}
	}
	return &APIError{
		Status:  http.StatusBadRequest,
		Code:    "bad_request",
		Message: err.Error(),
		cause:   err,
	}
}

func NewBadRequest(message string, details map[string]any) *APIError {
	return &APIError{Status: http.StatusBadRequest, Code: "bad_request", Message: message, Details: details}
}

func NewUnauthorized(message string) *APIError {
	return &APIError{Status: http.StatusUnauthorized, Code: "unauthorized", Message: message}
}

func NewForbidden(message string) *APIError {
	return &APIError{Status: http.StatusForbidden, Code: "forbidden", Message: message}
}

func NewNotFound(message string) *APIError {
	return &APIError{Status: http.StatusNotFound, Code: "not_found", Message: message}
}

func NewMethodNotAllowed(message string) *APIError {
	return &APIError{Status: http.StatusMethodNotAllowed, Code: "method_not_allowed", Message: message}
}

func NewTooManyRequests(message string) *APIError {
	return &APIError{Status: http.StatusTooManyRequests, Code: "too_many_requests", Message: message, Retryable: true}
}

func NewUnsupportedAction(message string, retryable bool, details map[string]any) *APIError {
	return &APIError{Status: http.StatusBadRequest, Code: "unsupported_action", Message: message, Retryable: retryable, Details: details}
}

func NewInternal(message string) *APIError {
	return &APIError{Status: http.StatusInternalServerError, Code: "internal_error", Message: message, Retryable: true}
}

func From(err error) *APIError {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return NewInternal("unexpected server error")
}

type ErrorEnvelope struct {
	Error ErrorBody `json:"error"`
} // @Name ErrorEnvelope

type ErrorBody struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Status    int            `json:"status"`
	RequestID string         `json:"requestId,omitempty"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details,omitempty"`
} // @Name ErrorBody

func NewEnvelope(err *APIError, requestID string) ErrorEnvelope {
	return ErrorEnvelope{Error: ErrorBody{
		Code:      err.Code,
		Message:   err.Message,
		Status:    err.Status,
		RequestID: requestID,
		Retryable: err.Retryable,
		Details:   err.Details,
	}}
}
