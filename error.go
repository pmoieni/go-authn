package goauthn

type ErrorResponse struct {
	Status  int
	Message string
}

// custom error type for detecting known application errors
func (e *ErrorResponse) Error() string {
	return e.Message
}
