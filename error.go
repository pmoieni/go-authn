package goauthn

type errorResponse struct {
	Status  int
	Message string
}

// custom error type for detecting known application errors
func (e *errorResponse) Error() string {
	return e.Message
}
