// @title CPE Info API
// @version 1.0
// @description Collect CPE diagnostics over SSH with model-aware authentication.
// @BasePath /
// @schemes http https
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Use `Bearer <token>`.
package main

//go:generate go run github.com/swaggo/swag/cmd/swag@v1.16.6 init -g docs.go -d .,../../internal/httpapi,../../internal/cpe -o ../../internal/httpapi/swagdocs --parseInternal
