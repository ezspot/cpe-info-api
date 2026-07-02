
## CQRS Commands And Queries

When creating or updating files in `internal/app/command` or `internal/app/query`, reproduce the existing CQRS structure exactly.

### Required workflow

1. Start from the IDE template:
   - `.templates/Go Command (tracing).go`
   - `.templates/Go Query (tracing).go`
2. Keep handlers thin. Put orchestration in the handler and business/data operations behind the `*HandleModel` interface.
3. Wire every new command/query into the application composition root before finishing:
   - add the handler field to the appropriate struct in `internal/app/app.go`
   - instantiate the handler in `internal/service/application.go`

### Command structure

For a new command `DoThing` in `internal/app/command/do_thing.go`, use this layout:

1. `package command`
2. Imports:
   - always include `context`, `log/slog`, `internal/decorator`, and `go.opentelemetry.io/otel/trace`
   - include domain/package imports actually used by the command
3. Request DTO:
   - `type DoThing struct { ... }`
   - add `json` and `binding:"required"` tags where applicable
   - when creating/updating a model, use a single field in the DTO with the model as the type instead of using all model fields for maintainability
4. Result DTO:
   - always declare `type DoThingResult struct {}` even when empty
5. Handler alias:
   - `type DoThingHandler = decorator.CommandHandler[DoThing, DoThingResult]`
6. Handle model interface:
   - `type DoThingHandleModel interface { ... }`
   - keep it minimal and shaped around the exact dependency calls this handler needs
7. Constructor:
   - `func NewDoThingHandler(handleModel DoThingHandleModel, logger *slog.Logger, tracer trace.Tracer) DoThingHandler`
   - return `decorator.ApplyCommandDecorators(...)`
   - if the command does not need a model dependency, omit `handleModel` entirely, as in `internal/app/command/send_notification.go`
8. Private handler:
   - `type doThingHandler struct { handleModel DoThingHandleModel }`
   - if there is no model dependency, use an empty struct
9. Handle method:
   - `func (handler doThingHandler) Handle(ctx context.Context, cmd DoThing) (res DoThingResult, err error)`
   - prefer named returns for commands
   - delegate to `handleModel` and map any returned values into `res`

### Query structure

For a new query `GetThing` in `internal/app/query/get_thing.go`, use this layout:

1. `package query`
2. Imports:
   - always include `context`, `log/slog`, `internal/decorator`, and `go.opentelemetry.io/otel/trace`
   - include domain/package imports actually used by the query
3. Query DTO:
   - `type GetThing struct { ... }`
   - add `json` and `binding:"required"` tags where applicable
4. Handler alias:
   - `type GetThingHandler = decorator.QueryHandler[GetThing, ReturnType]`
5. Handle model interface:
   - `type GetThingHandleModel interface { ... }`
6. Constructor:
   - `func NewGetThingHandler(handleModel GetThingHandleModel, logger *slog.Logger, tracer trace.Tracer) GetThingHandler`
   - return `decorator.ApplyQueryDecorators(...)`
7. Private handler:
   - `type getThingHandler struct { handleModel GetThingHandleModel }`
8. Handle method:
   - `func (handler getThingHandler) Handle(ctx context.Context, query GetThing) (ReturnType, error)`
   - fetch data through `handleModel`
   - return the fetched value plus the error directly

### Conventions to preserve

- File names are snake_case versions of the command/query name.
- Public types use PascalCase. The concrete handler struct uses lowerCamelCase.
- The constructor is the only place decorators are applied.
- Prefer inferred type parameters for `ApplyCommandDecorators(...)` and `ApplyQueryDecorators(...)`. Use explicit type parameters only when inference becomes unclear.
- Keep comments rare. Existing handlers are mostly self-explanatory.
- Match existing spacing/import grouping produced by `gofmt`.
- Do not introduce new framework abstractions for handlers. Follow the existing `decorator.CommandHandler` and `decorator.QueryHandler` pattern.

### Wiring into the application

After creating a command or query, update both composition files.

1. `app/app.go`
   - add the new handler type to `type Commands struct { ... }` or `type Queries struct { ... }`
   - follow the existing naming pattern exactly, for example:
     - `CreateInvoice command.CreateInvoiceHandler`
     - `GetInvoice query.GetInvoiceHandler`
2. `service/application.go`
   - create the handler inside `app.Commands{ ... }` or `app.Queries{ ... }`
   - use the constructor from the new file, passing the correct dependency plus `logger` and `tracer`

Choose the dependency by matching the new handler's `*HandleModel` interface to an already-initialized adapter or client in `internal/service/application.go`. If no suitable dependency exists yet, add it there first and then pass it into the handler constructor.

Do not stop after creating the file. A command/query is incomplete until it is exposed from `app.Application` and instantiated in `service.NewApplication`.

### API endpoints and controllers

When exposing a command or query over HTTP, follow the existing Gin controller pattern as seen in the IDE template `.templates/Gin Controller.go`.

1. Create or extend a controller in `internal/ports/controllers/v1`
   - controller constructors follow `NewXController(app *app.Application, logger *slog.Logger) *XController`
   - controller structs keep `app *app.Application` and `logger *slog.Logger`
   - handler methods are methods on the controller, for example `func (controller *BookingController) Get(c *gin.Context)`
2. Add request/response DTOs near the top of the controller file when the endpoint needs HTTP-specific payload shapes
   - keep these DTOs private to the controller unless there is a reason to share them
   - add `json` and `binding` tags for Gin binding/validation
   - when Swagger needs a stable schema name, use `// @Name ...` on the DTO type, this needs to be inline after the closing curly bracket
3. Handler flow should match the existing pattern
   - parse path/query params from `gin.Context`
   - bind request bodies with `c.ShouldBind(&req)`
   - wrap request validation failures with `tcerr.WrapRequestValidationError(err)`
   - invoke the command/query through `controller.app.Commands...` or `controller.app.Queries...`
   - return JSON with `c.JSON(...)` when there is a response body, otherwise set status with `c.Status(...)`
   - forward domain/application errors with `c.Error(err)`

### Swagger annotations with swaggo

Every public Gin handler must include Swagger comments compatible with `swag` generation. Copy the format used in the IDE template `.templates/Gin Controller.go`.

Place the annotation block immediately above the handler method. Include the tags that apply to the endpoint:

- a short leading doc comment, for example `// GetBooking is a gin handler function.`
- `@Summary`
- `@Description` when the behavior is not obvious from the summary
- `@Tags`
- `@Accept json` for endpoints that read a body
- `@Produce json` for JSON responses
- one `@Param` line for each path/query/body parameter
- `@Success` lines with the real status code and response type when applicable
- `@Failure` lines for the expected error cases
- `@Router /resource/{id} [method]`

Swagger response/request types should match the actual HTTP contract:

- use controller request DTOs for body params when the HTTP shape differs from the command/query struct
- use command/query result types directly when they are the real response body
- use controller-local aliases with `// @Name ...` when generics or private types need a Swagger-friendly name

Do not add an endpoint without Swagger comments. The handler is incomplete until `swag` can discover it correctly.

### Route registration

After adding a controller method, wire the route in `internal/ports/http.go`.

1. Instantiate the controller in `NewHttpServer(...)`
2. Register the route under the correct router group, following the existing `/api` and resource subgroup structure
3. Match the HTTP verb and path to the `@Router` annotation exactly

For example, if the Swagger annotation says `@Router /bookings/{id}/approve [post]`, the router entry must be `bookings.POST(\"/:id/approve\", bookingController.ApproveBooking)`.

### Minimal examples

Command:

```go
type DoThing struct {
	EntityID int `json:"entityId" binding:"required"`
}

type DoThingResult struct{}

type DoThingHandler = decorator.CommandHandler[DoThing, DoThingResult]

type DoThingHandleModel interface {
	DoThing(ctx context.Context, entityID int) error
}

func NewDoThingHandler(handleModel DoThingHandleModel, logger *slog.Logger, tracer trace.Tracer) DoThingHandler {
	return decorator.ApplyCommandDecorators(
		doThingHandler{handleModel: handleModel},
		logger,
		tracer,
	)
}

type doThingHandler struct {
	handleModel DoThingHandleModel
}

func (handler doThingHandler) Handle(ctx context.Context, cmd DoThing) (res DoThingResult, err error) {
	err = handler.handleModel.DoThing(ctx, cmd.EntityID)
	return
}
```

Query:

```go
type GetThing struct {
	EntityID int `json:"entityId" binding:"required"`
}

type GetThingHandler = decorator.QueryHandler[GetThing, model.Thing]

type GetThingHandleModel interface {
	Get(ctx context.Context, id int) (model.Thing, error)
}

func NewGetThingHandler(handleModel GetThingHandleModel, logger *slog.Logger, tracer trace.Tracer) GetThingHandler {
	return decorator.ApplyQueryDecorators(
		getThingHandler{handleModel: handleModel},
		logger,
		tracer,
	)
}

type getThingHandler struct {
	handleModel GetThingHandleModel
}

func (handler getThingHandler) Handle(ctx context.Context, query GetThing) (model.Thing, error) {
	thing, err := handler.handleModel.Get(ctx, query.EntityID)
	if err != nil {
		return thing, err
	}

	return thing, nil
}
```

## CONSTRAINTS:
- Focus on production-readiness, not experimental features, and don't over-engineer.
- Minimize the use of comments, unless the action/code is not obvious, then describe it direct and short.
- Follow June 2026 enterprise best practices building scalable production ready applications

## REFERENCES:
- PostgreSQL 18:
  - https://www.postgresql.org/docs/18/index.html
- GoLang & Tools
  - https://go.dev/ref/spec
  - https://go.dev/doc/effective_go
  - https://go.dev/doc/go1.26
  - Gin: https://gin-gonic.com/docs
  - GORM: https://gorm.io/docs
  - gorm.io/gen: https://gorm.io/gen
  - otelgin: https://pkg.go.dev/go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin
  - OpenTelemetry Go: https://opentelemetry.io/docs/languages/go/
  - swaggo: https://github.com/swaggo/swag