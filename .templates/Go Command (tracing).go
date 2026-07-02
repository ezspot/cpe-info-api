package ${GO_PACKAGE_NAME}

import (
	"context"
	"log/slog"
)

#set($commandCamelCase = $Command.substring(0,1).toLowerCase() + $Command.substring(1))
type ${Command} struct {
  #[[$END$]]#
}

type ${Command}Result struct {
}

type ${Command}Handler = decorator.CommandHandler[${Command}, ${Command}Result]

type ${Command}HandleModel interface {
}

func New${Command}Handler(handleModel ${Command}HandleModel, logger *slog.Logger, tracer trace.Tracer) ${Command}Handler {
	return decorator.ApplyCommandDecorators[${Command}, ${Command}Result](
		${commandCamelCase}Handler{handleModel: handleModel},
		logger,
		tracer,
	)
}

type ${commandCamelCase}Handler struct {
	handleModel ${Command}HandleModel
}

func (handler ${commandCamelCase}Handler) Handle(ctx context.Context, cmd ${Command}) (res ${Command}Result, err error) {
	//TODO implement me
	panic("implement me")
}

