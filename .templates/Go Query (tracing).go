package ${GO_PACKAGE_NAME}

import (
  "context"
)

#set($queryCamelCase = $QueryName.substring(0,1).toLowerCase() + $QueryName.substring(1))
type ${QueryName} struct {
}

type ${QueryName}Handler decorator.QueryHandler[${QueryName}, ${ReturnType}]

type ${QueryName}HandleModel interface {}

func New${QueryName}Handler(handleModel ${QueryName}HandleModel, logger *slog.Logger, tracer trace.Tracer) ${QueryName}Handler {
    return decorator.ApplyQueryDecorators[${QueryName}, ${ReturnType}](
      ${queryCamelCase}Handler{handleModel: handleModel},
      logger,
      tracer,
    )
}

type ${queryCamelCase}Handler struct {
  handleModel ${QueryName}HandleModel
}

func (handler ${queryCamelCase}Handler) Handle(ctx context.Context, query ${QueryName}) (${ReturnType}, error) { 
  #[[$END$]]#
}
