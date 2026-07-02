package app

import (
	"cpe-api/internal/app/command"
	"cpe-api/internal/app/query"
)

type Application struct {
	Commands Commands
	Queries  Queries
}

type Commands struct {
	PerformCpeAction command.PerformCpeActionHandler
}

type Queries struct {
	CollectCpeInfo query.CollectCpeInfoHandler
}
