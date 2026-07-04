package app

import (
	"device-api/internal/app/command"
	"device-api/internal/app/query"
)

type Application struct {
	Commands Commands
	Queries  Queries
}

type Commands struct {
	PerformCpeAction command.PerformCpeActionHandler
}

type Queries struct {
	CollectCpeInfo    query.CollectCpeInfoHandler
	CollectSwitchPort query.CollectSwitchPortHandler
}
