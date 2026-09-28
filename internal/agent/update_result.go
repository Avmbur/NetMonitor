package agent

import "netmonitor/internal/protocol"

func protocolUpdate(id, phase, message string) protocol.UpdateResult {
	return protocol.UpdateResult{CommandID: id, Phase: phase, Error: message}
}
