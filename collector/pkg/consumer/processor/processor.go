package processor

import "collector/pkg/consumer"

type Processor interface {
	consumer.Consumer
}
