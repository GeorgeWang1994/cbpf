package exporter

import "collector/pkg/consumer"

type Exporter interface {
	consumer.Consumer
}
