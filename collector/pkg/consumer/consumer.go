package consumer

import "collector/pkg/model"

type Consumer interface {
	Consume(dataGroup *model.DataGroup) error
}
