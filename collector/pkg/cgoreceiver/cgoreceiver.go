package cgoreceiver

/*
#cgo LDFLAGS: -L ./ -lkindling  -lstdc++ -ldl
#cgo CFLAGS: -I .
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "cgo_func.h"
*/
import "C"
import (
	"collector/pkg"
	"collector/pkg/analyzer"
	"collector/pkg/model"
	"sync"
	"time"
	"unsafe"

	"github.com/Kindling-project/kindling/collector/pkg/component"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	Cgo = "cgoreceiver"
)

type CKindlingEventForGo C.struct_kindling_event_t_for_go

type CgoReceiver struct {
	cfg             *Config
	analyzerManager *analyzer.Manager
	shutdownWG      sync.WaitGroup // 停止标志
	telemetry       *component.TelemetryTools
	eventChannel    chan *model.Event // 事件channel
	stopCh          chan interface{}
	stats           eventCounter
}

func NewCgoReceiver(config interface{}, telemetry *component.TelemetryTools, analyzerManager *analyzer.Manager) pkg.Receiver {
	// 创建接收器
	cfg, ok := config.(*Config)
	if !ok {
		telemetry.Logger.Panicf("Cannot convert [%s] config", Cgo)
	}
	cgoReceiver := &CgoReceiver{
		cfg:             cfg,
		analyzerManager: analyzerManager,
		telemetry:       telemetry,
		eventChannel:    make(chan *model.Event, 3e5),
		stopCh:          make(chan interface{}, 1),
	}
	cgoReceiver.stats = newDynamicStats(cfg.SubscribeInfo)
	// 监控接受事件的指标
	//newSelfMetrics(telemetry.MeterProvider, cgoReceiver)
	return cgoReceiver
}

// 开始接收事件
func (r *CgoReceiver) Start() error {
	r.telemetry.Logger.Info("Start CgoReceiver")
	// 调用C语言中的runForGo，初始化probe
	C.runForGo()
	// 等待几s才开始订阅事件
	time.Sleep(2 * time.Second)
	// 订阅事件
	r.subEvent()
	// Wait for the C routine running
	time.Sleep(2 * time.Second)
	// 启动协程接收事件
	go r.consumeEvents()
	go r.startGetEvent()
	return nil
}

// 开始获取事件
func (r *CgoReceiver) startGetEvent() {
	var pKindlingEvent unsafe.Pointer
	r.shutdownWG.Add(1)
	for {
		select {
		case <-r.stopCh:
			r.shutdownWG.Done()
			return
		default:
			// 从cgo的getKindlingEvent函数中获取事件信息
			res := int(C.getKindlingEvent(&pKindlingEvent))
			if res == 1 {
				event := convertEvent((*CKindlingEventForGo)(pKindlingEvent))
				r.eventChannel <- event
				r.stats.add(event.Name, 1)
			}
		}
	}
}

// 消费事件
func (r *CgoReceiver) consumeEvents() {
	r.shutdownWG.Add(1)
	for {
		select {
		case <-r.stopCh:
			r.shutdownWG.Done()
			return
		case ev := <-r.eventChannel:
			// 发送到下一个消费者
			err := r.sendToNextConsumer(ev)
			if err != nil {
				r.telemetry.Logger.Info("Failed to send KindlingEvent: ", zap.Error(err))
			}
		}
	}
}

func (r *CgoReceiver) Shutdown() error {
	// TODO stop the C routine
	close(r.stopCh)
	r.shutdownWG.Wait()
	return nil
}

// 将C中获取到的事件转化成Go中的事件
func convertEvent(cgoEvent *CKindlingEventForGo) *model.Event {
	ev := new(model.Event)
	ev.Timestamp = uint64(cgoEvent.timestamp)
	ev.Name = C.GoString(cgoEvent.name)
	ev.Category = model.Category(cgoEvent.category)
	// 设置线程信息
	ev.Ctx.ThreadInfo.Pid = uint32(cgoEvent.context.tinfo.pid)
	ev.Ctx.ThreadInfo.Tid = uint32(cgoEvent.context.tinfo.tid)
	ev.Ctx.ThreadInfo.Uid = uint32(cgoEvent.context.tinfo.uid)
	ev.Ctx.ThreadInfo.Gid = uint32(cgoEvent.context.tinfo.gid)
	ev.Ctx.ThreadInfo.Comm = C.GoString(cgoEvent.context.tinfo.comm)
	ev.Ctx.ThreadInfo.ContainerId = C.GoString(cgoEvent.context.tinfo.containerId)
	// 设置文件信息
	ev.Ctx.FdInfo.Protocol = model.L4Proto(cgoEvent.context.fdInfo.protocol)
	ev.Ctx.FdInfo.Num = int32(cgoEvent.context.fdInfo.num)
	ev.Ctx.FdInfo.TypeFd = model.FDType(cgoEvent.context.fdInfo.fdType)
	ev.Ctx.FdInfo.Filename = C.GoString(cgoEvent.context.fdInfo.filename)
	ev.Ctx.FdInfo.Directory = C.GoString(cgoEvent.context.fdInfo.directory)
	ev.Ctx.FdInfo.Role = If(cgoEvent.context.fdInfo.role != 0, true, false).(bool)
	ev.Ctx.FdInfo.Sip = []uint32{uint32(cgoEvent.context.fdInfo.sip)}
	ev.Ctx.FdInfo.Dip = []uint32{uint32(cgoEvent.context.fdInfo.dip)}
	ev.Ctx.FdInfo.Sport = uint32(cgoEvent.context.fdInfo.sport)
	ev.Ctx.FdInfo.Dport = uint32(cgoEvent.context.fdInfo.dport)
	ev.Ctx.FdInfo.Source = uint64(cgoEvent.context.fdInfo.source)
	ev.Ctx.FdInfo.Destination = uint64(cgoEvent.context.fdInfo.destination)

	ev.ParamsNumber = uint16(cgoEvent.paramsNumber)
	for i := 0; i < int(ev.ParamsNumber); i++ {
		ev.UserAttributes[i].Key = C.GoString(cgoEvent.userAttributes[i].key)
		userAttributesLen := cgoEvent.userAttributes[i].len
		ev.UserAttributes[i].Value = C.GoBytes(unsafe.Pointer(cgoEvent.userAttributes[i].value), C.int(userAttributesLen))
		ev.UserAttributes[i].ValueType = model.ValueType(cgoEvent.userAttributes[i].valueType)
	}
	return ev
}

func If(condition bool, trueVal, falseVal interface{}) interface{} {
	if condition {
		return trueVal
	}
	return falseVal
}

// 发送给下个消费者
func (r *CgoReceiver) sendToNextConsumer(evt *model.Event) error {
	if ce := r.telemetry.Logger.Check(zapcore.DebugLevel, "Receive Event"); ce != nil {
		ce.Write(
			zap.String("event", evt.String()),
		)
	}
	// 根据事件名称获取到对应的消费者
	analyzers := r.analyzerManager.GetConsumableAnalyzers(evt.Name)
	if analyzers == nil || len(analyzers) == 0 {
		r.telemetry.Logger.Info("analyzer not found for event ", zap.String("eventName", evt.Name))
		return nil
	}
	// 遍历所有的分析器，并且调用分析器的消费事件函数
	for _, an := range analyzers {
		err := an.ConsumeEvent(evt)
		if err != nil {
			r.telemetry.Logger.Warn("Error sending event to next consumer: ", zap.Error(err))
		}
	}
	return nil
}

// 订阅事件
func (r *CgoReceiver) subEvent() {
	for _, value := range r.cfg.SubscribeInfo {
		C.subEventForGo(C.CString(value.Name), C.CString(value.Category))
	}
}
