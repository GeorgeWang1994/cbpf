package internal

import (
	"collector/pkg"
	"collector/pkg/analyzer"
	"collector/pkg/analyzer/tcp_analyzer"
	"collector/pkg/cgoreceiver"
	"collector/pkg/consumer"
	"collector/pkg/consumer/processor/k8s"
	"flag"
	"fmt"
	"github.com/Kindling-project/kindling/collector/pkg/component"
	"github.com/spf13/viper"
	"go.uber.org/multierr"
)

type Application struct {
	viper             *viper.Viper
	componentsFactory *ComponentsFactory // 组件工厂
	telemetry         *component.TelemetryManager
	receiver          pkg.Receiver
	analyzerManager   *analyzer.Manager
}

func NewApp() (*Application, error) {
	app := &Application{
		viper:             viper.New(),
		componentsFactory: NewComponentsFactory(),
		//telemetry:         component.NewTelemetryManager(),
	}
	app.registerFactory()
	// Initialize flags
	configPath := flag.String("config", "kindling-collector-config.yml", "Configuration file")
	flag.Parse()
	err := app.readInConfig(*configPath)
	if err != nil {
		return nil, fmt.Errorf("fail to read configuration: %w", err)
	}
	// Build processing pipeline
	err = app.buildPipeline()
	if err != nil {
		return nil, fmt.Errorf("failed to build pipeline: %w", err)
	}
	return app, nil
}

func (a *Application) Run() error {
	err := a.analyzerManager.StartAll(a.telemetry.Logger)
	if err != nil {
		return fmt.Errorf("failed to start application: %v", err)
	}
	// Wait until the receiver shutdowns
	err = a.receiver.Start()
	if err != nil {
		return fmt.Errorf("failed to start application: %v", err)
	}
	return nil
}

// 注册各个组件
func (a *Application) registerFactory() {
	a.componentsFactory.RegisterReceiver(cgoreceiver.Cgo, cgoreceiver.NewCgoReceiver, &cgoreceiver.Config{})

	//a.componentsFactory.RegisterExporter(otelexporter.Otel, otelexporter.NewExporter, &otelexporter.Config{})
	//a.componentsFactory.RegisterExporter(logexporter.Type, logexporter.New, &logexporter.Config{})
	//
	a.componentsFactory.RegisterProcessor(k8s.K8sMetadata, k8s.NewKubernetesProcessor, &k8s.DefaultConfig)
	//a.componentsFactory.RegisterProcessor(aggregateprocessor.Type, aggregateprocessor.New, aggregateprocessor.NewDefaultConfig())
	//
	//a.componentsFactory.RegisterAnalyzer(network.Network.String(), network.NewNetworkAnalyzer, &network.Config{})
	a.componentsFactory.RegisterAnalyzer(tcp_analyzer.TcpMetric.String(), tcp_analyzer.NewTcpMetricAnalyzer, nil)
	//a.componentsFactory.RegisterAnalyzer(loganalyzer.Type.String(), loganalyzer.New, &loganalyzer.Config{})
	//a.componentsFactory.RegisterAnalyzer(tcpconnectanalyzer.Type.String(), tcpconnectanalyzer.New, tcpconnectanalyzer.NewDefaultConfig())
}

func (a *Application) readInConfig(path string) error {
	a.viper.SetConfigFile(path)
	err := a.viper.ReadInConfig()
	if err != nil { // Handle errors reading the config file
		return fmt.Errorf("error happened while reading config file: %w", err)
	}
	//a.telemetry.ConstructConfig(a.viper)
	err = a.componentsFactory.ConstructConfig(a.viper)
	if err != nil {
		return fmt.Errorf("error happened while constructing config: %w", err)
	}
	return nil
}

// buildPipeline builds a event processing pipeline based on hard-code.
func (a *Application) buildPipeline() error {
	// TODO: Build pipeline via configuration to implement dependency injection

	// 初始化exporter
	//otelExporterFactory := a.componentsFactory.Exporters[otelexporter.Otel]
	//otelExporter := otelExporterFactory.NewFunc(otelExporterFactory.Config, a.telemetry.Telemetry)

	// 1. 数据集聚合
	//aggregateProcessorFactory := a.componentsFactory.Processors[aggregateprocessor.Type]
	//aggregateProcessor := aggregateProcessorFactory.NewFunc(aggregateProcessorFactory.Config, a.telemetry.Telemetry, otelExporter)
	// 2. k8s处理器 Kubernetes metadata processor
	k8sProcessorFactory := a.componentsFactory.Processors[k8s.K8sMetadata]
	//k8sMetadataProcessor := k8sProcessorFactory.NewFunc(k8sProcessorFactory.Config, a.telemetry.Telemetry, aggregateProcessor)

	// 初始化所有的分析器
	// 1. 正常的网络请求分析器
	//networkAnalyzerFactory := a.componentsFactory.Analyzers[network.Network.String()]
	// Now NetworkAnalyzer must be initialized before any other analyzers, because it will
	// use its configuration to initialize the conntracker module which is also used by others.
	//networkAnalyzer := networkAnalyzerFactory.NewFunc(networkAnalyzerFactory.Config, a.telemetry.Telemetry, []consumer.Consumer{k8sMetadataProcessor})
	// 2. 4层TCP检测分析器
	//aggregateProcessorForTcp := aggregateProcessorFactory.NewFunc(aggregateProcessorFactory.Config, a.telemetry.Telemetry, otelExporter)
	k8sMetadataProcessor2 := k8sProcessorFactory.NewFunc(k8sProcessorFactory.Config, a.telemetry.GetGlobalTelemetryTools(), nil)
	tcpAnalyzerFactory := a.componentsFactory.Analyzers[tcp_analyzer.TcpMetric.String()]
	tcpAnalyzer := tcpAnalyzerFactory.NewFunc(tcpAnalyzerFactory.Config, a.telemetry.GetGlobalTelemetryTools(), []consumer.Consumer{k8sMetadataProcessor2})
	//tcpConnectAnalyzerFactory := a.componentsFactory.Analyzers[tcpconnectanalyzer.Type.String()]
	//tcpConnectAnalyzer := tcpConnectAnalyzerFactory.NewFunc(tcpConnectAnalyzerFactory.Config, a.telemetry.Telemetry, []consumer.Consumer{k8sMetadataProcessor})

	// 初始化分析管理器 Initialize receiver packaged with multiple analyzers
	analyzerManager, err := analyzer.NewManager(tcpAnalyzer)
	if err != nil {
		return fmt.Errorf("error happened while creating analyzer manager: %w", err)
	}
	a.analyzerManager = analyzerManager

	cgoReceiverFactory := a.componentsFactory.Receivers[cgoreceiver.Cgo]
	cgoReceiver := cgoReceiverFactory.NewFunc(cgoReceiverFactory.Config, nil, nil)
	a.receiver = cgoReceiver
	return nil
}

func (a *Application) Shutdown() error {
	return multierr.Combine(a.receiver.Shutdown(), a.analyzerManager.ShutdownAll(a.telemetry.Logger))
}
