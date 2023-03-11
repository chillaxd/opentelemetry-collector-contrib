// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package acimosaicexporter // import "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/acimosaicexporter"

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"

	pub "github.pie.apple.com/telemetry/mosaic-go-publisher"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/resourcetotelemetry"
)

//	type mosaicMetricsPublisher struct {
//		endpoints       []string
//		workspace       string
//		namespace       string
//		certificateFile string
//		keyFile         string
//		cAFile          string
//		logger          *zap.Logger
//		client          *pub.MosaicClient
//	}

type mosaicMetricsPublisher struct {
	publisherConfig   pub.Config
	publisherMetadata pub.Metadata
	client            *pub.MosaicClient
	logger            *zap.Logger
}

// newMosaicMetricsExporter returns a new ACI Mosaic metrics exporter.
func newMosaicMetricsExporter(ctx context.Context, cfg *Config, set exporter.CreateSettings) (exporter.Metrics, error) {
	metricsPublisher := mosaicMetricsPublisher{
		logger: set.Logger,
	}

	metricsPublisher.publisherConfig = pub.Config{
		Servers:    strings.Split(cfg.Endpoints, ","),
		ServerType: pub.Discovery,
		Retries:    5,
		MtlsConfig: pub.MTLSConfig{
			ClientCertFile: cfg.CertificateFile,
			ClientKeyFile:  cfg.KeyFile,
			RootCAFile:     cfg.CAFile,
		},
	}

	metricsPublisher.publisherMetadata = pub.Metadata{
		Workspace: cfg.Workspace,
		Namespace: cfg.Namespace,
	}

	client, err := pub.NewMosaicClient(metricsPublisher.publisherConfig, metricsPublisher.publisherMetadata)
	if err != nil {
		metricsPublisher.logger.Error("mosaic: error creating gRPC client", zap.Error(err))
		return nil, err
	}
	metricsPublisher.client = client

	exporter, err := exporterhelper.NewMetricsExporter(
		ctx,
		set,
		cfg,
		metricsPublisher.PublishMetrics,
		exporterhelper.WithStart(metricsPublisher.Start),
		exporterhelper.WithShutdown(metricsPublisher.Shutdown),
	)
	if err != nil {
		metricsPublisher.logger.Error("mosaic: error creating exporter", zap.Error(err))
		return nil, err
	}

	return resourcetotelemetry.WrapMetricsExporter(cfg.ResourceToTelemetrySettings, exporter), nil
}

func (mmp *mosaicMetricsPublisher) PublishMetrics(ctx context.Context, md pmetric.Metrics) error {
	mosaicMetrics := convertToMosaicFormat(md, mmp.logger)
	if len(mosaicMetrics) == 0 {
		mmp.logger.Error("mosaic: no metrics converted into mosaic format")
		return fmt.Errorf("no metrics converted into mosaic format")
	}

	if !mmp.client.IsClientIntialized() {
		if err := mmp.client.ConnectWithContext(ctx); err != nil {
			mmp.logger.Error("mosaic: error occured when trying to connect", zap.Error(err))
			return err
		}

		mmp.logger.Info("mosaic: connected successfully to server")
	}

	_, err := mmp.client.WriteWithContext(ctx, mosaicMetrics, &mmp.publisherMetadata)
	if err != nil {
		mmp.logger.Error("mosaic: error occured when trying to write data", zap.Error(err))
	}

	mmp.logger.Info("mosaic: metrics wrote successfully")
	return nil
}

func (mmp *mosaicMetricsPublisher) Start(ctx context.Context, host component.Host) error {
	if err := mmp.client.ConnectWithContext(ctx); err != nil {
		mmp.logger.Error("mosaic: error occured when trying to connect", zap.Error(err))
		return err
	}

	mmp.logger.Info("mosaic: connected successfully to server")

	return nil
}

func (mmp *mosaicMetricsPublisher) Shutdown(context.Context) error {
	if err := mmp.client.Close(); err != nil {
		mmp.logger.Error("mosaic: error occured when trying to connect", zap.Error(err))
		return err
	}

	return nil
}
