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
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"

	pub "github.pie.apple.com/telemetry/mosaic-go-publisher"
)

func convertToMosaicFormat(md pmetric.Metrics, logger *zap.Logger) []*pub.Metric {
	if md.DataPointCount() == 0 {
		logger.Error("mosaic: no datapoints received")
		return nil
	}

	mMetrics := []*pub.Metric{}

	resourceMetricsSlice := md.ResourceMetrics()
	for i := 0; i < resourceMetricsSlice.Len(); i++ {
		resourceMetrics := resourceMetricsSlice.At(i)
		resource := resourceMetrics.Resource()
		scopeMetricsSlice := resourceMetrics.ScopeMetrics()

		for j := 0; j < scopeMetricsSlice.Len(); j++ {
			scopeMetrics := scopeMetricsSlice.At(j)
			metricSlice := scopeMetrics.Metrics()

			for k := 0; k < metricSlice.Len(); k++ {
				metric := metricSlice.At(k)
				metricName := metric.Name()
				if metricName == "" {
					logger.Error("mosaic: metric name is blank")
					continue
				}

				switch metric.Type() {
				case pmetric.MetricTypeGauge:
					dataPoints := metric.Gauge().DataPoints()
					if dataPoints.Len() == 0 {
						logger.Error("mosaic: empty data points. metric is dropped", zap.String("metric", metricName))
					}

					addGaugeDataPoints(resource, metricName, dataPoints, mMetrics)
				case pmetric.MetricTypeSum:
					dataPoints := metric.Sum().DataPoints()
					if dataPoints.Len() == 0 {
						logger.Error("mosaic: empty data points. metric is dropped", zap.String("metric", metricName))
					}

					addSumDataPoints(resource, metricName, dataPoints, mMetrics)
				case pmetric.MetricTypeHistogram:
					dataPoints := metric.Histogram().DataPoints()
					if dataPoints.Len() == 0 {
						logger.Error("mosaic: empty data points. metric is dropped", zap.String("metric", metricName))
					}

					addHistogramDataPoints(resource, metricName, dataPoints, mMetrics, logger)
				case pmetric.MetricTypeSummary:
					dataPoints := metric.Summary().DataPoints()
					if dataPoints.Len() == 0 {
						logger.Error("mosaic: empty data points. metric is dropped", zap.String("metric", metricName))
					}

					addSummaryDataPoints(resource, metricName, dataPoints, mMetrics, logger)
				}
			}
		}
	}

	return mMetrics
}

func generateLabels(resource pcommon.Resource, attributes pcommon.Map) map[string]string {
	labels := map[string]string{}

	// adding metric attributes as labels
	attributes.Range(func(key string, value pcommon.Value) bool {
		labels[key] = value.AsString()
		return true
	})

	// adding resource related attributes as labels
	resource.Attributes().Range(func(key string, value pcommon.Value) bool {
		labels[key] = value.AsString()
		return true
	})

	return labels
}

// convertTimeStamp converts OTLP timestamp in ns to timestamp in ms
func convertTimeStamp(timestamp pcommon.Timestamp) uint64 {
	return uint64(timestamp.AsTime().UnixNano()) / (uint64(time.Millisecond) / uint64(time.Nanosecond))
}

// A gauge is a metric that represents a single numerical value that can arbitrarily go up and down.
func addGaugeDataPoints(resource pcommon.Resource, metricName string, dataPoints pmetric.NumberDataPointSlice, mosaicMetrics []*pub.Metric) {
	for x := 0; x < dataPoints.Len(); x++ {
		dpt := dataPoints.At(x)
		labels := generateLabels(resource, dpt.Attributes())

		var metricValue float64

		switch dpt.ValueType() {
		case pmetric.NumberDataPointValueTypeInt:
			metricValue = float64(dpt.IntValue())
		case pmetric.NumberDataPointValueTypeDouble:
			metricValue = dpt.DoubleValue()
		}

		mm, _ := pub.CreateGauge(metricName, labels, metricValue, 30, convertTimeStamp(dpt.Timestamp()))

		mosaicMetrics = append(mosaicMetrics, &mm)
	}
}

// A Sum or A counter is a cumulative metric that represents a single monotonically increasing counter,
// whose value can only increase or be reset to zero on restart.
func addSumDataPoints(resource pcommon.Resource, metricName string, dataPoints pmetric.NumberDataPointSlice, mosaicMetrics []*pub.Metric) {
	for x := 0; x < dataPoints.Len(); x++ {
		dpt := dataPoints.At(x)
		labels := generateLabels(resource, dpt.Attributes())

		var metricValue float64

		switch dpt.ValueType() {
		case pmetric.NumberDataPointValueTypeInt:
			metricValue = float64(dpt.IntValue())
		case pmetric.NumberDataPointValueTypeDouble:
			metricValue = dpt.DoubleValue()
		}

		mm, _ := pub.CreateCounter(metricName, labels, metricValue, 30, convertTimeStamp(dpt.Timestamp()))

		mosaicMetrics = append(mosaicMetrics, &mm)
	}
}

// A histogram samples observations (usually things like request durations or response sizes) and
// counts them in configurable buckets. It also provides a sum of all observed values.
// Examples:
// https://pkg.go.dev/github.com/prometheus/client_golang/prometheus?utm_source=godoc#example-NewConstHistogram
func addHistogramDataPoints(resource pcommon.Resource, metricName string, dataPoints pmetric.HistogramDataPointSlice, mosaicMetrics []*pub.Metric, logger *zap.Logger) {
	for x := 0; x < dataPoints.Len(); x++ {
		dpt := dataPoints.At(x)

		labels := generateLabels(resource, dpt.Attributes())
		var populationSum float64

		populationCount := int64(dpt.Count())
		if populationCount == 0 {
			logger.Error("mosaic: empty population values. metric is dropped", zap.String("metric", metricName), zap.Int("datapoint", x))
			continue
		}

		if dpt.HasSum() {
			populationSum = dpt.Sum()
		}
		if populationSum == 0 {
			logger.Error("mosaic: empty population values. metric is dropped", zap.String("metric", metricName), zap.Int("datapoint", x))
			continue
		}

		histogramValues := map[float64]float64{}
		// cumulative count for conversion to cumulative histogram
		var cumulativeCount uint64

		// process each bound, based on histograms proto definition, # of buckets = # of explicit bounds + 1
		for i := 0; i < dpt.ExplicitBounds().Len() && i < dpt.BucketCounts().Len(); i++ {
			bound := dpt.ExplicitBounds().At(i)
			cumulativeCount += dpt.BucketCounts().At(i)

			histogramValues[bound] = float64(cumulativeCount)
		}

		mm, _ := pub.CreateHistogram(metricName, labels, histogramValues, populationSum, populationCount, 30, convertTimeStamp(dpt.Timestamp()))

		mosaicMetrics = append(mosaicMetrics, &mm)
	}
}

// Similar to a histogram, a summary samples observations (usually things like request durations and response sizes).
// While it also provides a total count of observations and a sum of all observed values,
// it calculates configurable quantiles over a sliding time window.
// Examples:
// https://pkg.go.dev/github.com/prometheus/client_golang/prometheus?utm_source=godoc#example-Summary
func addSummaryDataPoints(resource pcommon.Resource, metricName string, dataPoints pmetric.SummaryDataPointSlice, mosaicMetrics []*pub.Metric, logger *zap.Logger) {
	for x := 0; x < dataPoints.Len(); x++ {
		dpt := dataPoints.At(x)

		labels := generateLabels(resource, dpt.Attributes())

		populationCount := int64(dpt.Count())
		if populationCount == 0 {
			logger.Error("mosaic: empty population values. metric is dropped", zap.String("metric", metricName), zap.Int("datapoint", x))
			continue
		}

		populationSum := dpt.Sum()
		if populationSum == 0 {
			logger.Error("mosaic: empty population values. metric is dropped", zap.String("metric", metricName), zap.Int("datapoint", x))
			continue
		}

		summaryValues := map[float64]float64{}

		// process each percentile/quantile
		for i := 0; i < dpt.QuantileValues().Len(); i++ {
			qt := dpt.QuantileValues().At(i)

			summaryValues[qt.Quantile()] = qt.Value()
		}

		mm, _ := pub.CreateHistogram(metricName, labels, summaryValues, populationSum, populationCount, 30, convertTimeStamp(dpt.Timestamp()))

		mosaicMetrics = append(mosaicMetrics, &mm)
	}
}
