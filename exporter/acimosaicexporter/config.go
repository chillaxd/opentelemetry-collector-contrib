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
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/resourcetotelemetry"
)

// Defaults for not specified configuration settings.
const (
	DefaultEndpoint        = "mosaic-metrics-gateway-grpc-000.telemetry.g.apple.com:25189"
	DefaultWorkspace       = "playground-gala"
	DefaultNamespace       = "apple-ops-aa"
	DefaultCertificateFile = "~/.mosaic/client-cert.chain.pem"
	DefaultKeyFile         = "~/.mosaic/client-key.pem"
	DefaultCAFile          = "~/.mosaic/trusted-root.pem"
)

// Config defines configuration for Carbon exporter.
type Config struct {

	// Endpoints specifies comma separated host and port to send metrics in the ACI Mosaic.
	// The default value is defined by the DefaultEndpoint constant.
	Endpoints string `mapstructure:"endpoints"`

	// Workspace is the organization in mosaic to separate it out from other unit's
	// metrics.
	// The default value is defined by the DefaultWorkspace constant, this is shared workspace
	// to play around via different teams.
	Workspace string `mapstructure:"workspace"`

	// Namespace is the group of related metrics.
	// The default value is defined by the DefaultNamespace constant, which is created to test
	// the functionality.
	Namespace string `mapstructure:"namespace"`

	CertificateFile string `mapstructure:"cert_file"`
	KeyFile         string `mapstructure:"key_file"`
	CAFile          string `mapstructure:"ca_file"`

	// ResourceToTelemetrySettings is the option for converting resource attributes to telemetry attributes.
	// "Enabled" - A boolean field to enable/disable this option. Default is `false`.
	// If enabled, all the resource attributes will be converted to metric labels by default.
	ResourceToTelemetrySettings resourcetotelemetry.Settings `mapstructure:"resource_to_telemetry_conversion"`
}

// Validate checks if the exporter configuration is valid
func (cfg *Config) Validate() error {

	for _, enp := range strings.Split(cfg.Endpoints, ",") {
		if !strings.Contains(enp, "g.apple.com") {
			return fmt.Errorf("aci mosaic endpoint must be an apple endpoint")
		}

		if _, err := net.ResolveTCPAddr("tcp", enp); err != nil {
			return fmt.Errorf("exporter has an invalid TCP endpoint: %w", err)
		}
	}

	if len(cfg.Workspace) == 0 {
		return fmt.Errorf("mosaic workspace is mandatory parameter")
	}

	if len(cfg.Namespace) == 0 {
		return fmt.Errorf("mosaic namespace is mandatory parameter")
	}

	if _, err := os.Stat(cfg.CertificateFile); err != nil {
		return fmt.Errorf("certificate file path does not exists")
	}

	if _, err := os.Stat(cfg.KeyFile); err != nil {
		return fmt.Errorf("key file path does not exists")
	}

	if _, err := os.Stat(cfg.CAFile); err != nil {
		return fmt.Errorf("ca file path does not exists")
	}

	return nil
}
