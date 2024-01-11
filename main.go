package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/joeycumines/statsd"
)

func init() {
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	viper.SetDefault("log-level", "warn")
	viper.SetDefault("vault-addr", "")
	viper.SetDefault("statsd-addr", "")
	viper.SetDefault("tags", false)
	viper.SetDefault("tags-format", "") // influxdb, datadog
	viper.SetDefault("vault-addr-resolve", false)
	viper.SetDefault("report-interval", "30s")
	viper.SetDefault("prefix", "vault.status")
}

var (
	Version   = "--dev--"
	BuildTime = "--dev--"
)

func asInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func main() {
	if l, err := logrus.ParseLevel(viper.GetString("log-level")); err == nil {
		logrus.SetLevel(l)
	} else {
		logrus.SetLevel(logrus.WarnLevel)
	}
	logrus.SetFormatter(&logrus.TextFormatter{TimestampFormat: time.RFC3339, FullTimestamp: true})

	logrus.
		WithField("version", Version).
		WithField("build_time", BuildTime).
		WithField("vault_addr", viper.GetString("vault-addr")).
		WithField("statsd_addr", viper.GetString("statsd-addr")).
		WithField("tags", viper.GetBool("tags")).
		Info("Vault StatsD Reporter")

	vaultAddrs := strings.FieldsFunc(viper.GetString("vault-addr"), func(c rune) bool {
		return unicode.IsSpace(c) || c == ','
	})
	if len(vaultAddrs) == 0 {
		logrus.Fatal("Vault Addr must be a valid URL. Error: No vault address was configured")
	}
	if viper.GetString("statsd-addr") == "" {
		logrus.Fatalf("No statsd address was configured.")
	}

	var vaultHosts []*url.URL

	for _, vaultAddr := range vaultAddrs {
		vaultHost, err := url.ParseRequestURI(vaultAddr)
		if err != nil {
			logrus.Fatalf("Vault Addr must be a valid URL. Addr: %v Error: %v", vaultAddr, err)
		}
		if vaultHost.Port() == "" {
			switch vaultHost.Scheme {
			case "http":
				vaultHost.Host = vaultHost.Host + ":80"
			case "https":
				vaultHost.Host = vaultHost.Host + ":443"
			}

		}
		if viper.GetBool("vault-addr-resolve") {
			if host, port, err := net.SplitHostPort(vaultHost.Host); err == nil {
				if addrs, err := net.LookupIP(host); err == nil {
					for _, addr := range addrs {
						u := new(url.URL)
						*u = *vaultHost
						u.Host = net.JoinHostPort(addr.String(), port)
						vaultHosts = append(vaultHosts, u)
					}
				} else {
					logrus.Fatalf("Vault Addr or env is misconfigured, could not resolve host '%s'. Error: %v", host, err)
				}
			} else {
				logrus.Fatalf("Vault Addr is misconfigured, could not parse host. Error: %v", err)
			}
		} else {
			vaultHosts = append(vaultHosts, vaultHost)
		}
	}

	logrus.Infof("Reporting status of vault servers: %+v", vaultHosts)

	conn, err := statsd.NewUDPConn("udp", viper.GetString("statsd-addr"), time.Second*30)
	if err != nil {
		logrus.Fatalf("Failed to connect to statsd: %w", err)
	}
	options := []statsd.Option{
		statsd.WriteCloser(conn),
		statsd.TrimTrailingNewline(true), 
		statsd.UDPCheck(true),
		statsd.Prefix(viper.GetString("prefix")),
		statsd.ErrorHandler(func(err error) {
			logrus.Warnf("Statsd Error: %v", err)
		}),
	}
	withTags := viper.GetBool("tags")
	switch strings.ToLower(viper.GetString("tags-format")) {
	case "influxdb":
		options = append(options, statsd.TagsFormat(statsd.InfluxDB))
	case "datadog":
		options = append(options, statsd.TagsFormat(statsd.Datadog))
	case "":
		if withTags {
			logrus.Fatalf("Unrecognized tag format: %s", viper.GetString("tags-format"))
		}
	}
	c, err := statsd.New(options...)
	if err != nil {
		logrus.Fatalf("Failed to initialize statsd: %v", err)
	}

	ticker := time.NewTicker(viper.GetDuration("report-interval"))

	for {
		for _, vaultAddr := range vaultHosts {
			c := c
			if withTags {
				c = c.Clone(statsd.Tags("host", vaultAddr.Hostname()))
			}
			vaultAddr.Path = "/v1/sys/health"
			if resp, err := http.Get(vaultAddr.String()); err == nil {
				var health struct {
					Initialized                bool   `json:"initialized"`
					Sealed                     bool   `json:"sealed"`
					Standby                    bool   `json:"standby"`
					ReplicationPerformanceMode string `json:"replication_performance_mode"`
					ReplicationDrMode          string `json:"replication_dr_mode"`
					ServerTimeUTC              int    `json:"server_time_utc"`
					Version                    string `json:"version"`
					ClusterName                string `json:"cluster_name"`
					ClusterId                  string `json:"cluster_id"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&health); err == nil {
					c.Gauge("initialized", asInt(health.Initialized))
					c.Gauge("sealed", asInt(health.Sealed))
					c.Gauge("standby", asInt(health.Standby))

					c.Gauge("reachable", asInt(true))
					c.Gauge("unsealed", asInt(!health.Sealed))
					c.Gauge("leader", asInt(!health.Standby))
				} else {
					c.Gauge("reachable", asInt(false))
					logrus.Warnf("Failed to parse health JSON for %v: %v", vaultAddr.Host, err)
				}
				resp.Body.Close()
			} else {
				c.Gauge("reachable", asInt(false))
				logrus.Warnf("Failed to get health for %v: %v", vaultAddr.Host, err)
			}
			c.Flush()
		}
		<-ticker.C
	}

}
