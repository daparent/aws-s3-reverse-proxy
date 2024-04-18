package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	_ "net/http/pprof"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	log "github.com/sirupsen/logrus"
)

// Options for aws-s3-reverse-proxy command line arguments
type Options struct {
	Debug                 bool
	ListenAddr            string
	MetricsListenAddr     string
	PprofListenAddr       string
	AllowedSourceEndpoint string
	AllowedSourceSubnet   []string
	AwsCredentials        []string
	Region                string
	UpstreamInsecure      bool
	UpstreamEndpoint      string
	CertFile              string
	KeyFile               string
	WriteProdS3Bucket     string
	ReadProdS3Bucket      string
	UserS3Bucket          string
	AdminS3Bucket         string
}

// NewOptions defines and parses the raw command line arguments
func NewOptions() Options {
	var opts Options
	kingpin.Flag("verbose", "enable additional logging (env - VERBOSE)").Envar("VERBOSE").Short('v').BoolVar(&opts.Debug)
	kingpin.Flag("listen-addr", "address:port to listen for requests on (env - LISTEN_ADDR)").Default(":8099").Envar("LISTEN_ADDR").StringVar(&opts.ListenAddr)
	kingpin.Flag("metrics-listen-addr", "address:port to listen for Prometheus metrics on, empty to disable (env - METRICS_LISTEN_ADDR)").Default("").Envar("METRICS_LISTEN_ADDR").StringVar(&opts.MetricsListenAddr)
	kingpin.Flag("pprof-listen-addr", "address:port to listen for pprof on, empty to disable (env - PPROF_LISTEN_ADDR)").Default("").Envar("PPROF_LISTEN_ADDR").StringVar(&opts.PprofListenAddr)
	kingpin.Flag("allowed-endpoint", "allowed endpoint (Host header) to accept for incoming requests (env - ALLOWED_ENDPOINT)").Envar("ALLOWED_ENDPOINT").Required().PlaceHolder("my.host.example.com:8099").StringVar(&opts.AllowedSourceEndpoint)
	kingpin.Flag("allowed-source-subnet", "allowed source IP addresses with netmask (env - ALLOWED_SOURCE_SUBNET)").Default("127.0.0.1/32").Envar("ALLOWED_SOURCE_SUBNET").StringsVar(&opts.AllowedSourceSubnet)
	kingpin.Flag("aws-region", "send requests to this AWS S3 region (env - AWS_REGION)").Envar("AWS_REGION").Default("eu-central-1").StringVar(&opts.Region)
	kingpin.Flag("upstream-insecure", "use insecure HTTP for upstream connections (env - UPSTREAM_INSECURE)").Envar("UPSTREAM_INSECURE").BoolVar(&opts.UpstreamInsecure)
	kingpin.Flag("upstream-endpoint", "use this S3 endpoint for upstream connections, instead of public AWS S3 (env - UPSTREAM_ENDPOINT)").Envar("UPSTREAM_ENDPOINT").StringVar(&opts.UpstreamEndpoint)
	kingpin.Flag("cert-file", "path to the certificate file (env - CERT_FILE)").Envar("CERT_FILE").Default("").StringVar(&opts.CertFile)
	kingpin.Flag("key-file", "path to the private key file (env - KEY_FILE)").Envar("KEY_FILE").Default("").StringVar(&opts.KeyFile)
	kingpin.Flag("write-prod-s3-bucket-credentials", "set of credentials that provide write access to the prod s3 bucket").PlaceHolder("\"WRITE_PROD_S3_KEY_ID,WRITE_PROD_S3_ACCESS_KEY\"").Envar("WRITE_PROD_S3_BUCKET").StringVar(&opts.WriteProdS3Bucket)
	kingpin.Flag("read-prod-s3-bucket-credentials", "set of credentials that provide read access to the prod s3 bucket").PlaceHolder("\"READ_PROD_S3_KEY_ID,READ_PROD_S3_ACCESS_KEY\"").Envar("READ_PROD_S3_BUCKET").StringVar(&opts.ReadProdS3Bucket)
	kingpin.Flag("user-s3-bucket-credentials", "set of credentials that provide user read/write access to the users s3 bucket").PlaceHolder("\"READ_WRITE_USER_S3_KEY_ID,READ_WRITE_USER_S3_ACCESS_KEY\"").Envar("READ_WRITE_USER_CREDENTIALS").StringVar(&opts.UserS3Bucket)
	kingpin.Flag("admin-s3-bucket-credentials", "set of credentials that provide admin level access read/write access to all s3 buckets").PlaceHolder("\"ADMIN_S3_KEY_ID,ADMIN_S3_ACCESS_KEY\"").Envar("ADMIN_S3_BUCKET_CREDENTIALS").StringVar(&opts.AdminS3Bucket)
	kingpin.Parse()
	return opts
}

func ValidateJWTToken(token string) bool {
	return true
}

func CreateCred(argCred string) map[string]string {
	cred := make(map[string]string)
	d := strings.Split(argCred, ",")

	if len(d) != 2 || len(d[0]) < 16 || len(d[1]) < 1 {
		cred["UNKNOWN_ACCESS_KEY"] = "UNKNOWN_ACCESS_KEY"
	} else {
		cred[d[0]] = d[1]
	}

	return cred
}

// token may be used for validating the user, it's usage in this function is seeming less useful...
func ParseCreds(opts Options, token string) map[string]map[string]string {
	credMap := make(map[string]map[string]string)

	credMap["WRITER"] = CreateCred(opts.WriteProdS3Bucket)
	credMap["READER"] = CreateCred(opts.ReadProdS3Bucket)
	credMap["USER"] = CreateCred(opts.UserS3Bucket)
	credMap["ADMIN"] = CreateCred(opts.AdminS3Bucket)

	return credMap
}

// NewAwsS3ReverseProxy parses all options and creates a new HTTP Handler
func NewAwsS3ReverseProxy(opts Options) (*Handler, error) {
	log.SetLevel(log.InfoLevel)
	if opts.Debug {
		log.SetLevel(log.DebugLevel)
	}

	scheme := "https"
	if opts.UpstreamInsecure {
		scheme = "http"
	}

	var parsedAllowedSourceSubnet []*net.IPNet
	for _, sourceSubnet := range opts.AllowedSourceSubnet {
		_, subnet, err := net.ParseCIDR(sourceSubnet)
		if err != nil {
			return nil, fmt.Errorf("Invalid allowed source subnet: %v", sourceSubnet)
		}
		parsedAllowedSourceSubnet = append(parsedAllowedSourceSubnet, subnet)
	}

	if !ValidateJWTToken("test") {
		return nil, fmt.Errorf("invalid jwt token, blocking request at reverse proxy")
	}
	credMap := ParseCreds(opts, "test")
	signers := make(map[string]*v4.Signer)
	for _, cred := range credMap {
		for accessKeyID, secretAccessKey := range cred {
			log.Infof("accessKeyID: [%s], secretAccessKey: [%s]", accessKeyID, secretAccessKey)
			signers[accessKeyID] = v4.NewSigner(credentials.NewStaticCredentialsFromCreds(credentials.Value{
				AccessKeyID:     accessKeyID,
				SecretAccessKey: secretAccessKey,
			}))
		}
	}

	handler := &Handler{
		Debug:                 opts.Debug,
		UpstreamScheme:        scheme,
		UpstreamEndpoint:      opts.UpstreamEndpoint,
		AllowedSourceEndpoint: opts.AllowedSourceEndpoint,
		AllowedSourceSubnet:   parsedAllowedSourceSubnet,
		AllCredentials:        credMap,
		Signers:               signers,
	}
	return handler, nil
}

func main() {
	opts := NewOptions()
	handler, err := NewAwsS3ReverseProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	if len(handler.UpstreamEndpoint) > 0 {
		log.Infof("Sending requests to upstream AWS S3 to endpoint %s://%s.", handler.UpstreamScheme, handler.UpstreamEndpoint)
	} else {
		log.Infof("Auto-detecting S3 endpoint based on region: %s://s3.{region}.amazonaws.com", handler.UpstreamScheme)
	}

	for _, subnet := range handler.AllowedSourceSubnet {
		log.Infof("Allowing connections from %v.", subnet)
	}
	log.Infof("Accepting incoming requests for this endpoint: %v", handler.AllowedSourceEndpoint)
	for _, cred := range handler.AllCredentials {
		for key := range cred {
			log.Infof("Parsed 1 %s credential", key)
		}
	}

	if len(opts.PprofListenAddr) > 0 && len(strings.Split(opts.PprofListenAddr, ":")) == 2 {
		// avoid leaking pprof to the main application http servers
		pprofMux := http.DefaultServeMux
		http.DefaultServeMux = http.NewServeMux()
		// https://golang.org/pkg/net/http/pprof/
		log.Infof("Listening for pprof connections on %s", opts.PprofListenAddr)
		go func() {
			log.Fatal(
				http.ListenAndServe(opts.PprofListenAddr, pprofMux),
			)
		}()
	}

	var wrappedHandler http.Handler = handler
	if len(opts.MetricsListenAddr) > 0 && len(strings.Split(opts.MetricsListenAddr, ":")) == 2 {
		metricsHandler := http.NewServeMux()
		metricsHandler.Handle("/metrics", promhttp.Handler())

		log.Infof("Listening for secure Prometheus metrics on %s", opts.MetricsListenAddr)
		wrappedHandler = wrapPrometheusMetrics(handler)

		go func() {
			log.Fatal(
				http.ListenAndServe(opts.MetricsListenAddr, metricsHandler),
			)
		}()
	}

	if len(opts.CertFile) > 0 || len(opts.KeyFile) > 0 {
		log.Infof("Reading HTTPS certificate from %v and %v.", opts.CertFile, opts.KeyFile)
		log.Infof("Listening for secure HTTPS connections on %s", opts.ListenAddr)
		log.Fatal(
			http.ListenAndServeTLS(opts.ListenAddr, opts.CertFile, opts.KeyFile, wrappedHandler),
		)
	} else {
		log.Infof("Listening for HTTP connections on %s", opts.ListenAddr)
		log.Fatal(
			http.ListenAndServe(opts.ListenAddr, wrappedHandler),
		)
	}
}
