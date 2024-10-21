package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-gandi/go-gandi"
	"github.com/go-gandi/go-gandi/config"
	"github.com/go-gandi/go-gandi/livedns"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const (
	GandiMinTtl = 300 // Gandi reports an error for values < this value
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our gandi DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&gandiDNSProviderSolver{},
	)
}

// gandiDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type gandiDNSProviderSolver struct {
	client *kubernetes.Clientset
}

// gandiDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type gandiDNSProviderConfig struct {
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.
	PATSecretRef cmmeta.SecretKeySelector `json:"PATSecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *gandiDNSProviderSolver) Name() string {
	return "gandi"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *gandiDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.V(6).Infof("call function Present: namespace=%s, zone=%s, fqdn=%s",
		ch.ResourceNamespace, ch.ResolvedZone, ch.ResolvedFQDN)

	gandiClient, err := c.getGandiClient(ch.Config, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("unable to get Gandi client: %v", err)
	}

	challengeFQDN, domain := c.getDomainAndChallengeFQDN(ch)
	klog.V(6).Infof("present for challengeFQDN=%s, domain=%s", challengeFQDN, domain)

	domainRecord, err := gandiClient.GetDomainRecordByNameAndType(domain, challengeFQDN, "TXT")
	if err != nil {
		return fmt.Errorf("present: pre: unable to check TXT record: %v", err)
	}

	recordVal := [...]string{ch.Key}

	if domainRecord.RrsetName != "" && len(domainRecord.RrsetValues) > 0 {
		resp, err := gandiClient.UpdateDomainRecordByNameAndType(domain, challengeFQDN, "TXT", GandiMinTtl, recordVal[:])
		if err != nil {
			return fmt.Errorf("unable to change TXT record: %v", err)
		}
		if resp.Code != 200 {
			return fmt.Errorf("got code %d while trying to change TXT record: %v", resp.Code, domain)
		}
	} else {
		resp, err := gandiClient.UpdateDomainRecordByNameAndType(domain, challengeFQDN, "TXT", GandiMinTtl, recordVal[:])
		if err != nil {
			return fmt.Errorf("unable to create TXT record: %v", err)
		}
		if resp.Code != 200 {
			return fmt.Errorf("got code %d while trying to create TXT record: %v", resp.Code, domain)
		}
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *gandiDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.V(6).Infof("call function CleanUp: namespace=%s, zone=%s, fqdn=%s",
		ch.ResourceNamespace, ch.ResolvedZone, ch.ResolvedFQDN)

	gandiClient, err := c.getGandiClient(ch.Config, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("unable to get Gandi client: %v", err)
	}

	challengeFQDN, domain := c.getDomainAndChallengeFQDN(ch)

	domainRecord, err := gandiClient.GetDomainRecordByNameAndType(domain, challengeFQDN, "TXT")
	if err != nil {
		return fmt.Errorf("cleanup: pre: unable to check TXT record: %v", err)
	}

	if domainRecord.RrsetName != "" && len(domainRecord.RrsetValues) > 0 {
		klog.V(6).Infof("deleting challengeFQDN=%s, domain=%s", challengeFQDN, domain)
		err := gandiClient.DeleteDomainRecord(domain, challengeFQDN, "TXT")
		if err != nil {
			return fmt.Errorf("unable to remove TXT record: %v", err)
		}
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *gandiDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	klog.V(6).Infof("call function Initialize")
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("unable to get k8s client: %v", err)
	}
	c.client = cl
	return nil
}

// getGandiClient instantiates a go-gandi livedns client
// This replaces the previous 3 smaller methods, and makes caller functions cleaner
func (c *gandiDNSProviderSolver) getGandiClient(cfgJSON *extapi.JSON, namespace string) (*livedns.LiveDNS, error) {
	cfg := gandiDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return nil, fmt.Errorf("no configuration provided: %v", cfgJSON)
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return nil, fmt.Errorf("error decoding solver config: %v", err)
	}

	secretName := cfg.PATSecretRef.LocalObjectReference.Name

	klog.V(6).Infof("try to load secret `%s` with key `%s`", secretName, cfg.PATSecretRef.Key)

	sec, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get secret `%s`; %v", secretName, err)
	}

	secBytes, ok := sec.Data[cfg.PATSecretRef.Key]
	if !ok {
		return nil, fmt.Errorf("key %q not found in secret \"%s/%s\"", cfg.PATSecretRef.Key,
			cfg.PATSecretRef.LocalObjectReference.Name, namespace)
	}

	pat := string(secBytes)
	gandiConfig := config.Config{PersonalAccessToken: pat}

	liveDNSClient := gandi.NewLiveDNSClient(gandiConfig)

	return liveDNSClient, nil
}

func (c *gandiDNSProviderSolver) getDomainAndChallengeFQDN(ch *v1alpha1.ChallengeRequest) (string, string) {
	// Both ch.ResolvedZone and ch.ResolvedFQDN end with a dot: '.'
	entry := strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone)
	entry = strings.TrimSuffix(entry, ".")
	domain := strings.TrimSuffix(ch.ResolvedZone, ".")
	return entry, domain
}
