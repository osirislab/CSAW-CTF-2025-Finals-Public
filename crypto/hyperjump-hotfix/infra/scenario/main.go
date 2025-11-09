package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/ctfer-io/chall-manager/sdk"
	k8s "github.com/ctfer-io/chall-manager/sdk/kubernetes"
	"github.com/ctfer-io/recipes"
	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const (
	cloudflare_zone = "b90b313a332879c7fd5a2ff3924e0bf2"
	port            = 21009
)

type Config struct {
	Hostname string `form:"hostname"`
	Image    string `form:"image"`
}

func main() {
	recipes.Run(func(req *recipes.Request[Config], resp *sdk.Response, opts ...pulumi.ResourceOption) error {
		// Deploy the container, create networking resources
		cm, err := k8s.NewExposedMonopod(req.Ctx, "hyperjump-hotfix", &k8s.ExposedMonopodArgs{
			Identity: pulumi.String(req.Identity),
			Hostname: pulumi.String(req.Config.Hostname),
			Container: k8s.ContainerArgs{
				Image: pulumi.String(req.Config.Image),
				Ports: k8s.PortBindingArray{
					k8s.PortBindingArgs{
						Port:       pulumi.Int(port),
						ExposeType: k8s.ExposeLoadBalancer,
						Annotations: pulumi.StringMap{
							"service.beta.kubernetes.io/aws-load-balancer-backend-protocol":     pulumi.String("TCP"),
							"service.beta.kubernetes.io/aws-load-balancer-scheme":               pulumi.String("internet-facing"),
							"service.beta.kubernetes.io/aws-load-balancer-type":                 pulumi.String("external"),
							"service.beta.kubernetes.io/aws-load-balancer-healthcheck-protocol": pulumi.String("TCP"),
							"service.beta.kubernetes.io/aws-load-balancer-healthcheck-port":     pulumi.String("traffic-port"),
						},
					},
				},
			},
			Label: pulumi.String("hyperjump-hotfix"),
		}, opts...)
		if err != nil {
			return err
		}

		// Then connect to Cloudflare
		cloudflarePv, err := cloudflare.NewProvider(req.Ctx, "cloudflare", &cloudflare.ProviderArgs{
			ApiToken: pulumi.String(func() string {
				apiToken, ok := os.LookupEnv("CLOUDFLARE_API_TOKEN")
				if !ok {
					apiToken, ok = req.Ctx.GetConfig("hyperjump-hotfix:cloudflare_api_token")
					if !ok {
						panic("Cloudflare API token not defined")
					}
				}
				return apiToken
			}()),
		})
		if err != nil {
			return err
		}

		opts = append(opts, pulumi.Provider(cloudflarePv))

		// And create a new hostname and associates it to the AWS ELB external name
		// Hostname is not directly inherited from the identity, as it is also the seed of the
		// PRNG of the variation engine for the flag. If the identity leaks, you know how the
		// PRNG has been instantiated, and once you know yours you can do the backward work
		// to find the original flag, and for every other team, produce the valid flag.
		hostname := pulumi.Sprintf("%s.%s",
			randName(fmt.Sprintf("%s-%s-%d/%s",
				req.Identity,
				"one", // exposed monopod -> name is "one"
				21009,
				"TCP",
			))[:len(req.Identity)], // a non-guessable name, lifted from CM SDK
			req.Config.Hostname,
		)
		if _, err := cloudflare.NewDnsRecord(req.Ctx, "cname", &cloudflare.DnsRecordArgs{
			ZoneId:  pulumi.String(cloudflare_zone),
			Name:    hostname,
			Type:    pulumi.String("CNAME"),
			Ttl:     pulumi.Float64(1),
			Proxied: pulumi.Bool(false), // don't need to hide real ELB name, its ephemeral and does not leak much infra details ¯\_(ツ)_/¯
			Content: cm.URLs.MapIndex(pulumi.String("21009/TCP")).ApplyT(func(edp string) string {
				host, _, _ := strings.Cut(edp, ":")
				return host
			}).(pulumi.StringOutput),
		}, opts...); err != nil {
			return err
		}

		resp.ConnectionInfo = pulumi.Sprintf("nc %s 21009", hostname)
		return nil
	})
}

// randName is a pseudo-random name generator. It does not include
// random under the hood thus is reproducible.
// Is lifted from https://github.com/ctfer-io/chall-manager/blob/main/sdk/kubernetes/common.go
func randName(seed string) string {
	h := sha1.New()
	if _, err := h.Write([]byte(seed)); err != nil {
		// This will happen only if FIPS compliance is turned on
		panic(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}
