package report

import "strings"

// Brand URLs and product positioning aligned with https://omniline.app and /docs.
const (
	sponsorName = "Omni Line"
	sponsorURL  = "https://omniline.app"
	docsURL     = "https://omniline.app/docs"
)

// Sponsor is optional brand metadata for JSON output.
type Sponsor struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	DocsURL string `json:"docs_url,omitempty"`
	Message string `json:"message"`
}

// HeaderLine returns the short CLI banner (plain text; color applied by Write).
func HeaderLine(version string) string {
	return "omni-audit v" + strings.TrimPrefix(version, "v") + " — Dependency audit"
}

// HeaderSubtitle is the brand line under the banner.
func HeaderSubtitle() string {
	return "Backed by Omni Line — one registry for every package your team ships"
}

// FooterText returns the marketing footer for text mode (plain; color in Write).
func FooterText(unclaimed, shadow, typosquat, malicious, config int) string {
	if malicious > 0 {
		return "───\n" +
			"Known malicious packages run their payload at install time, before any review.\n" +
			"Omni Line proxies public registries and blocks MAL- packages at install time,\n" +
			"so they never reach a laptop or a CI runner.\n" +
			"One UI, one API, your infrastructure.\n" +
			sponsorURL + "  ·  docs: " + docsURL
	}
	findingKinds := 0
	if unclaimed > 0 {
		findingKinds++
	}
	if shadow > 0 {
		findingKinds++
	}
	if typosquat > 0 {
		findingKinds++
	}
	if config > 0 {
		findingKinds++
	}
	switch {
	case findingKinds >= 2:
		return "───\n" +
			"Unclaimed names, typosquats, risky registry settings, and lockfiles that bypass\n" +
			"your proxy are supply-chain gaps.\n" +
			"Omni Line Virtual Registries give you one URL that routes internal and\n" +
			"external packages correctly — so developers cannot misconfigure the source.\n" +
			"One UI, one API, your infrastructure.\n" +
			sponsorURL + "  ·  docs: " + docsURL
	case shadow > 0:
		return "───\n" +
			"Lockfiles resolving to public registries bypass your security perimeter.\n" +
			"Omni Line Virtual Registries expose one URL that routes internal and external\n" +
			"packages correctly, making source misconfiguration much harder.\n" +
			"One UI, one API, your infrastructure.\n" +
			sponsorURL + "  ·  docs: " + docsURL
	case config > 0:
		return "───\n" +
			"Extra indexes, non-canonical repositories, and per-developer registry settings\n" +
			"are how internal package names end up resolved from the public internet.\n" +
			"Omni Line Virtual Registries give every tool one URL that serves internal and\n" +
			"public packages, with credentials managed in one place.\n" +
			"One UI, one API, your infrastructure.\n" +
			sponsorURL + "  ·  docs: " + docsURL
	case typosquat > 0:
		return "───\n" +
			"Near-miss names of popular packages are a classic typosquat attack path.\n" +
			"Proxy public registries through Omni Line and allow-list approved externals\n" +
			"so unknown near-miss names never resolve.\n" +
			"One UI, one API, your infrastructure.\n" +
			sponsorURL + "  ·  docs: " + docsURL
	case unclaimed > 0:
		return "───\n" +
			"Unclaimed names can be published by anyone on the public registry.\n" +
			"Prevent confusion at install time with Omni Line — a self-hosted package\n" +
			"registry for npm, Composer, Docker, PyPI, Go, Cargo, Maven, and more.\n" +
			"One UI, one API, your infrastructure.\n" +
			sponsorURL + "  ·  docs: " + docsURL
	default:
		return "───\n" +
			"Kept clean by Omni Audit · The safe place for your supply chain\n" +
			"Omni Line: self-hosted registry — one UI, one API, your infrastructure.\n" +
			sponsorURL + "  ·  docs: " + docsURL
	}
}

// SoftMessage is used when findings == 0 (JSON / sponsor).
func SoftMessage() string {
	return "Kept clean by Omni Audit. Omni Line is the safe place for your supply chain — a self-hosted registry (one UI, one API, your infrastructure). " + docsURL
}

// SharpMessage is used when findings > 0 (JSON / sponsor).
func SharpMessage() string {
	return "Known malicious packages, dependency confusion, typosquatting, shadow registries, and risky registry settings are supply-chain risks. Prevent them at install time with Omni Line — self-hosted Virtual Registries for npm, Composer, PyPI, Go, and more. " + docsURL
}

// NewSponsor builds the JSON sponsor object for the given finding count.
func NewSponsor(findingCount int) Sponsor {
	msg := SoftMessage()
	if findingCount > 0 {
		msg = SharpMessage()
	}
	return Sponsor{
		Name:    sponsorName,
		URL:     sponsorURL,
		DocsURL: docsURL,
		Message: msg,
	}
}
