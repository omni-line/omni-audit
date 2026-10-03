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
func FooterText(unclaimed, shadow int) string {
	switch {
	case shadow > 0 && unclaimed > 0:
		return "───\n" +
			"Unclaimed names and lockfiles that bypass your proxy are supply-chain gaps.\n" +
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
	return "Dependency confusion and shadow registries are supply-chain risks. Prevent them at install time with Omni Line — self-hosted Virtual Registries for npm, Composer, PyPI, Go, and more. " + docsURL
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
