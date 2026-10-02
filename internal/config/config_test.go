package config

import (
	"flag"
	"slices"
	"testing"
)

func load(t *testing.T, args ...string) (*Config, error) {
	t.Helper()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	raw := Register(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return raw.Load()
}

func TestZones(t *testing.T) {
	c, err := load(t)
	if err != nil || len(c.Zones) != 0 || !c.OwnsZone("anything") {
		t.Fatalf("default must own every zone: %v %v", c.Zones, err)
	}
	c, err = load(t, "--zones", " qualif , qualif-eg ")
	if err != nil || !slices.Equal(c.Zones, []string{"qualif", "qualif-eg"}) {
		t.Fatalf("zones %v %v", c.Zones, err)
	}
	if !c.OwnsZone("qualif-eg") || c.OwnsZone("dev") {
		t.Fatal("OwnsZone must follow --zones")
	}
	if _, err = load(t, "--zones", "dev,Not_A_Zone"); err == nil {
		t.Fatal("an invalid Zone name must be refused")
	}
}

func TestZonesFromEnv(t *testing.T) {
	t.Setenv("SITE_OPERATOR_ZONES", "dev")
	c, err := load(t)
	if err != nil || !slices.Equal(c.Zones, []string{"dev"}) {
		t.Fatalf("zones %v %v", c.Zones, err)
	}
}
