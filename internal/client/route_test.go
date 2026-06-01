package client

import "testing"

func TestPhysicalDefaultGateway(t *testing.T) {
	gateway := physicalDefaultGateway()
	if gateway == "" {
		t.Skip("no physical default gateway on this host")
	}
	t.Logf("physical default gateway: %s", gateway)
}

func TestFullTunnelIPv4RoutesOverrideQuarterRoutes(t *testing.T) {
	routes := fullTunnelIPv4Routes()
	if len(routes) != 14 {
		t.Fatalf("route count = %d, want 14", len(routes))
	}
	if routes[0] != "0.0.0.0/4" || routes[len(routes)-1] != "208.0.0.0/4" {
		t.Fatalf("unexpected full tunnel route range: %v", routes)
	}
}

func TestRouteManagerPersistsAndCleansState(t *testing.T) {
	stateFile := t.TempDir() + "/routes.json"
	routes := &routeManager{stateFile: stateFile}
	routes.AddCleanup("/usr/bin/true")
	if err := CleanupRouteState(stateFile); err != nil {
		t.Fatal(err)
	}
	if err := CleanupRouteState(stateFile); err != nil {
		t.Fatal(err)
	}
}
