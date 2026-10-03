package maven_test

import (
	"testing"

	"github.com/omni-line/omni-audit/internal/manifest/maven"
)

func TestParseDependenciesAndManagement(t *testing.T) {
	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <properties>
    <guava.version>32.0.0-jre</guava.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>${guava.version}</version>
    </dependency>
    <dependency>
      <artifactId>internal-lib</artifactId>
      <version>1.0</version>
    </dependency>
  </dependencies>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.slf4j</groupId>
        <artifactId>slf4j-api</artifactId>
        <version>2.0.9</version>
      </dependency>
      <dependency>
        <groupId>com.google.guava</groupId>
        <artifactId>guava</artifactId>
        <version>31.0-jre</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
`)
	deps, err := maven.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	groups := map[string]string{}
	lines := map[string]int{}
	for _, d := range deps {
		got[d.Name] = d.Version
		groups[d.Name] = d.Group
		lines[d.Name] = d.Line
	}
	if got["com.google.guava:guava"] != "${guava.version}" {
		t.Fatalf("guava version kept verbatim: %#v", got)
	}
	if groups["com.google.guava:guava"] != "dependencies" {
		t.Fatalf("guava should come from dependencies (dedupe): %#v", groups)
	}
	if got["com.example:internal-lib"] != "1.0" {
		t.Fatalf("inherited groupId: %#v", got)
	}
	if groups["com.example:internal-lib"] != "dependencies" {
		t.Fatalf("internal-lib group: %#v", groups)
	}
	if got["org.slf4j:slf4j-api"] != "2.0.9" {
		t.Fatalf("dependencyManagement: %#v", got)
	}
	if groups["org.slf4j:slf4j-api"] != "dependencyManagement" {
		t.Fatalf("slf4j group: %#v", groups)
	}
	if len(deps) != 3 {
		t.Fatalf("len=%d want 3: %#v", len(deps), deps)
	}
	if lines["com.google.guava:guava"] == 0 {
		t.Fatal("expected line for guava artifactId")
	}
}

func TestParseParentGroupAndProjectProps(t *testing.T) {
	data := []byte(`
<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.0</version>
  </parent>
  <artifactId>demo</artifactId>
  <dependencies>
    <dependency>
      <groupId>${project.groupId}</groupId>
      <artifactId>sibling</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>${unresolved.group}</groupId>
      <artifactId>skip-me</artifactId>
    </dependency>
    <dependency>
      <artifactId></artifactId>
    </dependency>
  </dependencies>
</project>
`)
	deps, err := maven.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("len=%d want 1: %#v", len(deps), deps)
	}
	d := deps[0]
	if d.Name != "org.springframework.boot:sibling" {
		t.Fatalf("name=%q", d.Name)
	}
	if d.Version != "${project.version}" {
		t.Fatalf("version kept verbatim: %q", d.Version)
	}
}

func TestParseEmpty(t *testing.T) {
	deps, err := maven.Parse([]byte(`<project><groupId>a</groupId><artifactId>b</artifactId></project>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 0 {
		t.Fatalf("want empty, got %#v", deps)
	}
}

func TestParseInvalidXML(t *testing.T) {
	_, err := maven.Parse([]byte(`<project><unclosed>`))
	if err == nil {
		t.Fatal("expected error")
	}
}
