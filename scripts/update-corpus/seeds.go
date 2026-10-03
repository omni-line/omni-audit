package main

import "strings"

func dockerSeed() []string {
	// Official library images + widely used Hub namespaces.
	base := []string{
		"alpine", "ubuntu", "debian", "centos", "fedora", "busybox", "scratch",
		"nginx", "httpd", "caddy", "traefik", "haproxy",
		"redis", "memcached", "postgres", "mysql", "mariadb", "mongo", "cassandra",
		"elasticsearch", "kibana", "logstash", "rabbitmq", "zookeeper",
		"node", "python", "golang", "openjdk", "eclipse-temurin", "php", "ruby", "rust",
		"wordpress", "drupal", "ghost", "nextcloud",
		"jenkins", "sonarqube", "registry", "docker", "portainer",
		"prometheus", "grafana", "alertmanager",
		"amazonlinux", "amazoncorretto",
		"library/nginx", "library/redis", "library/postgres", "library/node",
		"prom/prometheus", "grafana/grafana", "jenkins/jenkins",
		"bitnami/nginx", "bitnami/redis", "bitnami/postgresql",
	}
	seen := map[string]struct{}{}
	var out []string
	for _, n := range base {
		n = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(n), "library/"))
		if n == "" || n == "scratch" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func conanSeed() []string {
	base := []string{
		"openssl", "zlib", "boost", "fmt", "nlohmann_json", "protobuf", "grpc",
		"cmake", "ninja", "bzip2", "libpng", "libjpeg", "freetype", "sqlite3",
		"poco", "asio", "spdlog", "gtest", "catch2", "benchmark", "abseil",
		"gflags", "glog", "curl", "libcurl", "c-ares", "re2", "flatbuffers",
		"eigen", "openblas", "lapack", "hdf5", "netcdf", "yaml-cpp", "tinyxml2",
		"pugixml", "rapidjson", "cereal", "range-v3", "span-lite", "expected-lite",
		"ms-gsl", "date", "fmtlog", "libuuid", "pcre2", "libffi", "expat",
		"libxml2", "libxslt", "icu", "harfbuzz", "cairo", "pango", "gtk",
		"qt", "sfml", "sdl", "glfw", "glew", "glm", "assimp", "bullet3",
		"ode", "box2d", "enet", "libevent", "libuv", "nghttp2", "mbedtls",
		"libsodium", "libsodium", "argon2", "xxhash", "zstd", "lz4", "snappy",
		"brotli", "minizip", "libarchive", "tar", "xz_utils", "libiconv",
		"gettext", "ncurses", "readline", "gmp", "mpfr", "mpc", "fftw",
		"openmpi", "mpich", "hwloc", "tbb", "onednn", "mkl", "cuda",
		"cudnn", "nccl", "tensorrt", "onnx", "opencv", "pcl", "vtk",
		"cgal", "gdal", "proj", "geos", "sqlite_orm", "soci", "libpq",
		"libmysqlclient", "mongo-c-driver", "mongo-cxx-driver", "redis-plus-plus",
		"hiredis", "aws-sdk-cpp", "azure-sdk-for-cpp", "google-cloud-cpp",
		"cpprestsdk", "pistache", "crow", "oatpp", "drogon", "seastar",
		"folly", "wangle", "proxygen", "thrift", "capnproto", "msgpack",
		"cpr", "restbed", "jwt-cpp", "libssh2", "libgit2", "libzip",
		"imgui", "implot", "skia", "harfbuzz", "fontconfig",
	}
	seen := map[string]struct{}{}
	var out []string
	for _, n := range base {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}
