package ingestion

import (
	"fmt"
	"strings"

	"github.com/cicekhasann/cvegrid/internal/model"
)

// ClassifyTaxonomy deterministically classifies vulnerability records into
// an ecosystem category and a list of technology tags.
func ClassifyTaxonomy(vendor, product, description, cweID string) (string, []string) {
	vendorLower := strings.ToLower(vendor)
	productLower := strings.ToLower(product)
	descLower := strings.ToLower(description)
	fullText := fmt.Sprintf("%s %s %s", vendorLower, productLower, descLower)

	var tags []string
	tagSet := make(map[string]struct{})

	addTag := func(t string) {
		if _, exists := tagSet[t]; !exists && t != "" {
			tagSet[t] = struct{}{}
			tags = append(tags, t)
		}
	}

	ecosystem := ""

	// 1. KERNEL & OPERATING SYSTEM
	isKernelOS := false
	if productLower == "kernel" ||
		productLower == "linux kernel" ||
		strings.Contains(fullText, "linux kernel") ||
		(strings.Contains(fullText, "linux") && strings.Contains(fullText, "kernel")) ||
		vendorLower == "linux" {
		addTag("Linux Kernel")
		isKernelOS = true
	}

	if strings.Contains(fullText, "android") && (strings.Contains(fullText, "kernel") || strings.Contains(fullText, "driver")) {
		addTag("Android Kernel")
		isKernelOS = true
	}

	if strings.Contains(fullText, "freebsd") || strings.Contains(fullText, "openbsd") || strings.Contains(fullText, "netbsd") ||
		strings.Contains(fullText, " bsd ") || vendorLower == "freebsd" {
		addTag("FreeBSD")
		isKernelOS = true
	}

	if strings.Contains(fullText, "windows nt") || strings.Contains(fullText, "windows kernel") ||
		strings.Contains(fullText, "ntoskrnl") || strings.Contains(fullText, "win32k") {
		addTag("Windows NT")
		isKernelOS = true
	}

	if strings.Contains(fullText, "xnu") || strings.Contains(fullText, "darwin kernel") || strings.Contains(fullText, "mach kernel") {
		addTag("XNU")
		isKernelOS = true
	}

	if strings.Contains(fullText, "qemu") || strings.Contains(fullText, "kvm") {
		addTag("KVM/QEMU")
		isKernelOS = true
	}

	if isKernelOS {
		ecosystem = model.EcosystemKernelOS
	}

	// 2. CORE LIBRARIES & PACKAGES
	isLibPkg := false
	if strings.Contains(fullText, "openssl") {
		addTag("OpenSSL")
		isLibPkg = true
	}
	if strings.Contains(fullText, "glibc") || strings.Contains(fullText, "gnu c library") {
		addTag("glibc")
		isLibPkg = true
	}
	if strings.Contains(fullText, "libcurl") || strings.Contains(fullText, "curl") {
		addTag("libcurl")
		isLibPkg = true
	}
	if strings.Contains(fullText, "libxml") || strings.Contains(fullText, "libxml2") {
		addTag("libxml2")
		isLibPkg = true
	}
	if strings.Contains(fullText, "sqlite") {
		addTag("SQLite")
		isLibPkg = true
	}
	if strings.Contains(fullText, "busybox") {
		addTag("BusyBox")
		isLibPkg = true
	}
	if strings.Contains(fullText, "bind9") || strings.Contains(fullText, "bind 9") || strings.Contains(fullText, "isc bind") {
		addTag("BIND 9")
		isLibPkg = true
	}
	if strings.Contains(fullText, "log4j") {
		addTag("Log4j")
		isLibPkg = true
	}
	if strings.Contains(fullText, "nginx") {
		addTag("Nginx")
		isLibPkg = true
	}
	if strings.Contains(fullText, "apache") || strings.Contains(fullText, "httpd") {
		addTag("Apache")
		isLibPkg = true
	}
	if strings.Contains(fullText, "sudo") {
		addTag("sudo")
		isLibPkg = true
	}
	if strings.Contains(fullText, "openssh") || strings.Contains(fullText, " ssh ") {
		addTag("OpenSSH")
		isLibPkg = true
	}
	if strings.Contains(fullText, "zlib") {
		addTag("zlib")
		isLibPkg = true
	}

	if isLibPkg && ecosystem == "" {
		ecosystem = model.EcosystemLibPkg
	}

	// 3. RUNTIMES & PROGRAMMING LANGUAGES
	isRuntimeLang := false

	if strings.Contains(fullText, "python") || vendorLower == "python" {
		addTag("Python")
		isRuntimeLang = true
	}
	if strings.Contains(fullText, "php") || vendorLower == "php" {
		addTag("PHP")
		isRuntimeLang = true
	}
	if strings.Contains(fullText, "golang") || strings.Contains(fullText, "go runtime") || strings.Contains(fullText, "go programming") || productLower == "go" {
		addTag("Go")
		isRuntimeLang = true
	}
	if strings.Contains(fullText, "rust") && (strings.Contains(fullText, "language") || strings.Contains(fullText, "runtime") || strings.Contains(fullText, "rustc")) {
		addTag("Rust")
		isRuntimeLang = true
	}
	if strings.Contains(fullText, "java") || strings.Contains(fullText, "spring") || strings.Contains(fullText, "struts") ||
		strings.Contains(fullText, "jvm") || strings.Contains(fullText, "openjdk") || strings.Contains(fullText, "log4j") {
		addTag("Java")
		isRuntimeLang = true
	}
	if strings.Contains(fullText, "node.js") || strings.Contains(fullText, "nodejs") || strings.Contains(fullText, "javascript") ||
		strings.Contains(fullText, "npm") || strings.Contains(fullText, " v8 ") {
		addTag("JavaScript")
		isRuntimeLang = true
	}
	if strings.Contains(fullText, "ruby") || strings.Contains(fullText, "rails") {
		addTag("Ruby")
		isRuntimeLang = true
	}
	if strings.Contains(fullText, ".net") || strings.Contains(fullText, "dotnet") || strings.Contains(fullText, "c#") || strings.Contains(fullText, "csharp") {
		addTag(".NET")
		isRuntimeLang = true
	}

	// Memory corruption CWEs on native / system software infer C/C++
	cweUpper := strings.ToUpper(cweID)
	isMemoryCorruptionCWE := cweUpper == "CWE-787" || // Out-of-bounds Write
		cweUpper == "CWE-416" || // Use-After-Free
		cweUpper == "CWE-120" || // Buffer Overflow
		cweUpper == "CWE-476" || // NULL Pointer Dereference
		cweUpper == "CWE-119" || // Memory Buffer Bounds
		cweUpper == "CWE-122" || // Heap Buffer Overflow
		cweUpper == "CWE-125" // Out-of-bounds Read

	if isMemoryCorruptionCWE {
		// If not an explicitly managed language, infer C/C++
		if !strings.Contains(fullText, "python") && !strings.Contains(fullText, "java") &&
			!strings.Contains(fullText, "node") && !strings.Contains(fullText, "php") &&
			!strings.Contains(fullText, "ruby") {
			addTag("C/C++")
			isRuntimeLang = true
		}
	} else if strings.Contains(fullText, " c/c++ ") || strings.Contains(fullText, "c++") ||
		(strings.Contains(fullText, " c ") && strings.Contains(fullText, "library")) {
		addTag("C/C++")
		isRuntimeLang = true
	}

	if isRuntimeLang && ecosystem == "" {
		ecosystem = model.EcosystemRuntimeLang
	}

	// 4. ENTERPRISE APPLICATIONS & NETWORK HARDWARE (FALLBACK)
	if ecosystem == "" {
		switch vendorLower {
		case "cisco", "fortinet", "palo alto networks", "paloalto", "juniper", "ivanti",
			"check point", "checkpoint", "sonicwall", "f5", "sophos", "netgear", "d-link", "zyxel":
			ecosystem = model.EcosystemNetworkHW
			addTag("Network Infrastructure")
		default:
			ecosystem = model.EcosystemEnterpriseApp
			addTag("Enterprise App")
		}
	}

	// Ensure at least one tag exists
	if len(tags) == 0 {
		switch ecosystem {
		case model.EcosystemKernelOS:
			addTag("System OS")
		case model.EcosystemRuntimeLang:
			addTag("Runtime / Language")
		case model.EcosystemLibPkg:
			addTag("Shared Library")
		case model.EcosystemNetworkHW:
			addTag("Network Infrastructure")
		default:
			addTag("Enterprise App")
		}
	}

	return ecosystem, tags
}
