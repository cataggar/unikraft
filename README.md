<div align="center">
  <picture>
    <img alt="Unikraft logo" src="https://raw.githubusercontent.com/unikraft/docs/main/static/assets/imgs/unikraft.svg" width="40%">
  </picture>
</div>

<br />

<div align="center">

[![](https://img.shields.io/badge/version-v0.21.0%20(Ijiraq)-%23EC591A)][unikraft-latest]
[![](https://img.shields.io/static/v1?label=license&message=BSD-3&color=%23385177)][unikraft-license]
[![](https://img.shields.io/discord/762976922531528725.svg?label=discord&logo=discord&logoColor=ffffff&color=7389D8&labelColor=6A7EC2)][unikraft-discord]
[![](https://img.shields.io/github/contributors/unikraft/unikraft)](https://github.com/unikraft/unikraft/graphs/contributors)
[![](https://app.codacy.com/project/badge/Grade/454f62251d96413fac8024b28df2ce5b)](https://app.codacy.com/gh/unikraft/unikraft/dashboard)

</div>

<h1 align="center">The fast, secure and open-source <br /> Unikernel Development Kit</h1>

<div align="center">
	Unikraft powers the next-generation of cloud native, containerless applications by enabling you to radically customize and build custom OS/kernels; unlocking best-in-class performance, security primitives and efficiency savings.
</div>

<br />

<p align="center">
	<a href="https://unikraft.org">Homepage</a>
	·
	<a href="https://unikraft.org/docs">Documentation</a>
	·
	<a href="https://github.com/unikraft/unikraft/issues/new?assignees=&labels=kind%2Fbug&projects=&template=bug_report.yml">Report Bug</a>
	·
	<a href="https://github.com/unikraft/unikraft/issues/new?assignees=&labels=kind%2Fenhancement&projects=&template=project_backlog.yml">Feature Request</a>
	·
	<a href="https://unikraft.org/discord">Join Our Discord</a>
	·
	<a href="https://x.com/UnikraftSDK">X.com</a>
</p>

<br />

<div align="center">
	<img src="https://unikraft.org/assets/imgs/monkey-business.gif" width="80%" />
</div>

<br />

## Features

- **Instantaneous Cold-boots** ⚡
   - While Linux-based systems might take tens of seconds to boot, Unikraft will be up in milliseconds.

- **Modular Design** 🧩
   - Unikraft boasts a modular design approach, allowing developers to include only necessary components, resulting in leaner and more efficient operating system configurations.

- **Optimized for Performance** 🚀
   - Built for performance, Unikraft minimizes overheads and leverages platform-specific optimizations, ensuring applications achieve peak performance levels.

- **Flexible Architecture Support** 💻
   - With support for multiple hardware architectures including x86, ARM, (and soon [RISC-V](https://riscv.org/)), Unikraft offers flexibility in deployment across diverse hardware platforms.

- **Broad Language and Application Support** 📚

  - Unikraft offers extensive support for multiple programming languages and hardware architectures, providing developers with the flexibility to choose the tools and platforms that best suit your needs.

- **Cloud and Edge Compatibility** ☁️
   - Designed for cloud and edge computing environments, Unikraft enables seamless deployment of applications across distributed computing infrastructures.

- **Reduced Attack Surface** 🛡️
   - By selectively including only necessary components, Unikraft reduces the attack surface, enhancing security in deployment scenarios.  Unikraft also includes many [additional modern security features][unikraft-security-features].

- **Developer Friendly** 🛠️
   - Unikraft's intuitive toolchain and user-friendly interface simplify the development process, allowing developers to focus on building innovative solutions.

- **Efficient Resource Utilization** 🪶
   - Unikraft optimizes resource utilization, leading to smaller footprints (meaning higher server saturation) and improved efficiency in resource-constrained environments.

- **Community-Driven Development** 👥
    - Unikraft is an open-source project driven by a vibrant community of over 100 developers, fostering collaboration and innovation from industry and academia.


## Quick Start

Install the companion command-line client [`kraft`][kraft]:

```shell
# Install on macOS, Linux, and Windows:
curl -sSfL https://get.kraftkit.sh | sh
```

> See [additional installation instructions][unikraft-cli-install].

Run your first ultra-lightweight unikernel virtual machine:

```
kraft run unikraft.org/helloworld:latest
```

View its status and manage multiple instances:

```
kraft ps --all
```

View the community image catalog in your CLI for more apps:

```
kraft pkg ls --update --apps
```

Or browse through one of the many [starter example projects][unikraft-catalog-examples].


## Why Unikraft?

Unikraft is a radical, yet Linux-compatible with effortless tooling, technology for running applications as highly optimized, lightweight and single-purpose virtual machines (known as unikernels).

In today's computing landscape, efficiency is paramount. Unikraft addresses this need with its modular design, enabling developers to create customized, lightweight operating systems tailored to specific application requirements. By trimming excess overhead and minimizing attack surfaces, Unikraft enhances security and performance in cloud and edge computing environments.

Unikraft's focus on optimization ensures that applications run smoothly, leveraging platform-specific optimizations to maximize efficiency. With support for various hardware architectures and programming languages, Unikraft offers flexibility without compromising performance. In a world where resources are precious, Unikraft provides a pragmatic solution for streamlined, high-performance computing.


## Getting Started

There are two ways to get started with Unikraft:

1. (**Recommended**) Using the companion command-line tool [`kraft`][kraft] (covered below).

2. Using the GNU Make-based system.  For this, see our [advanced usage guide][unikraft-guides-advanced].

### Zig build facade and experimental Zig C compiler support

Zig 0.16.0 provides a compatibility facade for the existing GNU Make build.
GNU Make remains the backend; this facade only maps Zig build steps and options
to Make targets and assignments. It does not yet model Unikraft's components
as a native Zig build graph.

From the Unikraft repository, build an application with:

```shell
zig build \
  -Dapp=/absolute/path/to/app \
  -Dconfig=/absolute/path/to/app/.config
```

When `-Doutput` is omitted, it safely defaults to `<app>/build`. The facade
canonicalizes existing symlinks and the nearest existing ancestor of new
outputs. It rejects repository/application ancestors, existing source
directories, filesystem roots, and unmarked existing directories. New output
directories receive a small marker so subsequent builds can distinguish them
from source trees.

The default step delegates to Make's `all` target. Named steps include
`images`, `libs`, `objs`, `preprocess`, `prepare`, `fetch`, configuration
targets such as `menuconfig` and `defconfig`, and `clean`, `properclean`, and
`distclean`. For example:

```shell
zig build menuconfig -Dapp=/absolute/path/to/app
zig build images -Dapp=/absolute/path/to/app -Dverbose=1
```

`-Dapp`, `-Doutput`, `-Dconfig`, and `-Dimage-name` map to Make's `A`, `O`,
`C`, and `N` variables. Repeat `-Dexternal-lib`, `-Dexternal-platform`, or
`-Dexclude` to construct the `L`, `P`, or `E` path lists. Relative paths are
resolved from the Unikraft repository root. Because the existing Make backend
does not quote these values end to end, the facade applies a conservative
ASCII allowlist before invoking Make. Paths accept letters, digits, `/`,
`-_.+@`; joined `L`, `P`, and `E` lists additionally use `:` as their
intentional separator. Image names accept letters, digits, and `-_.+@`.
Tool/flag values additionally accept spaces, `:`, `,`, and `=`. Whitespace in
paths and Make/shell syntax such as quotes, backslashes, `$()`, backticks,
`;&|<>`, globs, `#`, `%`, and control characters are rejected.
Additional Make assignments can be forwarded as individual, safely separated
arguments with repeated `-Dmake-arg=NAME=VALUE`. This option uses a strict
allowlist for compiler flags and non-path tools such as `AR`, `NM`, `OBJCOPY`,
`OBJDUMP`, `READELF`, `STRIP`, `UK_CFLAGS`, and `UK_LDFLAGS`.
Facade-managed, path, cleanup, configuration, and internal graph variables are
rejected and must use dedicated facade options where available.

Invoke only one Make-backed named step per `zig build` command. A portable,
non-blocking file lock rejects overlapping Make processes rather than allowing
selected steps such as `clean all` to race. For each effective UID, facade
invocations use one lock in a private `unikraft-zig-facade-<uid>` directory
beneath the OS runtime root (`TMPDIR`, `TEMP`, or `TMP`, with the platform
default as fallback). The facade requires that directory to be owned by the
current user with mode `0700`, and the regular, single-link lock to have mode
`0600`; symlinks and unsafe ownership or permissions are refused. The
surrounding runtime root must itself be an owner-secure directory or a
root-owned sticky shared directory. This preserves same-user serialization
across parent/nested outputs, caches, applications, and checkouts without
allowing one user to lock out another.

The private runtime directory must be outside every output tree; its persistent
lock file is never unlinked while held. Before invoking Make, the runner makes
the locked descriptor inheritable and replaces its own process image with the
backend. Make and its descendants therefore retain the same lock even if the
original runner PID is killed; the lock is released normally after the complete
backend tree exits. Hosts without process-image replacement are refused rather
than running without this lifetime guarantee. Run separate commands when
multiple phases are needed.

Non-destructive builds may use an external `-Dconfig`. The `distclean` step is
stricter because Make deletes the configuration and sibling metadata: every
canonical deletion target must remain inside the application tree. Otherwise,
the facade refuses `distclean` and leaves manual cleanup to the user.
`zig build test` runs the facade's path, argument, and lock unit checks.
`python3 -m unittest -v support.scripts.tests.test_zig_facade` adds
end-to-end metacharacter, cross-checkout parent/nested output, and orphaned
backend-tree lock-lifetime coverage, including hostile pre-existing runtime
entries and fallback temporary-root selection.

The experimental QEMU/x86_64 Zig compiler setup becomes:

```shell
zig build \
  -Dapp=/absolute/path/to/app \
  '-Dcompiler=zig cc -target x86_64-freestanding-none' \
  '-Dpartial-linker=zig ld.lld' \
  -Dpartial-linker-type=raw \
  '-Dhost-cc=zig cc' \
  '-Dhost-cxx=zig c++' \
  -Dhost-cflags=-fno-sanitize=null \
  '-Dmake-arg=AR=zig ar' \
  -Dmake-arg=NM=llvm-nm \
  -Dmake-arg=OBJCOPY=llvm-objcopy \
  -Dmake-arg=OBJDUMP=llvm-objdump \
  -Dmake-arg=READELF=llvm-readelf \
  -Dmake-arg=STRIP=llvm-strip \
  -Dmake-arg=UK_CFLAGS=-std=gnu17 \
  -Dmake-arg=UK_LDFLAGS=-rtlib=compiler-rt
```

Omitting `-Dlinker` makes the final link use the compiler driver. The x86_64
build requires Python 3 and the listed LLVM binary tools, but not GCC. The
`host-cflags` exception accommodates Kconfig's kernel-style, null-derived list
sentinel.

For QEMU/ARM64, use a target-selecting compiler and keep the existing GNU
linker and binutils, for example:

```shell
zig build \
  -Dapp=/absolute/path/to/app \
  '-Dcompiler=zig cc -target aarch64-freestanding-none' \
  -Dcompiler-targeted=true \
  -Dlinker=gcc \
  -Dmake-arg=UK_CFLAGS=-std=gnu17
```

ARM64 additionally requires an AArch64 GNU cross-toolchain. This compiler
support remains experimental, is limited to GNU Make-configured QEMU/x86_64
and QEMU/ARM64 applications, and does not support LTO.

### Toolchain Installation

You can install the companion command-line client [`kraft`][kraft] by using the interactive installer:

```shell
# Install on macOS, Linux, and Windows:
curl -sSfL https://get.kraftkit.sh | sh
```

#### macOS

```
brew install unikraft/cli/kraftkit
```

#### Debian/Fedora/RHEL/Arch/Windows

Use the interactive installer or see [additional installation instructions][unikraft-cli-install].

### Codespaces

Try out one of the examples in GitHub Codespaces:

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)][github-codespaces-catalog]

### Container Build Environment

You can use the pre-built development container environment which has all
dependencies necessary for building and trying out Unikraft in emulation mode.

Attach your working directory on your host as a mount path volume mapped to
`/workspace`, e.g.:

```shell
docker run --platform linux/x86_64 -it --rm -v $(pwd):/workspace --entrypoint bash kraftkit.sh/base:latest
```

The above command will drop you into a container shell.
Type `exit` or <kbd>Ctrl</kbd>+<kbd>D</kbd> to quit.


### Testing your Installation

Running unikernels with `kraft` is designed to be simple and familiar.
To test your installation of `kraft`, you can run the following:

```
kraft run unikraft.org/helloworld:latest
```

### Build your first unikernel

Building unikernels is also designed to be straightforward.  Build your first
unikernel by simply placing a `Kraftfile` into your repo and pointing it to your
existing `Dockerfile`:

```yaml
spec: v0.6

runtime: base:latest

rootfs: ./Dockerfile

cmd: ["/path/to/my-server-app"]
```

> Learn more about the [syntax of a `Kraftfile`][unikraft-kraftfile-syntax].

Once done, invoke in the context of your working directory:

```
kraft run .
```


## Example Projects and Pre-built Images

You can find some common project examples below:

| | Example |
|-|:-|
| ![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/c.svg) | [Simple "Hello, world!" application written in C](https://github.com/unikraft/catalog/tree/main/examples/helloworld-c) |
| ![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/cpp.svg) | [Simple "Hello, world!" application written in C++](https://github.com/unikraft/catalog/tree/main/examples/helloworld-cpp) |
| ![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/rust-white.svg#gh-dark-mode-only)![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/rust-black.svg#gh-light-mode-only) | [Simple "Hello, world!" application written in Rust built via `cargo`](https://github.com/unikraft/catalog/tree/main/examples/helloworld-rs) |
| ![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/js.svg) | [Simple NodeJS 18 HTTP Web Server with `http`](https://github.com/unikraft/catalog/tree/main/examples/http-node18) |
| ![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/go.svg) | [Simple Go 1.21 HTTP Web Server with `net/http`](https://github.com/unikraft/catalog/tree/main/examples/http-go1.21) |
| ![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/python3.svg) | [Simple Flask 3.0 HTTP Web Server](https://github.com/unikraft/catalog/tree/main/examples/http-python3.10-flask3.0) |
| ![](https://raw.githubusercontent.com/unikraft/catalog/main/.github/icons/python3.svg) | [Simple Python 3.10 HTTP Web Server with `http.server.HTTPServer`](https://github.com/unikraft/catalog/tree/main/examples/http-python3.10) |

Find [more examples and applications in our community catalog][unikraft-catalog]!


## Cloud Deployment

The creators of Unikraft have built [KraftCloud](https://kraft.cloud): a next generation cloud platform powered by technology intended to work in millisecond timescales.

| ✅ | Millisecond Scale-to-Zero | ✅ | Millisecond Autoscale   | ✅ | Millisecond Cold Boots |
|:-|:-|:-|:-|:-|:-|
| ✅ | Higher Throughput         | ✅ | Much Lower Cloud Bill   | ✅ | HW-Level Isolation     |
| ✅ | On-Prem or Cloud-Prem     | ✅ | Works with Docker & K8s | ✅ | Terraform Integration  |

### [Sign-up for the beta ↗](https://console.kraft.cloud/signup)

<br />

## Contributing

Unikraft is open-source and licensed under `BSD-3-Clause` and the copyright of its
authors.  If you would like to contribute:

1. Read the [Developer Certificate of Origin Version 1.1](https://developercertificate.org/).
1. Sign-off commits as described in the [Developer Certificate of Origin Version 1.1](https://developercertificate.org/).
1. Grant copyright as detailed in the [license header](https://unikraft.org/docs/contributing/coding-conventions#license-header).

This ensures that users, distributors, and other contributors can rely on all the software related to Unikraft being contributed under the terms of the License. No contributions will be accepted without following this process.

Afterwards, navigate to the [contributing guide](https://unikraft.org/docs/contributing/unikraft) to get started.
See also [Unikraft's coding conventions](https://unikraft.org/docs/contributing/coding-conventions).


## Additional resources

* [Quick-start guide][unikraft-gettingstarted]
* [What is a unikernel?][unikraft-concepts]
* [Unikraft's inherent security benefits][unikraft-security]
* [Performance of Unikraft][unikraft-performance]
* [POSIX-compatibility with Unikraft][unikraft-posix-compatibility]
* [Energy efficiency with Unikraft][Unikraft-green]
* [Unikraft Community][unikraft-community]
* [Unikraft Documentation][unikraft-docs]


## License

Unikraft Open-Source Project source code and its affiliated projects source code is licensed under a `BSD-3-Clause` if not otherwise stated.
For more information, please refer to [`COPYING.md`][unikraft-license].


## Affiliation

Unikraft is a member of the [Linux Foundation](https://www.linuxfoundation.org/) and is a [Xen Project](https://xenproject.org/)  Incubator Project.
The Unikraft name, logo and its mascot are trademark of [Unikraft GmbH](https://unikraft.io).

<br />

<div align="left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://www.linuxfoundation.org/hubfs/lf-stacked-white.svg">
    <img alt="LinuxFoundation logo" src="https://www.linuxfoundation.org/hubfs/lf-stacked-color.svg" width="20%">
  </picture>
	&nbsp;&nbsp;&nbsp;
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://xenproject.org/wp-content/uploads/sites/79/2018/09/logo_xenproject.png">
    <img alt="XenProject logo" src="https://downloads.xenproject.org/Branding/Logos/Green+Black/xen_project_logo_dualcolor_767x319.png" width="18%">
  </picture>
</div>


[unikraft-website]: https://unikraft.org
[unikraft-docs]: https://unikraft.org/docs
[unikraft-community]: https://unikraft.org/community
[unikraft-contributing]: https://unikraft.org/docs/contributing/
[unikraft-license]: https://github.com/unikraft/unikraft/blob/staging/COPYING.md
[unikraft-latest]: https://github.com/unikraft/unikraft/tree/RELEASE-0.21.0
[unikraft-gettingstarted]: http://unikraft.org/docs/getting-started
[unikraft-concepts]: https://unikraft.org/docs/concepts/
[unikraft-posix-compatibility]: https://unikraft.org/docs/features/posix-compatibility
[unikraft-performance]: https://unikraft.org/docs/features/performance/
[unikraft-security]: https://unikraft.org/docs/features/security/
[unikraft-security-features]: https://unikraft.org/docs/concepts/security#unikraft-security-features
[unikraft-green]: https://unikraft.org/docs/features/green/
[unikraft-discord]: https://bit.ly/UnikraftDiscord
[unikraft-cli-install]: https://unikraft.org/docs/cli/install
[unikraft-catalog]: https://github.com/unikraft/catalog
[unikraft-catalog-examples]: https://github.com/unikraft/catalog/tree/main/examples
[unikraft-guides-advanced]: https://unikraft.org/guides/internals
[unikraft-kraftfile-syntax]: https://unikraft.org/docs/cli/reference/kraftfile/latest
[github-codespaces-catalog]: https://codespaces.new/unikraft/catalog
[kraft]: https://github.com/unikraft/kraftkit
