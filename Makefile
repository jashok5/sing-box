NAME = sing-box
COMMIT = $(shell git rev-parse --short HEAD)
TAGS ?= $(shell cat release/DEFAULT_BUILD_TAGS_OTHERS)
WIN_TAGS ?= $(shell cat release/DEFAULT_BUILD_TAGS_WINDOWS)

GOHOSTOS = $(shell go env GOHOSTOS)
GOHOSTARCH = $(shell go env GOHOSTARCH)
VERSION=$(shell CGO_ENABLED=0 GOOS=$(GOHOSTOS) GOARCH=$(GOHOSTARCH) go run github.com/sagernet/sing-box/cmd/internal/read_tag@latest)

LDFLAGS_SHARED = $(shell cat release/LDFLAGS)
PARAMS = -v -trimpath -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=$(VERSION)' $(LDFLAGS_SHARED) -s -w -buildid="
MAIN_PARAMS = $(PARAMS) -tags "$(TAGS)"
MAIN = ./cmd/sing-box
PREFIX ?= $(shell go env GOPATH)
SING_FFI ?= sing-ffi
LIBBOX_FFI_CONFIG ?= ./experimental/libbox/ffi.json

LIB_MAIN = ./cmd/libbox_cshared
LIB_NAME = sing-box-lib
LINUX_LIBBOX_OUTPUT_DIR ?= ../linux/third_party/libbox/linux

.PHONY: test release docs build lib_darwin lib_linux lib_windows

build:
	export GOTOOLCHAIN=local && \
	go build $(MAIN_PARAMS) $(MAIN)

race:
	export GOTOOLCHAIN=local && \
	go build -race $(MAIN_PARAMS) $(MAIN)

ci_build:
	export GOTOOLCHAIN=local && \
	go build $(PARAMS) $(MAIN) && \
	go build $(MAIN_PARAMS) $(MAIN)

generate_completions:
	go run -v --tags "$(TAGS),generate,generate_completions" $(MAIN)

install:
	go build -o $(PREFIX)/bin/$(NAME) $(MAIN_PARAMS) $(MAIN)

fmt:
	@golangci-lint fmt

fmt_docs:
	go run ./cmd/internal/format_docs

lint:
	GOOS=linux golangci-lint run ./...
	GOOS=android golangci-lint run ./...
	GOOS=windows golangci-lint run ./...
	GOOS=darwin golangci-lint run ./...
#	GOOS=freebsd golangci-lint run ./...

lint_install:
	go install -v github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

proto:
	@go run ./cmd/internal/protogen
	@gofumpt -l -w .
	@gofumpt -l -w .

proto_install:
	go install -v google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install -v google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

update_certificates:
	go run ./cmd/internal/update_certificates

release:
	go run ./cmd/internal/build goreleaser release --clean --skip publish
	mkdir dist/release
	mv dist/*.tar.gz \
		dist/*.zip \
		dist/*.deb \
		dist/*.rpm \
		dist/*_amd64.pkg.tar.zst \
		dist/*_arm64.pkg.tar.zst \
		dist/release
	ghr --replace --draft --prerelease -p 5 "v${VERSION}" dist/release
	rm -r dist/release

release_repo:
	go run ./cmd/internal/build goreleaser release -f .goreleaser.fury.yaml --clean

release_install:
	go install -v github.com/tcnksm/ghr@latest

update_android_version:
	go run ./cmd/internal/update_android_version

build_android:
	cd ../sing-box-for-android && ./gradlew :app:clean :app:assembleOtherRelease :app:assembleOtherLegacyRelease && ./gradlew --stop

upload_android:
	mkdir -p dist/release_android
	cp ../sing-box-for-android/app/build/outputs/apk/other/release/*.apk dist/release_android
	cp ../sing-box-for-android/app/build/outputs/apk/otherLegacy/release/*.apk dist/release_android
	VERSION_CODE=$$(grep VERSION_CODE ../sing-box-for-android/version.properties | cut -d= -f2); \
	VERSION_NAME=$$(grep VERSION_NAME ../sing-box-for-android/version.properties | cut -d= -f2); \
	printf '{\n  "version_code": %s,\n  "version_name": "%s"\n}\n' "$$VERSION_CODE" "$$VERSION_NAME" > dist/release_android/SFA-version-metadata.json
	ghr --replace --draft --prerelease -p 5 "v${VERSION}" dist/release_android
	rm -rf dist/release_android

release_android: build_android upload_android

publish_android:
	cd ../sing-box-for-android && ./gradlew :app:publishPlayReleaseBundle && ./gradlew --stop

# TODO: find why and remove `-destination 'generic/platform=iOS'`
# TODO: remove xcode clean when fix control widget fixed
build_ios:
	cd ../sing-box-for-apple && \
	rm -rf build/SFI.xcarchive && \
	xcodebuild clean -scheme SFI && \
	xcodebuild archive -scheme SFI -configuration Release -destination 'generic/platform=iOS' -archivePath build/SFI.xcarchive -allowProvisioningUpdates | xcbeautify | grep -A 10 -e "Archive Succeeded" -e "ARCHIVE FAILED" -e "❌"

upload_ios_app_store:
	cd ../sing-box-for-apple && \
	xcodebuild -exportArchive -archivePath build/SFI.xcarchive -exportOptionsPlist SFI/Upload.plist -allowProvisioningUpdates

export_ios_ipa:
	cd ../sing-box-for-apple && \
	xcodebuild -exportArchive -archivePath build/SFI.xcarchive -exportOptionsPlist SFI/Export.plist -allowProvisioningUpdates -exportPath build/SFI && \
	cp build/SFI/sing-box.ipa dist/SFI.ipa

upload_ios_ipa:
	cd dist && \
	cp SFI.ipa "SFI-${VERSION}.ipa" && \
	ghr --replace --draft --prerelease "v${VERSION}" "SFI-${VERSION}.ipa"

release_ios: build_ios upload_ios_app_store

build_macos:
	cd ../sing-box-for-apple && \
	rm -rf build/SFM.xcarchive && \
	xcodebuild archive -scheme SFM -configuration Release -archivePath build/SFM.xcarchive -allowProvisioningUpdates | xcbeautify | grep -A 10 -e "Archive Succeeded" -e "ARCHIVE FAILED" -e "❌"

upload_macos_app_store:
	cd ../sing-box-for-apple && \
	xcodebuild -exportArchive -archivePath build/SFM.xcarchive -exportOptionsPlist SFI/Upload.plist -allowProvisioningUpdates

release_macos: build_macos upload_macos_app_store

build_macos_standalone:
	$(MAKE) -C ../sing-box-for-apple archive_macos_standalone

build_macos_dmg:
	$(MAKE) -C ../sing-box-for-apple build_macos_dmg

build_macos_pkg:
	$(MAKE) -C ../sing-box-for-apple build_macos_pkg

notarize_macos_dmg:
	$(MAKE) -C ../sing-box-for-apple notarize_macos_dmg

notarize_macos_pkg:
	$(MAKE) -C ../sing-box-for-apple notarize_macos_pkg

upload_macos_dmg:
	mkdir -p dist/SFM
	cp ../sing-box-for-apple/build/SFM-Apple.dmg "dist/SFM/SFM-${VERSION}-Apple.dmg"
	cp ../sing-box-for-apple/build/SFM-Intel.dmg "dist/SFM/SFM-${VERSION}-Intel.dmg"
	cp ../sing-box-for-apple/build/SFM-Universal.dmg "dist/SFM/SFM-${VERSION}-Universal.dmg"
	ghr --replace --draft --prerelease "v${VERSION}" "dist/SFM/SFM-${VERSION}-Apple.dmg"
	ghr --replace --draft --prerelease "v${VERSION}" "dist/SFM/SFM-${VERSION}-Intel.dmg"
	ghr --replace --draft --prerelease "v${VERSION}" "dist/SFM/SFM-${VERSION}-Universal.dmg"

upload_macos_pkg:
	mkdir -p dist/SFM
	cp ../sing-box-for-apple/build/SFM-Apple.pkg "dist/SFM/SFM-${VERSION}-Apple.pkg"
	cp ../sing-box-for-apple/build/SFM-Intel.pkg "dist/SFM/SFM-${VERSION}-Intel.pkg"
	cp ../sing-box-for-apple/build/SFM-Universal.pkg "dist/SFM/SFM-${VERSION}-Universal.pkg"
	ghr --replace --draft --prerelease "v${VERSION}" "dist/SFM/SFM-${VERSION}-Apple.pkg"
	ghr --replace --draft --prerelease "v${VERSION}" "dist/SFM/SFM-${VERSION}-Intel.pkg"
	ghr --replace --draft --prerelease "v${VERSION}" "dist/SFM/SFM-${VERSION}-Universal.pkg"

replace_macos_pkg:
	mkdir -p dist/SFM
	cp ../sing-box-for-apple/build/SFM-Apple.pkg "dist/SFM/SFM-${VERSION}-Apple.pkg"
	cp ../sing-box-for-apple/build/SFM-Intel.pkg "dist/SFM/SFM-${VERSION}-Intel.pkg"
	cp ../sing-box-for-apple/build/SFM-Universal.pkg "dist/SFM/SFM-${VERSION}-Universal.pkg"
	ghr --replace "v${VERSION}" "dist/SFM/SFM-${VERSION}-Apple.pkg"
	ghr --replace "v${VERSION}" "dist/SFM/SFM-${VERSION}-Intel.pkg"
	ghr --replace "v${VERSION}" "dist/SFM/SFM-${VERSION}-Universal.pkg"

upload_macos_dsyms:
	mkdir -p dist/SFM
	cd ../sing-box-for-apple/build/SFM.System-universal.xcarchive && zip -r SFM.dSYMs.zip dSYMs
	cp ../sing-box-for-apple/build/SFM.System-universal.xcarchive/SFM.dSYMs.zip "dist/SFM/SFM-${VERSION}.dSYMs.zip"
	ghr --replace --draft --prerelease "v${VERSION}" "dist/SFM/SFM-${VERSION}.dSYMs.zip"

replace_macos_dsyms:
	mkdir -p dist/SFM
	cd ../sing-box-for-apple/build/SFM.System-universal.xcarchive && zip -r SFM.dSYMs.zip dSYMs
	cp ../sing-box-for-apple/build/SFM.System-universal.xcarchive/SFM.dSYMs.zip "dist/SFM/SFM-${VERSION}.dSYMs.zip"
	ghr --replace "v${VERSION}" "dist/SFM/SFM-${VERSION}.dSYMs.zip"

release_macos_standalone: build_macos_pkg notarize_macos_pkg upload_macos_pkg upload_macos_dsyms

replace_macos_standalone: build_macos_pkg notarize_macos_pkg upload_macos_pkg upload_macos_dsyms

build_tvos:
	cd ../sing-box-for-apple && \
	rm -rf build/SFT.xcarchive && \
	xcodebuild archive -scheme SFT -configuration Release -archivePath build/SFT.xcarchive -allowProvisioningUpdates | xcbeautify | grep -A 10 -e "Archive Succeeded" -e "ARCHIVE FAILED" -e "❌"

upload_tvos_app_store:
	cd ../sing-box-for-apple && \
	xcodebuild -exportArchive -archivePath "build/SFT.xcarchive" -exportOptionsPlist SFI/Upload.plist -allowProvisioningUpdates

export_tvos_ipa:
	cd ../sing-box-for-apple && \
	xcodebuild -exportArchive -archivePath "build/SFT.xcarchive" -exportOptionsPlist SFI/Export.plist -allowProvisioningUpdates -exportPath build/SFT && \
	cp build/SFT/sing-box.ipa dist/SFT.ipa

upload_tvos_ipa:
	cd dist && \
	cp SFT.ipa "SFT-${VERSION}.ipa" && \
	ghr --replace --draft --prerelease "v${VERSION}" "SFT-${VERSION}.ipa"

release_tvos: build_tvos upload_tvos_app_store

update_apple_version:
	go run ./cmd/internal/update_apple_version

update_macos_version:
	MACOS_PROJECT_VERSION=$(shell go run -v ./cmd/internal/app_store_connect next_macos_project_version) go run ./cmd/internal/update_apple_version

release_apple: lib_apple update_apple_version release_ios release_macos release_tvos release_macos_standalone

release_apple_beta: update_apple_version release_ios release_macos release_tvos

publish_testflight:
	go run -v ./cmd/internal/app_store_connect publish_testflight $(filter-out $@,$(MAKECMDGOALS))

prepare_app_store:
	go run -v ./cmd/internal/app_store_connect prepare_app_store

publish_app_store:
	go run -v ./cmd/internal/app_store_connect publish_app_store

test:
	@go test -v ./... && \
	cd test && \
	go mod tidy && \
	go test -v -tags "$(TAGS_TEST)" .

test_stdio:
	@go test -v ./... && \
	cd test && \
	go mod tidy && \
	go test -v -tags "$(TAGS_TEST),force_stdio" .

lib_android:
	go run ./cmd/internal/build_libbox -target android

lib_apple:
	go run ./cmd/internal/build_libbox -target apple

lib_macos:
	rm -rf Libbox.xcframework
	rm -rf build/macos build/macos-arm64 build/macos-amd64 build/macos-x86_64
	go run ./cmd/internal/build_libbox -target apple -platform macos -output Libbox.xcframework

lib_windows:
	$(SING_FFI) generate --config $(LIBBOX_FFI_CONFIG) --platform-type csharp

lib_android_new:
	$(SING_FFI) generate --config $(LIBBOX_FFI_CONFIG) --platform-type android

lib_apple_new:
	$(SING_FFI) generate --config $(LIBBOX_FFI_CONFIG) --platform-type apple

lib_install:
	go install -v github.com/sagernet/gomobile/cmd/gomobile@v0.1.12
	go install -v github.com/sagernet/gomobile/cmd/gobind@v0.1.12

docs:
	venv/bin/mkdocs serve

publish_docs:
	venv/bin/mkdocs gh-deploy -m "Update" --force --ignore-version --no-history

docs_install:
	python3 -m venv venv
	source ./venv/bin/activate && pip install --force-reinstall mkdocs-material=="9.7.2" mkdocs-static-i18n=="1.2.*"

clean:
	rm -rf bin dist sing-box
	rm -f $(shell go env GOPATH)/sing-box

update:
	git fetch
	git reset FETCH_HEAD --hard
	git clean -fdx

build_all_platform: build_linux_amd64 build_linux_arm64 build_windows_amd64 build_windows_arm64 build_darwin_amd64 build_darwin_arm64

build_linux_amd64:
	GOOS=linux GOARCH=amd64 GOAMD64=v1 go build $(MAIN_PARAMS) -o sing-box_linux_amd64 $(MAIN)

build_linux_arm64:
	GOOS=linux GOARCH=arm64 go build $(MAIN_PARAMS) -o sing-box_linux_arm64 $(MAIN)

build_windows_amd64:
	GOOS=windows GOARCH=amd64 GOAMD64=v1 go build $(MAIN_PARAMS) -o sing-box_windows_amd64.exe $(MAIN)

build_windows_arm64:
	GOOS=windows GOARCH=arm64 go build $(MAIN_PARAMS) -o sing-box_windows_arm64.exe $(MAIN)

build_darwin_amd64:
	GOOS=darwin GOARCH=amd64 GOAMD64=v1 go build $(MAIN_PARAMS) -o sing-box_darwin_amd64 $(MAIN)

build_darwin_arm64:
	GOOS=darwin GOARCH=arm64 go build $(MAIN_PARAMS) -o sing-box_darwin_arm64 $(MAIN)

CC_LINUX_AMD64 ?= zig cc -target x86_64-linux-gnu.2.18 -O3 -s
CXX_LINUX_AMD64 ?= zig c++ -target x86_64-linux-gnu.2.18 -O3 -s

CC_LINUX_ARM64 ?= zig cc -target aarch64-linux-gnu.2.18 -O3 -s
CXX_LINUX_ARM64 ?= zig c++ -target aarch64-linux-gnu.2.18 -O3 -s

CC_WINDOWS_AMD64 ?= zig cc -target x86_64-windows-gnu -O3 -s
CXX_WINDOWS_AMD64 ?= zig c++ -target x86_64-windows-gnu -O3 -s

CC_WINDOWS_ARM64 ?= zig cc -target aarch64-windows-gnu -O3 -s
CXX_WINDOWS_ARM64 ?= zig c++ -target aarch64-windows-gnu -O3 -s

build_lib_linux:
	mkdir -p $(LINUX_LIBBOX_OUTPUT_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 CC="$(CC_LINUX_AMD64)" CXX="$(CXX_LINUX_AMD64)" go build $(PARAMS) -buildmode=c-shared -tags "$(TAGS)" -o $(LINUX_LIBBOX_OUTPUT_DIR)/sing-box-amd64.so ./cmd/libbox_cshared_linux
	GOOS=linux GOARCH=arm64 CGO_ENABLED=1 CC="$(CC_LINUX_ARM64)" CXX="$(CXX_LINUX_ARM64)" go build $(PARAMS) -buildmode=c-shared -tags "$(TAGS)" -o $(LINUX_LIBBOX_OUTPUT_DIR)/sing-box-arm64.so ./cmd/libbox_cshared_linux

build_lib_windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC="$(CC_WINDOWS_AMD64)" CXX="$(CXX_WINDOWS_AMD64)" go build $(PARAMS) -buildmode=c-shared -tags "$(WIN_TAGS)" -o sing-box-amd64.dll ./cmd/libbox_cshared_windows
	GOOS=windows GOARCH=arm64 CGO_ENABLED=1 CC="$(CC_WINDOWS_ARM64)" CXX="$(CXX_WINDOWS_ARM64)" go build $(PARAMS) -buildmode=c-shared -tags "$(WIN_TAGS)" -o sing-box-arm64.dll ./cmd/libbox_cshared_windows

build_lib_macos:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build $(PARAMS) -buildmode=c-shared -tags "$(TAGS)" -o sing-box-lib-macos-amd64.dylib ./cmd/libbox_cshared
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build $(PARAMS) -buildmode=c-shared -tags "$(TAGS)" -o sing-box-lib-macos-arm64.dylib ./cmd/libbox_cshared

%:
	@:
