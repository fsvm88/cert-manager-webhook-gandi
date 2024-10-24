OS ?= $(shell go env GOOS)
ARCH = amd64
#ARCH ?= $(shell go env GOARCH)

ifeq (Darwin, $(shell uname))
	GREP_PREGEX_FLAG := E
else
	GREP_PREGEX_FLAG := P
endif

GO_VERSION ?= $(shell go mod edit -json | grep -${GREP_PREGEX_FLAG}o '"Go":\s+"([0-9.]+)"' | sed -E 's/.+"([0-9.]+)"/\1/')

IMAGE_NAME := fsvm88/cert-manager-webhook-gandi
IMAGE_TAG := 0.2.0

OUT := $(shell pwd)/_out

K8S_VERSION=1.31.0

$(shell mkdir -p "${OUT}")

test: _test/controller-tools
	TEST_ASSET_ETCD=_test/controller-tools/envtest/etcd \
	TEST_ASSET_KUBE_APISERVER=_test/controller-tools/envtest/kube-apiserver \
	TEST_ASSET_KUBECTL=_test/controller-tools/envtest/kubectl \
	go test -v .

_test/controller-tools:
	mkdir -p _test
	curl -fSL https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-v${K8S_VERSION}/envtest-v${K8S_VERSION}-${OS}-${ARCH}.tar.gz -o _test/controller-tools.tar.gz
	tar -xvf _test/controller-tools.tar.gz -C _test/
	rm _test/controller-tools.tar.gz

clean:
	rm -rf _test/controller-tools

build:
	docker buildx build --target=image --platform=linux/amd64 --output=type=docker,name=${IMAGE_NAME}:${IMAGE_TAG} --tag=${IMAGE_NAME}:latest --build-arg=GO_VERSION=${GO_VERSION} .

package:
	helm package deploy/cert-manager-webhook-gandi -d charts/
	helm repo index charts/ --url https://fsvm88.github.io/cert-manager-webhook-gandi

.PHONY: rendered-manifest.yaml
rendered-manifest.yaml:
	helm template \
        --set image.repository=${IMAGE_NAME} \
        --set image.tag=${IMAGE_TAG} \
        deploy/cert-manager-webhook-gandi > "${OUT}/rendered-manifest.yaml"