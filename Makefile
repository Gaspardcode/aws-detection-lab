# Usage : make plan STACK=network   |   make apply STACK=network
# Les identifiants viennent du profil AWS courant (AWS_PROFILE=lab-admin).
STACK      ?= network
TF         := terraform -chdir=terraform/$(STACK)
PERSISTENT := bootstrap archive

.PHONY: bootstrap init plan apply destroy fmt validate scan

bootstrap:            ## 1re fois : state local, puis copier backend_hcl
	terraform -chdir=terraform/bootstrap init
	terraform -chdir=terraform/bootstrap apply
	@echo ">> Copier la sortie backend_hcl dans terraform/backend.hcl"

init:
	$(TF) init -backend-config=../backend.hcl

plan: init
	$(TF) plan -out=$(STACK).tfplan

apply:                ## applique le plan relu, jamais en aveugle
	$(TF) apply $(STACK).tfplan

destroy:
	@if echo "$(PERSISTENT)" | grep -qw "$(STACK)"; then \
	  echo "Refus : $(STACK) est persistant (voir ROADMAP)"; exit 1; fi
	$(TF) destroy

fmt:
	terraform fmt -recursive terraform

validate:
	@for s in bootstrap archive network workload logging detection; do \
	  terraform -chdir=terraform/$$s init -backend=false -input=false >/dev/null && \
	  terraform -chdir=terraform/$$s validate || exit 1; done

scan:
	trivy config --exit-code 1 --severity HIGH,CRITICAL terraform

.PHONY: test rules-test
test:                 ## tests hors ligne (pytest, moto) ; aucun appel AWS
	python -m pytest -q
