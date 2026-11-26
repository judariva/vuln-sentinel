# tflint (T16). Versiones fijadas, comprobadas en GitHub el 2026-11-26:
# tflint v0.66.0 (2026-11-08) y tflint-ruleset-azurerm v0.33.0 (2026-10-25).
# Uso: tflint --init --config "$PWD/infra/terraform/.tflint.hcl" y después
#      tflint --chdir <módulo o ejemplo> --config "$PWD/infra/terraform/.tflint.hcl"

plugin "terraform" {
  enabled = true
  preset  = "all"
}

plugin "azurerm" {
  enabled = true
  version = "0.33.0"
  source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
}
