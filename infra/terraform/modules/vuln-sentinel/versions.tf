# Restricciones mínimas (T16b, respuesta 5 de Juan): módulo reutilizable, `>=` con techo de mayor.
# Las versiones exactas y el lock van en la raíz que lo instancia (el ejemplo golden-lab las fija).
# Mínimo comprobado en el registro de Terraform el 2026-11-26:
# - azurerm 4.81.0, publicada el 2026-07-14: última de la rama 4.x.
#   https://registry.terraform.io/v1/providers/hashicorp/azurerm/versions
#   Techo < 5.0.0: la plataforma que instancia el módulo fija azurerm ~> 4.0.
# Sin azapi: la clave de firma la crea la plataforma (respuesta 8) y el módulo solo recibe su id.
terraform {
  required_version = ">= 1.9.0, < 2.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.81.0, < 5.0.0"
    }
  }
}
