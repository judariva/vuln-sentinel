# Versiones fijadas (T16). Comprobadas en el registro de Terraform el 2026-11-26:
# - azurerm 4.81.0, publicada el 2026-07-14: última de la rama 4.x.
#   https://registry.terraform.io/v1/providers/hashicorp/azurerm/versions
#   Se queda en 4.x (la 5.x ya existe) porque la plataforma que instancia el módulo fija
#   azurerm ~> 4.0: con 5.x su `terraform init` no resolvería.
# - azapi 2.14.0, publicada el 2026-11-17: última.
#   https://registry.terraform.io/v1/providers/Azure/azapi
#   Solo para la clave de firma, que se crea por el plano de control (el vault es privado y el
#   runner no llega a su plano de datos).
terraform {
  required_version = ">= 1.9.0, < 2.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.81.0"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "2.14.0"
    }
  }
}
