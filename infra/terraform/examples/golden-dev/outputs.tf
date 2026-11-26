output "required_platform_grants" {
  description = "Roles que el vending concede a la UAMI antes de aplicar (el módulo no crea ninguno)."
  value       = module.vuln_sentinel.required_platform_grants
}
