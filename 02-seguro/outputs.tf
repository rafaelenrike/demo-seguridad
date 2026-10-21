output "resource_group" {
  value = azurerm_resource_group.rg.name
}

output "vm_name" {
  value = azurerm_linux_virtual_machine.vm.name
}

output "vm_principal_id" {
  description = "Object ID de la identidad administrada de la VM"
  value       = azurerm_linux_virtual_machine.vm.identity[0].principal_id
}

output "key_vault_name" {
  value = azurerm_key_vault.kv.name
}

output "storage_account_name" {
  value = azurerm_storage_account.st.name
}

output "log_analytics_workspace_id" {
  description = "GUID del workspace (para consultas con az monitor log-analytics query)"
  value       = azurerm_log_analytics_workspace.law.workspace_id
}

# Nota didáctica: este output está marcado como sensible. Terraform lo
# oculta en pantalla... pero el valor SIGUE estando en el archivo de estado.
output "db_password" {
  value     = random_password.db.result
  sensitive = true
}
