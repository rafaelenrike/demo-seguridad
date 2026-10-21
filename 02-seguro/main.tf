# =====================================================================
#  DEMO SEGURIDAD - PARTE 2: LA MISMA IDEA, DESPLEGADA DE FORMA SEGURA
#  Principios aplicados (ver comentarios [OK]):
#   - Mínimo privilegio (RBAC, identidades administradas, NSG)
#   - Sin secretos en el código ni en la VM (Key Vault + Managed Identity)
#   - Superficie de ataque reducida (sin IP pública, sin SSH abierto)
#   - Defensa en profundidad (firewalls de servicio, egress controlado)
#   - Trazabilidad (diagnostic settings -> Log Analytics)
# =====================================================================

data "azurerm_client_config" "current" {}

resource "random_string" "sufijo" {
  length  = 5
  upper   = false
  special = false
}

locals {
  nombre = "${var.prefix}-${random_string.sufijo.result}"
  plano  = "${var.prefix}${random_string.sufijo.result}" # para nombres sin guiones
}

resource "azurerm_resource_group" "rg" {
  name     = "rg-${local.nombre}"
  location = var.location
  tags     = var.tags
}

# ------------------------------------------------------------ OBSERVABILIDAD
# [OK] Todo lo sensible deja rastro en un workspace central
resource "azurerm_log_analytics_workspace" "law" {
  name                = "law-${local.nombre}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags
}

# ------------------------------------------------------------ RED
resource "azurerm_virtual_network" "vnet" {
  name                = "vnet-${local.nombre}"
  address_space       = ["10.20.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tags                = var.tags
}

resource "azurerm_subnet" "app" {
  name                 = "snet-app"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.20.1.0/24"]
  # [OK] El tráfico hacia Key Vault y Storage viaja por la red troncal de
  #      Azure y esos servicios pueden restringirse a esta subred
  service_endpoints = ["Microsoft.KeyVault", "Microsoft.Storage"]
}

resource "azurerm_network_security_group" "app" {
  name                = "nsg-app-${local.nombre}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tags                = var.tags

  # [OK] Entrada: nada desde Internet (explícito, aunque la regla por
  #      defecto ya lo niega, deja intención documentada en el código)
  security_rule {
    name                       = "Deny-Internet-Inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  # [OK] Salida controlada (egress filtering) por etiquetas de servicio
  security_rule {
    name                       = "Allow-KeyVault-Out"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "AzureKeyVault"
  }

  security_rule {
    name                       = "Allow-AzureMonitor-Out"
    priority                   = 110
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "AzureMonitor"
  }

  security_rule {
    name                       = "Allow-Storage-Out"
    priority                   = 120
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "Storage"
  }

  security_rule {
    name                       = "Deny-Internet-Out"
    priority                   = 4000
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "Internet"
  }
}

resource "azurerm_subnet_network_security_group_association" "app" {
  subnet_id                 = azurerm_subnet.app.id
  network_security_group_id = azurerm_network_security_group.app.id
}

# ------------------------------------------------------------ CÓMPUTO
# [OK] Sin IP pública: la administración se hace con `az vm run-command`
#      (auditable, gobernado por RBAC) o con Azure Bastion
resource "azurerm_network_interface" "vm" {
  name                = "nic-vm-${local.nombre}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tags                = var.tags

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.app.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "vm" {
  #checkov:skip=CKV_AZURE_50:Se requieren extensiones para administrar sin SSH (Run Command) y para el agente de monitoreo
  name                  = "vm-app-${local.nombre}"
  resource_group_name   = azurerm_resource_group.rg.name
  location              = azurerm_resource_group.rg.location
  size                  = var.vm_size
  network_interface_ids = [azurerm_network_interface.vm.id]
  tags                  = var.tags

  admin_username = "azureuser"
  # [OK] Solo llave SSH, nunca contraseña
  disable_password_authentication = true
  admin_ssh_key {
    username   = "azureuser"
    public_key = file(pathexpand(var.ssh_public_key_path))
  }

  # [OK] Identidad administrada: la VM obtiene tokens de Entra ID sin
  #      que exista ninguna credencial almacenada en ella
  identity {
    type = "SystemAssigned"
  }

  # [OK] Trusted Launch: arranque seguro + vTPM
  secure_boot_enabled = true
  vtpm_enabled        = true

  # [OK] Evaluación periódica de parches por la plataforma
  patch_assessment_mode = "AutomaticByPlatform"

  boot_diagnostics {}

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  # [OK] custom_data sin secretos: solo el NOMBRE del vault y del secreto
  custom_data = base64encode(templatefile("${path.module}/cloud-init.yaml", {
    key_vault_name = azurerm_key_vault.kv.name
    secret_name    = "app-db-password"
  }))
}

# ------------------------------------------------------------ SECRETOS
resource "azurerm_key_vault" "kv" {
  #checkov:skip=CKV2_AZURE_32:Private Endpoint fuera del alcance (costo); se usa firewall + service endpoint
  name                = "kv-${local.plano}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"
  tags                = var.tags

  # [OK] Autorización por Azure RBAC (no access policies)
  #      En azurerm >= 4.4x este argumento se llama rbac_authorization_enabled
  rbac_authorization_enabled = true

  # [OK] Protección ante borrado accidental o malicioso
  purge_protection_enabled   = true
  soft_delete_retention_days = 7

  # [OK] Firewall del servicio: solo la IP del operador y la subred de la app
  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    ip_rules                   = ["${var.my_ip}/32"]
    virtual_network_subnet_ids = [azurerm_subnet.app.id]
  }
}

# Quien ejecuta Terraform puede ADMINISTRAR secretos...
resource "azurerm_role_assignment" "operador_kv" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# ...la VM solo puede LEERLOS (mínimo privilegio)
resource "azurerm_role_assignment" "vm_kv" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_virtual_machine.vm.identity[0].principal_id
}

# La propagación de RBAC tarda; se espera antes de escribir el secreto
resource "time_sleep" "rbac" {
  create_duration = "90s"
  depends_on      = [azurerm_role_assignment.operador_kv, azurerm_role_assignment.operador_blob]
}

resource "random_password" "db" {
  length           = 24
  special          = true
  override_special = "!#%*-_=+"
}

resource "time_offset" "expira_secreto" {
  offset_days = 90
}

# [OK] Secreto generado (nadie lo conoce), con tipo y fecha de expiración
resource "azurerm_key_vault_secret" "db" {
  name            = "app-db-password"
  value           = random_password.db.result
  key_vault_id    = azurerm_key_vault.kv.id
  content_type    = "password"
  expiration_date = time_offset.expira_secreto.rfc3339
  depends_on      = [time_sleep.rbac]
}

# [OK] Cada lectura/escritura de secretos queda auditada
resource "azurerm_monitor_diagnostic_setting" "kv" {
  name                       = "diag-kv"
  target_resource_id         = azurerm_key_vault.kv.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id

  enabled_log {
    category = "AuditEvent"
  }
}

# ------------------------------------------------------------ ALMACENAMIENTO
# Riesgos ACEPTADOS y documentados (cada skip lleva su justificación):
resource "azurerm_storage_account" "st" {
  #checkov:skip=CKV2_AZURE_1:Llaves administradas por el cliente (CMK) fuera del alcance de la demo; se usa cifrado de plataforma + doble cifrado
  #checkov:skip=CKV2_AZURE_33:Private Endpoint fuera del alcance (costo); se usa service endpoint + firewall
  #checkov:skip=CKV_AZURE_59:El acceso publico queda limitado por firewall (IP del operador + subred); deshabilitarlo exige Private Endpoint
  #checkov:skip=CKV_AZURE_206:ZRS es suficiente para la demo; produccion evaluaria GZRS
  #checkov:skip=CKV_AZURE_33:No se usa Queue service en esta cuenta
  name                     = "st${local.plano}"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "ZRS" # [OK] resiliencia zonal
  tags                     = var.tags

  https_traffic_only_enabled        = true     # [OK]
  min_tls_version                   = "TLS1_2" # [OK]
  allow_nested_items_to_be_public   = false    # [OK] nada anónimo
  infrastructure_encryption_enabled = true     # [OK] doble cifrado en reposo
  shared_access_key_enabled         = false    # [OK] solo identidades de Entra ID, no llaves

  sas_policy {
    expiration_period = "00.02:00:00" # [OK] SAS de máximo 2 horas
  }

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    ip_rules                   = [var.my_ip]
    virtual_network_subnet_ids = [azurerm_subnet.app.id]
  }

  blob_properties {
    versioning_enabled = true # [OK] recuperación ante ransomware/borrados
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
  }
}

# Sin llaves compartidas, Terraform necesita un rol de datos para crear contenedores
resource "azurerm_role_assignment" "operador_blob" {
  scope                = azurerm_storage_account.st.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_storage_container" "datos" {
  #checkov:skip=CKV2_AZURE_21:El registro de lecturas se hace con diagnostic setting StorageRead (abajo); el check solo reconoce Storage Analytics clasico
  name                  = "datos-clientes"
  storage_account_id    = azurerm_storage_account.st.id
  container_access_type = "private" # [OK]
  depends_on            = [time_sleep.rbac]
}

# [OK] Auditoría de lecturas/escrituras/borrados de blobs
resource "azurerm_monitor_diagnostic_setting" "blob" {
  name                       = "diag-blob"
  target_resource_id         = "${azurerm_storage_account.st.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.law.id

  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }
}
