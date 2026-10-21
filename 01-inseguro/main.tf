# =====================================================================
#  DEMO SEGURIDAD - PARTE 1: INFRAESTRUCTURA INSEGURA (ANTI-PATRÓN)
#  ---------------------------------------------------------------------
#  ESTE CÓDIGO NO SE DESPLIEGA. Se usa solo para escanearlo con
#  Checkov / Trivy y discutir con los estudiantes cada hallazgo.
#  Cada bloque marcado con  [X]  es un error de seguridad intencional.
# =====================================================================

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  # [X] Credenciales de un Service Principal escritas en el código
  subscription_id = "00000000-0000-0000-0000-000000000000"
  client_id       = "11111111-1111-1111-1111-111111111111"
  client_secret   = "S3cr3t0-Sup3r-S3gur0!!"
  tenant_id       = "22222222-2222-2222-2222-222222222222"
}

variable "admin_password" {
  # [X] Secreto con valor por defecto en el repositorio
  default = "P@ssw0rd1234!"
}

resource "azurerm_resource_group" "rg" {
  name     = "rg-demo-inseguro"
  location = "eastus2"
}

# ---------------------------------------------------------------- RED
resource "azurerm_virtual_network" "vnet" {
  name                = "vnet-inseguro"
  address_space       = ["10.10.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "web" {
  name                 = "snet-web"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.10.1.0/24"]
}

resource "azurerm_network_security_group" "nsg" {
  name                = "nsg-inseguro"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  # [X] SSH abierto a todo Internet
  security_rule {
    name                       = "allow-ssh-any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # [X] RDP abierto a todo Internet
  security_rule {
    name                       = "allow-rdp-any"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "web" {
  subnet_id                 = azurerm_subnet.web.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

# [X] IP pública asignada directamente a la VM
resource "azurerm_public_ip" "pip" {
  name                = "pip-vm-inseguro"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_interface" "nic" {
  name                = "nic-vm-inseguro"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.web.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.pip.id
  }
}

# ---------------------------------------------------------------- CÓMPUTO
resource "azurerm_linux_virtual_machine" "vm" {
  name                  = "vm-inseguro"
  resource_group_name   = azurerm_resource_group.rg.name
  location              = azurerm_resource_group.rg.location
  size                  = "Standard_B1s"
  network_interface_ids = [azurerm_network_interface.nic.id]

  admin_username = "azureuser"
  # [X] Autenticación por contraseña habilitada (sin llave SSH)
  admin_password                  = var.admin_password
  disable_password_authentication = false

  # [X] Extensiones sin control, sin identidad administrada, sin cifrado en host
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

  # [X] Cadena de conexión con llave de cuenta en custom_data (texto plano)
  custom_data = base64encode(<<-EOT
    #!/bin/bash
    echo "DefaultEndpointsProtocol=https;AccountName=stinseguro;AccountKey=abc123==" > /etc/app.conf
  EOT
  )
}

# ---------------------------------------------------------------- ALMACENAMIENTO
resource "azurerm_storage_account" "st" {
  name                     = "stdemoinseguro001"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # [X] Contenedores pueden ser públicos
  allow_nested_items_to_be_public = true
  # [X] Versión mínima de TLS obsoleta
  min_tls_version = "TLS1_0"
  # [X] Permite HTTP sin cifrar
  https_traffic_only_enabled = false
  # [X] Acceso desde cualquier red (sin network_rules)
  public_network_access_enabled = true
}

resource "azurerm_storage_container" "datos" {
  name               = "datos-clientes"
  storage_account_id = azurerm_storage_account.st.id
  # [X] Contenedor con lectura anónima
  container_access_type = "blob"
}

# ---------------------------------------------------------------- SECRETOS
data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "kv" {
  name                = "kv-demo-inseguro-001"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  # [X] Sin protección contra purga, acceso de red abierto, sin RBAC
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id
    # [X] Permisos excesivos (todo)
    secret_permissions = ["Backup", "Delete", "Get", "List", "Purge", "Recover", "Restore", "Set"]
    key_permissions    = ["Backup", "Create", "Decrypt", "Delete", "Encrypt", "Get", "Import", "List", "Purge", "Recover", "Restore", "Sign", "UnwrapKey", "Update", "Verify", "WrapKey"]
  }
}

# [X] Secreto sin fecha de expiración ni tipo de contenido
resource "azurerm_key_vault_secret" "db" {
  name         = "db-password"
  value        = "Admin123*"
  key_vault_id = azurerm_key_vault.kv.id
}

# [X] Sin Log Analytics, sin diagnostic settings, sin alertas: nadie se entera
