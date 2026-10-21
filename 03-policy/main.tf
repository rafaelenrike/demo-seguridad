# =====================================================================
#  DEMO SEGURIDAD - PARTE 3: GOBIERNO CON AZURE POLICY (Policy as Code)
#  Las políticas son "guardas" de la plataforma: aunque alguien se salte
#  el pipeline y use el portal o la CLI, Azure rechaza el recurso.
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
}

variable "location" {
  type    = string
  default = "eastus2"
}

data "azurerm_subscription" "actual" {}

resource "azurerm_resource_group" "gob" {
  name     = "rg-demo-policy"
  location = var.location
  tags = {
    curso = "infraestructura-ti"
    tema  = "policy"
  }
}

# ---------------------------------------------------------------------
# 1) Política PERSONALIZADA (Deny): ninguna cuenta de almacenamiento puede
#    permitir acceso público anónimo a blobs.
# ---------------------------------------------------------------------
resource "azurerm_policy_definition" "no_blob_publico" {
  name         = "deny-storage-blob-publico"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "[Curso] Denegar cuentas de almacenamiento con acceso público a blobs"
  description  = "Rechaza cualquier Storage Account cuyo allowBlobPublicAccess no sea false."

  metadata = jsonencode({ category = "Storage", version = "1.0.0" })

  policy_rule = jsonencode({
    "if" = {
      allOf = [
        { field = "type", equals = "Microsoft.Storage/storageAccounts" },
        {
          field     = "Microsoft.Storage/storageAccounts/allowBlobPublicAccess"
          notEquals = false
        }
      ]
    }
    "then" = { effect = "deny" }
  })
}

resource "azurerm_resource_group_policy_assignment" "no_blob_publico" {
  name                 = "asg-no-blob-publico"
  resource_group_id    = azurerm_resource_group.gob.id
  policy_definition_id = azurerm_policy_definition.no_blob_publico.id
  display_name         = "No blobs públicos en rg-demo-policy"
}

# ---------------------------------------------------------------------
# 2) Política INTEGRADA (built-in): exigir la etiqueta "responsable"
#    en todos los recursos del grupo.
# ---------------------------------------------------------------------
data "azurerm_policy_definition" "requiere_tag" {
  display_name = "Require a tag on resources"
}

resource "azurerm_resource_group_policy_assignment" "requiere_tag" {
  name                 = "asg-requiere-tag-responsable"
  resource_group_id    = azurerm_resource_group.gob.id
  policy_definition_id = data.azurerm_policy_definition.requiere_tag.id
  display_name         = "Exigir etiqueta 'responsable'"

  parameters = jsonencode({
    tagName = { value = "responsable" }
  })
}

output "resource_group" {
  value = azurerm_resource_group.gob.name
}

output "subscription" {
  value = data.azurerm_subscription.actual.display_name
}
