terraform {
  required_version = ">= 1.6"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
  }

  # Estado remoto cifrado y con bloqueo (descomentar tras crear la cuenta
  # de almacenamiento del estado; ver guía, paso 0). El estado CONTIENE
  # SECRETOS (p. ej. el valor de random_password), por eso nunca va a Git.
  # backend "azurerm" {
  #   resource_group_name  = "rg-tfstate"
  #   storage_account_name = "sttfstate<sufijo>"
  #   container_name       = "tfstate"
  #   key                  = "demo-seguridad.tfstate"
  #   use_azuread_auth     = true
  # }
}

# Sin credenciales en el código: la autenticación viene de `az login`
# (local) o de OIDC (GitHub Actions). La suscripción se toma de la
# variable de entorno ARM_SUBSCRIPTION_ID.
provider "azurerm" {
  # Operaciones de datos en Storage con Entra ID (la cuenta no admite llaves)
  storage_use_azuread = true

  features {
    key_vault {
      # Con purge protection activa no se puede purgar; Terraform solo
      # hace soft-delete al destruir.
      purge_soft_delete_on_destroy = false
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}
