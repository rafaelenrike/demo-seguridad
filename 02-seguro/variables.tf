variable "location" {
  description = "Región de Azure (verifique las regiones permitidas en su suscripción Azure for Students)"
  type        = string
  default     = "eastus2"
}

variable "prefix" {
  description = "Prefijo corto para nombrar recursos"
  type        = string
  default     = "segdemo"
}

variable "my_ip" {
  description = "IP pública del equipo que ejecuta Terraform (curl -s ifconfig.me). Se usa en los firewalls de Key Vault y Storage."
  type        = string

  validation {
    condition     = can(regex("^\\d{1,3}(\\.\\d{1,3}){3}$", var.my_ip))
    error_message = "my_ip debe ser una IPv4 simple, sin máscara (ej. 181.50.10.20)."
  }
}

variable "ssh_public_key_path" {
  description = "Ruta a la llave pública SSH (la VM no acepta contraseñas)"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

variable "vm_size" {
  description = "Tamaño de la VM"
  type        = string
  default     = "Standard_B1s"
}

variable "tags" {
  description = "Etiquetas obligatorias de gobierno"
  type        = map(string)
  default = {
    curso       = "infraestructura-ti"
    tema        = "seguridad-nube"
    ambiente    = "demo"
    responsable = "profesor"
  }
}
