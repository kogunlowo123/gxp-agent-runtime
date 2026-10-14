variable "name" {
  description = "Resource name prefix"
  type        = string
  default     = "gxp-agent-runtime"
}

variable "subscription_id" {
  description = "Azure subscription"
  type        = string
}

variable "resource_group_name" {
  description = "Existing resource group"
  type        = string
}

variable "db_subnet_id" {
  description = "Subnet delegated to Microsoft.DBforPostgreSQL/flexibleServers"
  type        = string
}

variable "db_private_dns_zone_id" {
  description = "Private DNS zone privatelink.postgres.database.azure.com linked to the VNet"
  type        = string
}

variable "db_sku" {
  description = "PostgreSQL Flexible Server SKU"
  type        = string
  default     = "GP_Standard_D4ds_v5"
}

variable "db_storage_mb" {
  description = "Database storage"
  type        = number
  default     = 65536
}

variable "aks_oidc_issuer_url" {
  description = "AKS cluster OIDC issuer URL (az aks show --query oidcIssuerProfile.issuerUrl)"
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace of the gxp"
  type        = string
  default     = "gxp-runtime"
}

variable "service_account" {
  description = "Kubernetes service account of the gxp"
  type        = string
  default     = "gxp-agent-runtime"
}

variable "audit_retention_days" {
  description = "Immutability period for audit exports and validation evidence"
  type        = number
  default     = 3650
}

variable "tags" {
  description = "Tags applied to every resource"
  type        = map(string)
  default     = { "app.kubernetes.io/part-of" = "gxp-agent-runtime" }
}
