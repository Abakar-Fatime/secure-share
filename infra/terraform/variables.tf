variable "project" {
  description = "Name prefix for every resource."
  type        = string
  default     = "secure-share"
}

variable "region" {
  description = "AWS region for the API, database and file storage."
  type        = string
  default     = "ap-northeast-1"
}

variable "lambda_zip" {
  description = "Path to the API deployment package built by CI (scripts/build_lambda.sh)."
  type        = string
  default     = "../../build/lambda.zip"
}

variable "max_upload_mb" {
  description = "Largest file a user can upload."
  type        = number
  default     = 50
}

variable "google_client_id" {
  description = "OAuth client ID for 'Sign in with Google'. Leave empty to turn Google sign-in off."
  type        = string
  default     = ""
}

variable "google_client_secret" {
  description = "OAuth client secret for 'Sign in with Google'."
  type        = string
  default     = ""
  sensitive   = true
}

variable "budget_email" {
  description = "If set, AWS emails this address when the monthly cost forecast passes the budget."
  type        = string
  default     = ""
}

variable "monthly_budget_usd" {
  description = "Monthly cost budget in USD."
  type        = number
  default     = 5
}
