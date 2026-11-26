output "app_url" {
  description = "Open this in a browser."
  value       = "https://${aws_cloudfront_distribution.app.domain_name}"
}

output "web_bucket" {
  value = aws_s3_bucket.web.bucket
}

output "files_bucket" {
  value = aws_s3_bucket.files.bucket
}

output "distribution_id" {
  value = aws_cloudfront_distribution.app.id
}

output "function_name" {
  value = aws_lambda_function.api.function_name
}

output "google_redirect_uri" {
  description = "Add this as an authorised redirect URI in the Google Cloud console."
  value       = "https://${aws_cloudfront_distribution.app.domain_name}/api/auth/google/callback"
}
