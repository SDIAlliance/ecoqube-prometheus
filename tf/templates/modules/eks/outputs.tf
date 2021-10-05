output "eks_cluster_endpoint" {
  value = aws_eks_cluster.cluster.endpoint
}

output "efs_id" {
  value = aws_efs_file_system.efs.id
}

output "s3_bucket_thanos" {
  value = aws_s3_bucket.thanos.id
}

