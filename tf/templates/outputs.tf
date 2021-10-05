output "vpc_id" {
  value = module.vpc.vpc_id
}

output "public_subnet_1a" {
  value = module.vpc.public_subnets[0]
}

output "public_subnet_1b" {
  value = module.vpc.public_subnets[1]
}

output "private_subnet_1a" {
  value = module.vpc.private_subnets[0]
}

output "private_subnet_1b" {
  value = module.vpc.private_subnets[1]
}

output "eks_cluster_endpoint" {
  value = module.eks.eks_cluster_endpoint
}

output "efs_id" {
  value = module.eks.efs_id
}

output "s3_bucket_thanos" {
  value = module.eks.s3_bucket_thanos
}
