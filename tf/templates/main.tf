variable "cidr_blocks_prefix" {
  default = {
    dev = "10.100"
    prd = "10.101"
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.7.0"

  name                    = "${var.project}-${var.env}-vpc"
  cidr                    = "${var.cidr_blocks_prefix[var.env]}.0.0/16"
  azs                     = ["eu-central-1a", "eu-central-1b"]
  map_public_ip_on_launch = false
  enable_dns_hostnames    = true
  public_subnets          = ["${var.cidr_blocks_prefix[var.env]}.101.0/24", "${var.cidr_blocks_prefix[var.env]}.102.0/24"]
  private_subnets         = ["${var.cidr_blocks_prefix[var.env]}.1.0/24", "${var.cidr_blocks_prefix[var.env]}.2.0/24"]
  one_nat_gateway_per_az  = true
  enable_nat_gateway      = true
  single_nat_gateway      = false
  public_subnet_tags = {
    Terraform                = "true"
    Project                  = var.project
    Environment              = var.env
    "kubernetes.io/role/elb" = "1"
  }
  private_subnet_tags = {
    Terraform                         = "true"
    Project                           = var.project
    Environment                       = var.env
    "kubernetes.io/role/internal-elb" = "1"
  }
  tags = {
    Terraform   = "true"
    Project     = var.project
    Environment = var.env
  }
}

module "eks" {
  source = "./modules/eks"

  project                          = var.project
  env                              = var.env
  kubernetes_version               = var.kubernetes_version
  image_id                         = var.image_id
  workspace_iam_role               = var.workspace_iam_roles[var.env]
  enable_eks_addons                = var.enable_eks_addons
  aws_eks_addon_version_kube_proxy = var.aws_eks_addon_version_kube_proxy
  aws_eks_addon_version_coredns    = var.aws_eks_addon_version_coredns
  aws_eks_addon_version_vpc_cni    = var.aws_eks_addon_version_vpc_cni
  vpc_id                           = module.vpc.vpc_id
  public_subnets                   = module.vpc.public_subnets
  private_subnets                  = module.vpc.private_subnets
}

