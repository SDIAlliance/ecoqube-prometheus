variable "project" {
  type = string
}

variable "env" {
  type = string
}

variable "kubernetes_version" {
  type = string
}

variable "image_id" {
  type = string
}

variable "instance_type" {
  type    = string
  default = "t3.large"
}

variable "use_spot_instances" {
  type    = bool
  default = true
}

variable "asg_min_instances" {
  type    = string
  default = "2"
}

variable "asg_max_instances" {
  type    = string
  default = "10"
}

variable "workspace_iam_role" {
  type = string
}

variable "enable_eks_addons" {
  type    = bool
  default = true
}

variable "aws_eks_addon_version_kube_proxy" {
  type = string
}

variable "aws_eks_addon_version_coredns" {
  type = string
}

variable "aws_eks_addon_version_vpc_cni" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "public_subnets" {
  type = list(string)
}

variable "private_subnets" {
  type = list(string)
}

variable "grafana_hostname" {
  type = string
}

variable "thanos_hostname" {
  type = string
}

