# Import dependencies
#####################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

#############################################################################################################
# EKS CLUSTER
#############################################################################################################


# EKS Cluster Role
##################
resource "aws_iam_role" "cluster" {
  name = "${var.project}-${var.env}-eks-cluster-controlplane-role"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "cluster-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}
resource "aws_iam_role_policy_attachment" "cluster-AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.cluster.name
}

# Cluster Log Group
###################
resource "aws_cloudwatch_log_group" "cluster" {
  name              = "/aws/eks/${var.project}-${var.env}-cluster/cluster"
  retention_in_days = 7
}

# Cluster Security Group
########################
resource "aws_security_group" "cluster" {
  name   = "${var.project}-${var.env}-eks-cluster"
  vpc_id = var.vpc_id
}

resource "aws_security_group_rule" "cluster_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.cluster.id
  description       = "Allow outgoing traffic"
}

resource "aws_security_group_rule" "cluster_ingress_1" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.cluster.id
  security_group_id        = aws_security_group.cluster.id
  description              = "Allow traffic from EKS worker nodes"
}

resource "aws_security_group_rule" "cluster_ingress_2" {
  type                     = "ingress"
  from_port                = 1025
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.nodes.id
  security_group_id        = aws_security_group.cluster.id
  description              = "Allow traffic from EKS worker nodes"
}

resource "aws_security_group_rule" "cluster_ingress_3" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.nodes.id
  security_group_id        = aws_security_group.cluster.id
  description              = "Allow traffic from EKS worker nodes"
}

# EKS Cluster
#############
resource "aws_eks_cluster" "cluster" {
  name     = "${var.project}-${var.env}-cluster"
  role_arn = aws_iam_role.cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids = [
      var.private_subnets[0],
      var.private_subnets[1],
      var.public_subnets[0],
      var.public_subnets[1],
    ]
    endpoint_private_access = true
    endpoint_public_access  = true
    security_group_ids      = [aws_security_group.cluster.id]
  }
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role.cluster,
    aws_iam_role_policy_attachment.cluster-AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.cluster-AmazonEKSVPCResourceController,
    aws_cloudwatch_log_group.cluster
  ]
}

# OIDC Provider
###############
data "tls_certificate" "cluster" {
  url = aws_eks_cluster.cluster.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "cluster" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.cluster.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.cluster.identity[0].oidc[0].issuer
}

#############################################################################################################
# Service Account IAM Roles
#############################################################################################################

# AWS Node Role
###############
data "aws_iam_policy_document" "aws_node_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.cluster.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-node"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.cluster.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role_policy_attachment" "aws-node-AmazonEKS_CNI_Policy" {
  role       = aws_iam_role.aws_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "aws-node-CloudWatchAgentServerPolicy" {
  role       = aws_iam_role.aws_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role" "aws_node_role" {
  assume_role_policy = data.aws_iam_policy_document.aws_node_policy.json
  name               = "${var.project}-${var.env}-eks-service-account-role-aws-node"
}

# Cluster Autoscaler Role
#########################
data "aws_iam_policy_document" "cluster_autoscaler_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.cluster.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:cluster-autoscaler"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.cluster.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "cluster_autoscaler_role" {
  assume_role_policy = data.aws_iam_policy_document.cluster_autoscaler_policy.json
  name               = "${var.project}-${var.env}-eks-service-account-role-cluster-autoscaler"
}

data "aws_iam_policy_document" "cluster_autoscaler_asg_policy_document" {
  statement {
    actions   = ["autoscaling:Describe*", "autoscaling:SetDesiredCapacity", "autoscaling:TerminateInstanceInAutoScalingGroup", "ec2:DescribeLaunchTemplateVersions"]
    resources = ["*"]
    effect    = "Allow"
  }
}

resource "aws_iam_policy" "cluster_autoscaler_asg_policy" {
  name   = "${var.project}-${var.env}-eks-service-account-role-cluster-autoscaler-asg-policy"
  path   = "/"
  policy = data.aws_iam_policy_document.cluster_autoscaler_asg_policy_document.json
}

resource "aws_iam_role_policy_attachment" "cluster_autoscaler_asg_policy_attachment" {
  role       = aws_iam_role.cluster_autoscaler_role.name
  policy_arn = aws_iam_policy.cluster_autoscaler_asg_policy.arn
}

# AWS Load Balancer Controller
##############################
data "aws_iam_policy_document" "aws_lb_controller_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.cluster.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-load-balancer-controller"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.cluster.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "aws_lb_controller_role" {
  assume_role_policy = data.aws_iam_policy_document.aws_lb_controller_policy.json
  name               = "${var.project}-${var.env}-eks-service-account-role-aws-lb-controller"
}

data "aws_iam_policy_document" "aws_lb_controller_policy_document" {
  statement {
    actions   = ["iam:CreateServiceLinkedRole", "ec2:Describe*", "ec2:GetCoipPoolUsage", "ec2:DescribeCoipPools", "ec2:CreateTags", "ec2:DeleteTags", "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress", "ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress", "ec2:DeleteSecurityGroup", "elasticloadbalancing:*", "cognito-idp:DescribeUserPoolClient", "acm:ListCertificates", "acm:DescribeCertificate", "iam:ListServerCertificates", "iam:GetServerCertificate", "waf-regional:GetWebACL", "waf-regional:GetWebACLForResource", "waf-regional:AssociateWebACL", "waf-regional:DisassociateWebACL", "wafv2:GetWebACL", "wafv2:GetWebACLForResource", "wafv2:AssociateWebACL", "wafv2:DisassociateWebACL", "shield:GetSubscriptionState", "shield:DescribeProtection", "shield:CreateProtection", "shield:DeleteProtection"]
    resources = ["*"]
    effect    = "Allow"
  }
}

resource "aws_iam_policy" "aws_lb_controller_policy" {
  name   = "${var.project}-${var.env}-eks-service-account-role-aws-lb-controller-policy"
  path   = "/"
  policy = data.aws_iam_policy_document.aws_lb_controller_policy_document.json
}

resource "aws_iam_role_policy_attachment" "aws_lb_controller_policy_attachment" {
  role       = aws_iam_role.aws_lb_controller_role.name
  policy_arn = aws_iam_policy.aws_lb_controller_policy.arn
}

# External DNS
##############
data "aws_iam_policy_document" "external_dns_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.cluster.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:external-dns"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.cluster.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "external_dns_role" {
  assume_role_policy = data.aws_iam_policy_document.external_dns_policy.json
  name               = "${var.project}-${var.env}-eks-service-account-role-external-dns"
}

data "aws_iam_policy_document" "external_dns_policy_document" {
  statement {
    actions   = ["route53:ChangeResourceRecordSets"]
    resources = ["arn:aws:route53:::hostedzone/*"]
    effect    = "Allow"
  }
  statement {
    actions   = ["route53:ListHostedZones", "route53:ListResourceRecordSets"]
    resources = ["*"]
    effect    = "Allow"
  }
}

resource "aws_iam_policy" "external_dns_policy" {
  name   = "${var.project}-${var.env}-eks-service-account-role-external_dns-policy"
  path   = "/"
  policy = data.aws_iam_policy_document.external_dns_policy_document.json
}

resource "aws_iam_role_policy_attachment" "external_dns_policy_attachment" {
  role       = aws_iam_role.external_dns_role.name
  policy_arn = aws_iam_policy.external_dns_policy.arn
}

# EFS Role
##########
data "aws_iam_policy_document" "efs_csi_controller_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.cluster.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:efs-csi-controller-sa"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.cluster.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "efs_csi_controller_role" {
  assume_role_policy = data.aws_iam_policy_document.efs_csi_controller_policy.json
  name               = "${var.project}-${var.env}-eks-service-account-role-efs-csi-controller"
}

data "aws_iam_policy_document" "efs_csi_controller_asg_policy_document" {
  statement {
    actions   = ["elasticfilesystem:DescribeAccessPoints", "elasticfilesystem:DescribeFileSystems"]
    resources = ["*"]
    effect    = "Allow"
  }
  statement {
    actions   = ["elasticfilesystem:DeleteAccessPoint"]
    resources = ["*"]
    effect    = "Allow"
    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/efs.csi.aws.com/cluster"
      values   = ["true"]
    }
  }
  statement {
    actions   = ["elasticfilesystem:CreateAccessPoint"]
    resources = ["*"]
    effect    = "Allow"
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/efs.csi.aws.com/cluster"
      values   = ["true"]
    }
  }
}

resource "aws_iam_policy" "efs_csi_controller_asg_policy" {
  name   = "${var.project}-${var.env}-eks-service-account-role-efs-csi-controller-policy"
  path   = "/"
  policy = data.aws_iam_policy_document.efs_csi_controller_asg_policy_document.json
}

resource "aws_iam_role_policy_attachment" "efs_csi__controller_asg_policy_attachment" {
  role       = aws_iam_role.efs_csi_controller_role.name
  policy_arn = aws_iam_policy.efs_csi_controller_asg_policy.arn
}

# S3 Import Role
################
data "aws_iam_policy_document" "s3_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    principals {
      identifiers = [aws_iam_openid_connect_provider.cluster.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "s3_role" {
  assume_role_policy = data.aws_iam_policy_document.s3_assume_role_policy.json
  name               = "${var.project}-${var.env}-eks-service-account-role-s3-thanos"
}

data "aws_iam_policy_document" "s3_policy_document" {
  statement {
    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::${var.project}-${var.env}-thanos-${data.aws_caller_identity.current.account_id}/*",
      "arn:aws:s3:::${var.project}-${var.env}-thanos-${data.aws_caller_identity.current.account_id}"
    ]
    effect = "Allow"
  }
}

resource "aws_iam_policy" "s3_policy" {
  name   = "${var.project}-${var.env}-eks-service-account-role-s3-thanos-policy"
  path   = "/"
  policy = data.aws_iam_policy_document.s3_policy_document.json
}

resource "aws_iam_role_policy_attachment" "s3_policy_attachment" {
  role       = aws_iam_role.s3_role.name
  policy_arn = aws_iam_policy.s3_policy.arn
}

#############################################################################################################
# EKS Add-Ons
#############################################################################################################

resource "aws_eks_addon" "kube_proxy" {
  count             = var.enable_eks_addons ? 1 : 0
  cluster_name      = aws_eks_cluster.cluster.name
  addon_name        = "kube-proxy"
  addon_version     = var.aws_eks_addon_version_kube_proxy
  resolve_conflicts = "OVERWRITE"
  depends_on = [
    aws_autoscaling_group.nodes,
    aws_eks_cluster.cluster
  ]
}

resource "aws_eks_addon" "coredns" {
  count             = var.enable_eks_addons ? 1 : 0
  cluster_name      = aws_eks_cluster.cluster.name
  addon_name        = "coredns"
  addon_version     = var.aws_eks_addon_version_coredns
  resolve_conflicts = "OVERWRITE"
  depends_on = [
    aws_autoscaling_group.nodes,
    aws_eks_cluster.cluster
  ]
}

resource "aws_eks_addon" "vpc_cni" {
  count                    = var.enable_eks_addons ? 1 : 0
  cluster_name             = aws_eks_cluster.cluster.name
  addon_name               = "vpc-cni"
  addon_version            = var.aws_eks_addon_version_vpc_cni
  resolve_conflicts        = "OVERWRITE"
  service_account_role_arn = aws_iam_role.aws_node_role.arn
  depends_on = [
    aws_autoscaling_group.nodes,
    aws_eks_cluster.cluster
  ]
}

#############################################################################################################
# EKS WORKER NODES
#############################################################################################################


# Node Security Group
#####################
resource "aws_security_group" "nodes" {
  name   = "${var.project}-${var.env}-eks-nodes"
  vpc_id = var.vpc_id
  tags = {
    "${var.project}-cluster" = "owned"
  }
}

resource "aws_security_group_rule" "nodes_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.nodes.id
  description       = "Allow outgoing traffic"
}

resource "aws_security_group_rule" "nodes_ingress_1" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "-1"
  source_security_group_id = aws_security_group.nodes.id
  security_group_id        = aws_security_group.nodes.id
  description              = "Allow traffic from EKS worker nodes"
}

resource "aws_security_group_rule" "nodes_ingress_2" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "-1"
  source_security_group_id = aws_security_group.cluster.id
  security_group_id        = aws_security_group.nodes.id
  description              = "Allow traffic from EKS control plane"
}

# Instance Profile & Role
#########################
resource "aws_iam_instance_profile" "nodes" {
  name = "${var.project}-${var.env}-eks-node-instance-profile"
  role = aws_iam_role.nodes.name
}

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "nodes" {
  name               = "${var.project}-${var.env}-eks-node-role"
  path               = "/"
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEKSWorkerNodePolicy" {
  role       = aws_iam_role.nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEC2RoleforSSM" {
  role       = aws_iam_role.nodes.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEC2ContainerRegistryReadOnly" {
  role       = aws_iam_role.nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEKS_CNI_Policy" {
  role       = aws_iam_role.nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

# Launch Template
#################
resource "aws_launch_template" "nodes" {
  depends_on = [
    aws_security_group.nodes
  ]
  name = "${var.project}-${var.env}-eks-nodes"
  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size = "100"
    }
  }
  capacity_reservation_specification {
    capacity_reservation_preference = "open"
  }
  credit_specification {
    cpu_credits = "standard"
  }
  disable_api_termination = false
  iam_instance_profile {
    name = aws_iam_instance_profile.nodes.name
  }
  image_id                             = var.image_id
  instance_initiated_shutdown_behavior = "terminate"
  instance_type                        = var.instance_type
  monitoring {
    enabled = true
  }
  vpc_security_group_ids = [aws_security_group.nodes.id]

  user_data = base64encode(<<USERDATA
#!/bin/bash
# Install SSM agent
yum -y install https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
sudo systemctl enable amazon-ssm-agent
sudo systemctl restart amazon-ssm-agent
# Configure EKS
set -o xtrace
/etc/eks/bootstrap.sh ${var.project}-${var.env}-cluster --kubelet-extra-args --node-labels=nodegroup=main,nodetype=custom,multi-az=true
USERDATA
  )

  lifecycle {
    create_before_destroy = true
  }
}

# data "external" "asg_desired_instances" {
#   program = ["bash", "${path.module}/scripts/get_asg_desired_instances.sh"]
#   query = {
#     asg_name_tag       = "${var.project}-${var.service}-${var.env}"
#     region             = data.aws_region.current.name
#     desired_capacity   = var.asg_min_instances
#     workspace_iam_role = var.workspace_iam_role
#   }
# }

# Autoscaling Group
###################
resource "aws_autoscaling_group" "nodes" {
  name = "${aws_launch_template.nodes.name}-${aws_launch_template.nodes.latest_version}"

  vpc_zone_identifier = [
    var.private_subnets[0],
    var.private_subnets[1]
  ]

  max_size = var.asg_max_instances
  min_size = var.asg_min_instances
  # desired_capacity          = data.external.asg_desired_instances.result.desired_count
  wait_for_capacity_timeout = "300s"

  mixed_instances_policy {
    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.nodes.id
        version            = aws_launch_template.nodes.latest_version
      }
    }

    instances_distribution {
      on_demand_base_capacity                  = 0
      on_demand_percentage_above_base_capacity = var.use_spot_instances ? 0 : 100
      spot_allocation_strategy                 = "lowest-price"
      spot_instance_pools                      = 10
    }
  }

  metrics_granularity = "1Minute"
  enabled_metrics     = ["GroupDesiredCapacity", "GroupInServiceCapacity", "GroupPendingCapacity", "GroupMinSize", "GroupMaxSize", "GroupInServiceInstances", "GroupPendingInstances", "GroupStandbyInstances", "GroupStandbyCapacity", "GroupTerminatingCapacity", "GroupTerminatingInstances", "GroupTotalCapacity", "GroupTotalInstances"]

  health_check_grace_period = 300
  health_check_type         = "EC2"
  # min_elb_capacity          = var.asg_enable_min_elb_capacity ? var.asg_min_instances : 0

  tag {
    key                 = "Name" # Should be capitalized to display properly in EC2 web console
    value               = "${var.project}-${var.env}-eks-node"
    propagate_at_launch = true
  }
  tag {
    key                 = "project"
    value               = var.project
    propagate_at_launch = true
  }
  tag {
    key                 = "env"
    value               = var.env
    propagate_at_launch = true
  }
  tag {
    key                 = "kubernetes.io/cluster/${var.project}-${var.env}-cluster"
    value               = "owned"
    propagate_at_launch = true
  }
  tag {
    key                 = "k8s.io/cluster-autoscaler/enabled"
    value               = true
    propagate_at_launch = true
  }
  tag {
    key                 = "k8s.io/cluster-autoscaler/${var.project}-${var.env}-cluster"
    value               = true
    propagate_at_launch = true
  }
  tag {
    key                 = "multi-az"
    value               = true
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_eks_cluster.cluster,
  ]

}

############################################################################################################
# Management IAM Roles
#############################################################################################################

# Master Role
#############
data "aws_iam_policy_document" "master_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type = "AWS"
      identifiers = [
        # "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/users-administrator-role",
        # "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/users-poweruser-role",
        # "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/users-readonly-role",
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/Access9apps-AdministratorRole-I8U6G3HQU2VA"
      ]
    }
  }
}

resource "aws_iam_role" "master" {
  name               = "${var.project}-${var.env}-eks-master-role"
  path               = "/"
  assume_role_policy = data.aws_iam_policy_document.master_assume_role_policy.json
}

data "aws_iam_policy_document" "master" {
  statement {
    actions = [
      "eks:DescribeCluster",
      "eks:ListClusters",
      "ecr:*"
    ]
    resources = [
      "*"
    ]
  }
}

resource "aws_iam_policy" "master" {
  name   = "${var.project}-${var.env}-eks-master-policy"
  path   = "/"
  policy = data.aws_iam_policy_document.master.json
}

resource "aws_iam_role_policy_attachment" "master" {
  role       = aws_iam_role.master.name
  policy_arn = aws_iam_policy.master.arn
}

# Read-Only Role
################
data "aws_iam_policy_document" "developer_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type = "AWS"
      identifiers = [
        # "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/users-administrator-role",
        # "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/users-poweruser-role",
        # "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/users-readonly-role",
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/Access9apps-AdministratorRole-I8U6G3HQU2VA"
      ]
    }
  }
}

resource "aws_iam_role" "developer" {
  name               = "${var.project}-${var.env}-eks-developer-role"
  path               = "/"
  assume_role_policy = data.aws_iam_policy_document.developer_assume_role_policy.json
}

data "aws_iam_policy_document" "developer" {
  statement {
    actions = [
      "eks:DescribeCluster",
      "eks:ListClusters"
    ]
    resources = [
      "*"
    ]
  }
}

resource "aws_iam_policy" "developer" {
  name   = "${var.project}-${var.env}-eks-developer-policy"
  path   = "/"
  policy = data.aws_iam_policy_document.developer.json
}

resource "aws_iam_role_policy_attachment" "developer" {
  role       = aws_iam_role.developer.name
  policy_arn = aws_iam_policy.developer.arn
}


############################################################################################################
# S3 Buckets
############################################################################################################

resource "aws_s3_bucket" "thanos" {
  bucket = "${var.project}-${var.env}-thanos-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name    = "${var.project}-${var.env}-thanos-${data.aws_caller_identity.current.account_id}"
    Project = var.project
    Env     = var.env
  }
}

############################################################################################################
# EFS
############################################################################################################

resource "aws_efs_file_system" "efs" {
  creation_token = "${var.project}-${var.env}"
  encrypted      = true
  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }
}

resource "aws_security_group" "efs" {
  name   = "${var.project}-${var.env}-eks-efs"
  vpc_id = var.vpc_id
}

resource "aws_security_group_rule" "efs_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.efs.id
  description       = "Allow outgoing traffic"
}

resource "aws_security_group_rule" "efs_ingress_1" {
  type                     = "ingress"
  from_port                = 2049
  to_port                  = 2049
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.nodes.id
  security_group_id        = aws_security_group.efs.id
  description              = "Allow NFS traffic from EKS worker nodes"
}

resource "aws_efs_mount_target" "efs_a" {
  file_system_id  = aws_efs_file_system.efs.id
  subnet_id       = var.private_subnets[0]
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_mount_target" "efs_b" {
  file_system_id  = aws_efs_file_system.efs.id
  subnet_id       = var.private_subnets[1]
  security_groups = [aws_security_group.efs.id]
}


############################################################################################################
# EFS
############################################################################################################
resource "aws_ssm_parameter" "vpc_id" {
  name  = "/${var.project}/${var.env}/env/vpc_id"
  type  = "String"
  value = var.vpc_id
}

resource "aws_ssm_parameter" "public_subnet_1a" {
  name  = "/${var.project}/${var.env}/env/public_subnet_1a"
  type  = "String"
  value = var.public_subnets[0]
}

resource "aws_ssm_parameter" "public_subnet_1b" {
  name  = "/${var.project}/${var.env}/env/public_subnet_1b"
  type  = "String"
  value = var.public_subnets[1]
}

resource "aws_ssm_parameter" "private_subnet_1a" {
  name  = "/${var.project}/${var.env}/env/private_subnet_1a"
  type  = "String"
  value = var.private_subnets[0]
}

resource "aws_ssm_parameter" "private_subnet_1b" {
  name  = "/${var.project}/${var.env}/env/private_subnet_1b"
  type  = "String"
  value = var.private_subnets[1]
}

resource "aws_ssm_parameter" "efs_id" {
  name  = "/${var.project}/${var.env}/env/efs_id"
  type  = "String"
  value = aws_efs_file_system.efs.id
}
