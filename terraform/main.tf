# ==============================================================================
# Infrastructure as Code (IaC) - AWS Free Tier EC2 & Docker Deployment
# ==============================================================================

terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# -----------------------------------------------------------------------------
# Input Variables
# -----------------------------------------------------------------------------
variable "aws_region" {
  description = "AWS deployment region"
  type        = string
  default     = "ap-south-1" # Mumbai region
}

variable "instance_type" {
  description = "EC2 Instance size (Free Tier eligible)"
  type        = string
  default     = "t2.micro"
}

# -----------------------------------------------------------------------------
# Security Group: Least Privilege Firewall Configuration
# -----------------------------------------------------------------------------
resource "aws_security_group" "detector_sg" {
  name        = "phishing-detector-sg"
  description = "Allow inbound HTTP and SSH traffic, unrestricted outbound"

  ingress {
    description = "HTTP Traffic from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH Access for administration"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Outbound traffic for package installation & DNS lookups"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "phishing-detector-sg"
    Environment = "Production"
  }
}

# -----------------------------------------------------------------------------
# EC2 Instance: Host for Containerized Application
# -----------------------------------------------------------------------------
resource "aws_instance" "app_server" {
  ami           = "ami-03f4878e83d3e20c8" # Ubuntu 22.04 LTS (ap-south-1)
  instance_type = var.instance_type

  security_groups = [aws_security_group.detector_sg.name]

  # Cloud-init bootstrap script installing Docker and running the container
  user_data = <<-EOF
              #!/bin/bash
              set -e
              apt-get update -y
              apt-get install -y docker.io
              systemctl start docker
              systemctl enable docker
              docker run -d --restart always -p 80:8000 suryahanuman/phishing-url-detector:latest
              EOF

  tags = {
    Name        = "PhishingDetector-Server"
    Environment = "Production"
    Project     = "PhishingURLDetector"
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "server_public_ip" {
  description = "Public IP address of the deployed EC2 server"
  value       = aws_instance.app_server.public_ip
}

output "server_public_dns" {
  description = "Public DNS hostname of the deployed EC2 server"
  value       = aws_instance.app_server.public_dns
}
