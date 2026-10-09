# Intentionally insecure Terraform for scanner testing. Never apply this.
resource "aws_s3_bucket" "data" {
  bucket = "aegis-demo-public-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "open" {
  name        = "open-sg"
  description = "Allows SSH from anywhere"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}