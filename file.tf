provider "aws" {
	 region= "ap-south-1"
	 profile = "lwprofile"
}

#Creating Kay pair

resource "aws_key_pair" "deployer" {
  key_name  = "deployer-key"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEA774D52cxL8jFhpRpgvydhGMppmFH7OrSAo6B8BDv6HPz5SkaKr9OrLa57TXufhjNkdF1r58AHWf3tqlborB+Vr53vAFrqU8z0HWNa46W1a/7WDcuxwFjATsp8oD48mkLcUPqcxc6oenicPgqOjvseBmmLm7zn369OVMkBN66kSHO1g6bXffL2GZlRuZh1BDT67nSyCJTrczcwXihINUUHsuVBF045BmMtrVEeSWi7B0+deShvac0s7Z0c3csA+lD6E28kfspAQW2j/fgcU4+T1W/ImRzK7WpzyV8Jc5tVdlGx9wsQNwsvuxL86+BGC4wGU1THB6HU7FQ5fJxO2sUbw== rsa-key-20200611"

}

#Creating Security Group
resource "aws_security_group" "allow_http" {
  name        = "allow_http"
  description = "Allow HTTP inbound traffic"


ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }


ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_http"
  }
}

#Creating an AWS instance

resource "aws_instance" "web" {
	ami = "ami-0447a12f28fddb066"
	instance_type = "t2.micro"
	availability_zone = "ap-south-1a"
	security_groups = ["${aws_security_group.allow_http.name}"]
	key_name = "deployer-key"
	tags = {
		Name = "TerraForm Server"
	}

connection {
    type     = "ssh"
    user     = "ec2-user"
    port     =  22
    private_key = file("/root/Downloads/deployer-key.pem")
    host     = aws_instance.web.public_ip
  }

provisioner "remote-exec" {
    inline = [
      "sudo yum install httpd  php git -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd",
    ]
}
}

# Creating EBS

resource "aws_ebs_volume" "terravolume1" {
  availability_zone = aws_instance.web.availability_zone
  size = 1
  tags = {
    Name = "VolumeForTerraform"
  }
}
resource "aws_volume_attachment" "terravolume_attached" {
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.terravolume1.id
  instance_id = aws_instance.web.id
  force_detach = true
}
output "Terraform_Server_IP" {
  value = aws_instance.web.public_ip
}

resource "null_resource" "nullremote3"  {

depends_on = [
    aws_volume_attachment.terravolume_attached,
  ]
connection {
    type     = "ssh"
    user     = "ec2-user"
    port     =  22
    private_key = file("/root/Downloads/deployer-key.pem")
    host     = aws_instance.web.public_ip
  }

provisioner "remote-exec" {
    inline = [
      "sudo mkfs.ext4  /dev/xvdh",
      "sudo mount  /dev/xvdh  /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/Gaurav1829/Terraform.git  /var/www/html/"
    ]
  }
}


#Creating S3 Bucket

resource "aws_s3_bucket" "bucket" {
  bucket = "terrabucket2021"
  acl = "private"
  region = "ap-south-1"
}

resource "aws_s3_bucket_object" "object" {
	bucket = "terrabucket2021"
	key = "vimalsir.jpg"
	source = "/root/Downloads/VimalSir.JPG"
}

locals {
  s3_origin_id = "myS3Origin"
}
resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "OAI"
}
resource "aws_cloudfront_distribution" "s3_distribution" {
origin {
    domain_name = aws_s3_bucket.bucket.bucket_regional_domain_name
    origin_id   = local.s3_origin_id
s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
    }
  }
enabled             = true
  is_ipv6_enabled     = true
default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id
forwarded_values {
      query_string = false
cookies {
        forward = "none"
      }
    }
viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }
restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
viewer_certificate {
    cloudfront_default_certificate = true
  }
}

data "aws_iam_policy_document" "s3_policy" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.bucket.arn}/*"]
principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }
statement {
    actions   = ["s3:ListBucket"]
    resources = ["${aws_s3_bucket.bucket.arn}"]
principals {
      type        = "AWS"
      identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
    }
  }
}
resource "aws_s3_bucket_policy" "example" {
  bucket = aws_s3_bucket.bucket.id
  policy = data.aws_iam_policy_document.s3_policy.json
}

