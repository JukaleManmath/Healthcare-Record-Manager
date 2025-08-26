#!/bin/bash

# Healthcare Platform AWS Deployment Script
# This script deploys the complete healthcare platform infrastructure to AWS

set -e  # Exit on any error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
STACK_PREFIX="healthcare"
DEFAULT_REGION="us-east-1"
DEFAULT_ENVIRONMENT="production"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install it first."
        exit 1
    fi
    
    # Check jq
    if ! command -v jq &> /dev/null; then
        print_error "jq is not installed. Please install it first."
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials are not configured. Please run 'aws configure' first."
        exit 1
    fi
    
    print_success "All prerequisites are satisfied"
}

# Function to get AWS account ID
get_aws_account_id() {
    aws sts get-caller-identity --query Account --output text
}

# Function to build and push Docker image
build_and_push_image() {
    local environment=$1
    local region=$2
    local account_id=$3
    
    print_status "Building and pushing Docker image..."
    
    # Build the image
    docker build -t healthcare-platform:latest "$PROJECT_ROOT"
    
    # Get ECR login token
    aws ecr get-login-password --region "$region" | docker login --username AWS --password-stdin "$account_id.dkr.ecr.$region.amazonaws.com"
    
    # Tag the image
    docker tag healthcare-platform:latest "$account_id.dkr.ecr.$region.amazonaws.com/healthcare-platform:latest"
    
    # Push the image
    docker push "$account_id.dkr.ecr.$region.amazonaws.com/healthcare-platform:latest"
    
    print_success "Docker image pushed successfully"
}

# Function to create secrets in AWS Secrets Manager
create_secrets() {
    local environment=$1
    local region=$2
    
    print_status "Creating secrets in AWS Secrets Manager..."
    
    # Generate secrets
    local secret_key=$(openssl rand -hex 32)
    local jwt_secret_key=$(openssl rand -hex 32)
    local encryption_key=$(openssl rand -base64 32)
    local db_password=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    
    # Create app secrets
    aws secretsmanager create-secret \
        --name "healthcare/$environment/app-secret" \
        --description "Healthcare platform application secrets" \
        --secret-string "{\"secret_key\":\"$secret_key\",\"jwt_secret_key\":\"$jwt_secret_key\",\"encryption_key\":\"$encryption_key\"}" \
        --region "$region" \
        --tags Key=Environment,Value="$environment" Key=Project,Value=healthcare || true
    
    # Create database secrets
    aws secretsmanager create-secret \
        --name "healthcare/$environment/database" \
        --description "Healthcare platform database credentials" \
        --secret-string "{\"username\":\"admin\",\"password\":\"$db_password\"}" \
        --region "$region" \
        --tags Key=Environment,Value="$environment" Key=Project,Value=healthcare || true
    
    print_success "Secrets created successfully"
}

# Function to deploy CloudFormation stack
deploy_stack() {
    local stack_name=$1
    local template_file=$2
    local parameters=$3
    local region=$4
    
    print_status "Deploying stack: $stack_name"
    
    # Check if stack exists
    if aws cloudformation describe-stacks --stack-name "$stack_name" --region "$region" &> /dev/null; then
        print_warning "Stack $stack_name already exists. Updating..."
        aws cloudformation update-stack \
            --stack-name "$stack_name" \
            --template-body "file://$template_file" \
            --parameters "$parameters" \
            --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
            --region "$region"
        
        # Wait for update to complete
        aws cloudformation wait stack-update-complete --stack-name "$stack_name" --region "$region"
    else
        print_status "Creating new stack: $stack_name"
        aws cloudformation create-stack \
            --stack-name "$stack_name" \
            --template-body "file://$template_file" \
            --parameters "$parameters" \
            --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
            --region "$region"
        
        # Wait for creation to complete
        aws cloudformation wait stack-create-complete --stack-name "$stack_name" --region "$region"
    fi
    
    print_success "Stack $stack_name deployed successfully"
}

# Function to get stack output
get_stack_output() {
    local stack_name=$1
    local output_key=$2
    local region=$3
    
    aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --region "$region" \
        --query "Stacks[0].Outputs[?OutputKey=='$output_key'].OutputValue" \
        --output text
}

# Function to deploy network infrastructure
deploy_network() {
    local environment=$1
    local region=$2
    
    print_status "Deploying network infrastructure..."
    
    local stack_name="$STACK_PREFIX-network"
    local template_file="$PROJECT_ROOT/infrastructure/network.yml"
    local parameters="ParameterKey=Environment,ParameterValue=$environment"
    
    deploy_stack "$stack_name" "$template_file" "$parameters" "$region"
    
    print_success "Network infrastructure deployed"
}

# Function to deploy database infrastructure
deploy_database() {
    local environment=$1
    local region=$2
    
    print_status "Deploying database infrastructure..."
    
    # Get network outputs
    local vpc_id=$(get_stack_output "$STACK_PREFIX-network" "VpcId" "$region")
    local private_subnet1_id=$(get_stack_output "$STACK_PREFIX-network" "PrivateSubnet1Id" "$region")
    local private_subnet2_id=$(get_stack_output "$STACK_PREFIX-network" "PrivateSubnet2Id" "$region")
    local db_security_group_id=$(get_stack_output "$STACK_PREFIX-network" "DatabaseSecurityGroupId" "$region")
    
    # Get database password from secrets
    local db_password=$(aws secretsmanager get-secret-value \
        --secret-id "healthcare/$environment/database" \
        --region "$region" \
        --query SecretString \
        --output text | jq -r .password)
    
    local stack_name="$STACK_PREFIX-database"
    local template_file="$PROJECT_ROOT/infrastructure/rds.yml"
    local parameters="ParameterKey=Environment,ParameterValue=$environment \
                     ParameterKey=VpcId,ParameterValue=$vpc_id \
                     ParameterKey=PrivateSubnet1Id,ParameterValue=$private_subnet1_id \
                     ParameterKey=PrivateSubnet2Id,ParameterValue=$private_subnet2_id \
                     ParameterKey=DatabaseSecurityGroupId,ParameterValue=$db_security_group_id \
                     ParameterKey=DatabasePassword,ParameterValue=$db_password"
    
    deploy_stack "$stack_name" "$template_file" "$parameters" "$region"
    
    print_success "Database infrastructure deployed"
}

# Function to deploy ElastiCache Redis
deploy_redis() {
    local environment=$1
    local region=$2
    
    print_status "Deploying ElastiCache Redis..."
    
    # Get network outputs
    local vpc_id=$(get_stack_output "$STACK_PREFIX-network" "VpcId" "$region")
    local private_subnet1_id=$(get_stack_output "$STACK_PREFIX-network" "PrivateSubnet1Id" "$region")
    local private_subnet2_id=$(get_stack_output "$STACK_PREFIX-network" "PrivateSubnet2Id" "$region")
    local redis_security_group_id=$(get_stack_output "$STACK_PREFIX-network" "RedisSecurityGroupId" "$region")
    
    # Create Redis subnet group
    aws elasticache create-cache-subnet-group \
        --cache-subnet-group-name "$environment-healthcare-redis-subnet-group" \
        --cache-subnet-group-description "Redis subnet group for healthcare platform" \
        --subnet-ids "$private_subnet1_id" "$private_subnet2_id" \
        --region "$region" || true
    
    # Create Redis cluster
    aws elasticache create-cache-cluster \
        --cache-cluster-id "$environment-healthcare-redis" \
        --engine redis \
        --cache-node-type cache.t3.micro \
        --num-cache-nodes 1 \
        --cache-subnet-group-name "$environment-healthcare-redis-subnet-group" \
        --security-group-ids "$redis_security_group_id" \
        --region "$region" || true
    
    print_success "ElastiCache Redis deployed"
}

# Function to deploy application infrastructure
deploy_application() {
    local environment=$1
    local region=$2
    local account_id=$3
    
    print_status "Deploying application infrastructure..."
    
    # Get network outputs
    local vpc_id=$(get_stack_output "$STACK_PREFIX-network" "VpcId" "$region")
    local public_subnet1_id=$(get_stack_output "$STACK_PREFIX-network" "PublicSubnet1Id" "$region")
    local public_subnet2_id=$(get_stack_output "$STACK_PREFIX-network" "PublicSubnet2Id" "$region")
    local private_subnet1_id=$(get_stack_output "$STACK_PREFIX-network" "PrivateSubnet1Id" "$region")
    local private_subnet2_id=$(get_stack_output "$STACK_PREFIX-network" "PrivateSubnet2Id" "$region")
    local alb_security_group_id=$(get_stack_output "$STACK_PREFIX-network" "ALBSecurityGroupId" "$region")
    local ecs_security_group_id=$(get_stack_output "$STACK_PREFIX-network" "ECSSecurityGroupId" "$region")
    
    # Get database outputs
    local database_endpoint=$(get_stack_output "$STACK_PREFIX-database" "DatabaseEndpoint" "$region")
    local database_name=$(get_stack_output "$STACK_PREFIX-database" "DatabaseName" "$region")
    
    # Get Redis endpoint
    local redis_endpoint=$(aws elasticache describe-cache-clusters \
        --cache-cluster-id "$environment-healthcare-redis" \
        --region "$region" \
        --query "CacheClusters[0].ConfigurationEndpoint.Address" \
        --output text)
    
    local ecr_repository_uri="$account_id.dkr.ecr.$region.amazonaws.com/healthcare-platform"
    
    local stack_name="$STACK_PREFIX-application"
    local template_file="$PROJECT_ROOT/infrastructure/ecs.yml"
    local parameters="ParameterKey=Environment,ParameterValue=$environment \
                     ParameterKey=VpcId,ParameterValue=$vpc_id \
                     ParameterKey=PublicSubnet1Id,ParameterValue=$public_subnet1_id \
                     ParameterKey=PublicSubnet2Id,ParameterValue=$public_subnet2_id \
                     ParameterKey=PrivateSubnet1Id,ParameterValue=$private_subnet1_id \
                     ParameterKey=PrivateSubnet2Id,ParameterValue=$private_subnet2_id \
                     ParameterKey=ALBSecurityGroupId,ParameterValue=$alb_security_group_id \
                     ParameterKey=ECSSecurityGroupId,ParameterValue=$ecs_security_group_id \
                     ParameterKey=DatabaseEndpoint,ParameterValue=$database_endpoint \
                     ParameterKey=DatabaseName,ParameterValue=$database_name \
                     ParameterKey=RedisEndpoint,ParameterValue=$redis_endpoint \
                     ParameterKey=ECRRepositoryUri,ParameterValue=$ecr_repository_uri"
    
    deploy_stack "$stack_name" "$template_file" "$parameters" "$region"
    
    print_success "Application infrastructure deployed"
}

# Function to create S3 bucket for file storage
create_s3_bucket() {
    local environment=$1
    local region=$2
    local account_id=$3
    
    print_status "Creating S3 bucket for file storage..."
    
    local bucket_name="$environment-healthcare-records-$account_id"
    
    # Create bucket
    aws s3 mb "s3://$bucket_name" --region "$region" || true
    
    # Enable versioning
    aws s3api put-bucket-versioning \
        --bucket "$bucket_name" \
        --versioning-configuration Status=Enabled \
        --region "$region"
    
    # Enable encryption
    aws s3api put-bucket-encryption \
        --bucket "$bucket_name" \
        --server-side-encryption-configuration '{
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }
            ]
        }' \
        --region "$region"
    
    # Block public access
    aws s3api put-public-access-block \
        --bucket "$bucket_name" \
        --public-access-block-configuration \
        BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
        --region "$region"
    
    print_success "S3 bucket created: $bucket_name"
}

# Function to initialize database
initialize_database() {
    local environment=$1
    local region=$2
    
    print_status "Initializing database..."
    
    # Get ALB DNS name
    local alb_dns=$(get_stack_output "$STACK_PREFIX-application" "ALBDNSName" "$region")
    
    # Wait for ALB to be ready
    print_status "Waiting for Application Load Balancer to be ready..."
    sleep 30
    
    # Create admin user
    print_status "Creating admin user..."
    curl -X POST "http://$alb_dns/api/auth/register" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "admin",
            "email": "admin@healthcare.com",
            "password": "Admin123!",
            "first_name": "System",
            "last_name": "Administrator",
            "role": "admin"
        }' || print_warning "Admin user creation failed (may already exist)"
    
    # Create sample users
    print_status "Creating sample users..."
    local users=(
        '{"username":"doctor","email":"doctor@healthcare.com","password":"Doctor123!","first_name":"John","last_name":"Smith","role":"doctor"}'
        '{"username":"nurse","email":"nurse@healthcare.com","password":"Nurse123!","first_name":"Jane","last_name":"Doe","role":"nurse"}'
        '{"username":"clerk","email":"clerk@healthcare.com","password":"Clerk123!","first_name":"Bob","last_name":"Johnson","role":"clerk"}'
        '{"username":"patient","email":"patient@healthcare.com","password":"Patient123!","first_name":"Alice","last_name":"Brown","role":"patient"}'
    )
    
    for user in "${users[@]}"; do
        curl -X POST "http://$alb_dns/api/auth/register" \
            -H "Content-Type: application/json" \
            -d "$user" || print_warning "User creation failed (may already exist)"
    done
    
    print_success "Database initialized successfully"
}

# Function to display deployment information
display_deployment_info() {
    local environment=$1
    local region=$2
    
    print_status "Deployment completed successfully!"
    echo
    echo "=== Healthcare Platform Deployment Information ==="
    echo "Environment: $environment"
    echo "Region: $region"
    echo
    
    # Get ALB DNS name
    local alb_dns=$(get_stack_output "$STACK_PREFIX-application" "ALBDNSName" "$region")
    echo "Application URL: http://$alb_dns"
    echo "Health Check: http://$alb_dns/api/health/health"
    echo "API Documentation: http://$alb_dns/api/docs"
    echo
    
    echo "=== Default Login Credentials ==="
    echo "Admin: admin@healthcare.com / Admin123!"
    echo "Doctor: doctor@healthcare.com / Doctor123!"
    echo "Nurse: nurse@healthcare.com / Nurse123!"
    echo "Clerk: clerk@healthcare.com / Clerk123!"
    echo "Patient: patient@healthcare.com / Patient123!"
    echo
    
    echo "=== Load Testing ==="
    echo "Run load tests with: locust -f tests/locustfile.py --host=http://$alb_dns"
    echo "Access Locust UI: http://localhost:8089"
    echo
    
    echo "=== Monitoring ==="
    echo "CloudWatch Logs: /aws/ecs/$environment-healthcare"
    echo "CloudWatch Metrics: ECS service metrics"
    echo
    
    echo "=== Cleanup ==="
    echo "To delete all resources, run:"
    echo "aws cloudformation delete-stack --stack-name $STACK_PREFIX-application --region $region"
    echo "aws cloudformation delete-stack --stack-name $STACK_PREFIX-database --region $region"
    echo "aws cloudformation delete-stack --stack-name $STACK_PREFIX-network --region $region"
    echo
}

# Main deployment function
main() {
    local environment=${1:-$DEFAULT_ENVIRONMENT}
    local region=${2:-$DEFAULT_REGION}
    
    echo "🏥 Healthcare Platform AWS Deployment"
    echo "====================================="
    echo "Environment: $environment"
    echo "Region: $region"
    echo
    
    # Check prerequisites
    check_prerequisites
    
    # Get AWS account ID
    local account_id=$(get_aws_account_id)
    print_status "AWS Account ID: $account_id"
    
    # Build and push Docker image
    build_and_push_image "$environment" "$region" "$account_id"
    
    # Create secrets
    create_secrets "$environment" "$region"
    
    # Deploy infrastructure
    deploy_network "$environment" "$region"
    deploy_database "$environment" "$region"
    deploy_redis "$environment" "$region"
    deploy_application "$environment" "$region" "$account_id"
    
    # Create S3 bucket
    create_s3_bucket "$environment" "$region" "$account_id"
    
    # Initialize database
    initialize_database "$environment" "$region"
    
    # Display deployment information
    display_deployment_info "$environment" "$region"
    
    print_success "🎉 Healthcare Platform is now deployed and ready to use!"
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -r|--region)
                REGION="$2"
                shift 2
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  -e, --environment ENV    Environment (default: production)"
                echo "  -r, --region REGION      AWS region (default: us-east-1)"
                echo "  -h, --help               Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Run main deployment
    main "$ENVIRONMENT" "$REGION"
fi
