# Healthcare Record Automation Platform (AWS-Native)

A production-ready **AWS-native healthcare platform** built with Flask, PostgreSQL, and comprehensive AWS services integration. Features **RBAC**, **HIPAA-aligned controls**, **audit logging**, **Docker containerization**, and **Infrastructure as Code** with CloudFormation.

> ⚠️ **HIPAA Compliance Note:** This platform includes controls aligned with HIPAA best practices (RBAC, audit logs, encryption, least-privilege, etc.) but **does not constitute legal compliance advice**. Complete a comprehensive compliance review before handling real PHI.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    AWS Cloud Infrastructure                 │
├─────────────────────────────────────────────────────────────┤
│  Route 53 → CloudFront → ALB → ECS Fargate → Flask API     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   RDS       │  │  ElastiCache │  │     S3      │        │
│  │ PostgreSQL  │  │    Redis    │  │ File Storage│        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  Secrets    │  │ CloudWatch  │  │   Lambda    │        │
│  │  Manager    │  │   Logs      │  │ Background  │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Features

### Core Platform
- **Flask API** with JWT authentication and RBAC (ADMIN, DOCTOR, NURSE, CLERK, PATIENT)
- **SQLAlchemy models**: `User`, `Patient`, `Record`, `AuditLog`, `Appointment`
- **HIPAA-aligned security**: Encryption at rest/transit, audit logging, access controls
- **Docker containerization** with ECS Fargate for serverless compute
- **Auto-scaling** based on CPU/memory utilization

### AWS Services Integration
- **RDS PostgreSQL** with Multi-AZ for high availability
- **ElastiCache Redis** for session management and caching
- **S3** with encryption for file storage and backups
- **Secrets Manager** for secure credential management
- **CloudWatch** for monitoring, logging, and alerting
- **Lambda** for background processing and automation
- **Route 53** with ACM for SSL/TLS termination
- **CloudFront** for global content delivery

### Infrastructure as Code
- **CloudFormation templates** for complete infrastructure deployment
- **VPC with public/private subnets** across multiple AZs
- **Application Load Balancer** with health checks
- **Auto Scaling Groups** for horizontal scaling
- **Security Groups** with least-privilege access

## 🏥 RBAC Matrix

| Endpoint | Method | Roles | Description |
|----------|--------|-------|-------------|
| `/auth/login` | POST | Public | User authentication |
| `/auth/register` | POST | Public | User registration |
| `/patients/` | POST | ADMIN, CLERK, DOCTOR, NURSE | Create patient |
| `/patients/{id}` | GET | ADMIN, CLERK, DOCTOR, NURSE | View patient |
| `/patients/{id}` | PUT | ADMIN, CLERK | Update patient |
| `/patients/search` | GET | ADMIN, CLERK, DOCTOR, NURSE | Search patients |
| `/records/` | POST | ADMIN, DOCTOR, NURSE | Create medical record |
| `/records/patient/{id}` | GET | ADMIN, DOCTOR, NURSE | View patient records |
| `/audit/logs` | GET | ADMIN | View audit logs |
| `/users/` | GET | ADMIN | User management |

## 🛡️ HIPAA-Aligned Controls

### Access Control
- **JWT authentication** with role-based access control
- **Least-privilege principle** implemented at API level
- **Session management** with Redis and secure token handling

### Data Protection
- **Encryption at rest**: RDS encryption, S3 server-side encryption
- **Encryption in transit**: TLS 1.3 termination at ALB
- **Field-level encryption** for sensitive patient data
- **Secure credential storage** in AWS Secrets Manager

### Audit & Compliance
- **Comprehensive audit logging** for all data access and modifications
- **CloudWatch Logs** with structured logging and retention policies
- **Security monitoring** with CloudWatch alarms and SNS notifications
- **Compliance reporting** with automated audit trail generation

### Backup & Disaster Recovery
- **Automated RDS backups** with point-in-time recovery
- **Multi-AZ deployment** for high availability
- **S3 cross-region replication** for data redundancy
- **Automated failover** with Route 53 health checks

## 🚀 Quick Start

### Local Development
```bash
# Clone repository
git clone <repository-url>
cd Healthcare

# Setup environment
cp env.example .env
# Edit .env with your configuration

# Start local development
docker-compose up --build

# Access services
# API: http://localhost:5000
# Health Check: http://localhost:5000/api/health/health
```

### AWS Deployment

#### Prerequisites
- AWS CLI configured with appropriate permissions
- Docker installed and configured
- jq for JSON parsing

#### 1. Build and Push Docker Image
```bash
# Build image
docker build -t healthcare-platform .

# Tag for ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com
docker tag healthcare-platform:latest $AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/healthcare-platform:latest
docker push $AWS_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/healthcare-platform:latest
```

#### 2. Deploy Infrastructure
```bash
# Deploy network infrastructure
aws cloudformation deploy \
  --template-file infrastructure/network.yml \
  --stack-name healthcare-network \
  --capabilities CAPABILITY_IAM

# Deploy database
aws cloudformation deploy \
  --template-file infrastructure/rds.yml \
  --stack-name healthcare-database \
  --parameter-overrides \
    VpcId=$(aws cloudformation describe-stacks --stack-name healthcare-network --query 'Stacks[0].Outputs[?OutputKey==`VpcId`].OutputValue' --output text)

# Deploy application
aws cloudformation deploy \
  --template-file infrastructure/ecs.yml \
  --stack-name healthcare-application \
  --parameter-overrides \
    VpcId=$(aws cloudformation describe-stacks --stack-name healthcare-network --query 'Stacks[0].Outputs[?OutputKey==`VpcId`].OutputValue' --output text) \
    DatabaseEndpoint=$(aws cloudformation describe-stacks --stack-name healthcare-database --query 'Stacks[0].Outputs[?OutputKey==`DatabaseEndpoint`].OutputValue' --output text)
```

#### 3. Initialize Database
```bash
# Get ALB DNS name
ALB_DNS=$(aws cloudformation describe-stacks --stack-name healthcare-application --query 'Stacks[0].Outputs[?OutputKey==`ALBDNSName`].OutputValue' --output text)

# Initialize database (replace with your admin credentials)
curl -X POST http://$ALB_DNS/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@healthcare.com",
    "password": "secure_password_123",
    "first_name": "Admin",
    "last_name": "User",
    "role": "admin"
  }'
```

## 📊 Monitoring & Observability

### CloudWatch Dashboards
- **Application Metrics**: Request count, response time, error rate
- **Infrastructure Metrics**: CPU, memory, disk usage
- **Database Metrics**: Connections, query performance, storage
- **Security Metrics**: Failed logins, suspicious activities

### Alerts & Notifications
- **High CPU/Memory usage** → SNS notification
- **Database connection limits** → PagerDuty/Slack
- **Failed authentication attempts** → Security team
- **Application errors** → Development team

### Logging
- **Structured logging** with correlation IDs
- **Centralized log aggregation** in CloudWatch
- **Log retention policies** for compliance
- **Real-time log analysis** with CloudWatch Insights

## 🔧 Configuration Management

### Environment Variables
```bash
# Application
FLASK_ENV=production
SECRET_KEY=<from-secrets-manager>
JWT_SECRET_KEY=<from-secrets-manager>

# Database
DATABASE_URL=<rds-endpoint>
REDIS_URL=<elasticache-endpoint>

# AWS Services
AWS_REGION=us-east-1
AWS_S3_BUCKET=<bucket-name>
AWS_SECRETS_ARN=<secrets-arn>

# Security
ENCRYPTION_KEY=<from-secrets-manager>
BCRYPT_LOG_ROUNDS=12
```

### Secrets Management
```bash
# Store secrets in AWS Secrets Manager
aws secretsmanager create-secret \
  --name healthcare/production/database \
  --secret-string '{"username":"admin","password":"secure_password"}'

# Retrieve in application
aws secretsmanager get-secret-value --secret-id healthcare/production/database
```

## 🧪 Testing

### Load Testing
```bash
# Install Locust
pip install locust

# Run load test
locust -f tests/locustfile.py --host=http://localhost:5000

# Access Locust UI: http://localhost:8089
```

### Unit Tests
```bash
# Run tests
pytest tests/

# With coverage
pytest --cov=app tests/

# Security tests
bandit -r app/
```

## 📈 Scaling & Performance

### Auto Scaling
- **CPU-based scaling**: Scale up at 70% CPU utilization
- **Memory-based scaling**: Scale up at 80% memory usage
- **Request-based scaling**: Scale based on ALB request count
- **Scheduled scaling**: Scale down during off-hours

### Performance Optimization
- **Redis caching** for frequently accessed data
- **Database connection pooling** with SQLAlchemy
- **CDN caching** with CloudFront
- **Database read replicas** for read-heavy workloads

## 🔒 Security Best Practices

### Network Security
- **VPC with private subnets** for database and application
- **Security groups** with minimal required access
- **NACLs** for additional network layer protection
- **VPC Flow Logs** for network traffic monitoring

### Application Security
- **Input validation** and sanitization
- **SQL injection prevention** with parameterized queries
- **XSS protection** with proper output encoding
- **CSRF protection** with token validation

### Infrastructure Security
- **IAM roles** with least-privilege access
- **KMS encryption** for sensitive data
- **VPC endpoints** for AWS service access
- **Security Hub** integration for compliance monitoring

## 🚀 Production Deployment Checklist

- [ ] **Infrastructure**: Deploy all CloudFormation stacks
- [ ] **Security**: Configure WAF, security groups, IAM roles
- [ ] **Monitoring**: Set up CloudWatch dashboards and alerts
- [ ] **Backup**: Enable RDS backups and S3 replication
- [ ] **SSL**: Configure ACM certificate and HTTPS
- [ ] **DNS**: Set up Route 53 with health checks
- [ ] **Secrets**: Store all credentials in Secrets Manager
- [ ] **Logging**: Configure structured logging and retention
- [ ] **Testing**: Run load tests and security scans
- [ ] **Documentation**: Update runbooks and procedures

## 📚 API Documentation

### Authentication
```bash
# Login
POST /api/auth/login
{
  "username": "doctor@healthcare.com",
  "password": "password123"
}

# Response
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "user": {...}
}
```

### Patient Management
```bash
# Create patient (requires DOCTOR role)
POST /api/patients/
Authorization: Bearer <token>
{
  "first_name": "John",
  "last_name": "Doe",
  "date_of_birth": "1980-01-01",
  "gender": "Male",
  "phone": "+1-555-0123",
  "email": "john.doe@email.com"
}

# Get patient
GET /api/patients/1
Authorization: Bearer <token>
```

### Medical Records
```bash
# Create record
POST /api/records/
Authorization: Bearer <token>
{
  "patient_id": 1,
  "record_type": "consultation",
  "title": "Annual Checkup",
  "content": "Patient presents for annual checkup..."
}

# Get patient records
GET /api/records/?patient_id=1
Authorization: Bearer <token>
```

## 🔄 Version History

- **v1.0.0** - Initial release with core functionality
- **v1.1.0** - Added automated record processing
- **v1.2.0** - Enhanced security features and HIPAA controls
- **v1.3.0** - AWS integration and cloud deployment
- **v1.4.0** - Auto-scaling and performance optimization
- **v1.5.0** - Advanced monitoring and observability

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check the `/docs` directory
- **Issues**: Create an issue in the repository
- **Security**: Report security issues to security@healthcare.com
- **Compliance**: Contact compliance@healthcare.com for HIPAA questions
