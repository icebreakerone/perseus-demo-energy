# Perseus Resource Service CDK Deployment

This directory contains the CDK deployment for the Perseus Resource Service, which provides an mTLS + OAuth secured data endpoint for retrieving energy data.

## Architecture

The deployment creates:

- **API Gateway** with mTLS authentication and custom domain
- **Lambda Function** running the FastAPI application
- **Lambda Authorizer** for certificate validation
- **S3 Bucket** for truststore storage
- **Route53** DNS records
- **IAM roles and policies** for secure access

## Prerequisites

1. AWS CLI configured with appropriate permissions
2. CDK CLI installed (`npm install -g aws-cdk`)
3. Python 3.12+
4. Dependencies installed: `pip install -r requirements.txt`

## Deployment

### Development Environment

```bash
cd resource/deployment
pip install -r requirements.txt
cdk deploy --context deployment_context=dev
```

### Production Environment

```bash
cd resource/deployment
pip install -r requirements.txt
cdk deploy --context deployment_context=prod
```

## Truststore Setup

Before deploying, you need to upload the truststore.pem file to the S3 bucket:

1. Deploy the stack first to create the S3 bucket
2. Upload your truststore.pem file to the bucket:
   ```bash
   aws s3 cp truststore.pem s3://perseus-resource-truststore-{env}-{account}/truststore.pem
   ```
3. Redeploy the stack to update the API Gateway mTLS configuration

## Environment Variables

The Lambda function is configured with the following environment variables:

- `LOG_LEVEL`: Logging level (info)
- `ISSUER_URL`: OAuth issuer URL
- `API_DOMAIN`: API domain name
- `ENV`: Environment name (dev/prod)
- `SIGNING_KEY`: SSM parameter path for signing key
- `SIGNING_ROOT_CA_CERTIFICATE`: S3 path to root CA certificate
- `SIGNING_BUNDLE`: S3 path to certificate bundle
- `AUTHENTICATION_SERVER`: Authentication server URL
- `AWS_DEFAULT_REGION`: AWS region

## Certificate Flow

1. Client presents mTLS certificate to API Gateway
2. API Gateway validates certificate against truststore
3. Lambda authorizer extracts certificate information
4. Certificate PEM is passed to FastAPI Lambda via headers
5. FastAPI application validates certificate and OAuth token
6. Energy data is returned with provenance records

## Testing

After deployment, test the endpoints:

- `GET /` - Root endpoint
- `GET /datasources` - List available data sources
- `GET /datasources/{id}/{measure}` - Get energy consumption data

## Cleanup

To destroy the stack:

```bash
cdk destroy --context deployment_context=dev
```

## Differences from Copilot Deployment

This CDK deployment provides:

- Serverless architecture (Lambda vs ECS)
- Pay-per-request pricing model
- Automatic scaling
- Simplified operational overhead
- Native AWS service integration
