# mail_phishing
# Email Phishing Detection Backend

A robust, AI-powered email phishing detection system built with FastAPI and machine learning. This backend service provides comprehensive email analysis capabilities and can be easily integrated with GitHub workflows.

## 🚀 Features

- **Real-time Email Analysis**: Analyze emails for phishing indicators using ML and rule-based detection
- **Multiple Input Formats**: Support for EML files, JSON, and raw email content
- **Comprehensive Feature Extraction**: 20+ phishing detection features including:
  - Header analysis and sender verification
  - URL and link analysis
  - Content pattern recognition
  - Linguistic analysis for urgent/suspicious language
- **RESTful API**: Clean, documented API endpoints
- **GitHub Integration Ready**: Structured for easy CI/CD integration
- **Extensible Architecture**: Modular design for easy customization

## 📁 Project Structure

```
phishing_detector_backend/
│
├── app/
│   ├── main.py              # FastAPI application entry point
│   ├── api/
│   │   └── routes.py        # API endpoints
│   ├── services/
│   │   ├── analyzer.py      # Core phishing detection logic
│   │   ├── feature_extractor.py # Feature extraction engine
│   │   └── model.py         # ML model service
│   ├── utils/
│   │   ├── email_parser.py  # Email parsing utilities
│   │   └── validators.py    # Input validation
│   └── __init__.py
│
├── tests/
│   ├── test_api.py          # API endpoint tests
│   ├── test_analyzer.py     # Analysis logic tests
│   └── test_parser.py       # Parser tests
│
├── models/
│   ├── phishing_model.pkl   # Trained ML model
│   └── train_model.py       # Model training script
│
├── requirements.txt
└── README.md
```

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd phishing_detector_backend
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Train the model (optional)**
   ```bash
   python models/train_model.py
   ```

## 🚀 Usage

### Starting the Server

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`

### API Documentation

Visit `http://localhost:8000/docs` for interactive API documentation (Swagger UI)

## 📡 API Endpoints

### Analyze Email (JSON)
```http
POST /api/v1/analyze/email
Content-Type: application/json

{
  "sender": "suspicious@example.com",
  "subject": "URGENT: Verify your account",
  "body": "Click here to verify: http://fake-site.com",
  "headers": {},
  "links": ["http://fake-site.com"]
}
```

### Analyze Email File
```http
POST /api/v1/analyze/file
Content-Type: multipart/form-data

file: [upload .eml, .msg, or .json file]
```

### Analyze Raw Email
```http
POST /api/v1/analyze/raw
Content-Type: text/plain

From: sender@example.com
Subject: Test Email

Email body content...
```

### Response Format
```json
{
  "is_phishing": true,
  "confidence": 0.85,
  "risk_score": 0.78,
  "features": {
    "urgent_language": true,
    "suspicious_links": 1,
    "spoofed_sender": false,
    ...
  },
  "explanation": "This email is likely phishing (confidence: 85%)",
  "recommendations": [
    "Do not click any links in this email",
    "Report this email to your IT security team"
  ]
}
```

## 🧪 Testing

Run the test suite:

```bash
pytest tests/ -v
```

Run specific tests:
```bash
pytest tests/test_api.py -v
pytest tests/test_analyzer.py -v
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file for environment-specific configuration:

```env
# Model settings
MODEL_PATH=models/phishing_model.pkl
MODEL_THRESHOLD=0.5

# API settings
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=false

# Security
SECRET_KEY=your-secret-key-here
ALLOWED_HOSTS=localhost,127.0.0.1

# Rate limiting
REQUESTS_PER_MINUTE=100
```

## 🐳 Docker Deployment

Create a `Dockerfile`:

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Build and run:
```bash
docker build -t phishing-detector .
docker run -p 8000:8000 phishing-detector
```

## 🔄 GitHub Integration

### GitHub Actions Workflow

Create `.github/workflows/ci.yml`:

```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    
    - name: Run tests
      run: |
        pytest tests/ -v
    
    - name: Run linting
      run: |
        flake8 app/
```

## 🎯 Performance & Monitoring

### Metrics Endpoint

Monitor system health:
```http
GET /health
```

### Logging

The system uses structured logging. Logs include:
- Request processing times
- Model prediction confidence
- Error tracking
- Feature extraction metrics

## 🔒 Security Considerations

- **Input Validation**: All inputs are validated before processing
- **File Size Limits**: Upload limits prevent DoS attacks
- **Rate Limiting**: Configurable request rate limiting
- **Sanitization**: Email content is sanitized before analysis
- **No Data Persistence**: Emails are not stored after analysis

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:
- Create an issue in the GitHub repository
- Check the API documentation at `/docs`
- Review the test files for usage examples

## 🚧 Roadmap

- [ ] Advanced ML model with deep learning
- [ ] Real-time threat intelligence integration
- [ ] Batch email processing
- [ ] Advanced reporting and analytics
- [ ] Multi-language support
- [ ] Integration with popular email clients
    