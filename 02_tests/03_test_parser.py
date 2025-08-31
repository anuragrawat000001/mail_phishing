import pytest
import io
from unittest.mock import Mock
from app.utils.email_parser import EmailParser

class TestEmailParser:
    
    @pytest.fixture
    def parser(self):
        return EmailParser()
    
    def test_parse_eml(self, parser):
        eml_content = """From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 1 Sep 2025 12:00:00 +0000

This is a test email body with a link: https://example.com"""
        
        result = parser.parse_eml(eml_content)
        
        assert result["sender"] == "sender@example.com"
        assert result["subject"] == "Test Email"
        assert "test email body" in result["body"].lower()
        assert "https://example.com" in result["links"]
        assert isinstance(result["headers"], dict)
    
    def test_parse_multipart_email(self, parser):
        eml_content = """From: sender@example.com
Subject: Multipart Test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

This is the plain text part.

--boundary123
Content-Type: text/html

<html><body>This is the HTML part with <a href="https://test.com">a link</a>.</body></html>

--boundary123--"""
        
        result = parser.parse_eml(eml_content)
        
        assert "plain text part" in result["body"]
        assert "HTML part" in result["body"]
        assert any("https://test.com" in link for link in result["links"])
    
    def test_extract_links(self, parser):
        body = """Check out these links:
        - https://example.com/page
        - http://test.org/path?param=value
        - <a href="https://link.com">Click here</a>
        - Visit http://another-site.net"""
        
        links = parser._extract_links(body)
        
        assert "https://example.com/page" in links
        assert "http://test.org/path?param=value" in links
        assert "https://link.com" in links
        assert "http://another-site.net" in links
    
    def test_strip_html(self, parser):
        html_content = "<html><body><p>Hello <b>World</b>!</p></body></html>"
        result = parser._strip_html(html_content)
        assert result == "Hello World!"
    
    @pytest.mark.asyncio
    async def test_parse_file_eml(self, parser):
        eml_content = """From: test@example.com
Subject: Test
        
Test body"""
        
        mock_file = Mock()
        mock_file.filename = "test.eml"
        mock_file.read.return_value = eml_content.encode()
        
        result = await parser.parse_file(mock_file)
        
        assert result["sender"] == "test@example.com"
        assert result["subject"] == "Test"
    
    @pytest.mark.asyncio
    async def test_parse_file_json(self, parser):
        json_content = {
            "sender": "test@example.com",
            "subject": "JSON Test",
            "body": "Test body",
            "headers": {},
            "links": []
        }
        
        mock_file = Mock()
        mock_file.filename = "test.json"
        mock_file.read.return_value = str(json_content).replace("'", '"').encode()
        
        result = await parser.parse_file(mock_file)
        
        assert result["sender"] == "test@example.com"
        assert result["subject"] == "JSON Test"
    
    def test_parse_text_email(self, parser):
        text_content = """From: sender@example.com
Subject: Plain Text Email

This is the email body.
It has multiple lines.
And a link: https://example.com"""
        
        result = parser._parse_text_email(text_content)
        
        assert result["sender"] == "sender@example.com"
        assert result["subject"] == "Plain Text Email"
        assert "multiple lines" in result["body"]
        assert "https://example.com" in result["links"]