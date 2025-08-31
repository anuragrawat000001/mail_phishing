import email
import json
from typing import Dict, Any
from fastapi import UploadFile
import logging
import re

logger = logging.getLogger(__name__)

class EmailParser:
    def __init__(self):
        pass
    
    async def parse_file(self, file: UploadFile) -> Dict[str, Any]:
        """Parse uploaded email file"""
        content = await file.read()
        
        if file.filename.endswith('.eml'):
            return self.parse_eml(content.decode('utf-8', errors='ignore'))
        elif file.filename.endswith('.json'):
            return json.loads(content.decode('utf-8'))
        else:
            # Try to parse as raw email
            return self.parse_raw_email(content.decode('utf-8', errors='ignore'))
    
    def parse_eml(self, eml_content: str) -> Dict[str, Any]:
        """Parse EML format email"""
        try:
            msg = email.message_from_string(eml_content)
            
            # Extract basic fields
            sender = msg.get('From', '')
            subject = msg.get('Subject', '')
            
            # Extract body
            body = self._extract_body(msg)
            
            # Extract headers
            headers = dict(msg.items())
            
            # Extract links
            links = self._extract_links(body)
            
            return {
                'sender': sender,
                'subject': subject,
                'body': body,
                'headers': headers,
                'links': links
            }
            
        except Exception as e:
            logger.error(f"EML parsing error: {e}")
            raise ValueError(f"Failed to parse EML file: {e}")
    
    def parse_raw_email(self, raw_content: str) -> Dict[str, Any]:
        """Parse raw email content"""
        try:
            # Try to parse as email message
            msg = email.message_from_string(raw_content)
            return self.parse_eml(raw_content)
            
        except Exception:
            # If email parsing fails, try to extract basic info
            return self._parse_text_email(raw_content)
    
    def _extract_body(self, msg) -> str:
        """Extract email body from message object"""
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                elif part.get_content_type() == "text/html":
                    # Strip HTML tags for analysis
                    html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    body += self._strip_html(html_content)
        else:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        
        return body
    
    def _extract_links(self, body: str) -> list:
        """Extract links from email body"""
        # Find URLs in text
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        links = re.findall(url_pattern, body)
        
        # Find HTML links
        html_link_pattern = r'href=["\']([^"\']+)["\']'
        html_links = re.findall(html_link_pattern, body, re.IGNORECASE)
        
        return list(set(links + html_links))
    
    def _strip_html(self, html_content: str) -> str:
        """Strip HTML tags from content"""
        clean = re.compile('<.*?>')
        return re.sub(clean, '', html_content)
    
    def _parse_text_email(self, content: str) -> Dict[str, Any]:
        """Parse plain text email content"""
        lines = content.split('\n')
        
        sender = ""
        subject = ""
        body_lines = []
        in_body = False
        
        for line in lines:
            line = line.strip()
            
            if line.lower().startswith('from:'):
                sender = line[5:].strip()
            elif line.lower().startswith('subject:'):
                subject = line[8:].strip()
            elif line == "" and not in_body:
                in_body = True
            elif in_body:
                body_lines.append(line)
        
        body = '\n'.join(body_lines)
        links = self._extract_links(body)
        
        return {
            'sender': sender,
            'subject': subject,
            'body': body,
            'headers': {},
            'links': links
        }