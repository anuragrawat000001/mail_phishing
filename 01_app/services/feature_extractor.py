import re
import asyncio
from typing import Dict, Any, List
from urllib.parse import urlparse
import email.utils
import dns.resolver
import logging

logger = logging.getLogger(__name__)

class FeatureExtractor:
    def __init__(self):
        # Phishing keywords
        self.urgent_keywords = [
            'urgent', 'immediate', 'expires', 'suspended', 'verify',
            'click here', 'act now', 'limited time', 'confirm', 'update'
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.bit', '.onion'
        ]
    
    async def extract_all_features(self, sender: str, subject: str, body: str,
                                 headers: Dict[str, str], links: List[str]) -> Dict[str, Any]:
        """Extract all phishing detection features"""
        features = {}
        
        # Run feature extraction tasks concurrently
        tasks = [
            self._extract_sender_features(sender, headers),
            self._extract_subject_features(subject),
            self._extract_body_features(body),
            self._extract_link_features(links),
            self._extract_header_features(headers)
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Combine all features
        for result in results:
            features.update(result)
        
        return features
    
    async def _extract_sender_features(self, sender: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Extract sender-related features"""
        features = {}
        
        try:
            # Parse sender email
            parsed_sender = email.utils.parseaddr(sender)
            sender_domain = parsed_sender[1].split('@')[-1] if '@' in parsed_sender[1] else ''
            
            features['sender_domain'] = sender_domain
            features['sender_name'] = parsed_sender[0]
            
            # Check for spoofing indicators
            features['spoofed_sender'] = self._check_sender_spoofing(sender, headers)
            
            # Check domain reputation (simplified)
            features['suspicious_domain'] = any(tld in sender_domain for tld in self.suspicious_tlds)
            
            # Check if external sender
            features['external_sender'] = not self._is_internal_domain(sender_domain)
            
        except Exception as e:
            logger.warning(f"Sender feature extraction error: {e}")
            features.update({
                'sender_domain': '',
                'sender_name': '',
                'spoofed_sender': False,
                'suspicious_domain': False,
                'external_sender': True
            })
        
        return features
    
    async def _extract_subject_features(self, subject: str) -> Dict[str, Any]:
        """Extract subject line features"""
        features = {}
        
        # Check for urgent language
        features['urgent_language'] = any(
            keyword.lower() in subject.lower() 
            for keyword in self.urgent_keywords
        )
        
        # Check for excessive punctuation
        features['excessive_punctuation'] = len(re.findall(r'[!?]{2,}', subject)) > 0
        
        # Check for all caps
        features['all_caps_subject'] = subject.isupper() and len(subject) > 10
        
        # Subject length
        features['subject_length'] = len(subject)
        
        return features
    
    async def _extract_body_features(self, body: str) -> Dict[str, Any]:
        """Extract email body features"""
        features = {}
        
        # Text analysis
        features['body_length'] = len(body)
        features['word_count'] = len(body.split())
        
        # Check for urgent language in body
        features['urgent_body_language'] = any(
            keyword.lower() in body.lower() 
            for keyword in self.urgent_keywords
        )
        
        # Check for typos/grammar issues (simplified)
        features['typos_count'] = self._count_potential_typos(body)
        
        # Check for suspicious patterns
        features['has_forms'] = bool(re.search(r'<form|<input', body, re.IGNORECASE))
        features['has_scripts'] = bool(re.search(r'<script', body, re.IGNORECASE))
        
        # Check for personal information requests
        features['requests_personal_info'] = self._check_personal_info_requests(body)
        
        return features
    
    async def _extract_link_features(self, links: List[str]) -> Dict[str, Any]:
        """Extract link-related features"""
        features = {}
        
        features['link_count'] = len(links)
        features['suspicious_links'] = 0
        features['shortened_links'] = 0
        features['external_links'] = 0
        
        for link in links:
            try:
                parsed = urlparse(link)
                domain = parsed.netloc.lower()
                
                # Check for suspicious domains
                if any(tld in domain for tld in self.suspicious_tlds):
                    features['suspicious_links'] += 1
                
                # Check for URL shorteners
                if self._is_url_shortener(domain):
                    features['shortened_links'] += 1
                
                # Check for external links
                if not self._is_internal_domain(domain):
                    features['external_links'] += 1
                    
            except Exception as e:
                logger.warning(f"Link analysis error for {link}: {e}")
                features['suspicious_links'] += 1
        
        return features
    
    async def _extract_header_features(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Extract email header features"""
        features = {}
        
        # Security headers
        security_headers = ['dkim-signature', 'spf', 'dmarc', 'arc-authentication-results']
        features['missing_security_headers'] = sum(
            1 for header in security_headers 
            if header.lower() not in [h.lower() for h in headers.keys()]
        )
        
        # Check for suspicious routing
        received_headers = [v for k, v in headers.items() if k.lower() == 'received']
        features['hop_count'] = len(received_headers)
        features['suspicious_routing'] = self._check_suspicious_routing(received_headers)
        
        return features
    
    def _check_sender_spoofing(self, sender: str, headers: Dict[str, str]) -> bool:
        """Check for sender spoofing indicators"""
        # Check if Return-Path differs from From header
        return_path = headers.get('Return-Path', '').strip('<>')
        from_header = headers.get('From', '')
        
        if return_path and from_header:
            return return_path.lower() != sender.lower()
        
        return False
    
    def _is_internal_domain(self, domain: str) -> bool:
        """Check if domain is internal (customize for your organization)"""
        internal_domains = ['yourcompany.com', 'localhost']
        return any(internal in domain for internal in internal_domains)
    
    def _is_url_shortener(self, domain: str) -> bool:
        """Check if domain is a URL shortener"""
        shorteners = [
            'bit.ly', 'tinyurl.com', 'short.link', 't.co', 'goo.gl',
            'ow.ly', 'is.gd', 'buff.ly', 'adf.ly'
        ]
        return domain in shorteners
    
    def _count_potential_typos(self, text: str) -> int:
        """Simple typo detection (can be enhanced)"""
        # Look for repeated characters, unusual patterns
        typo_patterns = [
            r'(.)\1{2,}',  # Repeated characters
            r'\b\w*[0-9]+\w*\b',  # Numbers in words
            r'\b[a-z]*[A-Z]+[a-z]*\b'  # Mixed case in middle of words
        ]
        
        count = 0
        for pattern in typo_patterns:
            count += len(re.findall(pattern, text))
        
        return count
    
    def _check_personal_info_requests(self, body: str) -> bool:
        """Check if email requests personal information"""
        patterns = [
            r'social security', r'ssn', r'credit card', r'password',
            r'bank account', r'pin', r'verification code', r'login'
        ]
        
        return any(re.search(pattern, body, re.IGNORECASE) for pattern in patterns)
    
    def _check_suspicious_routing(self, received_headers: List[str]) -> bool:
        """Check for suspicious email routing"""
        # Look for unusual routing patterns
        if len(received_headers) > 10:  # Too many hops
            return True
        
        # Check for suspicious server names in routing
        suspicious_keywords = ['temp', 'fake', 'test', 'spam']
        for header in received_headers:
            if any(keyword in header.lower() for keyword in suspicious_keywords):
                return True
        
        return False
    
    def get_feature_list(self) -> List[str]:
        """Return list of all extractable features"""
        return [
            'sender_domain', 'sender_name', 'spoofed_sender', 'suspicious_domain',
            'external_sender', 'urgent_language', 'excessive_punctuation',
            'all_caps_subject', 'subject_length', 'body_length', 'word_count',
            'urgent_body_language', 'typos_count', 'has_forms', 'has_scripts',
            'requests_personal_info', 'link_count', 'suspicious_links',
            'shortened_links', 'external_links', 'missing_security_headers',
            'hop_count', 'suspicious_routing'
        ]