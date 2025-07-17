# community/services/content_safety.py
import re
import logging
from typing import Dict, List, Tuple
from django.conf import settings

logger = logging.getLogger(__name__)

class ContentSafetyService:
    """Service for detecting potentially unsafe content in community posts."""
    
    # Common PHI patterns (simplified for example)
    PHI_PATTERNS = [
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
        r'\b\d{10,}\b',  # Long number sequences (could be medical record numbers)
        r'\b[A-Z]{2}\d{8}\b',  # State ID patterns
        r'\b\d{1,2}\/\d{1,2}\/\d{4}\b',  # Date patterns (birth dates)
        r'\b\d{3}\.\d{3}\.\d{4}\b',  # Phone number patterns
        r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',  # Email patterns
    ]
    
    # Sensitive health terms that require warnings
    SENSITIVE_HEALTH_TERMS = [
        'suicide', 'self-harm', 'overdose', 'medication names', 'dosage',
        'specific test results', 'genetic markers', 'mental health crisis'
    ]
    
    @classmethod
    def analyze_content(cls, content: str) -> Dict:
        """
        Analyze content for potential PHI and sensitive information.
        
        Returns:
            dict: Analysis results with flags and recommendations
        """
        result = {
            'contains_potential_phi': False,
            'contains_sensitive_content': False,
            'requires_content_warning': False,
            'detected_patterns': [],
            'recommendations': [],
            'risk_level': 'LOW'
        }
        
        # Check for potential PHI patterns
        phi_detected = cls._check_phi_patterns(content)
        if phi_detected:
            result['contains_potential_phi'] = True
            result['detected_patterns'].extend(phi_detected)
            result['risk_level'] = 'HIGH'
            result['recommendations'].append(
                "Content may contain PHI. Please review and remove any personal identifiers."
            )
        
        # Check for sensitive health terms
        sensitive_detected = cls._check_sensitive_terms(content)
        if sensitive_detected:
            result['contains_sensitive_content'] = True
            result['requires_content_warning'] = True
            result['detected_patterns'].extend(sensitive_detected)
            if result['risk_level'] == 'LOW':
                result['risk_level'] = 'MEDIUM'
            result['recommendations'].append(
                "Content contains sensitive health information. Consider adding content warning."
            )
        
        return result
    
    @classmethod
    def _check_phi_patterns(cls, content: str) -> List[str]:
        """Check for potential PHI patterns in content."""
        detected = []
        
        for pattern in cls.PHI_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                detected.append(f"Potential PHI pattern: {pattern}")
        
        return detected
    
    @classmethod
    def _check_sensitive_terms(cls, content: str) -> List[str]:
        """Check for sensitive health terms."""
        detected = []
        content_lower = content.lower()
        
        for term in cls.SENSITIVE_HEALTH_TERMS:
            if term in content_lower:
                detected.append(f"Sensitive term: {term}")
        
        return detected
    
    @classmethod
    def suggest_content_warning(cls, content: str) -> str:
        """Suggest appropriate content warning text."""
        content_lower = content.lower()
        
        if any(term in content_lower for term in ['suicide', 'self-harm']):
            return "Content Warning: Discussion of self-harm. Please contact emergency services if you are in crisis."
        elif any(term in content_lower for term in ['medication', 'dosage', 'treatment']):
            return "Medical Disclaimer: This is shared experience, not medical advice. Consult your healthcare provider."
        elif any(term in content_lower for term in ['test results', 'diagnosis']):
            return "Personal Medical Information: Individual experiences may vary. Consult your healthcare provider."
        else:
            return "Content may contain sensitive health information."
    
    @classmethod
    def auto_moderate_content(cls, content: str) -> Tuple[bool, str]:
        """
        Determine if content should be auto-moderated.
        
        Returns:
            tuple: (should_moderate, reason)
        """
        analysis = cls.analyze_content(content)
        
        if analysis['contains_potential_phi']:
            return True, "Content contains potential PHI and requires review"
        
        # Add more auto-moderation rules as needed
        spam_indicators = ['click here', 'buy now', 'miracle cure', 'guaranteed results']
        if any(indicator in content.lower() for indicator in spam_indicators):
            return True, "Content flagged as potential spam"
        
        return False, ""