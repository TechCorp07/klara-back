# healthcare/services/genetic_analysis_service.py
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db.models import Count, Q

from ..models import FamilyHistory, GeneticAnalysis, GeneticRiskFactor

User = get_user_model()
logger = logging.getLogger(__name__)


class GeneticAnalysisService:
    """Service for generating genetic analysis from family history data."""
    
    # Define rare disease patterns and their genetic characteristics
    RARE_DISEASE_PATTERNS = {
        'cancer': {
            'keywords': ['cancer', 'carcinoma', 'tumor', 'malignancy', 'oncology'],
            'inheritance': 'autosomal_dominant',
            'genes': ['BRCA1', 'BRCA2', 'TP53', 'MLH1', 'MSH2'],
            'risk_multiplier': 2.0,
            'screening': ['Regular cancer screening', 'Genetic counseling', 'MRI screening'],
        },
        'neurological': {
            'keywords': ['alzheimer', 'parkinson', 'huntington', 'neuropathy', 'dementia'],
            'inheritance': 'complex',
            'genes': ['APP', 'PSEN1', 'PSEN2', 'APOE'],
            'risk_multiplier': 1.8,
            'screening': ['Neurological assessment', 'Cognitive testing', 'MRI monitoring'],
        },
        'cardiac': {
            'keywords': ['heart', 'cardiac', 'cardiomyopathy', 'arrhythmia', 'coronary'],
            'inheritance': 'autosomal_dominant',
            'genes': ['MYH7', 'MYBPC3', 'TNNT2', 'TNNI3'],
            'risk_multiplier': 1.5,
            'screening': ['Echocardiogram', 'ECG monitoring', 'Stress testing'],
        },
        'genetic_syndrome': {
            'keywords': ['syndrome', 'genetic', 'hereditary', 'congenital'],
            'inheritance': 'autosomal_recessive',
            'genes': ['CFTR', 'SMN1', 'HEXA'],
            'risk_multiplier': 2.5,
            'screening': ['Genetic testing', 'Specialty consultations', 'Carrier screening'],
        },
        'metabolic': {
            'keywords': ['diabetes', 'metabolic', 'endocrine', 'thyroid'],
            'inheritance': 'complex',
            'genes': ['MODY1', 'MODY2', 'MODY3'],
            'risk_multiplier': 1.3,
            'screening': ['Metabolic panel', 'Glucose monitoring', 'Endocrine evaluation'],
        }
    }
    
    RELATIONSHIP_WEIGHTS = {
        'mother': 0.5,
        'father': 0.5,
        'sibling': 0.5,
        'child': 0.5,
        'grandmother': 0.25,
        'grandfather': 0.25,
        'aunt': 0.25,
        'uncle': 0.25,
        'cousin': 0.125,
        'niece': 0.25,
        'nephew': 0.25,
    }
    
    @classmethod
    def generate_analysis(cls, patient: User) -> GeneticAnalysis:
        """Generate a comprehensive genetic analysis for a patient."""
        try:
            # Get patient's medical record
            medical_record = getattr(patient, 'medical_record', None)
            if not medical_record:
                raise ValueError("Patient does not have a medical record")
            
            # Get family history data
            family_history = FamilyHistory.objects.filter(
                medical_record=medical_record
            ).order_by('relationship')
            
            if not family_history.exists():
                raise ValueError("No family history data available for analysis")
            
            # Analyze family history
            analysis_results = cls._analyze_family_history(family_history)
            
            # Create genetic analysis record
            genetic_analysis = GeneticAnalysis.objects.create(
                patient=patient,
                medical_record=medical_record,
                total_relatives_analyzed=analysis_results['total_relatives'],
                affected_relatives_count=analysis_results['affected_relatives'],
                generations_analyzed=analysis_results['generations'],
                overall_risk_score=analysis_results['overall_risk_score'],
                rare_disease_risk=analysis_results['rare_disease_risk'],
                oncological_risk=analysis_results['oncological_risk'],
                neurological_risk=analysis_results['neurological_risk'],
                cardiac_risk=analysis_results['cardiac_risk'],
                risk_factors=analysis_results['risk_factors'],
                rare_diseases_found=analysis_results['rare_diseases'],
                inheritance_patterns=analysis_results['inheritance_patterns'],
                genetic_testing_recommendations=analysis_results['genetic_testing'],
                screening_recommendations=analysis_results['screening'],
                lifestyle_recommendations=analysis_results['lifestyle'],
                counseling_recommended=analysis_results['counseling_recommended'],
            )
            
            # Create individual risk factor records
            for risk_factor_data in analysis_results['detailed_risk_factors']:
                GeneticRiskFactor.objects.create(
                    analysis=genetic_analysis,
                    **risk_factor_data
                )
            
            logger.info(f"Generated genetic analysis for patient {patient.id}")
            return genetic_analysis
            
        except Exception as e:
            logger.error(f"Error generating genetic analysis for patient {patient.id}: {str(e)}")
            raise
    
    @classmethod
    def _analyze_family_history(cls, family_history) -> Dict[str, Any]:
        """Analyze family history and generate risk assessment."""
        
        # Initialize analysis results
        results = {
            'total_relatives': family_history.count(),
            'affected_relatives': 0,
            'generations': cls._count_generations(family_history),
            'overall_risk_score': 0,
            'rare_disease_risk': 0,
            'oncological_risk': 0,
            'neurological_risk': 0,
            'cardiac_risk': 0,
            'risk_factors': [],
            'rare_diseases': [],
            'inheritance_patterns': {},
            'detailed_risk_factors': [],
            'genetic_testing': [],
            'screening': [],
            'lifestyle': [],
            'counseling_recommended': False,
        }
        
        # Analyze each family member
        condition_analysis = {}
        
        for member in family_history:
            if member.condition:
                condition = member.condition.lower().strip()
                
                # Initialize condition tracking
                if condition not in condition_analysis:
                    condition_analysis[condition] = {
                        'count': 0,
                        'relationships': [],
                        'total_weight': 0,
                        'category': cls._categorize_condition(condition),
                        'is_rare': cls._is_rare_disease(condition),
                    }
                
                # Add this occurrence
                condition_analysis[condition]['count'] += 1
                condition_analysis[condition]['relationships'].append(member.relationship)
                
                # Calculate genetic weight based on relationship
                weight = cls.RELATIONSHIP_WEIGHTS.get(member.relationship.lower(), 0.125)
                condition_analysis[condition]['total_weight'] += weight
                
                if member.condition:
                    results['affected_relatives'] += 1
        
        # Generate risk factors and scores
        for condition, data in condition_analysis.items():
            risk_factor = cls._calculate_risk_factor(condition, data)
            results['detailed_risk_factors'].append(risk_factor)
            
            # Add to summary lists
            results['risk_factors'].append({
                'condition': condition.title(),
                'risk_level': risk_factor['risk_level'],
                'family_count': data['count']
            })
            
            if data['is_rare']:
                results['rare_diseases'].append(condition.title())
            
            # Update category-specific risk scores
            category = data['category']
            if category == 'cancer':
                results['oncological_risk'] += min(risk_factor['risk_score'], 30)
            elif category == 'neurological':
                results['neurological_risk'] += min(risk_factor['risk_score'], 25)
            elif category == 'cardiac':
                results['cardiac_risk'] += min(risk_factor['risk_score'], 25)
            
            results['rare_disease_risk'] += risk_factor['risk_score'] if data['is_rare'] else 0
        
        # Calculate overall risk score
        results['overall_risk_score'] = min(
            int(sum(rf['risk_score'] for rf in results['detailed_risk_factors']) / 
                max(len(results['detailed_risk_factors']), 1) * 1.2), 
            85
        )
        
        # Cap individual scores
        results['rare_disease_risk'] = min(results['rare_disease_risk'], 75)
        results['oncological_risk'] = min(results['oncological_risk'], 75)
        results['neurological_risk'] = min(results['neurological_risk'], 65)
        results['cardiac_risk'] = min(results['cardiac_risk'], 65)
        
        # Generate recommendations
        results.update(cls._generate_recommendations(condition_analysis, results))
        
        return results
    
    @classmethod
    def _categorize_condition(cls, condition: str) -> str:
        """Categorize a medical condition based on keywords."""
        condition_lower = condition.lower()
        
        for category, pattern in cls.RARE_DISEASE_PATTERNS.items():
            if any(keyword in condition_lower for keyword in pattern['keywords']):
                return category
        
        return 'other'
    
    @classmethod
    def _is_rare_disease(cls, condition: str) -> bool:
        """Determine if a condition is considered a rare disease."""
        rare_keywords = [
            'rare', 'syndrome', 'genetic', 'hereditary', 'congenital',
            'dystrophy', 'atrophy', 'neuropathy', 'cardiomyopathy'
        ]
        
        condition_lower = condition.lower()
        return any(keyword in condition_lower for keyword in rare_keywords)
    
    @classmethod
    def _calculate_risk_factor(cls, condition: str, data: Dict) -> Dict[str, Any]:
        """Calculate risk factor for a specific condition."""
        base_risk = 15  # Base risk percentage
        
        # Adjust risk based on family history count and relationships
        count_multiplier = min(data['count'] * 0.3, 2.0)
        weight_multiplier = min(data['total_weight'] * 2, 3.0)
        
        # Get pattern-specific multiplier
        category = data['category']
        pattern_multiplier = 1.0
        inheritance_pattern = 'unknown'
        relevant_genes = []
        
        if category in cls.RARE_DISEASE_PATTERNS:
            pattern = cls.RARE_DISEASE_PATTERNS[category]
            pattern_multiplier = pattern['risk_multiplier']
            inheritance_pattern = pattern['inheritance']
            relevant_genes = pattern['genes']
        
        # Calculate final risk score
        risk_score = int(base_risk * count_multiplier * weight_multiplier * pattern_multiplier)
        risk_score = min(risk_score, 80)  # Cap at 80%
        
        # Determine risk level
        if risk_score >= 60:
            risk_level = 'very_high'
        elif risk_score >= 40:
            risk_level = 'high'
        elif risk_score >= 20:
            risk_level = 'moderate'
        else:
            risk_level = 'low'
        
        # Generate prevention recommendations
        prevention_recs = [
            f"Regular screening for {condition.title()}",
            "Maintain healthy lifestyle",
            "Genetic counseling consultation"
        ]
        
        if data['is_rare']:
            prevention_recs.append("Specialist consultation recommended")
        
        # Age of onset estimation
        age_ranges = {
            'cancer': '40-70 years',
            'neurological': '50-80 years',
            'cardiac': '30-60 years',
            'genetic_syndrome': 'Variable, often early onset',
            'metabolic': '30-50 years',
        }
        
        return {
            'condition': condition.title(),
            'risk_level': risk_level,
            'risk_score': risk_score,
            'family_history_count': data['count'],
            'affected_relationships': data['relationships'],
            'inheritance_pattern': inheritance_pattern,
            'age_of_onset_range': age_ranges.get(category, '30-60 years'),
            'prevention_recommendations': prevention_recs,
            'screening_recommendations': cls.RARE_DISEASE_PATTERNS.get(category, {}).get('screening', []),
            'relevant_genes': relevant_genes,
            'testing_available': bool(relevant_genes),
            'testing_recommended': risk_level in ['high', 'very_high'],
        }
    
    @classmethod
    def _count_generations(cls, family_history) -> int:
        """Count the number of generations represented in family history."""
        generation_indicators = {
            'grandparent': 3, 'grandmother': 3, 'grandfather': 3,
            'parent': 2, 'mother': 2, 'father': 2,
            'sibling': 1, 'self': 1,
            'child': 1, 'son': 1, 'daughter': 1,
        }
        
        max_generation = 1
        for member in family_history:
            for indicator, gen in generation_indicators.items():
                if indicator in member.relationship.lower():
                    max_generation = max(max_generation, gen)
                    break
        
        return max_generation
    
    @classmethod
    def _generate_recommendations(cls, condition_analysis: Dict, results: Dict) -> Dict[str, Any]:
        """Generate personalized recommendations based on analysis."""
        genetic_testing = set()
        screening = set()
        lifestyle = [
            "Maintain a healthy diet rich in fruits and vegetables",
            "Engage in regular physical activity (150 minutes/week)",
            "Avoid smoking and limit alcohol consumption",
            "Maintain a healthy weight",
            "Manage stress through relaxation techniques",
        ]
        
        counseling_recommended = False
        
        # Generate recommendations based on identified conditions
        for condition, data in condition_analysis.items():
            category = data['category']
            
            if category in cls.RARE_DISEASE_PATTERNS:
                pattern = cls.RARE_DISEASE_PATTERNS[category]
                
                # Add genetic testing recommendations
                if data['total_weight'] > 0.5:  # Close family members affected
                    genetic_testing.update([
                        f"Genetic testing for {condition.title()}",
                        f"Gene panel screening for {category} conditions"
                    ])
                    counseling_recommended = True
                
                # Add screening recommendations
                screening.update(pattern['screening'])
        
        # Add general recommendations based on overall risk
        if results['overall_risk_score'] > 50:
            genetic_testing.add("Comprehensive genetic counseling")
            screening.add("Annual comprehensive health evaluation")
            counseling_recommended = True
        
        if results['oncological_risk'] > 30:
            screening.update([
                "Regular cancer screening appropriate for age",
                "Consider earlier/more frequent mammography",
                "Dermatological screening annually"
            ])
        
        if results['cardiac_risk'] > 25:
            screening.update([
                "Annual cardiovascular assessment",
                "Blood pressure monitoring",
                "Cholesterol screening"
            ])
        
        if results['neurological_risk'] > 20:
            screening.update([
                "Cognitive assessment every 2-3 years after age 50",
                "Neurological evaluation if symptoms develop"
            ])
        
        return {
            'genetic_testing': list(genetic_testing),
            'screening': list(screening),
            'lifestyle': lifestyle,
            'counseling_recommended': counseling_recommended,
        }
    
    @classmethod
    def get_latest_analysis(cls, patient: User) -> GeneticAnalysis:
        """Get the most recent genetic analysis for a patient."""
        return GeneticAnalysis.objects.filter(patient=patient).first()
    
    @classmethod
    def update_analysis(cls, analysis: GeneticAnalysis) -> GeneticAnalysis:
        """Update an existing genetic analysis with fresh family history data."""
        # Delete old risk factors
        analysis.identified_risk_factors.all().delete()
        
        # Regenerate analysis
        new_analysis = cls.generate_analysis(analysis.patient)
        
        # Delete the old analysis
        analysis.delete()
        
        return new_analysis