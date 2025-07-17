import logging
import numpy as np
from datetime import datetime, timedelta
from django.utils import timezone
from typing import Dict, List, Any
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

class AIInsightsService:
    """AI-powered insights for rare disease analytics."""
    
    @staticmethod
    def analyze_medication_adherence_patterns(patient_data):
        """Use ML to identify medication adherence patterns."""
        try:
            # Prepare feature matrix
            features = []
            for patient in patient_data:
                feature_vector = [
                    patient.get('adherence_rate', 0),
                    patient.get('days_since_diagnosis', 0),
                    patient.get('medication_count', 0),
                    patient.get('side_effect_count', 0),
                    patient.get('appointment_frequency', 0),
                    patient.get('caregiver_present', 0)  # 1 if has caregiver, 0 otherwise
                ]
                features.append(feature_vector)
            
            if len(features) < 10:  # Need minimum data for ML
                return {"error": "Insufficient data for pattern analysis"}
            
            # Standardize features
            scaler = StandardScaler()
            features_scaled = scaler.fit_transform(features)
            
            # Detect anomalies using Isolation Forest
            iso_forest = IsolationForest(contamination=0.1, random_state=42)
            anomaly_scores = iso_forest.fit_predict(features_scaled)
            
            # Identify patients at risk
            at_risk_patients = []
            for i, score in enumerate(anomaly_scores):
                if score == -1:  # Anomaly detected
                    at_risk_patients.append({
                        'patient_index': i,
                        'risk_factors': {
                            'low_adherence': features[i][0] < 0.8,
                            'high_medication_burden': features[i][2] > 5,
                            'frequent_side_effects': features[i][3] > 3,
                            'no_caregiver_support': features[i][5] == 0
                        }
                    })
            
            return {
                'total_patients_analyzed': len(features),
                'at_risk_count': len(at_risk_patients),
                'at_risk_patients': at_risk_patients,
                'recommendations': AIInsightsService._generate_adherence_recommendations(at_risk_patients)
            }
            
        except Exception as e:
            logger.error(f"Error in adherence pattern analysis: {str(e)}")
            return {"error": "Pattern analysis failed"}
    
    @staticmethod
    def _generate_adherence_recommendations(at_risk_patients):
        """Generate personalized recommendations for at-risk patients."""
        recommendations = []
        
        for patient in at_risk_patients:
            risk_factors = patient['risk_factors']
            patient_recommendations = []
            
            if risk_factors['low_adherence']:
                patient_recommendations.append("Increase medication reminder frequency")
                patient_recommendations.append("Consider smartwatch integration for alerts")
            
            if risk_factors['high_medication_burden']:
                patient_recommendations.append("Review medication schedule with provider")
                patient_recommendations.append("Consider pill organizer or automated dispensing")
            
            if risk_factors['frequent_side_effects']:
                patient_recommendations.append("Schedule provider consultation for side effect management")
                patient_recommendations.append("Consider alternative treatment options")
            
            if risk_factors['no_caregiver_support']:
                patient_recommendations.append("Connect with caregiver support services")
                patient_recommendations.append("Join patient support community")
            
            recommendations.append({
                'patient_index': patient['patient_index'],
                'recommendations': patient_recommendations
            })
        
        return recommendations
    
    @staticmethod
    def predict_treatment_outcomes(historical_data):
        """Predict treatment outcomes based on historical patterns."""
        # This would use more sophisticated ML models in production
        try:
            outcomes = {
                'success_probability': 0.75,  # Placeholder - would be ML-computed
                'time_to_improvement': 45,    # days
                'risk_factors': [
                    'Patient age > 65',
                    'Multiple comorbidities',
                    'Poor medication adherence history'
                ],
                'optimization_suggestions': [
                    'Implement daily medication reminders',
                    'Increase telemedicine consultation frequency',
                    'Add caregiver to care team'
                ]
            }
            
            return outcomes
            
        except Exception as e:
            logger.error(f"Error in outcome prediction: {str(e)}")
            return {"error": "Prediction failed"}