# medication/services/interactions.py
import requests
from django.conf import settings
from typing import List, Dict, Any, Optional
import logging

from ..models import Medication, DrugInteraction

logger = logging.getLogger(__name__)

# Drug interaction database - for production, integrate with real API
INTERACTION_DATABASE = {
    # Example interactions for rare disease medications
    'methotrexate': {
        'severe': ['warfarin', 'phenytoin'],
        'moderate': ['aspirin', 'ibuprofen'],
        'mild': ['folic_acid']
    },
    'rituximab': {
        'severe': ['live_vaccines', 'natalizumab'],
        'moderate': ['methotrexate', 'corticosteroids']
    }
    # Add more as needed
}

def check_interactions(medication1: Medication, medication2: Medication) -> Optional[DrugInteraction]:
    """
    Check for drug interactions between two medications.
    Critical for rare disease patients on complex medication regimens.
    """
    # Normalize medication names for lookup
    med1_name = medication1.name.lower().replace(' ', '_')
    med2_name = medication2.name.lower().replace(' ', '_')
    
    # Check both directions
    interaction_severity = None
    interaction_description = ""
    
    # Check med1 -> med2
    if med1_name in INTERACTION_DATABASE:
        for severity, interacting_drugs in INTERACTION_DATABASE[med1_name].items():
            if med2_name in interacting_drugs:
                interaction_severity = severity
                interaction_description = f"Known {severity} interaction between {medication1.name} and {medication2.name}"
                break
    
    # Check med2 -> med1 if no interaction found
    if not interaction_severity and med2_name in INTERACTION_DATABASE:
        for severity, interacting_drugs in INTERACTION_DATABASE[med2_name].items():
            if med1_name in interacting_drugs:
                interaction_severity = severity
                interaction_description = f"Known {severity} interaction between {medication2.name} and {medication1.name}"
                break
    
    # If interaction found, create or update record
    if interaction_severity:
        interaction, created = DrugInteraction.objects.get_or_create(
            patient=medication1.patient,
            medication1=medication1,
            medication2=medication2,
            defaults={
                'severity': interaction_severity,
                'description': interaction_description,
                'identified_date': timezone.now().date(),
                'source': 'internal_database'
            }
        )
        
        # Alert prescriber for severe interactions
        if interaction_severity == 'severe':
            _alert_severe_interaction(interaction)
        
        return interaction
    
    return None

def check_all_interactions(patient) -> List[DrugInteraction]:
    """Check for interactions among all active medications for a patient."""
    active_medications = patient.medications.filter(active=True)
    interactions = []
    
    # Check each pair of medications
    for i, med1 in enumerate(active_medications):
        for med2 in active_medications[i+1:]:
            interaction = check_interactions(med1, med2)
            if interaction:
                interactions.append(interaction)
    
    return interactions

def _alert_severe_interaction(interaction: DrugInteraction):
    """Alert providers about severe drug interactions."""
    from communication.tasks import send_interaction_alert
    
    # Alert prescribers of both medications
    prescribers = set()
    if interaction.medication1.prescriber:
        prescribers.add(interaction.medication1.prescriber)
    if interaction.medication2.prescriber:
        prescribers.add(interaction.medication2.prescriber)
    
    for prescriber in prescribers:
        send_interaction_alert.delay(
            prescriber_id=prescriber.id,
            interaction_id=interaction.id
        )

def get_interaction_api_data(medication_name: str) -> Dict[str, Any]:
    """
    Get interaction data from external API (RxNorm, OpenFDA, etc.)
    For production, implement real API integration.
    """
    # Placeholder for external API integration
    # Example: OpenFDA API, RxNorm API, etc.
    try:
        # This would be a real API call in production
        response = {
            'medication': medication_name,
            'interactions': [],
            'source': 'external_api',
            'last_updated': timezone.now().isoformat()
        }
        return response
    except Exception as e:
        logger.error(f"Failed to fetch interaction data for {medication_name}: {str(e)}")
        return {}