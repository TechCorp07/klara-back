import logging
import requests
from django.utils import timezone
from django.conf import settings

logger = logging.getLogger(__name__)

def check_interactions(medication_a, medication_b):
    """
    Check for interactions between two medications.
    
    This function checks for interactions between two medications using
    RxNorm codes if available. If an interaction is found, it creates
    a DrugInteraction record.
    
    Args:
        medication_a: First Medication object
        medication_b: Second Medication object
        
    Returns:
        DrugInteraction object if interaction found, None otherwise
    """
    # Import models here to avoid circular imports
    from ..models import DrugInteraction
    
    # Skip if medications are the same
    if medication_a.id == medication_b.id:
        return None
    
    # Check if interaction already exists
    existing_interaction = DrugInteraction.objects.filter(
        medication_a=medication_a,
        medication_b=medication_b,
        patient=medication_a.patient
    ).first()
    
    if existing_interaction and existing_interaction.resolved_date is None:
        # Interaction already exists and is not resolved
        return existing_interaction
    
    # Check for interaction using external API or database
    interaction_data = get_interaction_from_api(medication_a, medication_b)
    
    if not interaction_data:
        return None
    
    # Create interaction record
    interaction = DrugInteraction.objects.create(
        medication_a=medication_a,
        medication_b=medication_b,
        patient=medication_a.patient,
        description=interaction_data.get('description', 'Potential drug interaction detected'),
        severity=interaction_data.get('severity', 'moderate'),
        detected_date=timezone.now().date()
    )
    
    # Return created interaction
    return interaction


def check_all_interactions(patient):
    """
    Check interactions for all of a patient's active medications.
    
    Args:
        patient: User object to check interactions for
        
    Returns:
        List of DrugInteraction objects
    """
    # Import models here to avoid circular imports
    from ..models import Medication
    
    # Get active medications for this patient
    medications = Medication.objects.filter(patient=patient, active=True)
    
    # Check all pairs of medications
    interactions = []
    
    for i, med_a in enumerate(medications):
        for med_b in medications[i+1:]:  # Only check each pair once
            interaction = check_interactions(med_a, med_b)
            if interaction:
                interactions.append(interaction)
    
    return interactions


def get_interaction_from_api(medication_a, medication_b):
    """
    Get interaction data from an external API.
    
    This is a placeholder implementation that would typically use
    a real drug interaction API like NIH RxNav or a commercial service.
    
    Args:
        medication_a: First Medication object
        medication_b: Second Medication object
        
    Returns:
        Dictionary with interaction data or None if no interaction found
    """
    # Check if we have RxNorm codes to use
    rxnorm_a = medication_a.rxnorm_code
    rxnorm_b = medication_b.rxnorm_code
    
    if rxnorm_a and rxnorm_b:
        # In a real implementation, this would call an external API like:
        # https://rxnav.nlm.nih.gov/REST/interaction/list.json?rxcuis={rxnorm_a}+{rxnorm_b}
        
        try:
            # This is a mock implementation - in a real system, you would call the actual API
            # response = requests.get(
            #    f"https://rxnav.nlm.nih.gov/REST/interaction/list.json?rxcuis={rxnorm_a}+{rxnorm_b}"
            # )
            # if response.status_code == 200:
            #    return parse_rxnav_response(response.json())
            
            # For now, return mock data based on medication names
            return mock_interaction_check(medication_a.name, medication_b.name)
            
        except Exception as e:
            logger.error(f"Error checking interactions via API: {str(e)}")
            return None
    else:
        # Fall back to name-based check
        return mock_interaction_check(medication_a.name, medication_b.name)


def mock_interaction_check(med_a_name, med_b_name):
    """
    Mock implementation of drug interaction check based on common interactions.
    
    Args:
        med_a_name: Name of first medication
        med_b_name: Name of second medication
        
    Returns:
        Dictionary with interaction data or None if no interaction found
    """
    # List of common interactions (lowercase for case-insensitive matching)
    common_interactions = {
        ('warfarin', 'aspirin'): {
            'description': 'Increased risk of bleeding when warfarin is used with aspirin',
            'severity': 'major'
        },
        ('simvastatin', 'atorvastatin'): {
            'description': 'Increased risk of muscle pain or damage when multiple statins are used together',
            'severity': 'moderate'
        },
        ('lisinopril', 'spironolactone'): {
            'description': 'Increased risk of high potassium levels when used together',
            'severity': 'moderate'
        },
        ('fluoxetine', 'tramadol'): {
            'description': 'Increased risk of serotonin syndrome when used together',
            'severity': 'major'
        },
        ('methotrexate', 'ibuprofen'): {
            'description': 'NSAIDs may increase methotrexate levels and toxicity',
            'severity': 'major'
        },
        ('ciprofloxacin', 'calcium'): {
            'description': 'Calcium may decrease absorption of ciprofloxacin',
            'severity': 'moderate'
        },
        ('levothyroxine', 'calcium'): {
            'description': 'Calcium may decrease absorption of levothyroxine',
            'severity': 'moderate'
        },
        ('amiodarone', 'simvastatin'): {
            'description': 'Increased risk of muscle damage when used together',
            'severity': 'major'
        },
        ('digoxin', 'furosemide'): {
            'description': 'Increased risk of digoxin toxicity due to potassium depletion',
            'severity': 'moderate'
        },
        ('lithium', 'hydrochlorothiazide'): {
            'description': 'Increased risk of lithium toxicity',
            'severity': 'major'
        },
        ('sildenafil', 'nitroglycerin'): {
            'description': 'Dangerous drop in blood pressure when used together',
            'severity': 'contraindicated'
        },
        ('erythromycin', 'simvastatin'): {
            'description': 'Increased risk of muscle damage when used together',
            'severity': 'major'
        },
        ('carbamazepine', 'oral contraceptives'): {
            'description': 'May decrease effectiveness of oral contraceptives',
            'severity': 'moderate'
        },
        ('warfarin', 'vitamin k'): {
            'description': 'Vitamin K may reduce effectiveness of warfarin',
            'severity': 'moderate'
        },
        ('phenytoin', 'folic acid'): {
            'description': 'Folic acid may decrease phenytoin levels',
            'severity': 'minor'
        }
    }
    
    # Normalize medication names (lowercase)
    med_a_lower = med_a_name.lower()
    med_b_lower = med_b_name.lower()
    
    # Check for interactions
    for (drug1, drug2), interaction in common_interactions.items():
        # Check both directions
        if ((drug1 in med_a_lower and drug2 in med_b_lower) or
            (drug1 in med_b_lower and drug2 in med_a_lower)):
            return interaction
    
    # Check for class-based interactions
    class_interactions = check_drug_classes(med_a_lower, med_b_lower)
    if class_interactions:
        return class_interactions
    
    # No interaction found
    return None


def check_drug_classes(med_a_name, med_b_name):
    """
    Check for class-based drug interactions.
    
    Args:
        med_a_name: Name of first medication (lowercase)
        med_b_name: Name of second medication (lowercase)
        
    Returns:
        Dictionary with interaction data or None if no interaction found
    """
    # Define drug classes (common suffixes and keywords)
    drug_classes = {
        'statin': ['statin', 'vastatin'],
        'ssri': ['ssri', 'zoloft', 'prozac', 'lexapro', 'celexa', 'paxil', 'fluoxetine', 'sertraline', 'escitalopram'],
        'nsaid': ['nsaid', 'ibuprofen', 'naproxen', 'aspirin', 'celecoxib', 'diclofenac', 'indomethacin'],
        'acei': ['pril', 'ace inhibitor', 'lisinopril', 'enalapril', 'ramipril'],
        'arb': ['sartan', 'valsartan', 'losartan', 'candesartan', 'olmesartan'],
        'benzodiazepine': ['azepam', 'diazepam', 'lorazepam', 'alprazolam', 'clonazepam'],
        'calcium_channel_blocker': ['dipine', 'amlodipine', 'nifedipine', 'diltiazem', 'verapamil'],
        'beta_blocker': ['olol', 'metoprolol', 'atenolol', 'propranolol', 'carvedilol'],
        'opioid': ['opioid', 'codeine', 'morphine', 'oxycodone', 'hydrocodone', 'tramadol', 'fentanyl'],
        'anticoagulant': ['anticoagulant', 'warfarin', 'apixaban', 'rivaroxaban', 'dabigatran', 'heparin']
    }
    
    # Identify drug classes for each medication
    med_a_classes = []
    med_b_classes = []
    
    for class_name, class_keywords in drug_classes.items():
        if any(keyword in med_a_name for keyword in class_keywords):
            med_a_classes.append(class_name)
        if any(keyword in med_b_name for keyword in class_keywords):
            med_b_classes.append(class_name)
    
    # Class-based interaction rules
    class_interactions = {
        ('statin', 'statin'): {
            'description': 'Increased risk of muscle pain or damage when multiple statins are used together',
            'severity': 'moderate'
        },
        ('ssri', 'opioid'): {
            'description': 'Increased risk of serotonin syndrome when SSRIs are used with opioids',
            'severity': 'moderate'
        },
        ('nsaid', 'anticoagulant'): {
            'description': 'Increased risk of bleeding when NSAIDs are used with anticoagulants',
            'severity': 'major'
        },
        ('acei', 'arb'): {
            'description': 'Increased risk of kidney problems and high potassium levels',
            'severity': 'moderate'
        },
        ('benzodiazepine', 'opioid'): {
            'description': 'Increased risk of severe drowsiness, respiratory depression, and death',
            'severity': 'major'
        }
    }
    
    # Check for class-based interactions
    for a_class in med_a_classes:
        for b_class in med_b_classes:
            # Check both directions
            if (a_class, b_class) in class_interactions:
                return class_interactions[(a_class, b_class)]
            elif (b_class, a_class) in class_interactions:
                return class_interactions[(b_class, a_class)]
    
    # No class-based interaction found
    return None


def parse_rxnav_response(response_data):
    """
    Parse response from NIH RxNav API.
    
    Args:
        response_data: JSON response from RxNav API
        
    Returns:
        Dictionary with interaction data or None if no interaction found
    """
    try:
        # Check if interactions were found
        if 'fullInteractionTypeGroup' not in response_data:
            return None
        
        interactions = response_data['fullInteractionTypeGroup']
        
        if not interactions:
            return None
        
        # Get first interaction (in real implementation, might want to return all)
        interaction = interactions[0]['fullInteractionType'][0]
        
        # Extract description and severity
        description = interaction['description']
        
        # RxNav doesn't provide severity directly, so we estimate based on description
        severity = 'moderate'  # Default
        
        # Check for keywords indicating severity
        if any(word in description.lower() for word in ['fatal', 'death', 'life-threatening', 'contraindicated']):
            severity = 'contraindicated'
        elif any(word in description.lower() for word in ['severe', 'serious', 'significant', 'major']):
            severity = 'major'
        elif any(word in description.lower() for word in ['mild', 'minor', 'minimal']):
            severity = 'minor'
        
        return {
            'description': description,
            'severity': severity
        }
        
    except Exception as e:
        logger.error(f"Error parsing RxNav response: {str(e)}")
        return None
