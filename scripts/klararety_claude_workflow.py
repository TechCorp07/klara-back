#!/usr/bin/env python3
"""
Klararety and Claude Integration Workflow Example

This script demonstrates a complete workflow integrating Klararety healthcare data with Claude AI:
1. Authenticate with Klararety API
2. Generate a medication adherence report
3. Analyze the report with Claude AI
4. Extract recommendations from Claude's analysis
5. Generate a patient-friendly summary

For a production environment:
- Store API keys securely (not hardcoded)
- Implement proper error handling
- Implement rate limiting for API calls
- Add logging for audit purposes
"""

import os
import sys
import json
import time
import requests
import anthropic
from datetime import datetime, timedelta

# API Configuration
KLARARETY_API_URL = "https://api.klararety.com/api"
KLARARETY_USERNAME = os.environ.get("KLARARETY_USERNAME")
KLARARETY_PASSWORD = os.environ.get("KLARARETY_PASSWORD")
CLAUDE_API_KEY = os.environ.get("CLAUDE_API_KEY")

# Check for required environment variables
if not all([KLARARETY_USERNAME, KLARARETY_PASSWORD, CLAUDE_API_KEY]):
    print("Error: Please set KLARARETY_USERNAME, KLARARETY_PASSWORD, and CLAUDE_API_KEY environment variables")
    sys.exit(1)

def authenticate():
    """Authenticate with Klararety API and return token."""
    print("Authenticating with Klararety API...")
    
    auth_url = f"{KLARARETY_API_URL}/users/login/"
    
    try:
        response = requests.post(
            auth_url,
            json={"username": KLARARETY_USERNAME, "password": KLARARETY_PASSWORD}
        )
        
        if response.status_code == 200:
            token = response.json()["token"]
            print("✓ Authentication successful")
            return token
        else:
            print(f"✗ Authentication failed: {response.json().get('detail', 'Unknown error')}")
            sys.exit(1)
    except Exception as e:
        print(f"✗ Authentication failed: {str(e)}")
        sys.exit(1)

def generate_adherence_report(token, patient_id=None, time_period="90d"):
    """Generate a medication adherence report."""
    print(f"Generating medication adherence report for the past {time_period}...")
    
    # Get report configuration
    config_url = f"{KLARARETY_API_URL}/reports/report-configurations/"
    
    config_data = {
        "name": f"Medication Adherence Report - {datetime.now().strftime('%Y-%m-%d')}",
        "description": "Report on medication adherence patterns",
        "report_type": "patient_adherence",
        "parameters": {
            "time_period": time_period,
            "include_demographics": True
        },
        "schedule": "on_demand",
        "is_public": False,
        "allowed_roles": ["provider", "pharmco"]
    }
    
    # Add patient filter if specified
    if patient_id:
        config_data["parameters"]["patient_id"] = patient_id
    
    # Create report configuration
    try:
        response = requests.post(
            config_url,
            json=config_data,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 201:
            config_id = response.json()["id"]
            print(f"✓ Report configuration created (ID: {config_id})")
        else:
            print(f"✗ Failed to create report configuration: {response.json().get('detail', 'Unknown error')}")
            sys.exit(1)
    except Exception as e:
        print(f"✗ Failed to create report configuration: {str(e)}")
        sys.exit(1)
    
    # Generate report from configuration
    generate_url = f"{KLARARETY_API_URL}/reports/report-configurations/{config_id}/generate_report/"
    
    try:
        response = requests.post(
            generate_url,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 201:
            report = response.json()
            report_id = report["id"]
            print(f"✓ Report generation started (ID: {report_id})")
            
            # Wait for report to complete
            report_url = f"{KLARARETY_API_URL}/reports/reports/{report_id}/"
            max_wait = 60  # Maximum wait time in seconds
            start_time = time.time()
            
            while time.time() - start_time < max_wait:
                print("   Waiting for report to complete...")
                response = requests.get(
                    report_url,
                    headers={"Authorization": f"Bearer {token}"}
                )
                
                if response.status_code == 200:
                    report = response.json()
                    if report["status"] == "COMPLETED":
                        print(f"✓ Report completed successfully")
                        return report
                    elif report["status"] == "FAILED":
                        print(f"✗ Report generation failed: {report.get('error_message', 'Unknown error')}")
                        sys.exit(1)
                
                time.sleep(5)  # Wait 5 seconds before checking again
            
            print("✗ Timed out waiting for report to complete")
            sys.exit(1)
        else:
            print(f"✗ Failed to generate report: {response.json().get('detail', 'Unknown error')}")
            sys.exit(1)
    except Exception as e:
        print(f"✗ Failed to generate report: {str(e)}")
        sys.exit(1)

def analyze_with_claude(report, token):
    """Analyze the report with Claude using Klararety's AI Analysis API."""
    print("Analyzing report with Claude AI...")
    
    analysis_url = f"{KLARARETY_API_URL}/reports/ai-analysis/analyze_report/"
    
    payload = {
        "report_id": report["id"],
        "reason": "Analyze medication adherence patterns and provide recommendations"
    }
    
    try:
        response = requests.post(
            analysis_url,
            json=payload,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            analysis = response.json()
            print("✓ Analysis completed successfully")
            return analysis
        else:
            error = response.json().get('detail', 'Unknown error')
            
            # If the integrated API is not available, fall back to direct Claude API
            if "API key not configured" in error or "Service unavailable" in error:
                print("ℹ Falling back to direct Claude API...")
                return analyze_with_claude_direct(report)
            else:
                print(f"✗ Analysis failed: {error}")
                sys.exit(1)
    except Exception as e:
        print(f"✗ Analysis failed: {str(e)}")
        sys.exit(1)

def analyze_with_claude_direct(report):
    """Analyze the report directly with Claude API as a fallback."""
    print("Analyzing report directly with Claude API...")
    
    try:
        # Initialize Claude client
        client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
        
        # Create system prompt
        system_prompt = """You are a healthcare analytics expert specializing in medication adherence analysis. 
Your task is to analyze medication adherence data and provide insights that could help improve patient outcomes 
and treatment effectiveness. Provide clear, actionable recommendations based on the patterns you identify."""
        
        # Create user prompt with report data
        report_type = report.get("configuration", {}).get("report_type", "medication adherence")
        report_data = report.get("results_json", {})
        
        user_prompt = f"""Please analyze this {report_type} report and provide your key insights, observations, and recommendations. 
Focus on the most significant findings and provide actionable recommendations based on the data.

Report Data: {json.dumps(report_data)}

Please structure your analysis with the following sections:
1. Executive Summary
2. Key Findings
3. Detailed Analysis
4. Recommendations
5. Potential Next Steps"""
        
        # Call Claude API
        message = client.messages.create(
            model="claude-3-opus-20240229",
            max_tokens=4000,
            system=system_prompt,
            messages=[
                {"role": "user", "content": user_prompt}
            ]
        )
        
        # Format response similar to Klararety API
        analysis = {
            "analysis": message.content,
            "report_id": report["id"] if "id" in report else "unknown",
            "report_type": report_type,
            "analyzed_at": datetime.now().isoformat(),
            "model_used": "claude-3-opus-20240229"
        }
        
        print("✓ Direct analysis completed successfully")
        return analysis
    except Exception as e:
        print(f"✗ Direct analysis failed: {str(e)}")
        sys.exit(1)

def extract_recommendations(analysis):
    """Extract recommendations from Claude's analysis."""
    print("Extracting recommendations from analysis...")
    
    # Use Claude to extract key recommendations
    try:
        client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
        
        system_prompt = """You are an assistant that extracts key recommendations from a longer analysis. 
Your task is to identify the most important, actionable recommendations and present them in a clear, 
concise bullet point format."""
        
        user_prompt = f"""Please extract the key recommendations from the following medication adherence analysis. 
Present them as a bulleted list of clear, actionable items.

Analysis:
{analysis['analysis']}"""
        
        # Call Claude API
        message = client.messages.create(
            model="claude-3-haiku-20240307",  # Using smaller model for extraction task
            max_tokens=1000,
            system=system_prompt,
            messages=[
                {"role": "user", "content": user_prompt}
            ]
        )
        
        print("✓ Recommendations extracted successfully")
        return message.content
    except Exception as e:
        print(f"✗ Failed to extract recommendations: {str(e)}")
        return "Could not extract recommendations due to an error."

def generate_patient_summary(analysis):
    """Generate a patient-friendly summary from the analysis."""
    print("Generating patient-friendly summary...")
    
    # Use Claude to create patient-friendly summary
    try:
        client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
        
        system_prompt = """You are a healthcare communicator that specializes in translating complex 
medical analytics into clear, easy-to-understand language for patients. Your summaries should be 
supportive, non-judgmental, and focus on positive steps patients can take."""
        
        user_prompt = f"""Please create a patient-friendly summary of the following medication adherence analysis. 
The summary should:
1. Be written in simple, non-technical language
2. Be encouraging and non-judgmental
3. Focus on practical tips that can help improve medication adherence
4. Be brief (250-300 words)
5. Include a friendly opening and closing

Analysis:
{analysis['analysis']}"""
        
        # Call Claude API
        message = client.messages.create(
            model="claude-3-sonnet-20240229",  # Using balanced model for patient communication
            max_tokens=1500,
            system=system_prompt,
            messages=[
                {"role": "user", "content": user_prompt}
            ]
        )
        
        print("✓ Patient summary created successfully")
        return message.content
    except Exception as e:
        print(f"✗ Failed to create patient summary: {str(e)}")
        return "Could not create patient summary due to an error."

def save_outputs(report, analysis, recommendations, patient_summary):
    """Save all outputs to files."""
    print("Saving outputs to files...")
    
    # Create output directory if it doesn't exist
    os.makedirs("output", exist_ok=True)
    
    # Generate timestamp for filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save report
    with open(f"output/adherence_report_{timestamp}.json", 'w') as f:
        json.dump(report, f, indent=2)
    
    # Save analysis
    with open(f"output/analysis_{timestamp}.json", 'w') as f:
        json.dump(analysis, f, indent=2)
    
    # Save analysis text
    with open(f"output/analysis_{timestamp}.txt", 'w') as f:
        f.write(analysis['analysis'])
    
    # Save recommendations
    with open(f"output/recommendations_{timestamp}.txt", 'w') as f:
        f.write(recommendations)
    
    # Save patient summary
    with open(f"output/patient_summary_{timestamp}.txt", 'w') as f:
        f.write(patient_summary)
    
    print(f"✓ All outputs saved to the 'output' directory with timestamp {timestamp}")

def main():
    """Run the full workflow."""
    print("\n" + "="*80)
    print("KLARARETY + CLAUDE INTEGRATION WORKFLOW")
    print("="*80 + "\n")
    
    # Step 1: Authenticate
    token = authenticate()
    
    # Step 2: Generate report
    report = generate_adherence_report(token, time_period="90d")
    
    # Step 3: Analyze with Claude
    analysis = analyze_with_claude(report, token)
    
    # Step 4: Extract recommendations
    recommendations = extract_recommendations(analysis)
    
    # Step 5: Generate patient-friendly summary
    patient_summary = generate_patient_summary(analysis)
    
    # Step 6: Save all outputs
    save_outputs(report, analysis, recommendations, patient_summary)
    
    print("\n" + "="*80)
    print("WORKFLOW COMPLETED SUCCESSFULLY")
    print("="*80 + "\n")
    
    # Display summary of results
    print("RECOMMENDATIONS:\n")
    print(recommendations)
    print("\nPATIENT SUMMARY:\n")
    print(patient_summary)
    print("\n" + "="*80)

if __name__ == "__main__":
    main()
