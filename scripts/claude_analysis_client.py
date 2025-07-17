#!/usr/bin/env python3
"""
Klararety - Claude AI Analysis Client

This script provides a command-line interface for using the Klararety AI Analysis API
to analyze healthcare data with Claude. It can be used to analyze either raw data or
existing reports.

Example usage:
    # Analyze medication adherence data
    python claude_analysis_client.py --data-type patient_adherence --time-period 90d --reason "Medication efficacy analysis"

    # Analyze an existing report
    python claude_analysis_client.py --report-id 12345 --reason "Detailed report analysis"

    # Customize the AI prompt
    python claude_analysis_client.py --data-type vitals_trends --custom-prompt "Analyze this data focusing on blood pressure patterns"
"""

import os
import sys
import json
import argparse
import requests
from datetime import datetime
from getpass import getpass

# Set default API base URL - can be overridden with environment variable
DEFAULT_API_URL = "https://api.klararety.com/api/reports"
API_BASE_URL = os.environ.get("KLARARETY_API_URL", DEFAULT_API_URL)

def get_auth_token(api_url, username=None, password=None):
    """Get authentication token from Klararety API."""
    if not username:
        username = input("Klararety username: ")
    
    if not password:
        password = getpass("Klararety password: ")
    
    auth_url = f"{api_url.split('/api/')[0]}/api/users/login/"
    
    try:
        response = requests.post(
            auth_url,
            json={"username": username, "password": password}
        )
        
        if response.status_code == 200:
            return response.json()["token"]
        else:
            print(f"Authentication failed: {response.json().get('detail', 'Unknown error')}")
            sys.exit(1)
    except Exception as e:
        print(f"Authentication failed: {str(e)}")
        sys.exit(1)

def analyze_data(token, data_type, time_period, reason, custom_prompt=None, system_prompt=None):
    """Analyze data with Claude AI."""
    url = f"{API_BASE_URL}/ai-analysis/analyze_data/"
    
    # Prepare request payload
    payload = {
        "data_type": data_type,
        "time_period": time_period,
        "reason": reason
    }
    
    if custom_prompt:
        payload["custom_prompt"] = custom_prompt
    
    if system_prompt:
        payload["system_prompt"] = system_prompt
    
    # Send request
    try:
        response = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Analysis failed: {response.json().get('detail', 'Unknown error')}")
            sys.exit(1)
    except Exception as e:
        print(f"Analysis failed: {str(e)}")
        sys.exit(1)

def analyze_report(token, report_id, reason, custom_prompt=None, system_prompt=None):
    """Analyze an existing report with Claude AI."""
    url = f"{API_BASE_URL}/ai-analysis/analyze_report/"
    
    # Prepare request payload
    payload = {
        "report_id": report_id,
        "reason": reason
    }
    
    if custom_prompt:
        payload["custom_prompt"] = custom_prompt
    
    if system_prompt:
        payload["system_prompt"] = system_prompt
    
    # Send request
    try:
        response = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Report analysis failed: {response.json().get('detail', 'Unknown error')}")
            sys.exit(1)
    except Exception as e:
        print(f"Report analysis failed: {str(e)}")
        sys.exit(1)

def save_analysis(analysis, output_file=None):
    """Save analysis results to a file."""
    if not output_file:
        # Generate default filename based on analysis type and timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if 'report_id' in analysis:
            output_file = f"report_analysis_{analysis['report_id']}_{timestamp}.json"
        else:
            output_file = f"{analysis['data_type']}_analysis_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump(analysis, f, indent=2)
    
    print(f"Analysis saved to {output_file}")
    
    # Also save a text-only version of the analysis
    text_file = output_file.replace('.json', '.txt')
    with open(text_file, 'w') as f:
        f.write(analysis['analysis'])
    
    print(f"Analysis text saved to {text_file}")

def display_analysis(analysis):
    """Display analysis results to the console."""
    print("\n" + "="*80)
    print("ANALYSIS RESULTS")
    print("="*80)
    
    if 'report_id' in analysis:
        print(f"Report ID: {analysis['report_id']}")
        print(f"Report Type: {analysis['report_type']}")
    else:
        print(f"Data Type: {analysis['data_type']}")
        print(f"Time Period: {analysis['time_period']}")
    
    print(f"Analyzed At: {analysis['analyzed_at']}")
    print(f"Model: {analysis['model_used']}")
    print("="*80)
    print("\nANALYSIS:\n")
    print(analysis['analysis'])
    print("\n" + "="*80)

def main():
    """Main function to parse arguments and run analysis."""
    parser = argparse.ArgumentParser(description="Klararety - Claude AI Analysis Client")
    
    # Authentication options
    parser.add_argument("--username", help="Klararety username")
    parser.add_argument("--password", help="Klararety password")
    parser.add_argument("--token", help="Klararety API token (if you already have one)")
    
    # Analysis options
    analysis_group = parser.add_mutually_exclusive_group(required=True)
    analysis_group.add_argument("--data-type", help="Type of data to analyze", 
                              choices=["patient_adherence", "patient_vitals", 
                                       "provider_performance", "population_health", 
                                       "medication_efficacy", "telemedicine_usage"])
    analysis_group.add_argument("--report-id", help="ID of an existing report to analyze")
    
    # Common parameters
    parser.add_argument("--time-period", default="30d", 
                      choices=["7d", "30d", "90d", "6m", "1y"],
                      help="Time period for data analysis (default: 30d)")
    parser.add_argument("--reason", required=True, 
                      help="Reason for analysis (required for HIPAA compliance)")
    
    # Custom prompts
    parser.add_argument("--custom-prompt", help="Custom prompt for Claude AI")
    parser.add_argument("--system-prompt", help="Custom system prompt for Claude AI")
    
    # Output options
    parser.add_argument("--output", help="Output file path (default: auto-generated)")
    parser.add_argument("--quiet", action="store_true", 
                      help="Don't display analysis results to console")
    parser.add_argument("--no-save", action="store_true",
                      help="Don't save analysis results to file")
    
    args = parser.parse_args()
    
    # Get authentication token
    if args.token:
        token = args.token
    else:
        token = get_auth_token(API_BASE_URL, args.username, args.password)
    
    # Run analysis
    if args.data_type:
        # Analyze data
        analysis = analyze_data(
            token=token,
            data_type=args.data_type,
            time_period=args.time_period,
            reason=args.reason,
            custom_prompt=args.custom_prompt,
            system_prompt=args.system_prompt
        )
    else:
        # Analyze report
        analysis = analyze_report(
            token=token,
            report_id=args.report_id,
            reason=args.reason,
            custom_prompt=args.custom_prompt,
            system_prompt=args.system_prompt
        )
    
    # Display results
    if not args.quiet:
        display_analysis(analysis)
    
    # Save results
    if not args.no_save:
        save_analysis(analysis, args.output)

if __name__ == "__main__":
    main()
