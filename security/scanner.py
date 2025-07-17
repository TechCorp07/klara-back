"""
Security scanning tools integration for Klararety platform.
Implements automated vulnerability scanning and security testing.
"""
import subprocess
import json
import os
import logging
from django.conf import settings
from datetime import datetime

logger = logging.getLogger('security')

class SecurityScanner:
    """
    Security scanner for automated vulnerability detection.
    Integrates multiple scanning tools for comprehensive security testing.
    """
    
    def __init__(self, output_dir=None):
        """
        Initialize the security scanner.
        
        Args:
            output_dir (str, optional): Directory to store scan results
        """
        self.output_dir = output_dir or os.path.join(settings.BASE_DIR, 'security_scans')
        os.makedirs(self.output_dir, exist_ok=True)
        
    def run_dependency_scan(self):
        """
        Scan Python dependencies for vulnerabilities using safety.
        
        Returns:
            dict: Scan results
        """
        logger.info("Starting dependency vulnerability scan with safety")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f"dependency_scan_{timestamp}.json")
        
        try:
            # Run safety check
            result = subprocess.run(
                ['safety', 'check', '--json', '-o', output_file],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.info("No vulnerabilities found in dependencies")
                return {
                    'status': 'success',
                    'vulnerabilities': [],
                    'message': 'No vulnerabilities found',
                    'output_file': output_file
                }
            else:
                # Parse JSON output
                try:
                    with open(output_file, 'r') as f:
                        vulnerabilities = json.load(f)
                    
                    vuln_count = len(vulnerabilities)
                    logger.warning(f"Found {vuln_count} vulnerabilities in dependencies")
                    return {
                        'status': 'warning',
                        'vulnerabilities': vulnerabilities,
                        'message': f'Found {vuln_count} vulnerabilities',
                        'output_file': output_file
                    }
                except (json.JSONDecodeError, FileNotFoundError) as e:
                    logger.error(f"Failed to parse safety output: {e}")
                    return {
                        'status': 'error',
                        'message': f'Failed to parse safety output: {str(e)}',
                        'output': result.stdout,
                        'output_file': output_file
                    }
                    
        except Exception as e:
            logger.exception(f"Error scanning dependencies: {e}")
            return {
                'status': 'error',
                'message': f'Error scanning dependencies: {str(e)}'
            }
    
    def run_code_scan(self, directory=None):
        """
        Scan code for security issues using bandit.
        
        Args:
            directory (str, optional): Directory to scan. Defaults to project root.
            
        Returns:
            dict: Scan results
        """
        directory = directory or settings.BASE_DIR
        logger.info(f"Starting code security scan with bandit on {directory}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f"code_scan_{timestamp}.json")
        
        try:
            # Run bandit scan
            result = subprocess.run(
                ['bandit', '-r', directory, '-f', 'json', '-o', output_file],
                capture_output=True,
                text=True
            )
            
            # Parse JSON output
            try:
                with open(output_file, 'r') as f:
                    scan_data = json.load(f)
                
                metrics = scan_data.get('metrics', {}).get('_totals', {})
                high_severity = metrics.get('SEVERITY.HIGH', 0)
                medium_severity = metrics.get('SEVERITY.MEDIUM', 0)
                
                if high_severity > 0:
                    logger.warning(f"Found {high_severity} high severity issues in code scan")
                    status = 'warning'
                elif medium_severity > 0:
                    logger.info(f"Found {medium_severity} medium severity issues in code scan")
                    status = 'warning'
                else:
                    logger.info("No significant issues found in code scan")
                    status = 'success'
                
                return {
                    'status': status,
                    'results': scan_data,
                    'message': f"Scan completed: {high_severity} high severity, {medium_severity} medium severity issues found",
                    'output_file': output_file
                }
            except (json.JSONDecodeError, FileNotFoundError) as e:
                logger.error(f"Failed to parse bandit output: {e}")
                return {
                    'status': 'error',
                    'message': f'Failed to parse bandit output: {str(e)}',
                    'output': result.stdout,
                    'output_file': output_file
                }
                
        except Exception as e:
            logger.exception(f"Error scanning code: {e}")
            return {
                'status': 'error',
                'message': f'Error scanning code: {str(e)}'
            }
    
    def run_docker_scan(self, image_name):
        """
        Scan Docker image for vulnerabilities using trivy.
        
        Args:
            image_name (str): Name of Docker image to scan
            
        Returns:
            dict: Scan results
        """
        logger.info(f"Starting Docker image scan with trivy on {image_name}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f"docker_scan_{timestamp}.json")
        
        try:
            # Run trivy scan
            result = subprocess.run(
                ['trivy', 'image', '--format', 'json', '-o', output_file, image_name],
                capture_output=True,
                text=True
            )
            
            # Parse JSON output
            try:
                with open(output_file, 'r') as f:
                    scan_data = json.load(f)
                
                # Count vulnerabilities by severity
                vulnerabilities = scan_data.get('Results', [])
                vuln_count = sum(len(result.get('Vulnerabilities', [])) for result in vulnerabilities)
                critical_count = sum(
                    sum(1 for vuln in result.get('Vulnerabilities', []) if vuln.get('Severity') == 'CRITICAL')
                    for result in vulnerabilities
                )
                high_count = sum(
                    sum(1 for vuln in result.get('Vulnerabilities', []) if vuln.get('Severity') == 'HIGH')
                    for result in vulnerabilities
                )
                
                if critical_count > 0:
                    logger.warning(f"Found {critical_count} critical vulnerabilities in Docker image")
                    status = 'warning'
                elif high_count > 0:
                    logger.warning(f"Found {high_count} high severity vulnerabilities in Docker image")
                    status = 'warning'
                elif vuln_count > 0:
                    logger.info(f"Found {vuln_count} vulnerabilities in Docker image")
                    status = 'warning'
                else:
                    logger.info("No vulnerabilities found in Docker image")
                    status = 'success'
                
                return {
                    'status': status,
                    'results': scan_data,
                    'message': f"Scan completed for {image_name}: {critical_count} critical, {high_count} high severity vulnerabilities found",
                    'output_file': output_file
                }
            except (json.JSONDecodeError, FileNotFoundError) as e:
                logger.error(f"Failed to parse trivy output: {e}")
                return {
                    'status': 'error',
                    'message': f'Failed to parse trivy output: {str(e)}',
                    'output': result.stdout,
                    'output_file': output_file
                }
                
        except Exception as e:
            logger.exception(f"Error scanning Docker image: {e}")
            return {
                'status': 'error',
                'message': f'Error scanning Docker image: {str(e)}'
            }
    
    def run_api_scan(self, api_url, api_spec=None):
        """
        Scan API for security issues using OWASP ZAP.
        
        Args:
            api_url (str): URL of the API to scan
            api_spec (str, optional): Path to OpenAPI specification file
            
        Returns:
            dict: Scan results
        """
        logger.info(f"Starting API security scan with OWASP ZAP on {api_url}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f"api_scan_{timestamp}.json")
        
        try:
            # Build ZAP command
            zap_cmd = ['zap-cli', '--zap-url', 'http://localhost:8080', '--api-key', settings.ZAP_API_KEY, 'quick-scan', '--self-contained', '--spider', api_url]
            
            if api_spec:
                zap_cmd.extend(['--openapi', api_spec])
            
            # Run ZAP scan
            result = subprocess.run(
                zap_cmd,
                capture_output=True,
                text=True
            )
            
            # Get report
            report_cmd = ['zap-cli', '--zap-url', 'http://localhost:8080', '--api-key', settings.ZAP_API_KEY, 'report', '-o', output_file, '-f', 'json']
            report_result = subprocess.run(report_cmd, capture_output=True, text=True)
            
            # Parse JSON output
            try:
                with open(output_file, 'r') as f:
                    scan_data = json.load(f)
                
                # Count alerts by risk
                alerts = scan_data.get('site', [{}])[0].get('alerts', [])
                high_risk = sum(1 for alert in alerts if alert.get('riskcode') == '3')
                medium_risk = sum(1 for alert in alerts if alert.get('riskcode') == '2')
                
                if high_risk > 0:
                    logger.warning(f"Found {high_risk} high risk issues in API scan")
                    status = 'warning'
                elif medium_risk > 0:
                    logger.info(f"Found {medium_risk} medium risk issues in API scan")
                    status = 'warning'
                else:
                    logger.info("No significant issues found in API scan")
                    status = 'success'
                
                return {
                    'status': status,
                    'results': scan_data,
                    'message': f"Scan completed for {api_url}: {high_risk} high risk, {medium_risk} medium risk issues found",
                    'output_file': output_file
                }
            except (json.JSONDecodeError, FileNotFoundError) as e:
                logger.error(f"Failed to parse ZAP output: {e}")
                return {
                    'status': 'error',
                    'message': f'Failed to parse ZAP output: {str(e)}',
                    'output': result.stdout,
                    'output_file': output_file
                }
                
        except Exception as e:
            logger.exception(f"Error scanning API: {e}")
            return {
                'status': 'error',
                'message': f'Error scanning API: {str(e)}'
            }
    
    def run_full_scan(self):
        """
        Run all security scans.
        
        Returns:
            dict: Combined scan results
        """
        logger.info("Starting full security scan")
        results = {}
        
        # Run dependency scan
        results['dependency_scan'] = self.run_dependency_scan()
        
        # Run code scan
        results['code_scan'] = self.run_code_scan()
        
        # Run Docker scan if image is specified
        if hasattr(settings, 'DOCKER_IMAGE'):
            results['docker_scan'] = self.run_docker_scan(settings.DOCKER_IMAGE)
        
        # Run API scan if URL is specified
        if hasattr(settings, 'API_URL'):
            results['api_scan'] = self.run_api_scan(settings.API_URL, getattr(settings, 'API_SPEC', None))
        
        # Generate summary
        critical_issues = 0
        high_issues = 0
        medium_issues = 0
        
        for scan_type, result in results.items():
            if result.get('status') == 'warning':
                if 'critical' in result.get('message', '').lower():
                    critical_issues += 1
                elif 'high' in result.get('message', '').lower():
                    high_issues += 1
                else:
                    medium_issues += 1
        
        if critical_issues > 0:
            summary_status = 'critical'
            summary_message = f"Critical security issues found: {critical_issues} critical, {high_issues} high, {medium_issues} medium"
        elif high_issues > 0:
            summary_status = 'high'
            summary_message = f"High security issues found: {high_issues} high, {medium_issues} medium"
        elif medium_issues > 0:
            summary_status = 'medium'
            summary_message = f"Medium security issues found: {medium_issues} medium"
        else:
            summary_status = 'success'
            summary_message = "No significant security issues found"
        
        logger.info(f"Full security scan completed: {summary_message}")
        
        return {
            'status': summary_status,
            'message': summary_message,
            'results': results,
            'timestamp': datetime.now().isoformat()
        }


def install_security_tools():
    """
    Install required security scanning tools.
    """
    try:
        # Install Python packages
        subprocess.run(['pip', 'install', 'safety', 'bandit', 'zap-cli'], check=True)
        
        # Install trivy
        subprocess.run(['apt-get', 'update'], check=True)
        subprocess.run(['apt-get', 'install', '-y', 'wget', 'apt-transport-https', 'gnupg', 'lsb-release'], check=True)
        subprocess.run(['wget', '-qO', '-', 'https://aquasecurity.github.io/trivy-repo/deb/public.key', '|', 'apt-key', 'add', '-'], check=True, shell=True)
        subprocess.run(['echo', 'deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main', '|', 'tee', '-a', '/etc/apt/sources.list.d/trivy.list'], check=True, shell=True)
        subprocess.run(['apt-get', 'update'], check=True)
        subprocess.run(['apt-get', 'install', '-y', 'trivy'], check=True)
        
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install security tools: {e}")
        return False
    except Exception as e:
        logger.exception(f"Error installing security tools: {e}")
        return False
