import io
import csv
import json
import logging
from datetime import datetime
import pandas as pd
import xlsxwriter
from django.utils import timezone
from django.conf import settings
from django.http import HttpResponse
import os

logger = logging.getLogger('hipaa_audit')


class DataExportService:
    """Service for exporting data in various formats."""
    
    def export_report(self, report, export_format):
        """
        Export a report in the specified format.
        
        Args:
            report: Report instance to export
            export_format: Format to export (csv, excel, json, pdf)
            
        Returns:
            tuple: (file_content, file_name, content_type, file_size)
        """
        # Check if report is completed
        if report.status != 'COMPLETED':
            raise ValueError("Cannot export an incomplete report.")
        
        # Check if results are available
        if not report.results_json:
            raise ValueError("Report has no results to export.")
        
        # Get report data
        report_data = report.results_json
        config = report.configuration
        
        # Prepare filename base
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        filename_base = f"{config.report_type}_{timestamp}"
        
        # Export in the requested format
        if export_format == 'csv':
            return self._export_as_csv(report_data, filename_base)
        elif export_format == 'excel':
            return self._export_as_excel(report_data, filename_base)
        elif export_format == 'json':
            return self._export_as_json(report_data, filename_base)
        elif export_format == 'pdf':
            return self._export_as_pdf(report_data, filename_base)
        else:
            raise ValueError(f"Unsupported export format: {export_format}")
    
    def _export_as_csv(self, report_data, filename_base):
        """Export report data as CSV."""
        # Flatten the data structure for CSV export
        flattened_data = self._flatten_report_data(report_data)
        
        # Prepare CSV content
        output = io.StringIO()
        
        if flattened_data:
            # Initialize CSV writer
            writer = csv.DictWriter(output, fieldnames=flattened_data[0].keys())
            writer.writeheader()
            writer.writerows(flattened_data)
        else:
            # Write empty CSV with headers for report type and timestamp
            writer = csv.writer(output)
            writer.writerow(['Report Type', 'Generated At'])
            writer.writerow([report_data.get('report_type', 'Unknown'), 
                             report_data.get('generated_at', timezone.now().isoformat())])
        
        file_content = output.getvalue()
        file_name = f"{filename_base}.csv"
        content_type = 'text/csv'
        file_size = len(file_content)
        
        return file_content, file_name, content_type, file_size
    
    def _export_as_excel(self, report_data, filename_base):
        """Export report data as Excel spreadsheet."""
        # Flatten the data structure for Excel export
        # Multiple sections will become different sheets
        
        # Create in-memory Excel file
        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output)
        
        # Add metadata sheet
        metadata_sheet = workbook.add_worksheet('Metadata')
        metadata_sheet.write(0, 0, 'Report Type')
        metadata_sheet.write(0, 1, report_data.get('report_type', 'Unknown'))
        metadata_sheet.write(1, 0, 'Generated At')
        metadata_sheet.write(1, 1, report_data.get('generated_at', timezone.now().isoformat()))
        metadata_sheet.write(2, 0, 'Time Period')
        metadata_sheet.write(2, 1, report_data.get('time_period', 'Unknown'))
        
        # Add summary metrics sheet
        if 'metrics' in report_data:
            metrics_sheet = workbook.add_worksheet('Summary Metrics')
            row = 0
            for key, value in report_data['metrics'].items():
                metrics_sheet.write(row, 0, key)
                metrics_sheet.write(row, 1, value)
                row += 1
        
        # Process each major section in the report
        for key, data in report_data.items():
            # Skip metadata fields
            if key in ['report_type', 'generated_at', 'time_period', 'metrics']:
                continue
            
            # Skip non-list data
            if not isinstance(data, list):
                continue
            
            # Create sheet for this section
            sheet_name = key[:31]  # Excel limits sheet names to 31 chars
            sheet = workbook.add_worksheet(sheet_name)
            
            # Check if we have data to write
            if not data:
                sheet.write(0, 0, 'No data available')
                continue
            
            # Write headers
            for col, header in enumerate(data[0].keys()):
                sheet.write(0, col, header)
            
            # Write data
            for row, item in enumerate(data, start=1):
                for col, (_, value) in enumerate(item.items()):
                    sheet.write(row, col, value)
        
        # Close the workbook
        workbook.close()
        
        # Get the content
        output.seek(0)
        file_content = output.getvalue()
        file_name = f"{filename_base}.xlsx"
        content_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        file_size = len(file_content)
        
        return file_content, file_name, content_type, file_size
    
    def _export_as_json(self, report_data, filename_base):
        """Export report data as JSON."""
        file_content = json.dumps(report_data, indent=2)
        file_name = f"{filename_base}.json"
        content_type = 'application/json'
        file_size = len(file_content)
        
        return file_content, file_name, content_type, file_size
    
    def _export_as_pdf(self, report_data, filename_base):
        """
        Export report data as PDF.
        
        Note: A real implementation would use a PDF generation library like
        ReportLab, WeasyPrint, or xhtml2pdf to create a well-formatted PDF.
        For this example, we'll simulate PDF generation.
        """
        try:
            # Import PDF generation library
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            
            # Create PDF content
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            elements = []
            
            # Add title
            report_type = report_data.get('report_type', 'Unknown').replace('_', ' ').title()
            title = Paragraph(f"{report_type} Report", styles['Title'])
            elements.append(title)
            elements.append(Spacer(1, 12))
            
            # Add metadata
            elements.append(Paragraph(f"Generated At: {report_data.get('generated_at', timezone.now().isoformat())}", styles['Normal']))
            elements.append(Paragraph(f"Time Period: {report_data.get('time_period', 'Unknown')}", styles['Normal']))
            elements.append(Spacer(1, 12))
            
            # Add summary metrics
            if 'metrics' in report_data:
                elements.append(Paragraph("Summary Metrics", styles['Heading2']))
                metrics_data = [['Metric', 'Value']]
                for key, value in report_data['metrics'].items():
                    metrics_data.append([key.replace('_', ' ').title(), str(value)])
                
                metrics_table = Table(metrics_data, colWidths=[300, 200])
                metrics_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                elements.append(metrics_table)
                elements.append(Spacer(1, 12))
            
            # Process each major section in the report that contains list data
            for key, data in report_data.items():
                # Skip metadata fields
                if key in ['report_type', 'generated_at', 'time_period', 'metrics']:
                    continue
                
                # Skip non-list data
                if not isinstance(data, list) or not data:
                    continue
                
                # Add section title
                section_title = key.replace('_', ' ').title()
                elements.append(Paragraph(section_title, styles['Heading2']))
                elements.append(Spacer(1, 12))
                
                # Create table for this section
                table_data = [list(data[0].keys())]
                for item in data:
                    table_data.append(list(item.values()))
                
                # Create table with auto-width columns
                table = Table(table_data)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                elements.append(table)
                elements.append(Spacer(1, 12))
            
            # Build PDF
            doc.build(elements)
            
            # Get the content
            pdf_content = buffer.getvalue()
            buffer.close()
            
            file_name = f"{filename_base}.pdf"
            content_type = 'application/pdf'
            file_size = len(pdf_content)
            
            return pdf_content, file_name, content_type, file_size
            
        except ImportError:
            # If ReportLab is not available, indicate this in the response
            error_content = "PDF generation requires ReportLab library. Please install it or choose another format."
            file_name = "error.txt"
            content_type = 'text/plain'
            file_size = len(error_content)
            
            return error_content, file_name, content_type, file_size
    
    def _flatten_report_data(self, report_data):
        """
        Flatten the report data structure for CSV/Excel export.
        
        This method extracts and flattens tabular data from the report.
        For complex reports, it will focus on the main data section.
        """
        # Find the main data section (typically the largest list in the report)
        main_data = []
        main_data_key = None
        main_data_length = 0
        
        for key, value in report_data.items():
            if isinstance(value, list) and len(value) > main_data_length:
                main_data = value
                main_data_key = key
                main_data_length = len(value)
        
        # If we found some tabular data, return it
        if main_data_length > 0:
            logger.info(f"Using {main_data_key} as main data section for export with {main_data_length} rows")
            return main_data
        
        # If no tabular data found, create a flattened representation of metrics
        if 'metrics' in report_data:
            flattened_metrics = []
            for key, value in report_data['metrics'].items():
                flattened_metrics.append({'metric': key, 'value': value})
            return flattened_metrics
        
        # Last resort: create a simple key-value representation
        flattened = []
        for key, value in report_data.items():
            if isinstance(value, (str, int, float, bool)) or value is None:
                flattened.append({'field': key, 'value': value})
        
        return flattened
    
    def get_record_count(self, report):
        """
        Get the number of records included in the report.
        
        This is used for HIPAA compliance tracking of exported PHI.
        """
        try:
            # Try to get count from metrics
            if 'metrics' in report.results_json:
                metrics = report.results_json['metrics']
                if 'total_records' in metrics:
                    return metrics['total_records']
                elif 'total_patients' in metrics:
                    return metrics['total_patients']
            
            # Count items in the main data section
            for key, value in report.results_json.items():
                if isinstance(value, list):
                    return len(value)
            
            # Default to 1 if we can't determine the count
            return 1
            
        except Exception:
            # Default to 1 if any error occurs
            return 1
