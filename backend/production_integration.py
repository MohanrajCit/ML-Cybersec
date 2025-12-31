"""
Production Integration Example
===============================
Shows how to integrate CVE real-time processing into production systems.
"""

import logging
import json
from datetime import datetime
from typing import List, Dict
from cve_realtime_processor import (
    process_new_cves,
    predict_risk,
    detect_anomaly
)

# Configure production logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cve_processing.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class CVEMonitor:
    """
    Production-ready CVE monitoring system.
    """
    
    def __init__(self, api_key: str = None):
        """
        Initialize CVE monitor.
        
        Args:
            api_key (str, optional): NVD API key
        """
        self.api_key = api_key
        logger.info("CVE Monitor initialized")
    
    def fetch_and_analyze(self, days_back: int = 1, max_results: int = 100) -> Dict:
        """
        Fetch and analyze recent CVEs.
        
        Args:
            days_back (int): Days to look back
            max_results (int): Maximum CVEs to process
        
        Returns:
            dict: Analysis summary with categorized results
        """
        logger.info(f"Starting CVE analysis (days_back={days_back}, max={max_results})")
        
        try:
            # Fetch and process CVEs
            results = process_new_cves(
                days_back=days_back,
                max_results=max_results,
                api_key=self.api_key
            )
            
            # Categorize results
            summary = self._categorize_results(results)
            
            # Log summary
            logger.info(
                f"Analysis complete: {summary['total']} CVEs - "
                f"High Risk: {summary['high_risk_count']}, "
                f"Anomalous: {summary['anomalous_count']}"
            )
            
            return summary
        
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            raise
    
    def _categorize_results(self, results: List[Dict]) -> Dict:
        """
        Categorize analysis results.
        
        Args:
            results (list): Raw analysis results
        
        Returns:
            dict: Categorized summary
        """
        high_risk = [r for r in results if r['risk'] == 'HIGH']
        low_risk = [r for r in results if r['risk'] == 'LOW']
        anomalous = [r for r in results if r['anomalous']]
        critical_anomalies = [
            r for r in results 
            if r['risk'] == 'HIGH' and r['anomalous']
        ]
        
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'total': len(results),
            'high_risk_count': len(high_risk),
            'low_risk_count': len(low_risk),
            'anomalous_count': len(anomalous),
            'critical_anomalies_count': len(critical_anomalies),
            'high_risk_cves': high_risk,
            'low_risk_cves': low_risk,
            'anomalous_cves': anomalous,
            'critical_anomalies': critical_anomalies,
            'all_results': results
        }
    
    def generate_report(self, summary: Dict, output_file: str = None) -> str:
        """
        Generate human-readable report.
        
        Args:
            summary (dict): Analysis summary
            output_file (str, optional): Output file path
        
        Returns:
            str: Report text
        """
        report_lines = [
            "="*80,
            "CVE RISK ANALYSIS REPORT",
            "="*80,
            f"Generated: {summary['timestamp']}",
            f"Analysis Period: Last {summary.get('days_analyzed', 'N/A')} days",
            "",
            "SUMMARY",
            "-"*80,
            f"Total CVEs Analyzed:      {summary['total']}",
            f"High Risk CVEs:           {summary['high_risk_count']}",
            f"Low Risk CVEs:            {summary['low_risk_count']}",
            f"Anomalous Patterns:       {summary['anomalous_count']}",
            f"Critical Anomalies:       {summary['critical_anomalies_count']}",
            ""
        ]
        
        # Critical anomalies section
        if summary['critical_anomalies']:
            report_lines.extend([
                "⚠️  CRITICAL ANOMALIES (High Risk + Anomalous)",
                "-"*80
            ])
            for cve in summary['critical_anomalies']:
                report_lines.append(
                    f"  • {cve['cve_id']}: Risk={cve['risk']}, "
                    f"Confidence={cve['confidence']:.1%}"
                )
            report_lines.append("")
        
        # High risk CVEs
        if summary['high_risk_cves']:
            report_lines.extend([
                "🚨 HIGH RISK CVEs",
                "-"*80
            ])
            for cve in summary['high_risk_cves'][:10]:  # Top 10
                anomaly_flag = "⚠️" if cve['anomalous'] else "  "
                report_lines.append(
                    f"  {anomaly_flag} {cve['cve_id']}: "
                    f"Confidence={cve['confidence']:.1%}"
                )
            if len(summary['high_risk_cves']) > 10:
                report_lines.append(f"  ... and {len(summary['high_risk_cves']) - 10} more")
            report_lines.append("")
        
        report_lines.append("="*80)
        
        report_text = "\n".join(report_lines)
        
        # Save to file if specified
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            logger.info(f"Report saved to {output_file}")
        
        return report_text
    
    def save_results(self, summary: Dict, output_file: str):
        """
        Save results to JSON file.
        
        Args:
            summary (dict): Analysis summary
            output_file (str): Output file path
        """
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        logger.info(f"Results saved to {output_file}")


def scheduled_monitoring():
    """
    Example: Scheduled monitoring job (e.g., run daily via cron)
    """
    logger.info("="*60)
    logger.info("Starting scheduled CVE monitoring")
    logger.info("="*60)
    
    try:
        # Initialize monitor
        monitor = CVEMonitor()
        
        # Analyze last 24 hours
        summary = monitor.fetch_and_analyze(days_back=1, max_results=50)
        
        # Generate report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"cve_report_{timestamp}.txt"
        json_file = f"cve_results_{timestamp}.json"
        
        report = monitor.generate_report(summary, output_file=report_file)
        monitor.save_results(summary, output_file=json_file)
        
        # Send alerts if critical anomalies found
        if summary['critical_anomalies_count'] > 0:
            logger.warning(
                f"⚠️  ALERT: {summary['critical_anomalies_count']} "
                f"critical anomalies detected!"
            )
            # TODO: Send email/webhook notification
        
        logger.info("Scheduled monitoring completed successfully")
        return summary
    
    except Exception as e:
        logger.error(f"Scheduled monitoring failed: {e}")
        raise


def on_demand_analysis(cve_description: str) -> Dict:
    """
    Example: On-demand analysis of a single CVE description.
    
    Args:
        cve_description (str): CVE description text
    
    Returns:
        dict: Analysis result
    """
    logger.info("Starting on-demand CVE analysis")
    
    try:
        # Predict risk
        risk_result = predict_risk(cve_description)
        
        # Detect anomaly
        anomaly_result = detect_anomaly(cve_description)
        
        # Combine results
        result = {
            'description_preview': cve_description[:100] + "...",
            'risk': risk_result['risk'],
            'confidence': risk_result['confidence'],
            'anomalous': anomaly_result['anomalous'],
            'anomaly_score': anomaly_result['anomaly_score'],
            'timestamp': datetime.utcnow().isoformat()
        }
        
        logger.info(
            f"Analysis complete: Risk={result['risk']}, "
            f"Anomalous={result['anomalous']}"
        )
        
        return result
    
    except Exception as e:
        logger.error(f"On-demand analysis failed: {e}")
        raise


def webhook_integration(webhook_url: str, summary: Dict):
    """
    Example: Send results to webhook (Slack, Teams, etc.)
    
    Args:
        webhook_url (str): Webhook URL
        summary (dict): Analysis summary
    """
    import requests
    
    message = {
        "text": f"CVE Analysis Alert: {summary['critical_anomalies_count']} critical anomalies detected",
        "attachments": [
            {
                "title": "CVE Analysis Summary",
                "fields": [
                    {"title": "Total CVEs", "value": str(summary['total']), "short": True},
                    {"title": "High Risk", "value": str(summary['high_risk_count']), "short": True},
                    {"title": "Anomalous", "value": str(summary['anomalous_count']), "short": True},
                    {"title": "Critical", "value": str(summary['critical_anomalies_count']), "short": True}
                ],
                "color": "danger" if summary['critical_anomalies_count'] > 0 else "good"
            }
        ]
    }
    
    try:
        response = requests.post(webhook_url, json=message, timeout=10)
        response.raise_for_status()
        logger.info("Webhook notification sent successfully")
    except Exception as e:
        logger.error(f"Failed to send webhook notification: {e}")


# ===========================
# Example Usage
# ===========================

if __name__ == "__main__":
    print("\n" + "="*80)
    print("PRODUCTION INTEGRATION EXAMPLES")
    print("="*80 + "\n")
    
    # Example 1: Scheduled monitoring
    print("Example 1: Scheduled Monitoring")
    print("-"*80)
    try:
        summary = scheduled_monitoring()
        print(f"✅ Success: Analyzed {summary['total']} CVEs\n")
    except Exception as e:
        print(f"❌ Error: {e}\n")
    
    # Example 2: On-demand analysis
    print("Example 2: On-Demand Analysis")
    print("-"*80)
    test_description = "Remote code execution via SQL injection in web application"
    try:
        result = on_demand_analysis(test_description)
        print(f"✅ Risk: {result['risk']} ({result['confidence']:.1%})")
        print(f"   Anomalous: {result['anomalous']}\n")
    except Exception as e:
        print(f"❌ Error: {e}\n")
    
    print("="*80)
    print("See code for webhook integration and other examples")
    print("="*80 + "\n")
