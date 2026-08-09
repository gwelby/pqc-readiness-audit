"""
Smart Contract Security Analyzer

This module provides security analysis for Solidity smart contracts,
focusing on common vulnerabilities like reentrancy, overflow, and logic issues.
"""

import re
import os
import json
from pathlib import Path

# Constants from CLAUDE.md
PHI = 1.618033988749895  # Golden ratio
LAMBDA = 0.618033988749895  # Divine complement
PHI_PHI = PHI ** PHI  # Hyperdimensional constant

# Security vulnerability patterns
VULNERABILITY_PATTERNS = [
    {
        "name": "Reentrancy vulnerability",
        "pattern": r"(\w+)\s*\.\s*(?:transfer|send|call).*?(?:.*?balance|.*?mapping.*?\[.*?\].*?=)",
        "description": "External calls followed by state changes may be vulnerable to reentrancy attacks.",
        "severity": "high",
        "phi_factor": 1.0  # highest risk receives full phi factor
    },
    {
        "name": "Unchecked external call",
        "pattern": r"\.call\{.*?\}\(.*?\)(?!\s*(?:returns|return).*?success)",
        "description": "External call return value not checked. Always check return values from send(), call() and external calls.",
        "severity": "high",
        "phi_factor": 0.8
    },
    {
        "name": "Use of tx.origin for authorization",
        "pattern": r"tx\.origin(?!\s*!=)",
        "description": "Using tx.origin for authorization makes a contract vulnerable to phishing attacks.",
        "severity": "high",
        "phi_factor": 0.9
    },
    {
        "name": "Timestamp dependence",
        "pattern": r"(?:block\.timestamp|now).*?(?:==|>=|<=|>|<)",
        "description": "Using block.timestamp (or now) in comparisons can be manipulated by miners.",
        "severity": "medium",
        "phi_factor": 0.7
    },
    {
        "name": "Integer overflow/underflow (pre-0.8.0)",
        "pattern": r"pragma solidity\s*(?:<|0\.[1-7])",
        "description": "Solidity version < 0.8.0 is vulnerable to integer overflow/underflow without SafeMath.",
        "severity": "medium",
        "phi_factor": 0.6
    },
    {
        "name": "Missing zero address check",
        "pattern": r"=\s*address\s*\(.*?\)(?!\s*;.*?require.*?!=\s*address\s*\(\s*0\s*\))",
        "description": "Missing zero address check for critical operations.",
        "severity": "medium",
        "phi_factor": 0.5
    },
    {
        "name": "Unprotected self-destruct",
        "pattern": r"selfdestruct|suicide",
        "description": "Unprotected selfdestruct can be called by anyone.",
        "severity": "critical",
        "phi_factor": 1.0
    },
    {
        "name": "Unchecked arithmetic",
        "pattern": r"pragma solidity\s*(?:<|0\.[1-7]).*?(?:\+\+|\-\-|\+=|\-=|\*=|\/=)",
        "description": "Unchecked arithmetic operations can lead to vulnerabilities if Solidity < 0.8.0.",
        "severity": "medium",
        "phi_factor": 0.6
    },
    {
        "name": "Unprotected Ether withdrawal",
        "pattern": r"(?:transfer|send|call).*?\(.*?\.balance.*?\)",
        "description": "Functions that allow anyone to withdraw all Ether.",
        "severity": "high",
        "phi_factor": 0.9
    },
    {
        "name": "Public function that should be private",
        "pattern": r"function\s+\w+\s*\([^)]*\)\s+public(?!\s+view|\s+pure)",
        "description": "Functions that modify state and don't need to be public should be private/internal.",
        "severity": "low",
        "phi_factor": 0.3
    },
    {
        "name": "Denial of Service (DoS) vulnerability",
        "pattern": r"for\s*\([^;]*;\s*\w+\s*<\s*\w+\.length;\s*[^\)]*\)",
        "description": "Loops over arrays with no upper bound can cause DoS.",
        "severity": "medium",
        "phi_factor": 0.7
    },
    {
        "name": "Logic bug in access control",
        "pattern": r"require\s*\((?:msg\.sender|tx\.origin)\s*==\s*\w+\s*\|\|\s*(?:msg\.sender|tx\.origin)\s*==\s*\w+\s*\)",
        "description": "Suspicious access control logic that allows multiple addresses.",
        "severity": "medium",
        "phi_factor": 0.6
    }
]

# Advanced context-aware patterns that need deeper analysis
ADVANCED_PATTERNS = [
    {
        "name": "State change after external call",
        "description": "State changes after external calls may be vulnerable to reentrancy. Consider using checks-effects-interactions pattern.",
        "severity": "high",
        "phi_factor": 1.0
    },
    {
        "name": "Lack of event emission",
        "description": "Important state changes should emit events for off-chain monitoring.",
        "severity": "low",
        "phi_factor": 0.4
    },
    {
        "name": "Improper access control",
        "description": "Functions that change critical state should have proper access control.",
        "severity": "high",
        "phi_factor": 0.9
    }
]

def analyze_contract_security(file_path):
    """
    Analyze a Solidity contract for security vulnerabilities.
    
    Args:
        file_path: Path to the Solidity contract file
        
    Returns:
        A list of identified security vulnerabilities
    """
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Extract contract name (also handle library and interface)
    contract_match = re.search(r'(?:contract|library|interface)\s+(\w+)', content)
    if not contract_match:
        raise ValueError(f"Could not find contract declaration in {file_path}")
    
    contract_name = contract_match.group(1)
    
    # Find vulnerabilities using patterns
    vulnerabilities = []
    
    for pattern in VULNERABILITY_PATTERNS:
        matches = re.finditer(pattern["pattern"], content)
        
        for match in matches:
            line_no = content[:match.start()].count('\n') + 1
            line_content = content.split('\n')[line_no - 1].strip()
            
            vulnerabilities.append({
                "type": pattern["name"],
                "line": line_no,
                "code": line_content,
                "description": pattern["description"],
                "severity": pattern["severity"],
                "phi_factor": pattern["phi_factor"]
            })
    
    # Perform advanced context-aware analysis
    if detect_state_change_after_call(content):
        vulnerabilities.append({
            "type": "State change after external call",
            "line": None,  # This is a whole-contract issue
            "code": None,
            "description": "Potential reentrancy vulnerability: state changes after external calls detected",
            "severity": "high",
            "phi_factor": 1.0
        })
    
    if detect_missing_events(content):
        vulnerabilities.append({
            "type": "Lack of event emission",
            "line": None,
            "code": None,
            "description": "State-changing functions detected without event emissions",
            "severity": "low",
            "phi_factor": 0.4
        })
    
    if detect_improper_access_control(content):
        vulnerabilities.append({
            "type": "Improper access control",
            "line": None,
            "code": None,
            "description": "Critical functions found without proper access control",
            "severity": "high",
            "phi_factor": 0.9
        })
    
    return {
        "contract_name": contract_name,
        "file_path": file_path,
        "vulnerabilities": vulnerabilities
    }

def detect_state_change_after_call(content):
    """Detect if state changes occur after external calls (reentrancy risk)."""
    # Find all external calls
    external_calls = re.finditer(r'(\w+)\s*\.\s*(?:transfer|send|call)', content)
    
    for match in external_calls:
        # Get the position of the external call
        call_pos = match.end()
        
        # Check if there's a state change after the call in the same function
        # We'll look for the end of the function
        function_start = content[:call_pos].rfind('function')
        function_end = content[call_pos:].find('}')
        
        if function_start != -1 and function_end != -1:
            function_body = content[call_pos:call_pos + function_end]
            
            # Check for state changes (assignments to storage variables)
            if re.search(r'(?:mapping|\w+\s*\[\s*\w*\s*\])\s*=', function_body):
                return True
    
    return False

def detect_missing_events(content):
    """Detect if state-changing functions don't emit events."""
    # Find all non-view/pure functions
    functions = re.finditer(r'function\s+(\w+)\s*\([^)]*\)\s*(?:public|external)(?!\s+(?:view|pure))', content)
    
    for match in functions:
        func_name = match.group(1)
        func_start = match.start()
        
        # Find the function body
        open_brace = content[func_start:].find('{') + func_start
        
        if open_brace != -1:
            # Find the matching closing brace
            brace_count = 1
            pos = open_brace + 1
            
            while brace_count > 0 and pos < len(content):
                if content[pos] == '{':
                    brace_count += 1
                elif content[pos] == '}':
                    brace_count -= 1
                pos += 1
            
            if brace_count == 0:
                function_body = content[open_brace:pos]
                
                # Check if the function modifies state
                if re.search(r'(?:mapping|\w+\s*\[\s*\w*\s*\])\s*=|\w+\s*=', function_body):
                    # Check if the function emits events
                    if not re.search(r'emit\s+\w+', function_body):
                        return True
    
    return False

def detect_improper_access_control(content):
    """Detect if critical functions lack proper access control."""
    # Find critical operations
    critical_ops = [
        r'selfdestruct', r'suicide',  # Self-destruct
        r'transfer\s*\(', r'send\s*\(',  # Ether transfers
        r'_owner\s*=', r'owner\s*='  # Ownership changes
    ]
    
    for op in critical_ops:
        matches = re.finditer(op, content)
        
        for match in matches:
            op_pos = match.start()
            
            # Find the containing function
            function_start = content[:op_pos].rfind('function')
            
            if function_start != -1:
                # Check if the function has access control
                function_header = content[function_start:op_pos]
                
                # Look for access control modifiers/requires
                if not re.search(r'onlyOwner|require\s*\(\s*(?:msg\.sender|tx\.origin)\s*==', function_header):
                    return True
    
    return False

def calculate_security_score(vulnerabilities):
    """
    Calculate a security score based on vulnerabilities using phi-harmonic principles.
    
    Returns a score between 0 and 1, where 1 is most secure.
    """
    if not vulnerabilities:
        return 1.0  # Perfect score if no vulnerabilities
    
    # Total phi_factor for all vulnerabilities
    total_phi_factor = sum(vuln["phi_factor"] for vuln in vulnerabilities)
    
    # Apply phi scaling (more vulnerabilities have compounding effect)
    scaled_factor = total_phi_factor * (1 + LAMBDA * len(vulnerabilities) / PHI)
    
    # Convert to a score between 0 and 1
    security_score = max(0, 1 - (scaled_factor * LAMBDA))
    
    return round(security_score, 2)

def generate_security_report(analysis_result, output_dir=None):
    """
    Generate a comprehensive security report.
    
    Args:
        analysis_result: The result of analyze_contract_security()
        output_dir: Optional directory to write the report to
    
    Returns:
        The report as a dictionary and writes a JSON file if output_dir provided
    """
    contract_name = analysis_result["contract_name"]
    vulnerabilities = analysis_result["vulnerabilities"]
    
    # Calculate security score
    security_score = calculate_security_score(vulnerabilities)
    
    # Group vulnerabilities by severity
    severity_groups = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": []
    }
    
    for vuln in vulnerabilities:
        severity = vuln["severity"]
        if severity in severity_groups:
            severity_groups[severity].append(vuln)
    
    # Prepare report
    report = {
        "contract_name": contract_name,
        "file_path": analysis_result["file_path"],
        "security_score": security_score,
        "vulnerability_count": len(vulnerabilities),
        "severity_summary": {
            severity: len(vulns) for severity, vulns in severity_groups.items() if len(vulns) > 0
        },
        "vulnerabilities_by_severity": severity_groups
    }
    
    # Write report to file if output directory provided
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        report_path = os.path.join(output_dir, f"security_report_{contract_name}.json")
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Also generate a human-readable text report
        txt_report_path = os.path.join(output_dir, f"security_report_{contract_name}.txt")
        
        with open(txt_report_path, 'w') as f:
            f.write(f"Security Report for {contract_name}\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Security Score: {security_score:.2f}/1.0\n")
            f.write(f"Total Vulnerabilities: {len(vulnerabilities)}\n\n")
            
            # Write severity summary
            if report["severity_summary"]:
                f.write("Vulnerability Summary by Severity:\n")
                f.write("-"*60 + "\n")
                
                for severity, count in report["severity_summary"].items():
                    f.write(f"- {severity.upper()}: {count}\n")
            
            # Write detailed vulnerabilities
            f.write("\nDetailed Vulnerabilities:\n")
            f.write("-"*60 + "\n")
            
            for severity in ["critical", "high", "medium", "low"]:
                vulns = severity_groups[severity]
                
                if vulns:
                    f.write(f"\n{severity.upper()} Severity Issues:\n")
                    f.write("-"*40 + "\n")
                    
                    for i, vuln in enumerate(vulns):
                        f.write(f"Issue {i+1}: {vuln['type']}\n")
                        if vuln['line']:
                            f.write(f"Line {vuln['line']}: {vuln['code']}\n")
                        f.write(f"Description: {vuln['description']}\n\n")
            
            # Add recommendations
            f.write("\nRecommendations:\n")
            f.write("-"*60 + "\n")
            
            if len(vulnerabilities) == 0:
                f.write("No vulnerabilities detected. The contract appears secure based on our analysis.\n")
            else:
                for severity in ["critical", "high", "medium", "low"]:
                    for vuln in severity_groups[severity]:
                        vuln_type = vuln["type"]
                        
                        if vuln_type == "Reentrancy vulnerability":
                            f.write("- Implement the checks-effects-interactions pattern: perform all state changes before external calls.\n")
                        elif vuln_type == "Unchecked external call":
                            f.write("- Always check return values from low-level external calls (send, call).\n")
                        elif vuln_type == "Use of tx.origin for authorization":
                            f.write("- Use msg.sender instead of tx.origin for authorization checks.\n")
                        elif vuln_type == "Timestamp dependence":
                            f.write("- Avoid using block.timestamp for critical logic; it can be manipulated by miners.\n")
                        elif vuln_type == "Integer overflow/underflow":
                            f.write("- Use SafeMath library for arithmetic operations or upgrade to Solidity 0.8.0+.\n")
                        elif vuln_type == "Missing zero address check":
                            f.write("- Add zero address validation before critical operations.\n")
                        elif vuln_type == "Unprotected self-destruct":
                            f.write("- Add proper access control to functions that use selfdestruct.\n")
                        elif vuln_type == "Unchecked arithmetic":
                            f.write("- Use SafeMath library or upgrade to Solidity 0.8.0+ which has built-in overflow checking.\n")
                        elif vuln_type == "Unprotected Ether withdrawal":
                            f.write("- Add access control to functions that transfer Ether.\n")
                        elif vuln_type == "State change after external call":
                            f.write("- Restructure code to perform all state changes before making external calls.\n")
                        elif vuln_type == "Lack of event emission":
                            f.write("- Emit events for all important state changes to enable off-chain monitoring.\n")
                        elif vuln_type == "Improper access control":
                            f.write("- Add proper access control mechanisms (e.g., onlyOwner modifier) to critical functions.\n")
    
    return report, report_path if output_dir else None

def run_security_analysis(contract_path, output_dir=None):
    """Run complete security analysis on a contract."""
    try:
        # Analyze contract
        analysis = analyze_contract_security(contract_path)
        
        # Generate report
        report, report_path = generate_security_report(analysis, output_dir)
        
        # Print summary
        print(f"\nSecurity Analysis for {report['contract_name']}")
        print("="*60)
        print(f"Security Score: {report['security_score']:.2f}/1.0")
        print(f"Total Vulnerabilities: {report['vulnerability_count']}")
        
        if report['vulnerability_count'] > 0:
            print("\nVulnerability Summary:")
            for severity, count in report["severity_summary"].items():
                print(f"- {severity.upper()}: {count}")
            
            if output_dir:
                print(f"\nDetailed reports saved to:")
                print(f"- {report_path}")
                print(f"- {os.path.splitext(report_path)[0]}.txt")
        else:
            print("\nNo vulnerabilities detected! Your contract appears secure based on our analysis.")
        
        return report
        
    except Exception as e:
        print(f"Error analyzing contract security: {str(e)}")
        return None

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze Solidity contracts for security vulnerabilities')
    parser.add_argument('contract', help='Path to the Solidity contract file')
    parser.add_argument('--output', '-o', help='Directory to save the report')
    
    args = parser.parse_args()
    run_security_analysis(args.contract, args.output)