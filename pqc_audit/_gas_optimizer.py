#!/usr/bin/env python3
"""
Gas Optimization Analyzer

This module analyzes Solidity smart contracts for gas optimization opportunities
and provides recommendations for improving gas efficiency.
"""

import re
import os
import json
from pathlib import Path

# Constants from CLAUDE.md
PHI = 1.618033988749895  # Golden ratio
LAMBDA = 0.618033988749895  # Divine complement

# Gas optimization patterns with automatic fix information
GAS_PATTERNS = [
    {
        "name": "Use uint256 instead of smaller uints",
        "pattern": r"uint8|uint16|uint32|uint64|uint128",
        "recommendation": "Use uint256 instead of smaller uints, as EVM operates on 256-bit words. Smaller uints actually consume more gas due to additional conversion operations.",
        "can_auto_fix": True,
        "fix_type": "direct_replacement",
        "replacement_map": {
            "uint8": "uint256",
            "uint16": "uint256",
            "uint32": "uint256",
            "uint64": "uint256",
            "uint128": "uint256"
        }
    },
    {
        "name": "Use calldata instead of memory for read-only function parameters",
        "pattern": r"function\s+\w+\s*\(.*memory\s+(\w+).*\)\s+(external|public)\s+(view|pure)",
        "recommendation": "Use calldata instead of memory for read-only function parameters in external functions to save gas.",
        "can_auto_fix": True,
        "fix_type": "regex_replacement",
        "search_pattern": r"(function\s+\w+\s*\(.*?)memory(\s+\w+.*?\)\s+(?:external|public)\s+(?:view|pure))",
        "replacement": r"\1calldata\2"
    },
    {
        "name": "Use immutable for constants",
        "pattern": r"(uint|int|address|bool)\s+(public|private|internal)\s+(\w+)\s*=",
        "recommendation": "Use immutable for constants that are set in the constructor to save gas.",
        "can_auto_fix": True,
        "fix_type": "regex_replacement",
        "search_pattern": r"((?:uint|int|address|bool)(?:256|8|16|32|64|128)?)\s+((?:public|private|internal))\s+(\w+\s*=)",
        "replacement": r"\1 \2 immutable \3"
    },
    {
        "name": "Multiple address mappings can be combined",
        "pattern": r"mapping\s*\(\s*address\s*=>\s*\w+\s*\)\s*\w+\s*;.*mapping\s*\(\s*address\s*=>\s*\w+\s*\)",
        "recommendation": "Multiple address mappings can be combined into a single mapping to a struct to save storage slots.",
        "can_auto_fix": False,
        "fix_description": "This optimization requires analysis of related mappings and creation of a struct, which needs manual implementation."
    },
    {
        "name": "Use != 0 instead of > 0 for unsigned integers",
        "pattern": r"(\w+)\s*>\s*0",
        "recommendation": "Use != 0 instead of > 0 for unsigned integers to save gas.",
        "can_auto_fix": True,
        "fix_type": "regex_replacement",
        "search_pattern": r"(\w+)\s*>\s*0",
        "replacement": r"\1 != 0"
    },
    {
        "name": "Cache array length in loops",
        "pattern": r"for\s*\(\s*\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\.length\s*;",
        "recommendation": "Cache array length in a variable before the loop to avoid reading it in each iteration.",
        "can_auto_fix": True,
        "fix_type": "advanced_replacement",
        "fix_function": "generate_array_length_caching_fix"
    },
    {
        "name": "Prefix increments are cheaper than postfix",
        "pattern": r"(\w+)\+\+",
        "recommendation": "Use ++i instead of i++ to save gas (pre-increment is more efficient than post-increment).",
        "can_auto_fix": True,
        "fix_type": "regex_replacement",
        "search_pattern": r"(\w+)\+\+",
        "replacement": r"++\1"
    },
    {
        "name": "Short-circuit evaluation",
        "pattern": r"if\s*\(\s*\w+\s*[!=><]=\s*\w+\s*&&\s*\w+\s*[!=><]=\s*\w+",
        "recommendation": "Order conditions by gas cost (cheaper checks first) to leverage short-circuit evaluation.",
        "can_auto_fix": False,
        "fix_description": "This optimization requires analyzing the gas cost of each condition and reordering, which needs manual assessment."
    },
    {
        "name": "Use custom errors instead of require with string message",
        "pattern": r"require\s*\([^)]+,\s*[\"\'][^\"\']+[\"\']\s*\)",
        "recommendation": "Use custom errors (error CustomError();) instead of require with string messages to save gas.",
        "can_auto_fix": True,
        "fix_type": "advanced_replacement",
        "fix_function": "generate_custom_error_fix"
    },
    {
        "name": "Pack variables",
        "pattern": r"(uint256|address)(\s+\w+\s*;)(?:\s*)(uint8|bool|uint16)(\s+\w+\s*;)",
        "recommendation": "Reorder variables to pack smaller ones together within the same storage slot. Group uint8, bool together with higher size variables.",
        "can_auto_fix": False,
        "fix_description": "This optimization requires analyzing storage layout and carefully reordering variables, which needs manual implementation."
    }
]

def analyze_contract(file_path):
    """
    Analyze a Solidity contract for gas optimization opportunities.
    
    Args:
        file_path: Path to the Solidity contract file
        
    Returns:
        A list of optimization recommendations
    """
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Extract contract name (also handle library and interface)
    contract_match = re.search(r'(?:contract|library|interface)\s+(\w+)', content)
    if not contract_match:
        raise ValueError(f"Could not find contract declaration in {file_path}")
    
    contract_name = contract_match.group(1)
    
    # Find optimization opportunities
    recommendations = []
    
    for pattern in GAS_PATTERNS:
        matches = re.finditer(pattern["pattern"], content)
        matches_found = False
        
        for match in matches:
            matches_found = True
            line_no = content[:match.start()].count('\n') + 1
            line_content = content.split('\n')[line_no - 1].strip()
            
            # Get a few lines of context
            start_line = max(0, line_no - 3)
            end_line = min(len(content.split('\n')), line_no + 2)
            context_lines = content.split('\n')[start_line:end_line]
            
            # Calculate potential gas savings (rough estimate based on pattern type)
            savings = estimate_gas_savings(pattern["name"], line_content)
            
            recommendations.append({
                "type": pattern["name"],
                "line": line_no,
                "code": line_content,
                "context": context_lines,
                "recommendation": pattern["recommendation"],
                "estimated_savings": savings
            })
        
    # Sort recommendations by estimated gas savings
    recommendations.sort(key=lambda x: x["estimated_savings"], reverse=True)
    
    return {
        "contract_name": contract_name,
        "file_path": file_path,
        "recommendations": recommendations
    }

def estimate_gas_savings(pattern_name, code_line):
    """
    Estimate potential gas savings for each optimization type.
    These are rough estimates based on common gas costs.
    """
    # Base estimates in gas units
    estimates = {
        "Use uint256 instead of smaller uints": 200,
        "Use calldata instead of memory for read-only function parameters": 600,
        "Use immutable for constants": 20000,
        "Multiple address mappings can be combined": 5000,
        "Use != 0 instead of > 0 for unsigned integers": 300,
        "Cache array length in loops": lambda code: 1000 * code.count("length"),
        "Prefix increments are cheaper than postfix": 5,
        "Short-circuit evaluation": 2000,
        "Use custom errors instead of require with string message": 2100,
        "Pack variables": 20000
    }
    
    # Get the estimate
    estimate = estimates.get(pattern_name, 100)
    
    # If the estimate is a function, call it with the code line
    if callable(estimate):
        return estimate(code_line)
    
    return estimate

def calculate_phi_resonance(recommendations):
    """
    Calculate the phi resonance score of the contract based on gas optimizations.
    A higher score means more optimization opportunities.
    """
    if not recommendations:
        return 1.0  # Perfect score if no recommendations
    
    # Weight different optimization types based on impact
    weights = {
        "Use uint256 instead of smaller uints": 0.5,
        "Use calldata instead of memory for read-only function parameters": 0.7,
        "Use immutable for constants": 0.6,
        "Multiple address mappings can be combined": 0.8,
        "Use != 0 instead of > 0 for unsigned integers": 0.3,
        "Cache array length in loops": 0.6,
        "Prefix increments are cheaper than postfix": 0.4,
        "Short-circuit evaluation": 0.5,
        "Use custom errors instead of require with string message": 0.7,
        "Pack variables": 0.9
    }
    
    total_weight = 0
    weighted_count = 0
    
    for rec in recommendations:
        weight = weights.get(rec["type"], 0.5)
        total_weight += weight
        weighted_count += 1
    
    # Phi-harmonic scoring
    base_score = 1.0
    if weighted_count > 0:
        penalty = (total_weight / (weighted_count * PHI)) * LAMBDA
        score = max(0.0, base_score - penalty)
    else:
        score = base_score
    
    return round(score, 2)

def generate_optimization_report(analysis_result, output_dir=None):
    """
    Generate a comprehensive gas optimization report.
    
    Args:
        analysis_result: The result of analyze_contract()
        output_dir: Optional directory to write the report to
    
    Returns:
        The report as a dictionary and writes a JSON file if output_dir is provided
    """
    contract_name = analysis_result["contract_name"]
    recommendations = analysis_result["recommendations"]
    
    # Group recommendations by type
    grouped_recommendations = {}
    for rec in recommendations:
        rec_type = rec["type"]
        if rec_type not in grouped_recommendations:
            grouped_recommendations[rec_type] = []
        grouped_recommendations[rec_type].append(rec)
    
    # Calculate efficiency score
    phi_resonance = calculate_phi_resonance(recommendations)
    
    # Calculate total potential gas savings
    total_savings = sum(rec.get("estimated_savings", 0) for rec in recommendations)
    
    # Calculate savings by type
    savings_by_type = {}
    for rec_type, recs in grouped_recommendations.items():
        savings_by_type[rec_type] = sum(rec.get("estimated_savings", 0) for rec in recs)
    
    # Prepare report
    report = {
        "contract_name": contract_name,
        "file_path": analysis_result["file_path"],
        "phi_resonance_score": phi_resonance,
        "optimization_count": len(recommendations),
        "total_gas_savings": total_savings,
        "savings_by_type": savings_by_type,
        "optimization_summary": {
            rec_type: len(recs) for rec_type, recs in grouped_recommendations.items()
        },
        "detailed_recommendations": grouped_recommendations
    }
    
    # Write report to file if output directory provided
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        report_path = os.path.join(output_dir, f"gas_report_{contract_name}.json")
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Also generate a human-readable text report
        txt_report_path = os.path.join(output_dir, f"gas_report_{contract_name}.txt")
        with open(txt_report_path, 'w') as f:
            f.write(f"Gas Optimization Report for {contract_name}\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Phi-Resonance Score: {phi_resonance:.2f}/1.0\n")
            f.write(f"Total Optimization Opportunities: {len(recommendations)}\n")
            f.write(f"Estimated Gas Savings: {total_savings:,} gas units\n\n")
            
            f.write("Optimization Summary (sorted by potential savings):\n")
            f.write("-"*60 + "\n")
            
            # Sort by savings
            sorted_types = sorted(savings_by_type.items(), key=lambda x: x[1], reverse=True)
            for rec_type, savings in sorted_types:
                count = report["optimization_summary"][rec_type]
                f.write(f"- {rec_type}: {count} instances, ~{savings:,} gas\n")
            
            f.write("\nDetailed Recommendations:\n")
            f.write("-"*60 + "\n")
            
            # Sort types by savings for the detailed section too
            for rec_type, savings in sorted_types:
                recs = grouped_recommendations[rec_type]
                f.write(f"\n{rec_type} (~{savings:,} gas savings):\n")
                f.write("-"*60 + "\n")
                
                # Get the recommendation text (same for all instances of this type)
                recommendation = recs[0]["recommendation"]
                f.write(f"Recommendation: {recommendation}\n\n")
                
                for i, rec in enumerate(recs):
                    f.write(f"Instance {i+1} (Line {rec['line']}, ~{rec.get('estimated_savings', 0):,} gas):\n")
                    
                    # Show code context
                    if "context" in rec:
                        for j, context_line in enumerate(rec["context"]):
                            line_num = rec["line"] - 3 + j
                            if line_num == rec["line"]:
                                f.write(f"-> {line_num}: {context_line}\n")
                            else:
                                f.write(f"   {line_num}: {context_line}\n")
                    else:
                        f.write(f"-> {rec['line']}: {rec['code']}\n")
                    
                    f.write("\n")
    
    return report

def generate_array_length_caching_fix(recommendation, content):
    """
    Generate automatic fix for caching array length in loops.
    
    Args:
        recommendation: The recommendation dict with line, code, etc.
        content: The full content of the file
        
    Returns:
        A dict with fix information:
        - original_code: The original code snippet
        - fixed_code: The fixed code snippet
        - line_range: Range of lines affected (start, end)
    """
    line_num = recommendation['line']
    code_line = recommendation['code']
    lines = content.split('\n')
    
    # Find the array name from the pattern
    match = re.search(r'for\s*\(\s*\w+\s*=\s*0\s*;\s*(\w+)\s*<\s*(\w+)\.length\s*;', code_line)
    if not match:
        return None
    
    index_var = match.group(1)
    array_name = match.group(2)
    
    # Find the containing block by checking indentation
    start_line = max(0, line_num - 5)  # Look a few lines back to find the context
    context_lines = lines[start_line:line_num]
    
    # Generate the fix with proper indentation
    # We'll insert the length caching line before the for loop
    if context_lines:
        # Try to detect the indentation from the context
        indent = ''
        for line in reversed(context_lines):
            if line.strip():
                # Get the whitespace prefix of the non-empty line
                indent_match = re.match(r'^(\s*)', line)
                if indent_match:
                    indent = indent_match.group(1)
                break
    else:
        # Default indentation if we can't detect it
        indent = '    '
    
    # Get the original loop head and the following line
    original_snippet = lines[line_num - 1]
    if line_num < len(lines):
        original_snippet += '\n' + lines[line_num]
    
    # Create the fixed snippet with array length caching
    len_var_name = f"{array_name}Length"
    fixed_snippet = f"{indent}uint256 {len_var_name} = {array_name}.length;\n"
    fixed_snippet += f"{indent}for (uint256 {index_var} = 0; {index_var} < {len_var_name}; "
    
    # Preserve the increment part of the for loop
    increment_match = re.search(r'for\s*\([^;]*;[^;]*;\s*([^)]*)\)', code_line)
    if increment_match:
        increment = increment_match.group(1).strip()
        fixed_snippet += f"{increment})"
    else:
        # Default increment if we can't extract it
        fixed_snippet += f"++{index_var})"
    
    # Keep the rest of the line (e.g., opening brace)
    rest_match = re.search(r'\)[^\n]*', code_line)
    if rest_match:
        fixed_snippet += rest_match.group(0)
    
    # If possible, include the next line to show more context in the fix
    if line_num < len(lines):
        fixed_snippet += '\n' + lines[line_num]
    
    return {
        'original_code': original_snippet,
        'fixed_code': fixed_snippet,
        'line_range': (line_num, line_num + 1),
        'replacement_type': 'block',
        'description': f"Cached '{array_name}.length' in local variable '{len_var_name}' to avoid repeated storage reads in each loop iteration."
    }

def generate_custom_error_fix(recommendation, content):
    """
    Generate automatic fix for using custom errors instead of require with string messages.
    
    Args:
        recommendation: The recommendation dict with line, code, etc.
        content: The full content of the file
        
    Returns:
        A dict with fix information:
        - original_code: The original code snippet
        - fixed_code: The fixed code snippet
        - line_range: Range of lines affected (start, end)
        - contract_level_code: Code to add at the contract level (for custom error declarations)
    """
    line_num = recommendation['line']
    code_line = recommendation['code']
    
    # Extract the error message string from the require statement
    match = re.search(r'require\s*\([^,]+,\s*[\'"]([^\'"]+)[\'"]\s*\)', code_line)
    if not match:
        return None
    
    error_message = match.group(1)
    
    # Convert error message to a valid error name
    error_name = ''.join(word.capitalize() for word in re.sub(r'[^a-zA-Z0-9\s]', '', error_message).split())
    if not error_name:
        error_name = "CustomError"
    if not error_name[0].isalpha():
        error_name = "Error" + error_name
    error_name += "Error"
    
    # Extract the condition part of the require statement
    condition_match = re.search(r'require\s*\(([^,]+),', code_line)
    condition = condition_match.group(1).strip() if condition_match else ""
    
    # Get the indentation from the current line
    indent_match = re.match(r'^(\s*)', code_line)
    indent = indent_match.group(1) if indent_match else '    '
    
    # Create the fixed code
    original_snippet = code_line
    fixed_snippet = f"{indent}if (!{condition}) revert {error_name}();"
    
    # Create contract-level error declaration
    contract_level_code = f"error {error_name}(); // {error_message}"
    
    return {
        'original_code': original_snippet,
        'fixed_code': fixed_snippet,
        'line_range': (line_num, line_num),
        'replacement_type': 'line',
        'contract_level_code': contract_level_code,
        'description': f"Replaced require statement with custom error '{error_name}' for '{error_message}'"
    }

def generate_optimization_fix(recommendation, content):
    """
    Generate automatic fix for a gas optimization recommendation.
    
    Args:
        recommendation: The recommendation dict
        content: The full content of the file
        
    Returns:
        A dict with fix information or None if fix can't be generated
    """
    rec_type = recommendation['type']
    
    # Find the pattern info for this recommendation type
    pattern_info = None
    for pattern in GAS_PATTERNS:
        if pattern['name'] == rec_type:
            pattern_info = pattern
            break
    
    if not pattern_info or not pattern_info.get('can_auto_fix', False):
        return None
    
    fix_type = pattern_info.get('fix_type', '')
    
    if fix_type == 'direct_replacement':
        # Simple direct token replacement
        code_line = recommendation['code']
        replacement_map = pattern_info.get('replacement_map', {})
        fixed_line = code_line
        
        for old_str, new_str in replacement_map.items():
            fixed_line = re.sub(r'\b' + re.escape(old_str) + r'\b', new_str, fixed_line)
            
        if fixed_line != code_line:
            return {
                'original_code': code_line,
                'fixed_code': fixed_line,
                'line_range': (recommendation['line'], recommendation['line']),
                'replacement_type': 'line',
                'description': f"Replaced {rec_type.lower()}"
            }
    
    elif fix_type == 'regex_replacement':
        # More complex regex-based replacement
        code_line = recommendation['code']
        search_pattern = pattern_info.get('search_pattern', '')
        replacement = pattern_info.get('replacement', '')
        
        if search_pattern and replacement:
            fixed_line = re.sub(search_pattern, replacement, code_line)
            
            if fixed_line != code_line:
                return {
                    'original_code': code_line,
                    'fixed_code': fixed_line,
                    'line_range': (recommendation['line'], recommendation['line']),
                    'replacement_type': 'line',
                    'description': f"Implemented {rec_type.lower()}"
                }
    
    elif fix_type == 'advanced_replacement':
        # Call specialized function for more complex fixes
        fix_function_name = pattern_info.get('fix_function', '')
        if fix_function_name and fix_function_name in globals():
            fix_function = globals()[fix_function_name]
            return fix_function(recommendation, content)
    
    return None

def apply_optimization_fix(file_path, fix_info, dry_run=True):
    """
    Apply an optimization fix to a Solidity file.
    
    Args:
        file_path: Path to the Solidity file
        fix_info: Fix information dict
        dry_run: If True, only generate the changes without applying them
        
    Returns:
        A tuple of (success, message, new_content) where new_content is the updated file content
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Apply the fix
        if fix_info['replacement_type'] == 'line':
            # Line replacement
            lines = content.split('\n')
            line_num = fix_info['line_range'][0] - 1  # Convert to 0-indexed
            
            if 0 <= line_num < len(lines):
                lines[line_num] = fix_info['fixed_code']
                new_content = '\n'.join(lines)
            else:
                return (False, f"Line number {line_num+1} out of range", content)
        
        elif fix_info['replacement_type'] == 'block':
            # Block replacement (multiple lines)
            lines = content.split('\n')
            start_line = fix_info['line_range'][0] - 1  # Convert to 0-indexed
            end_line = fix_info['line_range'][1] - 1
            
            if 0 <= start_line <= end_line < len(lines):
                # Replace the block with the fixed code
                fixed_lines = fix_info['fixed_code'].split('\n')
                lines[start_line:end_line+1] = fixed_lines
                new_content = '\n'.join(lines)
            else:
                return (False, f"Line range {start_line+1}-{end_line+1} out of range", content)
        
        elif fix_info['replacement_type'] == 'full_content':
            # Replace entire file content
            new_content = fix_info['fixed_code']
        
        else:
            return (False, f"Unknown replacement type: {fix_info['replacement_type']}", content)
        
        # Add contract-level code if needed (like error declarations)
        if 'contract_level_code' in fix_info and fix_info['contract_level_code']:
            # Find appropriate place to insert the code (after contract declaration)
            contract_match = re.search(r'contract\s+(\w+)(?:\s+is\s+[^{]+)?\s*{', new_content)
            if contract_match:
                contract_end = contract_match.end()
                insertion_point = new_content.find('\n', contract_end) + 1
                
                if insertion_point > 0:
                    # Add indentation to the contract-level code
                    indent = '    '  # Default indentation
                    contract_level_code = indent + fix_info['contract_level_code']
                    
                    # Insert the code at the insertion point
                    new_content = new_content[:insertion_point] + contract_level_code + '\n' + new_content[insertion_point:]
        
        if not dry_run:
            # Write the changes back to the file
            with open(file_path, 'w') as f:
                f.write(new_content)
            
            return (True, f"Applied {fix_info['description']}", new_content)
        else:
            return (True, f"Would apply: {fix_info['description']} (dry run)", new_content)
    
    except Exception as e:
        return (False, f"Error applying fix: {str(e)}", content if 'content' in locals() else "")

def generate_auto_fix_preview(file_path, recommendation_id):
    """
    Generate a preview of an automatic fix for a specific recommendation.
    
    Args:
        file_path: Path to the Solidity file
        recommendation_id: ID of the recommendation to fix (index in the recommendations list)
    
    Returns:
        A dict with fix preview information:
        - success: Whether the fix could be generated
        - message: Information message
        - original_code: The original code snippet
        - fixed_code: The fixed code snippet
        - description: Description of the fix
    """
    try:
        # Analyze the contract
        analysis = analyze_contract(file_path)
        recommendations = analysis['recommendations']
        
        if not recommendations:
            return {
                'success': False,
                'message': "No optimization recommendations found for this contract."
            }
        
        # Get the specific recommendation
        if recommendation_id < 0 or recommendation_id >= len(recommendations):
            return {
                'success': False,
                'message': f"Recommendation ID {recommendation_id} out of range (0-{len(recommendations)-1})."
            }
        
        recommendation = recommendations[recommendation_id]
        
        # Get the file content
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Generate the fix
        fix_info = generate_optimization_fix(recommendation, content)
        
        if not fix_info:
            return {
                'success': False,
                'message': f"Cannot automatically fix this issue: {recommendation['type']}",
                'recommendation': recommendation
            }
        
        # Return fix preview
        return {
            'success': True,
            'message': "Auto-fix preview generated successfully",
            'original_code': fix_info['original_code'],
            'fixed_code': fix_info['fixed_code'],
            'description': fix_info['description'],
            'recommendation': recommendation,
            'fix_info': fix_info
        }
    
    except Exception as e:
        return {
            'success': False,
            'message': f"Error generating fix preview: {str(e)}"
        }

def apply_auto_fix(file_path, recommendation_id, dry_run=False):
    """
    Apply an automatic fix for a specific recommendation.
    
    Args:
        file_path: Path to the Solidity file
        recommendation_id: ID of the recommendation to fix
        dry_run: If True, only generate the changes without applying them
    
    Returns:
        A dict with fix result information
    """
    # Generate the fix preview first
    preview = generate_auto_fix_preview(file_path, recommendation_id)
    
    if not preview['success']:
        return preview
    
    # Apply the fix
    success, message, new_content = apply_optimization_fix(file_path, preview['fix_info'], dry_run)
    
    return {
        'success': success,
        'message': message,
        'original_code': preview['original_code'],
        'fixed_code': preview['fixed_code'],
        'description': preview['description'],
        'recommendation': preview['recommendation']
    }

def main():
    """Command-line interface for the gas optimizer."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze Solidity contracts for gas optimization')
    parser.add_argument('contract', help='Path to the Solidity contract file')
    parser.add_argument('--output', '-o', help='Directory to write the report to')
    parser.add_argument('--verbose', '-v', action='store_true', help='Display detailed recommendations')
    parser.add_argument('--fix', type=int, help='Apply automatic fix for recommendation ID')
    parser.add_argument('--dry-run', action='store_true', help='Show fix without applying it')
    
    args = parser.parse_args()
    
    try:
        # If --fix is specified, apply the fix
        if args.fix is not None:
            result = apply_auto_fix(args.contract, args.fix, args.dry_run)
            
            if result['success']:
                print(f"\nAutomatic fix for recommendation {args.fix}:")
                print(f"Description: {result['description']}")
                print("\nOriginal code:")
                print(f"{result['original_code']}")
                print("\nFixed code:")
                print(f"{result['fixed_code']}")
                print(f"\n{result['message']}")
            else:
                print(f"\nError: {result['message']}")
            
            return 0
        
        # Otherwise, perform analysis
        analysis = analyze_contract(args.contract)
        report = generate_optimization_report(analysis, args.output)
        
        # Print summary
        print(f"\nGas Optimization Analysis for {report['contract_name']}")
        print("="*60)
        print(f"Phi-Resonance Score: {report['phi_resonance_score']:.2f}/1.0")
        print(f"Total Optimization Opportunities: {report['optimization_count']}")
        
        if report['optimization_count'] > 0:
            # Show total potential gas savings
            print(f"Estimated Total Gas Savings: {report['total_gas_savings']:,} gas units")
            print(f"Approximate Cost Reduction: ~${report['total_gas_savings'] * 0.00000002:.2f} at 100 gwei")
            
            print("\nOptimization Summary (sorted by savings):")
            # Sort by savings
            sorted_types = sorted(report["savings_by_type"].items(), key=lambda x: x[1], reverse=True)
            for rec_type, savings in sorted_types:
                count = report["optimization_summary"][rec_type]
                print(f"- {rec_type}: {count} instances, ~{savings:,} gas")
            
            # Show detailed recommendations if verbose flag is set
            if args.verbose:
                print("\nTop Recommendations (with auto-fix info):")
                top_recs = sorted(analysis["recommendations"], key=lambda x: x.get("estimated_savings", 0), reverse=True)
                
                for i, rec in enumerate(top_recs):
                    # Find the pattern info for this recommendation type
                    can_auto_fix = False
                    for pattern in GAS_PATTERNS:
                        if pattern['name'] == rec['type']:
                            can_auto_fix = pattern.get('can_auto_fix', False)
                            break
                    
                    auto_fix_info = f"[Auto-fixable: Use --fix {i}]" if can_auto_fix else "[Manual fix required]"
                    
                    print(f"\n{i}. {rec['type']} (Line {rec['line']}, ~{rec.get('estimated_savings', 0):,} gas) {auto_fix_info}")
                    print(f"   Recommendation: {rec['recommendation']}")
                    
                    # Print code context
                    if "context" in rec:
                        print("\n   Code context:")
                        for j, context_line in enumerate(rec["context"]):
                            line_num = rec["line"] - 3 + j
                            if line_num == rec["line"]:
                                print(f"   -> {line_num}: {context_line}")
                            else:
                                print(f"      {line_num}: {context_line}")
            
            if args.output:
                contract_name = report["contract_name"]
                print("\nDetailed reports saved to:")
                print(f"- {os.path.join(args.output, f'gas_report_{contract_name}.json')}")
                print(f"- {os.path.join(args.output, f'gas_report_{contract_name}.txt')}")
                print("\nFor complete optimization details, check the text report.")
        else:
            print("\nCongratulations! Your contract appears to be well-optimized for gas efficiency.")
    
    except Exception as e:
        print(f"Error analyzing contract: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())